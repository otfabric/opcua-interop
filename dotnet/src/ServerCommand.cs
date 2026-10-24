// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Configuration;
using Opc.Ua.Identity;
using Opc.Ua.Server;

namespace OpcUaInterop
{
    /// <summary>The adapter's OPC UA server: StandardServer + the fixture node manager.</summary>
    internal sealed class InteropServer : StandardServer
    {
        private readonly Fixture m_fixture;

        public InteropServer(ITelemetryContext telemetry, Fixture fixture) : base(telemetry)
        {
            m_fixture = fixture;
        }

        public InteropNodeManager Interop { get; private set; }

        protected override IMasterNodeManager CreateMasterNodeManager(IServerInternal server, ApplicationConfiguration configuration)
        {
            Interop = new InteropNodeManager(server, configuration, m_fixture);
            return new MasterNodeManager(server, configuration, null, Interop);
        }

        protected override void OnServerStarted(IServerInternal server)
        {
            base.OnServerStarted(server);
            server.IdentityRegistry.Register(new FixtureUserAuthenticator(m_fixture));
        }

        protected override ServerProperties LoadServerProperties()
        {
            ServerProperties p = base.LoadServerProperties();
            p.ManufacturerName = "OTFabric";
            p.ProductName = "opcua-interop-dotnet";
            p.ProductUri = m_fixture.Server.ProductUri;
            p.SoftwareVersion = Capabilities.AdapterVersion;
            p.BuildNumber = Capabilities.StackVersion;
            return p;
        }
    }

    /// <summary>UserName tokens checked against the fixture users.</summary>
    internal sealed class FixtureUserAuthenticator : IUserTokenAuthenticator
    {
        private readonly Fixture m_fixture;

        public FixtureUserAuthenticator(Fixture fixture)
        {
            m_fixture = fixture;
        }

        public UserTokenType TokenType => UserTokenType.UserName;

        public string IssuedTokenProfileUri => null;

        public ValueTask<AuthenticationResult> AuthenticateAsync(AuthenticationContext context, CancellationToken ct = default)
        {
            if (context.TokenHandler is not UserNameIdentityTokenHandler userName)
            {
                return new ValueTask<AuthenticationResult>(AuthenticationResult.NotHandled);
            }
            string password = userName.DecryptedPassword == null
                ? string.Empty
                : System.Text.Encoding.UTF8.GetString(userName.DecryptedPassword.ToArray());
            bool ok = m_fixture.Users.Any(u => u.Username == userName.UserName && (u.Password ?? string.Empty) == password);
            return new ValueTask<AuthenticationResult>(ok
                ? AuthenticationResult.Accept(new UserIdentity(userName))
                : AuthenticationResult.Reject(new ServiceResult(StatusCodes.BadUserAccessDenied)));
        }
    }

    internal static class ServerCommand
    {
        private static readonly string[] s_refused =
        [
            "--lds", "--lds-cleanup-timeout", "--mdns-name", "--mdns-capability",
            "--reverse-connect", "--reverse-connect-interval-ms"
        ];

        /// <summary>ECC endpoints (off: see the comment in RunAsync).</summary>
        private static readonly bool EccEnabled = Environment.GetEnvironmentVariable("OPCUA_INTEROP_DOTNET_ECC") == "1";

        public static async Task<int> RunAsync(string[] args)
        {
            var a = new Args(args);
            foreach (string flag in s_refused)
            {
                if (a.Has(flag))
                {
                    Console.Error.WriteLine("[dotnet] error: " + flag + " is not supported by this adapter: " + RefusalReason(flag));
                    return 2;
                }
            }

            string fixturePath = a.Get("--fixture") ?? Environment.GetEnvironmentVariable("OPCUA_FIXTURE");
            if (fixturePath == null)
            {
                Console.Error.WriteLine("[dotnet] error: missing --fixture");
                return 1;
            }
            Fixture fixture;
            try
            {
                fixture = Fixture.Load(fixturePath);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet] error: fixture " + fixturePath + ": " + e.Message);
                return 1;
            }

            string bindAddress = a.Get("--bind-address") ?? "0.0.0.0";
            int bindPort = a.GetInt("--bind-port", fixture.Endpoint.Port);
            string advertisedHost = a.Get("--advertised-host") ?? "localhost";
            int advertisedPort = a.GetInt("--advertised-port", bindPort);
            string path = a.Get("--endpoint-path") ?? fixture.Endpoint.Path ?? "/";
            if (!path.StartsWith('/'))
            {
                path = "/" + path;
            }
            bool readyExplicit = a.Has("--ready-file");
            string readyFile = a.Get("--ready-file") ?? Environment.GetEnvironmentVariable("OPCUA_READY_FILE") ?? "/run/opcua-interop/ready";
            string pkiDir = a.Get("--pki-dir") ?? "/run/opcua-interop/pki";
            string certFile = a.Get("--certificate");
            string keyFile = a.Get("--private-key");
            string pubsubConfig = a.Get("--pubsub-config");
            if (pubsubConfig != null && !File.Exists(pubsubConfig))
            {
                Console.Error.WriteLine("[dotnet] error: --pubsub-config: " + pubsubConfig + ": no such file");
                return 1;
            }
            string eccDir = a.Get("--ecc-dir");
            if (eccDir != null && !EccEnabled)
            {
                Console.Error.WriteLine("[dotnet] warn: --ecc-dir ignored: UA-.NETStandard 2.0.1 does not accept the test PKI's RSA-CA-signed ECC application certificates");
            }
            string registerWith = a.Get("--register-with");
            int registerIntervalMs = Math.Max(500, a.GetInt("--register-interval-ms", 30000));

            string advertised = "opc.tcp://" + advertisedHost + ":" + advertisedPort.ToString(Inv.C) + path;
            Console.Error.WriteLine("[dotnet] info: fixture " + fixture.Id + ", advertised endpoint " + advertised + " (bind " + bindAddress + ":" + bindPort.ToString(Inv.C) + ")");
            if (bindAddress != "0.0.0.0" && bindAddress != "::")
            {
                Console.Error.WriteLine("[dotnet] warn: --bind-address " + bindAddress + ": the .NET TCP listener binds every interface of the base address port");
            }

            TryDelete(readyFile);

            ITelemetryContext telemetry = Telemetry.Create("dotnet");

            // ── PKI: the stack's directory stores, filled from the PEM test PKI ──
            string storeRoot = Pki.TempDir("opcua-dotnet-server-pki");
            var certIds = new List<CertificateIdentifier>();
            var policies = new List<(MessageSecurityMode Mode, string Uri)>();
            string applicationUri = fixture.Server.ApplicationUri;
            bool secure = certFile != null && keyFile != null;
            if (secure)
            {
                X509Certificate2 rsa;
                try
                {
                    rsa = Pki.LoadWithKey(certFile, keyFile);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("[dotnet] error: cannot load server certificate or key: " + e.Message);
                    return 6;
                }
                applicationUri = Pki.ApplicationUri(rsa) ?? applicationUri;
                string own = Path.Combine(storeRoot, "own");
                Pki.WriteOwn(own, "rsa", rsa);
                certIds.Add(new CertificateIdentifier
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = own,
                    SubjectName = rsa.Subject,
                    Thumbprint = rsa.Thumbprint,
                    CertificateType = ObjectTypeIds.RsaSha256ApplicationCertificateType
                });

                var eccLoaded = new HashSet<string>();
                foreach (Fixture.SecurityProfileDef sp in fixture.SecurityProfiles)
                {
                    string uri = Pki.PolicyUri(sp.SecurityPolicy);
                    MessageSecurityMode mode = Pki.Mode(sp.SecurityMode);
                    if (uri == null || mode == MessageSecurityMode.Invalid || mode == MessageSecurityMode.None)
                    {
                        continue;
                    }
                    string ecc = Pki.EccDir(sp.SecurityPolicy);
                    if (ecc != null)
                    {
                        // UA-.NETStandard 2.0.1 classifies an application certificate by its
                        // *signature* algorithm (CertificateIdentifier.ValidateCertificateType):
                        // the test PKI's ECC certificates are issued by the RSA test CA, so the
                        // stack never finds them as ECC application certificates. ECC endpoints
                        // are therefore not offered (see dotnet/README.md).
                        if (eccDir == null || !EccEnabled)
                        {
                            continue;
                        }
                        if (!eccLoaded.Contains(ecc))
                        {
                            string ec = Path.Combine(eccDir, ecc, "cert.crt");
                            string ek = Path.Combine(eccDir, ecc, "cert.key");
                            if (!File.Exists(ec) || !File.Exists(ek))
                            {
                                Console.Error.WriteLine("[dotnet] info: no " + ecc + " certificate in --ecc-dir; skipping " + sp.SecurityPolicy);
                                continue;
                            }
                            try
                            {
                                X509Certificate2 eccCert = Pki.LoadWithKey(ec, ek);
                                Pki.WriteOwn(own, ecc, eccCert);
                                certIds.Add(new CertificateIdentifier
                                {
                                    StoreType = CertificateStoreType.Directory,
                                    StorePath = own,
                                    SubjectName = eccCert.Subject,
                                    Thumbprint = eccCert.Thumbprint,
                                    CertificateType = Pki.EccCertificateType(sp.SecurityPolicy)
                                });
                                eccLoaded.Add(ecc);
                            }
                            catch (Exception e)
                            {
                                Console.Error.WriteLine("[dotnet] info: skipping " + sp.SecurityPolicy + ": " + e.Message);
                                continue;
                            }
                        }
                    }
                    policies.Add((mode, uri));
                }

                int trusted = Pki.CopyCertificates(Path.Combine(pkiDir, "trusted", "certs"), Path.Combine(storeRoot, "trusted"));
                Pki.CopyCrls(Path.Combine(pkiDir, "trusted", "crl"), Path.Combine(storeRoot, "trusted"));
                Pki.CopyCertificates(Path.Combine(pkiDir, "issuers", "certs"), Path.Combine(storeRoot, "issuer"));
                Pki.CopyCrls(Path.Combine(pkiDir, "issuers", "crl"), Path.Combine(storeRoot, "issuer"));
                Console.Error.WriteLine("[dotnet] info: server certificate " + rsa.Subject + " (" + applicationUri + "), " + trusted.ToString(Inv.C) + " trusted certificate(s)");
            }

            string rejectedRoot = Path.Combine(pkiDir, "rejected");
            try
            {
                Directory.CreateDirectory(Path.Combine(rejectedRoot, "certs"));
            }
            catch (Exception)
            {
                rejectedRoot = Path.Combine(storeRoot, "rejected");
            }

            ApplicationConfiguration config;
            string baseAddress;
            try
            {
                var app = new ApplicationInstance(telemetry)
                {
                    ApplicationName = fixture.Server.ApplicationName,
                    ApplicationType = ApplicationType.Server
                };
                baseAddress = "opc.tcp://" + advertisedHost + ":" + bindPort.ToString(Inv.C) + path;
                IApplicationConfigurationBuilderServerSelected sb = app
                    .Build(applicationUri, fixture.Server.ProductUri)
                    .AsServer([baseAddress])
                    .AddUnsecurePolicyNone();
                foreach ((MessageSecurityMode mode, string uri) in policies)
                {
                    sb = sb.AddPolicy(mode, uri);
                }
                sb = sb.AddUserTokenPolicy(UserTokenType.Anonymous);
                if (fixture.Users.Count > 0)
                {
                    sb = sb.AddUserTokenPolicy(UserTokenType.UserName);
                }
                sb.SetMinPublishingInterval(10)
                  .SetMinSubscriptionLifetime(1000)
                  .SetMaxNotificationQueueSize(1000)
                  .SetMinSupportedSamplingInterval(0)
                  .SetDiagnosticsEnabled(false)
                  .SetShutdownDelay(0);

                if (certIds.Count == 0)
                {
                    // the None endpoint still needs an application instance certificate: a
                    // self-signed one is created in the temporary store
                    certIds.Add(new CertificateIdentifier
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = Path.Combine(storeRoot, "own"),
                        SubjectName = "CN=opcua-interop dotnet server, O=OTFabric",
                        CertificateType = ObjectTypeIds.RsaSha256ApplicationCertificateType
                    });
                }

                config = await sb
                    .AddSecurityConfiguration(new ArrayOf<CertificateIdentifier>(certIds.ToArray()), storeRoot, rejectedRoot)
                    .SetAutoAcceptUntrustedCertificates(false)
                    .SetRejectSHA1SignedCertificates(true)
                    .SetRejectUnknownRevocationStatus(false)
                    .SetAddAppCertToTrustedStore(false)
                    .CreateAsync()
                    .ConfigureAwait(false);

                // the builder replaces "localhost" with the host name; the contract advertises
                // --advertised-host verbatim (default localhost)
                config.ServerConfiguration.BaseAddresses = new[] { baseAddress };

                ApplicationInstance.MessageDlg = new AutoApproveDialog();
                bool haveCert = await app.CheckApplicationInstanceCertificatesAsync(false, null).ConfigureAwait(false);
                if (!haveCert)
                {
                    Console.Error.WriteLine("[dotnet] error: application instance certificate invalid");
                    return 6;
                }

                var server = new InteropServer(telemetry, fixture);
                await app.StartAsync(server).ConfigureAwait(false);

                // §14.1: the PubSub configuration is in place before the ready file is written.
                PubSubServer pubsub = null;
                if (pubsubConfig != null)
                {
                    try
                    {
                        pubsub = await PubSubServer.StartAsync(pubsubConfig, server, telemetry).ConfigureAwait(false);
                    }
                    catch (Exception e)
                    {
                        string reason = e is PubSubConfigException or ServiceResultException ? e.Message : e.GetType().Name + ": " + e.Message;
                        Console.Error.WriteLine("[dotnet] error: --pubsub-config: " + reason);
                        await server.StopAsync().ConfigureAwait(false);
                        return 1;
                    }
                }

                foreach (EndpointDescription ep in server.GetEndpoints())
                {
                    Console.Error.WriteLine("[dotnet] info: endpoint " + ep.EndpointUrl + " " + Pki.PolicyName(ep.SecurityPolicyUri) + "/" + ep.SecurityMode);
                }

                try
                {
                    WriteReadyFile(readyFile, fixture.Id, advertised);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("[dotnet] error: cannot write ready file " + readyFile + ": " + e.Message);
                    if (readyExplicit || true)
                    {
                        return 6;
                    }
                }

                using var stop = new CancellationTokenSource();
                using PosixSignalRegistration sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx =>
                {
                    ctx.Cancel = true;
                    stop.Cancel();
                });
                using PosixSignalRegistration sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx =>
                {
                    ctx.Cancel = true;
                    stop.Cancel();
                });

                Registrar registrar = null;
                if (registerWith != null)
                {
                    registrar = new Registrar(config, telemetry, registerWith, applicationUri, fixture, advertised, registerIntervalMs);
                    registrar.Start(stop.Token);
                }

                try
                {
                    await Task.Delay(Timeout.Infinite, stop.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // shutdown
                }
                Console.Error.WriteLine("[dotnet] info: shutdown signal received");
                if (registrar != null)
                {
                    await registrar.UnregisterAsync().ConfigureAwait(false);
                }
                if (pubsub != null)
                {
                    await pubsub.DisposeAsync().ConfigureAwait(false);
                }
                try
                {
                    await server.StopAsync().ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("[dotnet] warn: stop: " + e.Message);
                }
                TryDelete(readyFile);
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet] error: server start failed: " + e);
                return 1;
            }
        }

        private static string RefusalReason(string flag) => flag switch
        {
            "--lds" or "--lds-cleanup-timeout" => "the adapter server is not a Local Discovery Server",
            "--mdns-name" or "--mdns-capability" => "mDNS announcement is not implemented by the adapter",
            "--reverse-connect" or "--reverse-connect-interval-ms" => "server reverse connect is not wired in this adapter",
            _ => "unsupported"
        };

        private static void TryDelete(string path)
        {
            try
            {
                File.Delete(path);
            }
            catch (Exception)
            {
                // ignore
            }
        }

        private static void WriteReadyFile(string path, string fixtureId, string endpoint)
        {
            string dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            var o = new JsonObject
            {
                ["ready"] = true,
                ["adapter"] = Result.Adapter,
                ["fixture"] = fixtureId,
                ["endpoint"] = endpoint
            };
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, Json.Serialize(o) + "\n");
            File.Move(tmp, path, true);
            Console.Error.WriteLine("[dotnet] info: ready file written: " + path);
        }
    }
}
