// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Configuration;
using Opc.Ua.Gds.Server;
using Opc.Ua.Gds.Server.Database.Linq;
using Opc.Ua.Server;
using Opc.Ua.Server.UserDatabase;

namespace OpcUaInterop
{
    /// <summary>
    /// The adapter's Global Discovery Server: the stack's GlobalDiscoverySampleServer
    /// (ApplicationsNodeManager with autoApprove, a JSON applications database in a temporary
    /// directory, the default CertificateGroup) with the fixture users and the adapter's BuildInfo.
    /// </summary>
    internal sealed class InteropGdsServer : GlobalDiscoverySampleServer
    {
        private readonly Fixture m_fixture;
        private readonly IUserDatabase m_users;

        public InteropGdsServer(Fixture fixture, JsonApplicationsDatabase database, ICertificateGroup group, IUserDatabase users)
            : base(database, database, group, users, autoApprove: true)
        {
            m_fixture = fixture;
            m_users = users;
        }

        protected override void OnServerStarted(IServerInternal server)
        {
            // the sample server's handler grants the user database roles (GdsRoleBasedIdentity);
            // this one, registered after it, rejects unknown users and wrong passwords
            base.OnServerStarted(server);
            server.SessionManager.ImpersonateUser += RejectInvalidUser;
        }

        private void RejectInvalidUser(Opc.Ua.Server.ISession session, ImpersonateEventArgs args)
        {
            if (args.NewIdentity is UserNameIdentityToken token &&
                !m_users.CheckCredentials(token.UserName, token.DecryptedPassword))
            {
                args.IdentityValidationError = new ServiceResult(StatusCodes.BadUserAccessDenied);
            }
        }

        protected override ServerProperties LoadServerProperties()
        {
            return new ServerProperties
            {
                ManufacturerName = "OTFabric",
                ProductName = "opcua-interop-dotnet-gds",
                ProductUri = m_fixture.Server.ProductUri,
                SoftwareVersion = Capabilities.AdapterVersion,
                BuildNumber = Capabilities.StackVersion,
                BuildDate = DateTime.UtcNow
            };
        }
    }

    internal static class GdsServerCommand
    {
        private static readonly string[] s_refused =
        [
            "--lds", "--lds-cleanup-timeout", "--mdns-name", "--mdns-capability",
            "--reverse-connect", "--reverse-connect-interval-ms", "--pubsub-config",
            "--https-port", "--wss-port", "--register-with"
        ];

        /// <summary>Fixture role names (BrowseNames) → the stack's roles.</summary>
        private static readonly Dictionary<string, Role> s_roles = new()
        {
            ["Observer"] = Role.Observer,
            ["Operator"] = Role.Operator,
            ["Engineer"] = Role.Engineer,
            ["Supervisor"] = Role.Supervisor,
            ["ConfigureAdmin"] = Role.ConfigureAdmin,
            ["SecurityAdmin"] = Role.SecurityAdmin,
            ["DiscoveryAdmin"] = GdsRole.DiscoveryAdmin,
            ["CertificateAuthorityAdmin"] = GdsRole.CertificateAuthorityAdmin,
            ["RegistrationAuthorityAdmin"] = GdsRole.RegistrationAuthorityAdmin
        };

        public static async Task<int> RunAsync(string[] args)
        {
            var a = new Args(args);
            foreach (string flag in s_refused)
            {
                if (a.Has(flag))
                {
                    Console.Error.WriteLine("[dotnet-gds] error: " + flag + " is not supported by the GDS adapter");
                    return 2;
                }
            }

            string fixturePath = a.Get("--fixture") ?? Environment.GetEnvironmentVariable("OPCUA_FIXTURE");
            if (fixturePath == null)
            {
                Console.Error.WriteLine("[dotnet-gds] error: missing --fixture");
                return 1;
            }
            Fixture fixture;
            try
            {
                fixture = Fixture.Load(fixturePath);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet-gds] error: fixture " + fixturePath + ": " + e.Message);
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
            string readyFile = a.Get("--ready-file") ?? Environment.GetEnvironmentVariable("OPCUA_READY_FILE") ?? "/run/opcua-interop/ready";
            string pkiDir = a.Get("--pki-dir") ?? "/run/opcua-interop/pki";
            string certFile = a.Get("--certificate");
            string keyFile = a.Get("--private-key");

            string advertised = "opc.tcp://" + advertisedHost + ":" + advertisedPort.ToString(Inv.C) + path;
            Console.Error.WriteLine("[dotnet-gds] info: fixture " + fixture.Id + ", advertised endpoint " + advertised + " (bind " + bindAddress + ":" + bindPort.ToString(Inv.C) + ")");
            TryDelete(readyFile);

            ITelemetryContext telemetry = Telemetry.Create("dotnet-gds");

            // ── PKI: the stack's directory stores, filled from the PEM test PKI ──
            string storeRoot = Pki.TempDir("opcua-dotnet-gds");
            string own = Path.Combine(storeRoot, "own");
            var certIds = new CertificateIdentifierCollection();
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
                    Console.Error.WriteLine("[dotnet-gds] error: cannot load server certificate or key: " + e.Message);
                    return 6;
                }
                applicationUri = Pki.ApplicationUri(rsa) ?? applicationUri;
                Pki.WriteOwn(own, "rsa", rsa);
                certIds.Add(new CertificateIdentifier
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = own,
                    SubjectName = rsa.Subject,
                    Thumbprint = rsa.Thumbprint,
                    CertificateType = ObjectTypeIds.RsaSha256ApplicationCertificateType
                });
                int trusted = Pki.CopyCertificates(Path.Combine(pkiDir, "trusted", "certs"), Path.Combine(storeRoot, "trusted"));
                Pki.CopyCrls(Path.Combine(pkiDir, "trusted", "crl"), Path.Combine(storeRoot, "trusted"));
                Pki.CopyCertificates(Path.Combine(pkiDir, "issuers", "certs"), Path.Combine(storeRoot, "issuer"));
                Pki.CopyCrls(Path.Combine(pkiDir, "issuers", "crl"), Path.Combine(storeRoot, "issuer"));
                Console.Error.WriteLine("[dotnet-gds] info: server certificate " + rsa.Subject + " (" + applicationUri + "), " + trusted.ToString(Inv.C) + " trusted certificate(s)");
            }
            else
            {
                // the None endpoint still needs an application instance certificate: a
                // self-signed one is created in the temporary store
                certIds.Add(new CertificateIdentifier
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = own,
                    SubjectName = "CN=opcua-interop dotnet-gds server, O=OTFabric",
                    CertificateType = ObjectTypeIds.RsaSha256ApplicationCertificateType
                });
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

            // ── GDS: database, CA store, application certificates ──
            string gdsRoot = Path.Combine(storeRoot, "gds");
            Directory.CreateDirectory(gdsRoot);
            var gdsConfig = new GlobalDiscoveryServerConfiguration
            {
                AuthoritiesStorePath = Path.Combine(gdsRoot, "authorities"),
                ApplicationCertificatesStorePath = Path.Combine(gdsRoot, "applications"),
                DefaultSubjectNameContext = "O=OTFabric",
                CertificateGroups =
                [
                    new CertificateGroupConfiguration
                    {
                        Id = "Default",
                        CertificateTypes = new StringCollection(GroupCertificateTypes),
                        SubjectName = "CN=opcua-interop dotnet-gds CA, O=OTFabric",
                        BaseStorePath = Path.Combine(gdsRoot, "CA", "default"),
                        DefaultCertificateHashSize = 256,
                        DefaultCertificateKeySize = 2048,
                        DefaultCertificateLifetime = 12,
                        CACertificateHashSize = 256,
                        CACertificateKeySize = 2048,
                        CACertificateLifetime = 60
                    }
                ],
                DatabaseStorePath = Path.Combine(gdsRoot, "gdsdb.json"),
                UsersDatabaseStorePath = Path.Combine(gdsRoot, "gdsusersdb.json")
            };

            try
            {
                var app = new ApplicationInstance(telemetry)
                {
                    ApplicationName = fixture.Server.ApplicationName,
                    ApplicationType = ApplicationType.Server
                };
                string baseAddress = "opc.tcp://" + advertisedHost + ":" + bindPort.ToString(Inv.C) + path;
                IApplicationConfigurationBuilderServerSelected sb = app
                    .Build(applicationUri, fixture.Server.ProductUri)
                    .AsServer([baseAddress])
                    .AddUnsecurePolicyNone();
                if (secure)
                {
                    foreach ((string policy, string mode) in Capabilities.SecurityProfiles)
                    {
                        if (policy != "None")
                        {
                            sb = sb.AddPolicy(Pki.Mode(mode), Pki.PolicyUri(policy));
                        }
                    }
                }
                ApplicationConfiguration config = await sb
                    .AddUserTokenPolicy(UserTokenType.Anonymous)
                    .AddUserTokenPolicy(UserTokenType.UserName)
                    .SetDiagnosticsEnabled(false)
                    .AddServerCapabilities("GDS")
                    .AddServerProfile("http://opcfoundation.org/UA-Profile/Server/GlobalDiscoveryAndCertificateManagement2017")
                    .SetShutdownDelay(0)
                    .AddSecurityConfiguration(certIds, storeRoot, rejectedRoot)
                    .SetAutoAcceptUntrustedCertificates(false)
                    .SetRejectSHA1SignedCertificates(true)
                    .SetRejectUnknownRevocationStatus(false)
                    .SetMinimumCertificateKeySize(1024)
                    .SetAddAppCertToTrustedStore(false)
                    .AddExtension<GlobalDiscoveryServerConfiguration>(null, gdsConfig)
                    .CreateAsync()
                    .ConfigureAwait(false);

                // the builder replaces "localhost" with the host name; the contract advertises
                // --advertised-host verbatim (default localhost)
                config.ServerConfiguration.BaseAddresses = [baseAddress];

                ApplicationInstance.MessageDlg = new AutoApproveDialog();
                bool haveCert = await app.CheckApplicationInstanceCertificatesAsync(false).ConfigureAwait(false);
                if (!haveCert)
                {
                    Console.Error.WriteLine("[dotnet-gds] error: application instance certificate invalid");
                    return 6;
                }

                var database = JsonApplicationsDatabase.Load(gdsConfig.DatabaseStorePath);
                var users = new LinqUserDatabase();
                foreach (Fixture.UserDef u in fixture.Users)
                {
                    var roles = new List<Role> { Role.AuthenticatedUser };
                    foreach (string r in u.Roles)
                    {
                        if (s_roles.TryGetValue(r, out Role role) && !roles.Contains(role))
                        {
                            roles.Add(role);
                        }
                    }
                    users.CreateUser(u.Username, Encoding.UTF8.GetBytes(u.Password ?? string.Empty), roles);
                    Console.Error.WriteLine("[dotnet-gds] info: user " + u.Username + ": " + string.Join(", ", roles.Select(r => r.Name)));
                }

                var server = new InteropGdsServer(fixture, database, new CertificateGroup(telemetry), users);
                await app.StartAsync(server).ConfigureAwait(false);

                foreach (EndpointDescription ep in server.GetEndpoints())
                {
                    Console.Error.WriteLine("[dotnet-gds] info: endpoint " + ep.EndpointUrl + " " + Pki.PolicyName(ep.SecurityPolicyUri) + "/" + ep.SecurityMode);
                }

                try
                {
                    WriteReadyFile(readyFile, fixture.Id, advertised);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("[dotnet-gds] error: cannot write ready file " + readyFile + ": " + e.Message);
                    return 6;
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
                try
                {
                    await Task.Delay(Timeout.Infinite, stop.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // shutdown
                }
                Console.Error.WriteLine("[dotnet-gds] info: shutdown signal received");
                try
                {
                    await server.StopAsync().ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("[dotnet-gds] warn: stop: " + e.Message);
                }
                TryDelete(readyFile);
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet-gds] error: server start failed: " + e);
                return 1;
            }
        }

        /// <summary>The CertificateTypes of the DefaultApplicationGroup.</summary>
        public static readonly string[] GroupCertificateTypes =
        [
            "RsaSha256ApplicationCertificateType",
            "EccNistP256ApplicationCertificateType"
        ];

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
            Console.Error.WriteLine("[dotnet-gds] info: ready file written: " + path);
        }
    }
}
