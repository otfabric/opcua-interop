// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using Opc.Ua.Gds.Client;
using GdsIds = Opc.Ua.Gds;
using ApplicationRecordDataType = Opc.Ua.Gds.ApplicationRecordDataType;

namespace OpcUaInterop
{
    /// <summary>The client subcommands: endpoints and gds-pull (docs/CLIENT_CONTRACT.md §16).</summary>
    internal static class GdsClientCommand
    {
        public static readonly string[] Operations = ["endpoints", "gds-pull"];

        public static async Task<int> RunAsync(string[] args)
        {
            if (args.Length < 1)
            {
                Console.Error.WriteLine("usage: client <" + string.Join('|', Operations) + "> --endpoint <url> [flags]");
                return 1;
            }
            string op = args[0];
            var a = new Args(args[1..]);
            if (!Operations.Contains(op))
            {
                Console.Error.WriteLine("unknown client subcommand: " + op);
                return 1;
            }
            ClientContext c = null;
            try
            {
                GdsPullOptions opts = op == "gds-pull" ? GdsPullOptions.Parse(a) : null;
                c = await ClientContext.CreateAsync(a).ConfigureAwait(false);
                return op switch
                {
                    "endpoints" => await EndpointsAsync(c).ConfigureAwait(false),
                    "gds-pull" => await GdsPull.RunAsync(c, opts).ConfigureAwait(false),
                    _ => 1
                };
            }
            catch (InputException e)
            {
                new Result(op).ServiceResult(StatusCodes.BadInvalidArgument).Error("input", e.Message).Print();
                return 2;
            }
            catch (TransportException e)
            {
                bool timeout = e.Code == StatusCodes.BadTimeout;
                new Result(op).ServiceResult(e.Code).Error(timeout ? "timeout" : "transport", e.Message).Print();
                return timeout ? 7 : 3;
            }
            catch (ServiceResultException e)
            {
                bool transport = IsTransport(e.StatusCode);
                new Result(op).Success(false).ServiceResult(e.StatusCode)
                    .Error(transport ? "transport" : "service", e.Message).Print();
                return transport ? 3 : 4;
            }
            catch (System.Net.Sockets.SocketException e)
            {
                new Result(op).ServiceResult(StatusCodes.BadNotConnected).Error("transport", e.Message).Print();
                return 3;
            }
            catch (InternalFailure e)
            {
                new Result(op).ServiceResult(StatusCodes.BadInternalError).Error("internal", e.Message).Print();
                return 6;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet-gds] error: client " + op + " failed: " + e);
                new Result(op).ServiceResult(StatusCodes.BadInternalError).Error("internal", e.Message).Print();
                return 6;
            }
            finally
            {
                if (c != null)
                {
                    await c.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        public static bool IsTransport(uint code)
        {
            uint bits = code & 0xFFFF0000;
            return bits == StatusCodes.BadNotConnected || bits == StatusCodes.BadConnectionClosed ||
                bits == StatusCodes.BadCommunicationError || bits == StatusCodes.BadSecureChannelClosed ||
                bits == StatusCodes.BadServerNotConnected || bits == StatusCodes.BadSecureChannelIdInvalid ||
                bits == StatusCodes.BadTcpInternalError || bits == StatusCodes.BadConnectionRejected ||
                bits == StatusCodes.BadDisconnect || bits == StatusCodes.BadNoCommunication ||
                bits == StatusCodes.BadServerHalted;
        }

        private static async Task<int> EndpointsAsync(ClientContext c)
        {
            EndpointDescriptionCollection eps;
            try
            {
                eps = await c.GetEndpointsAsync().ConfigureAwait(false);
            }
            catch (ServiceResultException e)
            {
                throw new TransportException("GetEndpoints " + c.EndpointUrl + ": " + e.Message, e.StatusCode);
            }
            var r = new Result("endpoints");
            foreach (EndpointDescription ep in eps)
            {
                r.Add(new JsonObject
                {
                    ["url"] = ep.EndpointUrl,
                    ["securityPolicy"] = ep.SecurityPolicyUri,
                    ["securityMode"] = ep.SecurityMode.ToString()
                });
            }
            r.Print();
            return 0;
        }
    }

    /// <summary>The flags of client gds-pull.</summary>
    internal sealed class GdsPullOptions
    {
        public string AppUri { get; private set; }
        public ApplicationType AppType { get; private set; }
        public List<string> DiscoveryUrls { get; private set; }
        public string Request { get; private set; }
        public string CertificateType { get; private set; }
        public NodeId CertificateTypeId { get; private set; }
        public bool Revoke { get; private set; }
        public bool Unregister { get; private set; }
        public int FinishTimeoutMs { get; private set; }

        public static GdsPullOptions Parse(Args a)
        {
            var o = new GdsPullOptions
            {
                AppUri = a.Get("--app-uri") ?? "urn:opcua-interop:gds-pull:app",
                DiscoveryUrls = a.All("--discovery-url"),
                Request = a.Get("--request") ?? "csr",
                CertificateType = a.Get("--certificate-type") ?? "RsaSha256",
                Revoke = a.Has("--revoke"),
                Unregister = a.Has("--unregister"),
                FinishTimeoutMs = a.GetInt("--finish-timeout-ms", 30000)
            };
            if (o.DiscoveryUrls.Count == 0)
            {
                o.DiscoveryUrls.Add("opc.tcp://localhost:4850");
            }
            o.AppType = (a.Get("--app-type") ?? "Server") switch
            {
                "Server" => ApplicationType.Server,
                "Client" => ApplicationType.Client,
                "ClientAndServer" => ApplicationType.ClientAndServer,
                string s => throw new InputException("invalid --app-type " + s + " (Server, Client, ClientAndServer)")
            };
            if (o.Request is not ("csr" or "new-key-pair"))
            {
                throw new InputException("invalid --request " + o.Request + " (csr, new-key-pair)");
            }
            o.CertificateTypeId = o.CertificateType switch
            {
                "RsaSha256" => ObjectTypeIds.RsaSha256ApplicationCertificateType,
                "NistP256" => ObjectTypeIds.EccNistP256ApplicationCertificateType,
                string s => throw new InputException("invalid --certificate-type " + s + " (RsaSha256, NistP256)")
            };
            if (o.FinishTimeoutMs < 0)
            {
                throw new InputException("invalid --finish-timeout-ms " + o.FinishTimeoutMs.ToString(Inv.C));
            }
            if (string.IsNullOrEmpty(o.AppUri))
            {
                throw new InputException("empty --app-uri");
            }
            return o;
        }

        /// <summary>The application name of the record: the last segment of the app uri.</summary>
        public string AppName
        {
            get
            {
                string s = AppUri.TrimEnd('/', ':');
                int i = s.LastIndexOfAny([':', '/']);
                string last = i >= 0 ? s[(i + 1)..] : s;
                return string.IsNullOrEmpty(last) ? "opcua-interop gds-pull app" : last;
            }
        }
    }

    /// <summary>The GDS pull model of Part 12 §6 / §7.9 with the stack's GlobalDiscoveryServerClient.</summary>
    internal static class GdsPull
    {
        private const string Op = "gds-pull";

        private sealed class StepFailed : Exception
        {
            public StepFailed(uint code) : base("step failed")
            {
                Code = code;
            }

            public uint Code { get; }
        }

        public static async Task<int> RunAsync(ClientContext c, GdsPullOptions o)
        {
            EndpointDescription endpoint = await c.SelectEndpointAsync().ConfigureAwait(false);
            var gds = new GlobalDiscoveryServerClient(c.Config, c.Identity(), new NoUpdateSessionFactory(c.Telemetry));
            try
            {
                var ec = EndpointConfiguration.Create(c.Config);
                ec.OperationTimeout = Math.Max(c.RequestTimeoutMs, 1000);
                using (var cts = new CancellationTokenSource(Math.Max(c.ConnectTimeoutMs, 1000) + 5000))
                {
                    try
                    {
                        await gds.ConnectAsync(new ConfiguredEndpoint(null, endpoint, ec), cts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        throw new TransportException("connect timeout (" + c.EndpointUrl + ")", StatusCodes.BadTimeout);
                    }
                    catch (ServiceResultException e)
                    {
                        throw new TransportException("connect " + c.EndpointUrl + ": " + e.Message, e.StatusCode);
                    }
                }
                gds.Session.OperationTimeout = Math.Max(c.RequestTimeoutMs, 1000);
                return await StepsAsync(gds, o).ConfigureAwait(false);
            }
            finally
            {
                try
                {
                    using var cts = new CancellationTokenSource(Math.Max(c.DisconnectTimeoutMs, 500));
                    await gds.DisconnectAsync(cts.Token).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // best effort
                }
                gds.Dispose();
            }
        }

        private static async Task<int> StepsAsync(GlobalDiscoveryServerClient gds, GdsPullOptions o)
        {
            var item = new JsonObject();
            uint failed = 0;
            string message = null;

            // runs one step; a ServiceResultException is the step's Bad status
            async Task<T> Step<T>(string statusKey, Func<Task<T>> call)
            {
                try
                {
                    T v = await call().ConfigureAwait(false);
                    if (statusKey != null)
                    {
                        item[statusKey] = StatusNames.Good;
                    }
                    return v;
                }
                catch (ServiceResultException e)
                {
                    if (GdsClientCommand.IsTransport(e.StatusCode))
                    {
                        throw;
                    }
                    if (statusKey != null)
                    {
                        item[statusKey] = StatusNames.Json(e.StatusCode);
                    }
                    message = statusKey + ": " + e.Message;
                    throw new StepFailed(e.StatusCode);
                }
            }

            ISession session = gds.Session;
            NodeId groupId = ExpandedNodeId.ToNodeId(GdsIds.ObjectIds.Directory_CertificateGroups_DefaultApplicationGroup, session.NamespaceUris);
            try
            {
                // FindApplications
                ApplicationRecordDataType[] found = await Step("findApplicationsStatus", () => gds.FindApplicationAsync(o.AppUri)).ConfigureAwait(false)
                    ?? [];
                item.Remove("findApplicationsStatus");
                item["findApplications"] = Json.Strings(found.Select(r => Canonical.NodeId(r.ApplicationId)));

                // RegisterApplication
                NodeId applicationId;
                if (found.Length > 0)
                {
                    applicationId = found[0].ApplicationId;
                    item["registered"] = false;
                }
                else
                {
                    var record = new ApplicationRecordDataType
                    {
                        ApplicationUri = o.AppUri,
                        ApplicationType = o.AppType,
                        ApplicationNames = [new LocalizedText("en-US", o.AppName)],
                        ProductUri = "urn:opcua-interop:dotnet-gds",
                        DiscoveryUrls = new StringCollection(o.AppType == ApplicationType.Client ? [] : o.DiscoveryUrls),
                        ServerCapabilities = o.AppType == ApplicationType.Client ? [] : ["NA"]
                    };
                    applicationId = await Step("registerStatus", () => gds.RegisterApplicationAsync(record)).ConfigureAwait(false);
                    item["registered"] = true;
                }
                item["applicationId"] = Canonical.NodeId(applicationId);

                // StartSigningRequest / StartNewKeyPairRequest
                item["requestKind"] = o.Request;
                NodeId requestId;
                if (o.Request == "csr")
                {
                    byte[] csr = CreateCsr(o);
                    requestId = await Step("startRequestStatus", () => gds.StartSigningRequestAsync(applicationId, groupId, o.CertificateTypeId, csr)).ConfigureAwait(false);
                }
                else
                {
                    requestId = await Step("startRequestStatus", () => gds.StartNewKeyPairRequestAsync(
                        applicationId, groupId, o.CertificateTypeId, "CN=" + o.AppName, ["localhost"], "PEM", null)).ConfigureAwait(false);
                }
                item["requestId"] = Canonical.NodeId(requestId);

                // FinishRequest until it issues (Bad_NothingToDo = pending)
                byte[] certificate;
                byte[] privateKey;
                byte[][] issuers;
                var deadline = DateTime.UtcNow.AddMilliseconds(o.FinishTimeoutMs);
                while (true)
                {
                    try
                    {
                        (certificate, privateKey, issuers) = await gds.FinishRequestAsync(applicationId, requestId).ConfigureAwait(false);
                        item["finishRequestStatus"] = StatusNames.Good;
                        break;
                    }
                    catch (ServiceResultException e) when (e.StatusCode == StatusCodes.BadNothingToDo && DateTime.UtcNow < deadline)
                    {
                        await Task.Delay(200).ConfigureAwait(false);
                    }
                    catch (ServiceResultException e) when (!GdsClientCommand.IsTransport(e.StatusCode))
                    {
                        item["finishRequestStatus"] = StatusNames.Json(e.StatusCode);
                        message = "finishRequest: " + e.Message;
                        throw new StepFailed(e.StatusCode);
                    }
                }
                item["certificate"] = certificate == null ? null : Convert.ToBase64String(certificate);
                if (o.Request == "new-key-pair")
                {
                    item["privateKeyFormat"] = "PEM";
                    item["privateKey"] = privateKey == null ? null : Convert.ToBase64String(privateKey);
                }
                item["issuerCertificates"] = Json.Strings((issuers ?? []).Select(Convert.ToBase64String));

                // GetCertificateGroups
                NodeId[] groups = await Step("getCertificateGroupsStatus", () => gds.GetCertificateGroupsAsync(applicationId)).ConfigureAwait(false);
                item.Remove("getCertificateGroupsStatus");
                item["certificateGroups"] = Json.Strings((groups ?? []).Select(Canonical.NodeId));

                // GetTrustList + read the TrustList (Open, Read, Close)
                NodeId trustListId = await Step("getTrustListStatus", () => gds.GetTrustListAsync(applicationId, groupId)).ConfigureAwait(false);
                item.Remove("getTrustListStatus");
                item["trustListId"] = Canonical.NodeId(trustListId);
                TrustListDataType tl = await Step("readTrustListStatus", () => gds.ReadTrustListAsync(trustListId)).ConfigureAwait(false);
                item.Remove("readTrustListStatus");
                item["trustList"] = TrustListJson(tl);

                // GetCertificateStatus
                bool updateRequired = await Step("getCertificateStatusStatus", () => gds.GetCertificateStatusAsync(applicationId, groupId, o.CertificateTypeId)).ConfigureAwait(false);
                item["updateRequired"] = updateRequired;

                if (o.Revoke)
                {
                    await Step("revokeStatus", async () =>
                    {
                        await gds.RevokeCertificateAsync(applicationId, certificate).ConfigureAwait(false);
                        return true;
                    }).ConfigureAwait(false);
                    (StatusCode certStatus, DateTime _) = await Step("checkRevocationStatus", () => gds.CheckRevocationStatusAsync(certificate)).ConfigureAwait(false);
                    item["certificateStatus"] = StatusNames.Json(certStatus);
                }

                if (o.Unregister)
                {
                    await Step("unregisterStatus", async () =>
                    {
                        await gds.UnregisterApplicationAsync(applicationId).ConfigureAwait(false);
                        return true;
                    }).ConfigureAwait(false);
                }
            }
            catch (StepFailed e)
            {
                failed = e.Code;
            }

            var r = new Result(Op).Add(item);
            if (failed != 0)
            {
                r.Success(false).ServiceResult(failed).Error("service", message);
                r.Print();
                return 4;
            }
            r.Print();
            return 0;
        }

        private static JsonObject TrustListJson(TrustListDataType tl)
        {
            static JsonArray B64(ByteStringCollection c) => Json.Strings((c ?? new ByteStringCollection()).Select(Convert.ToBase64String));
            return new JsonObject
            {
                ["specifiedLists"] = tl.SpecifiedLists,
                ["trustedCertificates"] = B64(tl.TrustedCertificates),
                ["trustedCrls"] = B64(tl.TrustedCrls),
                ["issuerCertificates"] = B64(tl.IssuerCertificates),
                ["issuerCrls"] = B64(tl.IssuerCrls)
            };
        }

        /// <summary>A PKCS #10 request with a fresh key: URI SAN = app uri, DNS SAN localhost.</summary>
        private static byte[] CreateCsr(GdsPullOptions o)
        {
            var san = new SubjectAlternativeNameBuilder();
            san.AddUri(new Uri(o.AppUri));
            san.AddDnsName("localhost");
            var subject = new X500DistinguishedName("CN=" + o.AppName);
            CertificateRequest req;
            if (o.CertificateType == "NistP256")
            {
                using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                req = new CertificateRequest(subject, ec, HashAlgorithmName.SHA256);
                req.CertificateExtensions.Add(san.Build());
                req.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
                return req.CreateSigningRequest();
            }
            using var rsa = RSA.Create(2048);
            req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(san.Build());
            req.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation |
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment, true));
            return req.CreateSigningRequest();
        }
    }

    /// <summary>
    /// Session factory that dials the endpoint as selected (the GDS client otherwise updates it
    /// from the server, which replaces the URL with the server's advertised host) and skips the
    /// domain check (container host names are not in the test certificates).
    /// </summary>
    internal sealed class NoUpdateSessionFactory : DefaultSessionFactory
    {
        public NoUpdateSessionFactory(ITelemetryContext telemetry) : base(telemetry)
        {
        }

        public override Task<ISession> CreateAsync(
            ApplicationConfiguration configuration,
            ConfiguredEndpoint endpoint,
            bool updateBeforeConnect,
            bool checkDomain,
            string sessionName,
            uint sessionTimeout,
            IUserIdentity identity,
            IList<string> preferredLocales,
            CancellationToken ct = default)
        {
            return base.CreateAsync(configuration, endpoint, false, false, sessionName, sessionTimeout, identity, preferredLocales, ct);
        }
    }

    /// <summary>
    /// Client application configuration and endpoint selection (§9) from the global client
    /// flags (§1). Adapted from dotnet/src/ClientSession.cs to the 1.5.378 API.
    /// </summary>
    internal sealed class ClientContext : IAsyncDisposable
    {
        public const string DefaultApplicationUri = "urn:otfabric:opcua-interop:client:dotnet-gds";

        private ClientContext(Args args)
        {
            Args = args;
        }

        public Args Args { get; }
        public ITelemetryContext Telemetry { get; private set; }
        public ApplicationConfiguration Config { get; private set; }
        public string EndpointUrl { get; private set; }
        public string PolicyName { get; private set; }
        public string PolicyUri { get; private set; }
        public MessageSecurityMode Mode { get; private set; }
        public int ConnectTimeoutMs { get; private set; }
        public int RequestTimeoutMs { get; private set; }
        public int DisconnectTimeoutMs { get; private set; }

        public static readonly HashSet<string> SupportedPolicies =
        [
            "None", "Basic128Rsa15", "Basic256", "Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss"
        ];

        /// <summary>Validates the global flags and builds the client configuration (no network).</summary>
        public static async Task<ClientContext> CreateAsync(Args a)
        {
            var c = new ClientContext(a);
            c.EndpointUrl = a.Get("--endpoint");
            if (string.IsNullOrEmpty(c.EndpointUrl))
            {
                throw new InputException("missing --endpoint");
            }
            if (a.Has("--reverse-listen") || a.Has("--reverse-server-uri"))
            {
                throw new InputException("--reverse-listen: client reverse connect is not wired in this adapter");
            }
            c.PolicyName = a.Get("--security-policy") ?? "None";
            string modeName = a.Get("--security-mode") ?? "None";
            c.PolicyUri = Pki.PolicyUri(c.PolicyName);
            if (c.PolicyUri == null || !SupportedPolicies.Contains(c.PolicyName))
            {
                throw new InputException("--security-policy " + c.PolicyName + " is not supported by this adapter");
            }
            c.Mode = Pki.Mode(modeName);
            if (c.Mode == MessageSecurityMode.Invalid)
            {
                throw new InputException("invalid --security-mode " + modeName);
            }
            if ((c.PolicyName == "None") != (c.Mode == MessageSecurityMode.None))
            {
                throw new InputException("--security-policy " + c.PolicyName + " does not match --security-mode " + modeName);
            }
            c.ConnectTimeoutMs = a.GetInt("--connect-timeout", 5) * 1000;
            c.RequestTimeoutMs = a.GetInt("--request-timeout", 5) * 1000;
            c.DisconnectTimeoutMs = a.GetInt("--disconnect-timeout", 2) * 1000;

            string certFile = a.Get("--certificate");
            string keyFile = a.Get("--private-key");
            if (c.Mode != MessageSecurityMode.None && (certFile == null || keyFile == null))
            {
                throw new InputException("--security-policy " + c.PolicyName + " requires --certificate and --private-key");
            }

            c.Telemetry = OpcUaInterop.Telemetry.Create("dotnet-gds");
            string root = Pki.TempDir("opcua-dotnet-gds-client");
            string applicationUri = a.Get("--application-uri");
            var certIds = new CertificateIdentifierCollection();
            if (certFile != null && keyFile != null)
            {
                X509Certificate2 cert;
                try
                {
                    cert = Pki.LoadWithKey(certFile, keyFile);
                }
                catch (Exception e)
                {
                    throw new InternalFailure("cannot load client certificate / key: " + e.Message);
                }
                applicationUri ??= Pki.ApplicationUri(cert);
                Pki.WriteOwn(Path.Combine(root, "own"), "client", cert);
                certIds.Add(new CertificateIdentifier
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = Path.Combine(root, "own"),
                    SubjectName = cert.Subject,
                    Thumbprint = cert.Thumbprint,
                    CertificateType = ObjectTypeIds.RsaSha256ApplicationCertificateType
                });
            }
            applicationUri ??= DefaultApplicationUri;

            List<string> trust = a.All("--trust-list");
            Directory.CreateDirectory(Path.Combine(root, "trusted", "certs"));
            Directory.CreateDirectory(Path.Combine(root, "trusted", "crl"));
            Directory.CreateDirectory(Path.Combine(root, "issuer", "certs"));
            int t = 0;
            foreach (string f in trust)
            {
                foreach (byte[] der in Pki.ReadCertificates(f))
                {
                    File.WriteAllBytes(Path.Combine(root, "trusted", "certs", "trust-" + (t++).ToString(Inv.C) + ".der"), der);
                }
            }

            if (certIds.Count == 0)
            {
                // None/None: the stack still wants an application certificate entry; a
                // self-signed one is created in the temporary store
                certIds.Add(new CertificateIdentifier
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = Path.Combine(root, "own"),
                    SubjectName = "CN=opcua-interop dotnet-gds client, O=OTFabric",
                    CertificateType = ObjectTypeIds.RsaSha256ApplicationCertificateType
                });
            }

            var app = new ApplicationInstance(c.Telemetry)
            {
                ApplicationName = "opcua-interop dotnet-gds client",
                ApplicationType = ApplicationType.Client
            };
            c.Config = await app
                .Build(applicationUri, "urn:otfabric:opcua-interop:dotnet-gds")
                .SetOperationTimeout(Math.Max(c.RequestTimeoutMs, 1000))
                .AsClient()
                .AddSecurityConfiguration(certIds, root, Path.Combine(root, "rejected"))
                // without --trust-list every server certificate is accepted (as the dotnet adapter does)
                .SetAutoAcceptUntrustedCertificates(trust.Count == 0)
                .SetRejectSHA1SignedCertificates(true)
                .SetRejectUnknownRevocationStatus(false)
                .SetMinimumCertificateKeySize(1024)
                .SetAddAppCertToTrustedStore(false)
                .CreateAsync()
                .ConfigureAwait(false);
            ApplicationInstance.MessageDlg = new AutoApproveDialog();
            if (!await app.CheckApplicationInstanceCertificatesAsync(false).ConfigureAwait(false))
            {
                throw new InternalFailure("client application instance certificate rejected by the stack");
            }
            bool acceptAll = trust.Count == 0;
            c.Config.CertificateValidator.CertificateValidation += (sender, e) =>
            {
                // the endpoint host (host.docker.internal / a container name) is not in the test
                // certificates' SANs: domain checks are not part of the interop contract
                if (acceptAll || e.Error.StatusCode == StatusCodes.BadCertificateHostNameInvalid)
                {
                    e.Accept = true;
                }
            };
            return c;
        }

        /// <summary>GetEndpoints on --endpoint.</summary>
        public async Task<EndpointDescriptionCollection> GetEndpointsAsync()
        {
            var ec = EndpointConfiguration.Create(Config);
            ec.OperationTimeout = Math.Max(RequestTimeoutMs, 1000);
            using var cts = new CancellationTokenSource(Math.Max(ConnectTimeoutMs, 1000));
            DiscoveryClient dc;
            try
            {
                dc = await DiscoveryClient.CreateAsync(Config, new Uri(EndpointUrl), ec, DiagnosticsMasks.None, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw new TransportException("connect timeout (" + EndpointUrl + ")", StatusCodes.BadTimeout);
            }
            try
            {
                return await dc.GetEndpointsAsync(null, CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                try
                {
                    await dc.CloseAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // ignore
                }
                dc.Dispose();
            }
        }

        /// <summary>Selects the endpoint of --security-policy / --security-mode (§9).</summary>
        public async Task<EndpointDescription> SelectEndpointAsync()
        {
            EndpointDescriptionCollection eps;
            try
            {
                eps = await GetEndpointsAsync().ConfigureAwait(false);
            }
            catch (ServiceResultException e)
            {
                throw new TransportException("GetEndpoints " + EndpointUrl + ": " + e.Message, e.StatusCode);
            }
            EndpointDescription chosen = eps.FirstOrDefault(ep =>
                ep.SecurityPolicyUri == PolicyUri && ep.SecurityMode == Mode &&
                (string.IsNullOrEmpty(ep.TransportProfileUri) || ep.TransportProfileUri == Profiles.UaTcpTransport));
            if (chosen == null)
            {
                throw new TransportException("no endpoint with SecurityPolicy=" + PolicyName + " and MessageSecurityMode=" + Mode + " at " + EndpointUrl);
            }
            // dial the URL we were given (the advertised host may not resolve here)
            chosen.EndpointUrl = EndpointUrl;
            return chosen;
        }

        public IUserIdentity Identity()
        {
            string user = Args.Get("--username");
            return user == null
                ? new UserIdentity()
                : new UserIdentity(user, Encoding.UTF8.GetBytes(Args.Get("--password") ?? string.Empty));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    /// <summary>Thrown for adapter-internal failures (exit 6).</summary>
    internal sealed class InternalFailure : Exception
    {
        public InternalFailure(string message) : base(message) { }
    }
}
