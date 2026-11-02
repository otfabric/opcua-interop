// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;

namespace OpcUaInterop
{
    /// <summary>
    /// Client application configuration, endpoint selection (§9) and session creation from the
    /// global client flags (§1).
    /// </summary>
    internal sealed class ClientContext : IAsyncDisposable
    {
        public const string DefaultApplicationUri = "urn:otfabric:opcua-interop:client:dotnet";

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
        public ISession Session { get; private set; }

        public static readonly HashSet<string> SupportedPolicies =
        [
            "None", "Basic128Rsa15", "Basic256", "Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss"
        ];

        /// <summary>Validates the global flags and builds the client configuration (no network).</summary>
        public static async Task<ClientContext> CreateAsync(Args a, bool requireEndpoint = true)
        {
            var c = new ClientContext(a);
            c.EndpointUrl = a.Get("--endpoint");
            if (requireEndpoint && string.IsNullOrEmpty(c.EndpointUrl))
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
                throw new InputException("--security-policy " + c.PolicyName + " is not supported by this adapter"
                    + (c.PolicyName.StartsWith("ECC_", StringComparison.Ordinal)
                        ? " (UA-.NETStandard 2.0.1 does not accept the test PKI's RSA-CA-signed ECC application certificates)"
                        : string.Empty));
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

            c.Telemetry = OpcUaInterop.Telemetry.Create("dotnet");
            string root = Pki.TempDir("opcua-dotnet-client-pki");
            string applicationUri = a.Get("--application-uri");
            var certIds = new List<CertificateIdentifier>();
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
                string ecc = Pki.EccDir(c.PolicyName);
                certIds.Add(new CertificateIdentifier
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = Path.Combine(root, "own"),
                    SubjectName = cert.Subject,
                    Thumbprint = cert.Thumbprint,
                    CertificateType = ecc != null ? Pki.EccCertificateType(c.PolicyName) : ObjectTypeIds.RsaSha256ApplicationCertificateType
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
                // None/None: the stack still wants an application certificate entry; it stays unused
                certIds.Add(new CertificateIdentifier
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = Path.Combine(root, "own"),
                    SubjectName = "CN=opcua-interop dotnet client, O=OTFabric",
                    CertificateType = ObjectTypeIds.RsaSha256ApplicationCertificateType
                });
            }

            var app = new ApplicationInstance(c.Telemetry)
            {
                ApplicationName = "opcua-interop dotnet client",
                ApplicationType = ApplicationType.Client
            };
            int lifetime = a.GetInt("--channel-lifetime-ms", 0);
            IApplicationConfigurationBuilderClientSelected cb = app
                .Build(applicationUri, "urn:otfabric:opcua-interop:dotnet")
                .SetOperationTimeout(Math.Max(c.RequestTimeoutMs, 1000))
                .SetChannelLifetime(lifetime > 0 ? lifetime : 600000)
                .SetSecurityTokenLifetime(lifetime > 0 ? lifetime : 3600000)
                .AsClient();
            c.Config = await cb
                .AddSecurityConfiguration(new ArrayOf<CertificateIdentifier>(certIds.ToArray()), root, Path.Combine(root, "rejected"))
                // without --trust-list every server certificate is accepted (as the Milo adapter does)
                .SetAutoAcceptUntrustedCertificates(trust.Count == 0)
                .SetRejectSHA1SignedCertificates(true)
                .SetRejectUnknownRevocationStatus(false)
                .SetAddAppCertToTrustedStore(false)
                .CreateAsync()
                .ConfigureAwait(false);
            if (certFile != null)
            {
                ApplicationInstance.MessageDlg = new AutoApproveDialog();
                if (!await app.CheckApplicationInstanceCertificatesAsync(false, null).ConfigureAwait(false))
                {
                    throw new InternalFailure("client application instance certificate rejected by the stack");
                }
            }
            if (c.Config.CertificateManager is CertificateManager cm)
            {
                // the endpoint host (host.docker.internal / a container name) is not in the test
                // certificates' SANs: domain checks are not part of the interop contract
                bool acceptAll = trust.Count == 0;
                cm.AcceptError = (cert, error) => acceptAll || error.StatusCode == StatusCodes.BadCertificateHostNameInvalid;
            }
            return c;
        }

        /// <summary>DiscoveryClient on --endpoint (None channel).</summary>
        public async Task<DiscoveryClient> DiscoveryAsync(string url = null)
        {
            var ec = EndpointConfiguration.Create(Config);
            ec.OperationTimeout = Math.Max(RequestTimeoutMs, 1000);
            using var cts = new CancellationTokenSource(Math.Max(ConnectTimeoutMs, 1000));
            try
            {
                return await DiscoveryClient.CreateAsync(new Uri(url ?? EndpointUrl), ec, Config, DiagnosticsMasks.None, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw new TransportException("connect timeout (" + (url ?? EndpointUrl) + ")", StatusCodes.BadTimeout.Code);
            }
        }

        /// <summary>GetEndpoints on --endpoint, unpatched (the server's own URLs).</summary>
        public async Task<ArrayOf<EndpointDescription>> GetEndpointsAsync()
        {
            DiscoveryClient dc = await DiscoveryAsync().ConfigureAwait(false);
            try
            {
                GetEndpointsResponse r = await dc.GetEndpointsAsync(null, EndpointUrl, default, default, CancellationToken.None).ConfigureAwait(false);
                return r.Endpoints;
            }
            finally
            {
                await dc.CloseAsync(CancellationToken.None).ConfigureAwait(false);
                dc.Dispose();
            }
        }

        /// <summary>Selects the endpoint of --security-policy / --security-mode and the transport of --endpoint (§9).</summary>
        public async Task<EndpointDescription> SelectEndpointAsync()
        {
            ArrayOf<EndpointDescription> eps;
            try
            {
                eps = await GetEndpointsAsync().ConfigureAwait(false);
            }
            catch (ServiceResultException e)
            {
                throw new TransportException("GetEndpoints " + EndpointUrl + ": " + e.Message, e.StatusCode.Code);
            }
            // the transport of --endpoint: opc.tcp, opc.wss (wss-uasc-uabinary) or opc.https
            // (https-uabinary); the JSON twins of the WSS / HTTPS endpoints are skipped
            string profile = TransportProfileOf(EndpointUrl);
            EndpointDescription chosen = null;
            foreach (EndpointDescription ep in eps)
            {
                if (ep.SecurityPolicyUri == PolicyUri && ep.SecurityMode == Mode &&
                    (ep.TransportProfileUri == profile ||
                     (string.IsNullOrEmpty(ep.TransportProfileUri) && TransportProfileOf(ep.EndpointUrl) == profile)))
                {
                    chosen = ep;
                    break;
                }
            }
            if (chosen == null)
            {
                throw new TransportException("no endpoint with SecurityPolicy=" + PolicyName + " and MessageSecurityMode=" + Mode + " at " + EndpointUrl);
            }
            // dial the URL we were given (the advertised host may not resolve here)
            chosen.EndpointUrl = EndpointUrl;
            return chosen;
        }

        /// <summary>The user identity of --username / --password (Anonymous without --username).</summary>
        public IUserIdentity Identity()
        {
            string user = Args.Get("--username");
            return user == null
                ? new UserIdentity()
                : new UserIdentity(user, Encoding.UTF8.GetBytes(Args.Get("--password") ?? string.Empty));
        }

        /// <summary>Selects the endpoint (§9) and opens a session.</summary>
        public async Task<ISession> ConnectAsync()
        {
            EndpointDescription chosen = await SelectEndpointAsync().ConfigureAwait(false);
            IUserIdentity identity = Identity();

            var ec = EndpointConfiguration.Create(Config);
            ec.OperationTimeout = Math.Max(RequestTimeoutMs, 1000);
            var configured = new ConfiguredEndpoint(null, chosen, ec);
            var factory = new DefaultSessionFactory(Telemetry);
            using var cts = new CancellationTokenSource(Math.Max(ConnectTimeoutMs, 1000) + 5000);
            try
            {
                Session = await factory.CreateAsync(
                    Config, configured, false, false, "opcua-interop-dotnet", 60000, identity, default, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw new TransportException("connect timeout (" + EndpointUrl + ")", StatusCodes.BadTimeout.Code);
            }
            catch (ServiceResultException e) when (e.StatusCode == StatusCodes.BadConfigurationError)
            {
                // e.g. a client certificate the stack refuses to use (no KeyUsage extension)
                throw new InternalFailure("client configuration rejected by the stack: " + e.Message);
            }
            catch (ServiceResultException e)
            {
                throw new TransportException("connect " + EndpointUrl + ": " + e.Message, e.StatusCode.Code);
            }
            Session.OperationTimeout = Math.Max(RequestTimeoutMs, 1000);
            return Session;
        }

        /// <summary>The binary transport profile of an endpoint URL, by its scheme.</summary>
        public static string TransportProfileOf(string url)
        {
            string scheme = url == null ? string.Empty : url.Split("://")[0].ToLowerInvariant();
            return scheme switch
            {
                "opc.wss" or "wss" => Profiles.UaWssTransport,
                "opc.https" or "https" => Profiles.HttpsBinaryTransport,
                _ => Profiles.UaTcpTransport
            };
        }

        /// <summary>Resolves a --node argument (nsu= through the session NamespaceArray).</summary>
        public NodeId Node(string s) => NodeIds.Parse(s, uri => Session.NamespaceUris.GetIndex(uri));

        public RequestHeader Header(int timeoutMs = 0) => new()
        {
            TimeoutHint = (uint)(timeoutMs > 0 ? timeoutMs : RequestTimeoutMs),
            Timestamp = DateTimeUtc.Now
        };

        public async ValueTask DisposeAsync()
        {
            if (Session != null)
            {
                try
                {
                    using var cts = new CancellationTokenSource(Math.Max(DisconnectTimeoutMs, 500));
                    await Session.CloseAsync(cts.Token).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // best effort
                }
                Session.Dispose();
                Session = null;
            }
        }
    }

    /// <summary>Thrown for adapter-internal failures (exit 6).</summary>
    internal sealed class InternalFailure : Exception
    {
        public InternalFailure(string message) : base(message) { }
    }

    /// <summary>
    /// A Publish loop on a raw subscription: the adapter drives Publish itself so it sees every
    /// NotificationMessage (sequence numbers, keep-alives, data changes and events).
    /// </summary>
    internal sealed class PublishLoop : IAsyncDisposable
    {
        private readonly ClientContext m_c;
        private readonly CancellationTokenSource m_cts = new();
        private readonly List<SubscriptionAcknowledgement> m_acks = [];
        private Task m_task;

        public PublishLoop(ClientContext c)
        {
            m_c = c;
        }

        public event Action<uint, MonitoredItemNotification> DataChange;
        public event Action<uint, EventFieldList> Event;

        public int Outstanding { get; init; } = 2;

        public void Start()
        {
            m_task = Task.WhenAll(Enumerable.Range(0, Outstanding).Select(_ => RunAsync(m_cts.Token)));
        }

        private async Task RunAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                SubscriptionAcknowledgement[] acks;
                lock (m_acks)
                {
                    acks = m_acks.ToArray();
                    m_acks.Clear();
                }
                PublishResponse r;
                try
                {
                    r = await m_c.Session.PublishAsync(m_c.Header(30000), new ArrayOf<SubscriptionAcknowledgement>(acks), ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (ServiceResultException e) when (e.StatusCode == StatusCodes.BadNoSubscription || e.StatusCode == StatusCodes.BadTooManyPublishRequests ||
                    e.StatusCode == StatusCodes.BadRequestTimeout || e.StatusCode == StatusCodes.BadTimeout)
                {
                    try
                    {
                        await Task.Delay(50, ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                    continue;
                }
                catch (Exception e)
                {
                    if (ct.IsCancellationRequested)
                    {
                        return;
                    }
                    Console.Error.WriteLine("[dotnet] warn: publish: " + e.Message);
                    try
                    {
                        await Task.Delay(100, ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                    continue;
                }
                NotificationMessage nm = r.NotificationMessage;
                if (nm == null)
                {
                    continue;
                }
                if (nm.NotificationData.Count > 0)
                {
                    lock (m_acks)
                    {
                        m_acks.Add(new SubscriptionAcknowledgement { SubscriptionId = r.SubscriptionId, SequenceNumber = nm.SequenceNumber });
                    }
                }
                foreach (ExtensionObject eo in nm.NotificationData)
                {
                    if (!eo.TryGetValue(out IEncodeable body, Codec.Context))
                    {
                        continue;
                    }
                    if (body is DataChangeNotification dcn)
                    {
                        foreach (MonitoredItemNotification mi in dcn.MonitoredItems)
                        {
                            DataChange?.Invoke(r.SubscriptionId, mi);
                        }
                    }
                    else if (body is EventNotificationList enl)
                    {
                        foreach (EventFieldList ev in enl.Events)
                        {
                            Event?.Invoke(r.SubscriptionId, ev);
                        }
                    }
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            m_cts.Cancel();
            if (m_task != null)
            {
                try
                {
                    await m_task.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // ignore
                }
            }
            m_cts.Dispose();
        }
    }
}
