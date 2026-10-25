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

    /// <summary>
    /// client gds-pull (docs/CLIENT_CONTRACT.md §16.2): the GDS pull model of Part 12 §6 / §7.9 with the
    /// stack's GlobalDiscoveryServerClient (Opc.Ua.Gds.Client 2.0.1), as in the dotnet-gds adapter.
    /// </summary>
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
                        throw new TransportException("connect timeout (" + c.EndpointUrl + ")", StatusCodes.BadTimeout.Code);
                    }
                    catch (ServiceResultException e)
                    {
                        throw new TransportException("connect " + c.EndpointUrl + ": " + e.Message, e.StatusCode.Code);
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
            async Task<T> Step<T>(string statusKey, Func<ValueTask<T>> call)
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
                    if (ClientCommand.IsTransport(e.StatusCode.Code))
                    {
                        throw;
                    }
                    if (statusKey != null)
                    {
                        item[statusKey] = StatusNames.Json(e.StatusCode);
                    }
                    message = statusKey + ": " + e.Message;
                    throw new StepFailed(e.StatusCode.Code);
                }
            }

            ISession session = gds.Session;
            NodeId groupId = ExpandedNodeId.ToNodeId(GdsIds.ObjectIds.Directory_CertificateGroups_DefaultApplicationGroup, session.NamespaceUris);
            try
            {
                // FindApplications
                ApplicationRecordDataType[] found = (await Step("findApplicationsStatus", () => gds.FindApplicationAsync(o.AppUri)).ConfigureAwait(false)).ToArray()
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
                        ApplicationNames = new[] { new LocalizedText("en-US", o.AppName) },
                        ProductUri = "urn:opcua-interop:dotnet",
                        DiscoveryUrls = o.AppType == ApplicationType.Client ? Array.Empty<string>() : o.DiscoveryUrls.ToArray(),
                        ServerCapabilities = o.AppType == ApplicationType.Client ? Array.Empty<string>() : new[] { "NA" }
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
                    requestId = await Step("startRequestStatus", () => gds.StartSigningRequestAsync(applicationId, groupId, o.CertificateTypeId, ByteString.From(csr))).ConfigureAwait(false);
                }
                else
                {
                    requestId = await Step("startRequestStatus", () => gds.StartNewKeyPairRequestAsync(
                        applicationId, groupId, o.CertificateTypeId, "CN=" + o.AppName, new[] { "localhost" }, "PEM", null)).ConfigureAwait(false);
                }
                item["requestId"] = Canonical.NodeId(requestId);

                // FinishRequest until it issues (Bad_NothingToDo = pending)
                ByteString certificate;
                ByteString privateKey;
                ArrayOf<ByteString> issuers;
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
                    catch (ServiceResultException e) when (!ClientCommand.IsTransport(e.StatusCode.Code))
                    {
                        item["finishRequestStatus"] = StatusNames.Json(e.StatusCode);
                        message = "finishRequest: " + e.Message;
                        throw new StepFailed(e.StatusCode.Code);
                    }
                }
                item["certificate"] = certificate.IsNull ? null : Convert.ToBase64String(certificate.Span);
                if (o.Request == "new-key-pair")
                {
                    item["privateKeyFormat"] = "PEM";
                    item["privateKey"] = privateKey.IsNull ? null : Convert.ToBase64String(privateKey.Span);
                }
                item["issuerCertificates"] = B64(issuers);

                // GetCertificateGroups
                NodeId[] groups = (await Step("getCertificateGroupsStatus", () => gds.GetCertificateGroupsAsync(applicationId)).ConfigureAwait(false)).ToArray();
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
                    (StatusCode certStatus, DateTimeUtc _) = await Step("checkRevocationStatus", () => gds.CheckRevocationStatusAsync(certificate)).ConfigureAwait(false);
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

        private static JsonArray B64(ArrayOf<ByteString> c) =>
            Json.Strings((c.ToArray() ?? []).Select(b => Convert.ToBase64String(b.Span)));

        private static JsonObject TrustListJson(TrustListDataType tl)
        {
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
    /// domain check (container host names are not in the test certificates). Still needed on
    /// 2.0.1: GlobalDiscoveryServerClient.ConnectAsync passes updateBeforeConnect: true.
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
            ArrayOf<string> preferredLocales,
            CancellationToken ct = default)
        {
            return base.CreateAsync(configuration, endpoint, false, false, sessionName, sessionTimeout, identity, preferredLocales, ct);
        }
    }
}
