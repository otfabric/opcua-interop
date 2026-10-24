// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>RegisterServer2 / RegisterServer against an LDS (shared by the client op and --register-with).</summary>
    internal static class Registration
    {
        public sealed class Outcome
        {
            public string Service { get; set; } = "RegisterServer2";
            public StatusCode Status { get; set; } = StatusCodes.Good;
            public bool Fallback { get; set; }
            public StatusCode? RegisterServer2Status { get; set; }
            public List<StatusCode> ConfigurationResults { get; } = [];
            public bool Ok => StatusCode.IsGood(Status) && ConfigurationResults.All(StatusCode.IsGood);
        }

        private static bool IsUnsupported(StatusCode sc)
        {
            uint b = sc.Code & 0xFFFF0000;
            return b == StatusCodes.BadServiceUnsupported.Code || b == StatusCodes.BadNotImplemented.Code || b == StatusCodes.BadNotSupported.Code;
        }

        public static async Task<Outcome> RegisterAsync(
            ApplicationConfiguration config, string ldsUrl, RegisteredServer server, string mdnsName,
            IEnumerable<string> capabilities, string service, int timeoutMs, CancellationToken ct = default)
        {
            var description = new EndpointDescription
            {
                EndpointUrl = ldsUrl,
                SecurityMode = MessageSecurityMode.None,
                SecurityPolicyUri = SecurityPolicies.None,
                TransportProfileUri = Profiles.UaTcpTransport
            };
            var ec = EndpointConfiguration.Create(config);
            ec.OperationTimeout = Math.Max(timeoutMs, 1000);
            RegistrationClient client;
            try
            {
                client = await RegistrationClient.CreateAsync(config, description, ec, null, DiagnosticsMasks.None, ct).ConfigureAwait(false);
            }
            catch (ServiceResultException e)
            {
                throw new TransportException("connect " + ldsUrl + ": " + e.Message, e.StatusCode.Code);
            }
            var o = new Outcome();
            try
            {
                var header = new RequestHeader { TimeoutHint = (uint)Math.Max(timeoutMs, 1000), Timestamp = DateTimeUtc.Now };
                if (service is "auto" or "RegisterServer2")
                {
                    var mdns = new MdnsDiscoveryConfiguration
                    {
                        MdnsServerName = mdnsName,
                        ServerCapabilities = new ArrayOf<string>(capabilities.ToArray())
                    };
                    StatusCode sc;
                    try
                    {
                        RegisterServer2Response r2 = await client.RegisterServer2Async(header, server,
                            new ArrayOf<ExtensionObject>(new[] { new ExtensionObject(mdns) }), ct).ConfigureAwait(false);
                        sc = r2.ResponseHeader.ServiceResult;
                        foreach (StatusCode cr in r2.ConfigurationResults)
                        {
                            o.ConfigurationResults.Add(cr);
                        }
                    }
                    catch (ServiceResultException e)
                    {
                        sc = e.StatusCode;
                    }
                    o.RegisterServer2Status = sc;
                    o.Status = sc;
                    if (service == "RegisterServer2" || !IsUnsupported(sc))
                    {
                        return o;
                    }
                    o.Fallback = true;
                    o.ConfigurationResults.Clear();
                }
                o.Service = "RegisterServer";
                try
                {
                    RegisterServerResponse r1 = await client.RegisterServerAsync(header, server, ct).ConfigureAwait(false);
                    o.Status = r1.ResponseHeader.ServiceResult;
                }
                catch (ServiceResultException e)
                {
                    o.Status = e.StatusCode;
                }
                return o;
            }
            finally
            {
                try
                {
                    await client.CloseAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // ignore
                }
                client.Dispose();
            }
        }
    }

    /// <summary>The server's --register-with loop (RegisterServer2 → RegisterServer, unregister on SIGTERM).</summary>
    internal sealed class Registrar
    {
        private readonly ApplicationConfiguration m_config;
        private readonly string m_lds;
        private readonly RegisteredServer m_server;
        private readonly string m_name;
        private readonly int m_intervalMs;
        private Task m_task;

        public Registrar(ApplicationConfiguration config, ITelemetryContext telemetry, string lds, string applicationUri,
            Fixture fixture, string advertised, int intervalMs)
        {
            m_config = config;
            m_lds = lds;
            m_intervalMs = intervalMs;
            m_name = fixture.Server.ApplicationName;
            m_server = new RegisteredServer
            {
                ServerUri = applicationUri,
                ProductUri = fixture.Server.ProductUri,
                ServerNames = new ArrayOf<LocalizedText>(new[] { new LocalizedText("en", fixture.Server.ApplicationName) }),
                ServerType = ApplicationType.Server,
                DiscoveryUrls = new ArrayOf<string>(new[] { advertised }),
                IsOnline = true
            };
        }

        public void Start(CancellationToken ct)
        {
            m_task = Task.Run(async () =>
            {
                while (!ct.IsCancellationRequested)
                {
                    try
                    {
                        Registration.Outcome o = await Registration.RegisterAsync(m_config, m_lds, m_server, m_name, ["NA"], "auto", 5000, ct).ConfigureAwait(false);
                        Console.Error.WriteLine("[dotnet] info: registered with " + m_lds + " via " + o.Service + ": " + StatusNames.Name(o.Status.Code));
                    }
                    catch (Exception e) when (!ct.IsCancellationRequested)
                    {
                        Console.Error.WriteLine("[dotnet] warn: registration with " + m_lds + " failed: " + e.Message);
                    }
                    try
                    {
                        await Task.Delay(m_intervalMs, ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                }
            });
        }

        public async Task UnregisterAsync()
        {
            var offline = new RegisteredServer
            {
                ServerUri = m_server.ServerUri,
                ProductUri = m_server.ProductUri,
                ServerNames = m_server.ServerNames,
                ServerType = m_server.ServerType,
                DiscoveryUrls = m_server.DiscoveryUrls,
                IsOnline = false
            };
            try
            {
                using var cts = new CancellationTokenSource(3000);
                Registration.Outcome o = await Registration.RegisterAsync(m_config, m_lds, offline, m_name, ["NA"], "auto", 2000, cts.Token).ConfigureAwait(false);
                Console.Error.WriteLine("[dotnet] info: unregistered from " + m_lds + " via " + o.Service + ": " + StatusNames.Name(o.Status.Code));
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet] warn: unregistration from " + m_lds + " failed: " + e.Message);
            }
        }
    }

    internal static partial class ClientCommand
    {
        private static async Task<int> FindServersOnNetworkAsync(ClientContext c)
        {
            uint start = (uint)c.Args.GetLong("--starting-record-id", 0);
            uint max = (uint)c.Args.GetLong("--max-records", 0);
            List<string> caps = c.Args.All("--capability");
            DiscoveryClient dc = await c.DiscoveryAsync().ConfigureAwait(false);
            FindServersOnNetworkResponse resp;
            try
            {
                resp = await dc.FindServersOnNetworkAsync(null, start, max, new ArrayOf<string>(caps.ToArray()), CancellationToken.None).ConfigureAwait(false);
            }
            catch (ServiceResultException e)
            {
                new Result("find-servers-on-network").ServiceResult(e.StatusCode).Error("service", "FindServersOnNetwork failed").Print();
                return 4;
            }
            finally
            {
                await dc.CloseAsync(CancellationToken.None).ConfigureAwait(false);
                dc.Dispose();
            }
            StatusCode sc = resp.ResponseHeader.ServiceResult;
            if (!StatusCode.IsGood(sc))
            {
                new Result("find-servers-on-network").ServiceResult(sc).Error("service", "FindServersOnNetwork failed").Print();
                return 4;
            }
            var r = new Result("find-servers-on-network");
            string reset = Canonical.HasTime(resp.LastCounterResetTime) ? Canonical.Time(resp.LastCounterResetTime) : null;
            foreach (ServerOnNetwork s in resp.Servers)
            {
                var item = new JsonObject
                {
                    ["recordId"] = s.RecordId,
                    ["serverName"] = s.ServerName ?? string.Empty,
                    ["discoveryUrl"] = s.DiscoveryUrl ?? string.Empty,
                    ["serverCapabilities"] = Json.Strings(s.ServerCapabilities.ToArray() ?? [])
                };
                if (reset != null)
                {
                    item["lastCounterResetTime"] = reset;
                }
                r.Add(item);
            }
            r.Print();
            return 0;
        }

        private static async Task<int> RegisterServerAsync(ClientContext c)
        {
            string serverUri = c.Args.Get("--server-uri");
            List<string> urls = c.Args.All("--discovery-url");
            if (serverUri == null || urls.Count == 0)
            {
                throw new InputException("usage: register-server --endpoint <lds-url> --server-uri <uri> --discovery-url <url> [...]");
            }
            string name = c.Args.Get("--server-name") ?? serverUri;
            string locale = c.Args.Get("--server-name-locale") ?? "en";
            string service = c.Args.Get("--service") ?? "auto";
            if (service is not ("auto" or "RegisterServer2" or "RegisterServer"))
            {
                throw new InputException("invalid --service " + service);
            }
            ApplicationType type = (c.Args.Get("--server-type") ?? "Server") switch
            {
                "Server" => ApplicationType.Server,
                "Client" => ApplicationType.Client,
                "ClientAndServer" => ApplicationType.ClientAndServer,
                "DiscoveryServer" => ApplicationType.DiscoveryServer,
                string s => throw new InputException("invalid --server-type " + s)
            };
            bool online = c.Args.GetBool("--online", true);
            var rs = new RegisteredServer
            {
                ServerUri = serverUri,
                ProductUri = c.Args.Get("--product-uri") ?? string.Empty,
                ServerNames = new ArrayOf<LocalizedText>(new[] { new LocalizedText(locale, name) }),
                ServerType = type,
                GatewayServerUri = c.Args.Get("--gateway-server-uri"),
                DiscoveryUrls = new ArrayOf<string>(urls.ToArray()),
                SemaphoreFilePath = c.Args.Get("--semaphore-file"),
                IsOnline = online
            };
            Registration.Outcome o = await Registration.RegisterAsync(c.Config, c.EndpointUrl, rs,
                c.Args.Get("--mdns-name") ?? name, c.Args.All("--capability"), service, c.RequestTimeoutMs).ConfigureAwait(false);
            var item = new JsonObject
            {
                ["service"] = o.Service,
                ["serverUri"] = serverUri,
                ["isOnline"] = online,
                ["statusCode"] = StatusNames.Json(o.Status),
                ["fallback"] = o.Fallback
            };
            if (o.RegisterServer2Status != null)
            {
                item["registerServer2StatusCode"] = StatusNames.Json(o.RegisterServer2Status.Value);
            }
            var cfg = new JsonArray();
            foreach (StatusCode sc in o.ConfigurationResults)
            {
                cfg.Add(StatusNames.Json(sc));
            }
            item["configurationResults"] = cfg;
            var r = new Result("register-server").ServiceResult(o.Status).Add(item);
            if (!o.Ok)
            {
                r.Error("service", o.Service + " failed");
            }
            r.Print();
            return o.Ok ? 0 : 4;
        }
    }
}
