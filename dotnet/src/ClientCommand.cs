// SPDX-License-Identifier: MIT
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;

namespace OpcUaInterop
{
    /// <summary>The client subcommands of docs/CLIENT_CONTRACT.md.</summary>
    internal static partial class ClientCommand
    {
        public static readonly string[] Operations =
        [
            "endpoints", "find-servers", "read", "write", "browse", "translate", "call", "subscribe",
            "subscription-lifecycle", "event-subscribe", "history-read", "republish", "transfer-subscriptions",
            "register-nodes", "node-management", "find-servers-on-network", "register-server", "codec",
            "pubsub-discover", "alarms"
        ];

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
                if (op == "codec")
                {
                    return await CodecCommand.RunAsync(a).ConfigureAwait(false);
                }
                if (op == "pubsub-discover")
                {
                    return await PubSubDiscover.RunAsync(a).ConfigureAwait(false);
                }
                if (op == "history-read" && a.Get("--endpoint") == null)
                {
                    // Same usage text as the reference adapters: consumers probe it for "--scenario continue".
                    throw new InputException("missing --endpoint, --node, --start, or --end [--scenario continue]");
                }
                c = await ClientContext.CreateAsync(a).ConfigureAwait(false);
                return op switch
                {
                    "endpoints" => await EndpointsAsync(c).ConfigureAwait(false),
                    "find-servers" => await FindServersAsync(c).ConfigureAwait(false),
                    "read" => await ReadAsync(c).ConfigureAwait(false),
                    "write" => await WriteAsync(c).ConfigureAwait(false),
                    "browse" => await BrowseAsync(c).ConfigureAwait(false),
                    "translate" => await TranslateAsync(c).ConfigureAwait(false),
                    "call" => await CallAsync(c).ConfigureAwait(false),
                    "subscribe" => await SubscribeAsync(c).ConfigureAwait(false),
                    "subscription-lifecycle" => await LifecycleAsync(c).ConfigureAwait(false),
                    "event-subscribe" => await EventSubscribeAsync(c).ConfigureAwait(false),
                    "history-read" => await HistoryReadAsync(c).ConfigureAwait(false),
                    "republish" => await RepublishAsync(c).ConfigureAwait(false),
                    "transfer-subscriptions" => await TransferAsync(c).ConfigureAwait(false),
                    "register-nodes" => await RegisterNodesAsync(c).ConfigureAwait(false),
                    "node-management" => await NodeManagementAsync(c).ConfigureAwait(false),
                    "find-servers-on-network" => await FindServersOnNetworkAsync(c).ConfigureAwait(false),
                    "register-server" => await RegisterServerAsync(c).ConfigureAwait(false),
                    "alarms" => await AlarmsAsync(c).ConfigureAwait(false),
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
                bool timeout = e.Code == StatusCodes.BadTimeout.Code;
                new Result(op).ServiceResult(e.Code).Error(timeout ? "timeout" : "transport", e.Message).Print();
                return timeout ? 7 : 3;
            }
            catch (ServiceResultException e)
            {
                bool transport = IsTransport(e.StatusCode.Code);
                new Result(op).Success(false).ServiceResult(e.StatusCode)
                    .Error(transport ? "transport" : "service", e.Message).Print();
                return transport ? 3 : 4;
            }
            catch (InternalFailure e)
            {
                new Result(op).ServiceResult(StatusCodes.BadInternalError).Error("internal", e.Message).Print();
                return 6;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet] error: client " + op + " failed: " + e);
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

        private static bool IsTransport(uint code)
        {
            uint bits = code & 0xFFFF0000;
            return bits == StatusCodes.BadNotConnected.Code || bits == StatusCodes.BadConnectionClosed.Code ||
                bits == StatusCodes.BadCommunicationError.Code || bits == StatusCodes.BadSecureChannelClosed.Code ||
                bits == StatusCodes.BadServerNotConnected.Code || bits == StatusCodes.BadSecureChannelIdInvalid.Code ||
                bits == StatusCodes.BadTcpInternalError.Code || bits == StatusCodes.BadConnectionRejected.Code ||
                bits == StatusCodes.BadDisconnect.Code;
        }

        // ------------------------------------------------------------------
        // discovery
        // ------------------------------------------------------------------

        private static async Task<int> EndpointsAsync(ClientContext c)
        {
            ArrayOf<EndpointDescription> eps;
            try
            {
                eps = await c.GetEndpointsAsync().ConfigureAwait(false);
            }
            catch (ServiceResultException e)
            {
                throw new TransportException("GetEndpoints " + c.EndpointUrl + ": " + e.Message, e.StatusCode.Code);
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

        private static async Task<int> FindServersAsync(ClientContext c)
        {
            DiscoveryClient dc = await c.DiscoveryAsync().ConfigureAwait(false);
            ArrayOf<ApplicationDescription> apps;
            try
            {
                FindServersResponse resp = await dc.FindServersAsync(null, c.EndpointUrl, default, default, CancellationToken.None).ConfigureAwait(false);
                apps = resp.Servers;
            }
            finally
            {
                await dc.CloseAsync(CancellationToken.None).ConfigureAwait(false);
                dc.Dispose();
            }
            var r = new Result("find-servers");
            foreach (ApplicationDescription app in apps)
            {
                r.Add(new JsonObject
                {
                    ["applicationUri"] = app.ApplicationUri ?? string.Empty,
                    ["applicationName"] = Json.Obj(
                        ("locale", JsonValue.Create(app.ApplicationName.Locale ?? string.Empty)),
                        ("text", JsonValue.Create(app.ApplicationName.Text ?? string.Empty))),
                    ["productUri"] = app.ProductUri ?? string.Empty,
                    ["discoveryUrls"] = Json.Strings(app.DiscoveryUrls.ToArray() ?? [])
                });
            }
            r.Print();
            return 0;
        }

        // ------------------------------------------------------------------
        // attribute / view / method services
        // ------------------------------------------------------------------

        private static TimestampsToReturn Timestamps(Args a) => (a.Get("--timestamps") ?? "Both") switch
        {
            "Source" => TimestampsToReturn.Source,
            "Server" => TimestampsToReturn.Server,
            "Neither" => TimestampsToReturn.Neither,
            "Both" => TimestampsToReturn.Both,
            string s => throw new InputException("invalid --timestamps " + s)
        };

        private static List<NodeId> ParseNodesOffline(Args a, string flag = "--node")
        {
            // syntax check before any network traffic (§8: malformed → exit 2, no request)
            var list = new List<NodeId>();
            foreach (string s in a.All(flag))
            {
                if (!s.StartsWith("nsu=", StringComparison.Ordinal))
                {
                    list.Add(NodeIds.Parse(s));
                }
                else if (s.IndexOf(';', 4) < 0)
                {
                    throw new InputException("malformed NodeId: '" + s + "'");
                }
            }
            return list;
        }

        private static async Task<int> ReadAsync(ClientContext c)
        {
            List<string> nodes = c.Args.All("--node");
            if (nodes.Count == 0)
            {
                throw new InputException("missing --node");
            }
            ParseNodesOffline(c.Args);
            string indexRange = c.Args.Get("--index-range");
            TimestampsToReturn ts = Timestamps(c.Args);
            await c.ConnectAsync().ConfigureAwait(false);
            List<NodeId> ids = nodes.Select(c.Node).ToList();
            ReadResponse resp = await c.Session.ReadAsync(c.Header(), 0, ts,
                new ArrayOf<ReadValueId>(ids.Select(n => new ReadValueId { NodeId = n, AttributeId = Attributes.Value, IndexRange = indexRange }).ToArray()),
                CancellationToken.None).ConfigureAwait(false);
            var r = new Result("read");
            bool anyBad = false;
            for (int i = 0; i < ids.Count; i++)
            {
                DataValue dv = resp.Results[i];
                var item = new JsonObject
                {
                    ["nodeId"] = Canonical.NodeId(ids[i]),
                    ["statusCode"] = StatusNames.Json(dv.StatusCode)
                };
                Canonical.PutValue(item, dv.WrappedValue);
                if (Canonical.HasTime(dv.SourceTimestamp))
                {
                    item["sourceTimestamp"] = Canonical.Time(dv.SourceTimestamp);
                }
                r.Add(item);
                if (!StatusCode.IsGood(dv.StatusCode))
                {
                    anyBad = true;
                }
            }
            if (ids.Count == 1)
            {
                r.ServiceResult(resp.Results[0].StatusCode);
            }
            if (anyBad)
            {
                r.Success(false);
            }
            r.Print();
            return anyBad ? 4 : 0;
        }

        private static async Task<int> WriteAsync(ClientContext c)
        {
            List<string> nodes = c.Args.All("--node");
            List<string> types = c.Args.All("--type");
            List<string> values = c.Args.All("--value");
            if (nodes.Count == 0 || nodes.Count != types.Count || nodes.Count != values.Count)
            {
                throw new InputException("write requires equal counts of --node, --type, and --value");
            }
            ParseNodesOffline(c.Args);
            string indexRange = c.Args.Get("--index-range");
            await c.ConnectAsync().ConfigureAwait(false);
            List<NodeId> ids = nodes.Select(c.Node).ToList();
            var wv = new WriteValue[ids.Count];
            for (int i = 0; i < ids.Count; i++)
            {
                wv[i] = new WriteValue
                {
                    NodeId = ids[i],
                    AttributeId = Attributes.Value,
                    IndexRange = indexRange,
                    Value = new DataValue(ValueParser.ParseLenient(types[i], values[i]))
                };
            }
            WriteResponse resp = await c.Session.WriteAsync(c.Header(), new ArrayOf<WriteValue>(wv), CancellationToken.None).ConfigureAwait(false);
            var r = new Result("write");
            bool anyBad = false;
            StatusCode firstBad = StatusCodes.Good;
            for (int i = 0; i < ids.Count; i++)
            {
                StatusCode sc = resp.Results[i];
                r.Add(new JsonObject { ["nodeId"] = Canonical.NodeId(ids[i]), ["statusCode"] = StatusNames.Json(sc) });
                if (!StatusCode.IsGood(sc))
                {
                    if (!anyBad)
                    {
                        firstBad = sc;
                    }
                    anyBad = true;
                }
            }
            if (ids.Count == 1)
            {
                r.ServiceResult(resp.Results[0]);
            }
            else if (anyBad)
            {
                r.ServiceResult(firstBad);
            }
            if (anyBad)
            {
                r.Success(false);
            }
            r.Print();
            return anyBad ? 4 : 0;
        }

        private static async Task<int> BrowseAsync(ClientContext c)
        {
            string nodeStr = c.Args.Get("--node") ?? "i=85";
            if (!nodeStr.StartsWith("nsu=", StringComparison.Ordinal))
            {
                NodeIds.Parse(nodeStr);
            }
            uint maxRefs = (uint)c.Args.GetLong("--max-refs", 0);
            uint nodeClassMask = (uint)c.Args.GetLong("--node-class-mask", 0);
            bool includeSubtypes = c.Args.GetBool("--include-subtypes", true);
            uint resultMask = (uint)c.Args.GetLong("--result-mask", (long)BrowseResultMask.All);
            await c.ConnectAsync().ConfigureAwait(false);
            NodeId node = c.Node(nodeStr);
            BrowseResponse resp = await c.Session.BrowseAsync(c.Header(), null, maxRefs,
                new ArrayOf<BrowseDescription>(new[]
                {
                    new BrowseDescription
                    {
                        NodeId = node,
                        BrowseDirection = BrowseDirection.Forward,
                        ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences,
                        IncludeSubtypes = includeSubtypes,
                        NodeClassMask = nodeClassMask,
                        ResultMask = resultMask
                    }
                }), CancellationToken.None).ConfigureAwait(false);
            BrowseResult first = resp.Results[0];
            var refs = new List<ReferenceDescription>(first.References.ToArray() ?? []);
            ByteString cp = first.ContinuationPoint;
            int guard = 0;
            while (!cp.IsNull && cp.Length > 0 && guard++ < 1000)
            {
                BrowseNextResponse next = await c.Session.BrowseNextAsync(c.Header(), false,
                    new ArrayOf<ByteString>(new[] { cp }), CancellationToken.None).ConfigureAwait(false);
                BrowseResult br = next.Results[0];
                refs.AddRange(br.References.ToArray() ?? []);
                cp = br.ContinuationPoint;
                if (!StatusCode.IsGood(br.StatusCode))
                {
                    break;
                }
            }
            var r = new Result("browse").ServiceResult(first.StatusCode).Success(StatusCode.IsGood(first.StatusCode));
            foreach (ReferenceDescription rd in refs)
            {
                r.Add(new JsonObject
                {
                    ["referenceTypeId"] = Canonical.NodeId(rd.ReferenceTypeId),
                    ["isForward"] = rd.IsForward,
                    ["nodeId"] = Canonical.NodeId(Canonical.Local(rd.NodeId)),
                    ["browseName"] = Json.Obj(("ns", JsonValue.Create((int)rd.BrowseName.NamespaceIndex)), ("name", JsonValue.Create(rd.BrowseName.Name ?? string.Empty))),
                    ["displayName"] = Json.Obj(("locale", JsonValue.Create(rd.DisplayName.Locale ?? string.Empty)), ("text", JsonValue.Create(rd.DisplayName.Text ?? string.Empty))),
                    ["nodeClass"] = rd.NodeClass.ToString()
                });
            }
            r.Print();
            return StatusCode.IsGood(first.StatusCode) ? 0 : 4;
        }

        private static async Task<int> TranslateAsync(ClientContext c)
        {
            string start = c.Args.Get("--starting-node") ?? "i=85";
            string path = c.Args.Get("--path");
            if (string.IsNullOrEmpty(path))
            {
                throw new InputException("missing --path");
            }
            string[] segments = path.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length == 0)
            {
                throw new InputException("empty --path");
            }
            ushort ns = (ushort)c.Args.GetInt("--namespace", 0);
            if (!start.StartsWith("nsu=", StringComparison.Ordinal))
            {
                NodeIds.Parse(start);
            }
            await c.ConnectAsync().ConfigureAwait(false);
            NodeId startNode = c.Node(start);
            var bp = new BrowsePath
            {
                StartingNode = startNode,
                RelativePath = new RelativePath
                {
                    Elements = new ArrayOf<RelativePathElement>(segments.Select(s => new RelativePathElement
                    {
                        ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences,
                        IsInverse = false,
                        IncludeSubtypes = true,
                        TargetName = new QualifiedName(s, ns)
                    }).ToArray())
                }
            };
            TranslateBrowsePathsToNodeIdsResponse resp = await c.Session.TranslateBrowsePathsToNodeIdsAsync(
                c.Header(), new ArrayOf<BrowsePath>(new[] { bp }), CancellationToken.None).ConfigureAwait(false);
            StatusCode service = resp.ResponseHeader.ServiceResult;
            StatusCode pathSc = resp.Results.Count > 0 ? resp.Results[0].StatusCode : service;
            bool ok = StatusCode.IsGood(service) && StatusCode.IsGood(pathSc);
            var r = new Result("translate").ServiceResult(service).Success(ok);
            if (resp.Results.Count > 0)
            {
                var targets = new JsonArray();
                foreach (BrowsePathTarget t in resp.Results[0].Targets)
                {
                    targets.Add(JsonValue.Create(Canonical.NodeId(Canonical.Local(t.TargetId))));
                }
                r.Add(new JsonObject { ["statusCode"] = StatusNames.Json(pathSc), ["targets"] = targets });
            }
            r.Print();
            return ok ? 0 : 4;
        }

        private static async Task<int> CallAsync(ClientContext c)
        {
            string obj = c.Args.Get("--object");
            string method = c.Args.Get("--method");
            if (obj == null || method == null)
            {
                throw new InputException("missing --object or --method");
            }
            var inputs = new List<Variant>();
            foreach (string spec in c.Args.All("--input"))
            {
                int colon = spec.IndexOf(':');
                if (colon > 0)
                {
                    inputs.Add(ValueParser.ParseLenient(spec[..colon], spec[(colon + 1)..]));
                }
            }
            await c.ConnectAsync().ConfigureAwait(false);
            NodeId objectId = c.Node(obj);
            NodeId methodId = c.Node(method);
            CallResponse resp = await c.Session.CallAsync(c.Header(), new ArrayOf<CallMethodRequest>(new[]
            {
                new CallMethodRequest { ObjectId = objectId, MethodId = methodId, InputArguments = new ArrayOf<Variant>(inputs.ToArray()) }
            }), CancellationToken.None).ConfigureAwait(false);
            CallMethodResult mr = resp.Results[0];
            var outs = new JsonArray();
            foreach (Variant v in mr.OutputArguments)
            {
                outs.Add(Canonical.Value(v));
            }
            bool ok = StatusCode.IsGood(mr.StatusCode);
            new Result("call").Success(ok).ServiceResult(mr.StatusCode).Add(new JsonObject
            {
                ["objectNodeId"] = Canonical.NodeId(objectId),
                ["methodNodeId"] = Canonical.NodeId(methodId),
                ["statusCode"] = StatusNames.Json(mr.StatusCode),
                ["outputArguments"] = outs
            }).Print();
            return ok ? 0 : 4;
        }

        private static async Task<int> RegisterNodesAsync(ClientContext c)
        {
            List<string> nodes = c.Args.All("--node");
            if (nodes.Count == 0)
            {
                throw new InputException("missing --node");
            }
            ParseNodesOffline(c.Args);
            await c.ConnectAsync().ConfigureAwait(false);
            List<NodeId> ids = nodes.Select(c.Node).ToList();
            RegisterNodesResponse reg = await c.Session.RegisterNodesAsync(c.Header(), new ArrayOf<NodeId>(ids.ToArray()), CancellationToken.None).ConfigureAwait(false);
            if (reg.RegisteredNodeIds.Count != ids.Count)
            {
                new Result("register-nodes").Success(false).ServiceResult(StatusCodes.BadUnexpectedError)
                    .Error("service", "RegisterNodes returned an unexpected number of ids").Print();
                return 4;
            }
            NodeId[] registered = reg.RegisteredNodeIds.ToArray();
            ReadResponse read = await c.Session.ReadAsync(c.Header(), 0, TimestampsToReturn.Source,
                new ArrayOf<ReadValueId>(registered.Select(n => new ReadValueId { NodeId = n, AttributeId = Attributes.Value }).ToArray()),
                CancellationToken.None).ConfigureAwait(false);
            StatusCode unreg;
            try
            {
                UnregisterNodesResponse u = await c.Session.UnregisterNodesAsync(c.Header(), new ArrayOf<NodeId>(registered), CancellationToken.None).ConfigureAwait(false);
                unreg = u.ResponseHeader.ServiceResult;
            }
            catch (ServiceResultException e)
            {
                unreg = e.StatusCode;
            }
            var r = new Result("register-nodes");
            bool anyBad = !StatusCode.IsGood(unreg);
            StatusCode? firstBad = anyBad ? unreg : null;
            for (int i = 0; i < ids.Count; i++)
            {
                DataValue dv = read.Results[i];
                var item = new JsonObject
                {
                    ["nodeId"] = Canonical.NodeId(ids[i]),
                    ["registeredNodeId"] = Canonical.NodeId(registered[i]),
                    ["statusCode"] = StatusNames.Json(dv.StatusCode)
                };
                if (StatusCode.IsGood(dv.StatusCode))
                {
                    Canonical.PutValue(item, dv.WrappedValue);
                }
                else
                {
                    anyBad = true;
                    firstBad ??= dv.StatusCode;
                }
                item["unregisterStatusCode"] = StatusNames.Json(unreg);
                r.Add(item);
            }
            if (firstBad != null)
            {
                r.ServiceResult(firstBad.Value);
            }
            if (anyBad)
            {
                r.Success(false);
            }
            r.Print();
            return anyBad ? 4 : 0;
        }

        private static async Task<int> NodeManagementAsync(ClientContext c)
        {
            string parent = c.Args.Get("--parent");
            string node = c.Args.Get("--node");
            if (parent == null || node == null)
            {
                throw new InputException("missing --parent or --node");
            }
            string browseName = c.Args.Get("--browse-name") ?? "InteropAdded";
            int value = c.Args.GetInt("--value", 42);
            await c.ConnectAsync().ConfigureAwait(false);
            NodeId parentId = c.Node(parent);
            NodeId newId = c.Node(node);
            var attrs = new VariableAttributes
            {
                SpecifiedAttributes = (uint)(NodeAttributesMask.AccessLevel | NodeAttributesMask.DataType | NodeAttributesMask.DisplayName |
                    NodeAttributesMask.UserAccessLevel | NodeAttributesMask.ValueRank | NodeAttributesMask.Value),
                DisplayName = new LocalizedText("en", browseName),
                Value = new Variant(value),
                DataType = DataTypeIds.Int32,
                ValueRank = ValueRanks.Scalar,
                AccessLevel = (byte)(AccessLevels.CurrentRead | AccessLevels.CurrentWrite),
                UserAccessLevel = (byte)(AccessLevels.CurrentRead | AccessLevels.CurrentWrite)
            };
            AddNodesResponse add = await c.Session.AddNodesAsync(c.Header(), new ArrayOf<AddNodesItem>(new[]
            {
                new AddNodesItem
                {
                    ParentNodeId = new ExpandedNodeId(parentId),
                    ReferenceTypeId = ReferenceTypeIds.HasComponent,
                    RequestedNewNodeId = new ExpandedNodeId(newId),
                    BrowseName = new QualifiedName(browseName, newId.NamespaceIndex),
                    NodeClass = NodeClass.Variable,
                    NodeAttributes = new ExtensionObject(attrs),
                    TypeDefinition = new ExpandedNodeId(VariableTypeIds.BaseDataVariableType)
                }
            }), CancellationToken.None).ConfigureAwait(false);
            StatusCode addSc = add.Results.Count == 1 ? add.Results[0].StatusCode : StatusCodes.BadUnexpectedError;
            var item = new JsonObject
            {
                ["parentNodeId"] = Canonical.NodeId(parentId),
                ["requestedNodeId"] = Canonical.NodeId(newId),
                ["addStatusCode"] = StatusNames.Json(addSc)
            };
            bool ok = false;
            StatusCode emit = addSc;
            if (StatusCode.IsGood(addSc))
            {
                NodeId added = add.Results[0].AddedNodeId;
                item["addedNodeId"] = Canonical.NodeId(added);
                var rid = new ArrayOf<ReadValueId>(new[] { new ReadValueId { NodeId = added, AttributeId = Attributes.Value } });
                DataValue dv = (await c.Session.ReadAsync(c.Header(), 0, TimestampsToReturn.Source, rid, CancellationToken.None).ConfigureAwait(false)).Results[0];
                item["readStatusCode"] = StatusNames.Json(dv.StatusCode);
                bool matches = false;
                if (StatusCode.IsGood(dv.StatusCode))
                {
                    Canonical.PutValue(item, dv.WrappedValue);
                    matches = dv.WrappedValue.TypeInfo.BuiltInType == BuiltInType.Int32 && dv.WrappedValue.GetInt32() == value;
                }
                DeleteNodesResponse del = await c.Session.DeleteNodesAsync(c.Header(), new ArrayOf<DeleteNodesItem>(new[]
                {
                    new DeleteNodesItem { NodeId = added, DeleteTargetReferences = true }
                }), CancellationToken.None).ConfigureAwait(false);
                StatusCode delSc = del.Results.Count == 1 ? del.Results[0] : StatusCodes.BadUnexpectedError;
                item["deleteStatusCode"] = StatusNames.Json(delSc);
                DataValue gone = (await c.Session.ReadAsync(c.Header(), 0, TimestampsToReturn.Source, rid, CancellationToken.None).ConfigureAwait(false)).Results[0];
                item["readAfterDeleteStatusCode"] = StatusNames.Json(gone.StatusCode);
                ok = StatusCode.IsGood(dv.StatusCode) && matches && StatusCode.IsGood(delSc) && StatusCode.IsBad(gone.StatusCode);
                if (!StatusCode.IsGood(dv.StatusCode))
                {
                    emit = dv.StatusCode;
                }
                else if (!StatusCode.IsGood(delSc))
                {
                    emit = delSc;
                }
            }
            var r = new Result("node-management").Add(item).ServiceResult(emit);
            if (!ok)
            {
                r.Success(false);
            }
            r.Print();
            return ok ? 0 : 4;
        }
    }
}
