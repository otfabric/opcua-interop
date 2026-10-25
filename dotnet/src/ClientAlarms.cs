// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>
    /// client alarms (docs/CLIENT_CONTRACT.md "alarms"): ConditionRefresh on an event monitored
    /// item, then Acknowledge / Confirm / AddComment on the refreshed condition (Part 9).
    /// </summary>
    internal static partial class ClientCommand
    {
        // SelectClauses 0..15 of the contract, in this order.
        internal static readonly (NodeId Type, string[] Path, uint Attribute)[] s_alarmClauses =
        [
            (ObjectTypeIds.BaseEventType, ["EventId"], Attributes.Value),
            (ObjectTypeIds.BaseEventType, ["EventType"], Attributes.Value),
            (ObjectTypeIds.BaseEventType, ["SourceNode"], Attributes.Value),
            (ObjectTypeIds.BaseEventType, ["SourceName"], Attributes.Value),
            (ObjectTypeIds.BaseEventType, ["Time"], Attributes.Value),
            (ObjectTypeIds.BaseEventType, ["Message"], Attributes.Value),
            (ObjectTypeIds.BaseEventType, ["Severity"], Attributes.Value),
            (ObjectTypeIds.ConditionType, ["ConditionName"], Attributes.Value),
            (ObjectTypeIds.ConditionType, ["BranchId"], Attributes.Value),
            (ObjectTypeIds.ConditionType, ["Retain"], Attributes.Value),
            (ObjectTypeIds.ConditionType, ["EnabledState", "Id"], Attributes.Value),
            (ObjectTypeIds.ConditionType, ["Comment"], Attributes.Value),
            (ObjectTypeIds.AcknowledgeableConditionType, ["AckedState", "Id"], Attributes.Value),
            (ObjectTypeIds.AcknowledgeableConditionType, ["ConfirmedState", "Id"], Attributes.Value),
            (ObjectTypeIds.AlarmConditionType, ["ActiveState", "Id"], Attributes.Value),
            (ObjectTypeIds.ConditionType, [], Attributes.NodeId)
        ];

        private const int FEventId = 0, FEventType = 1, FSourceNode = 2, FSourceName = 3, FTime = 4, FMessage = 5,
            FSeverity = 6, FConditionName = 7, FRetain = 9, FEnabled = 10, FComment = 11, FAcked = 12,
            FConfirmed = 13, FActive = 14, FConditionId = 15;

        /// <summary>A presence flag: "--x" alone or "--x true" is true, "--x false" / "--x 0" is false.</summary>
        internal static bool PresenceFlag(Args a, string flag)
        {
            string[] raw = a.Raw;
            int idx = Array.LastIndexOf(raw, flag);
            if (idx < 0)
            {
                return false;
            }
            string next = idx + 1 < raw.Length ? raw[idx + 1] : null;
            return !(next != null && (next.Equals("false", StringComparison.OrdinalIgnoreCase) || next == "0"));
        }

        private static object AlarmField(Variant[] f, int i)
        {
            if (f == null || i >= f.Length || f[i].IsNull || !f[i].TypeInfo.IsScalar)
            {
                return null;
            }
            return f[i].AsBoxedObject(Variant.BoxingBehavior.Legacy);
        }

        private static NodeId AlarmNodeId(Variant[] f, int i) => AlarmField(f, i) switch
        {
            NodeId n when !n.IsNull => n,
            ExpandedNodeId e when !e.IsNull => e.InnerNodeId,
            _ => NodeId.Null
        };

        private static JsonNode AlarmNodeJson(Variant[] f, int i)
        {
            NodeId n = AlarmNodeId(f, i);
            return n.IsNull ? null : JsonValue.Create(Canonical.NodeId(n));
        }

        private static JsonNode AlarmString(Variant[] f, int i) =>
            AlarmField(f, i) is string s ? JsonValue.Create(s) : null;

        private static string AlarmTextValue(Variant[] f, int i) => AlarmField(f, i) switch
        {
            LocalizedText lt => lt.Text ?? string.Empty,
            string s => s,
            _ => null
        };

        private static JsonNode AlarmText(Variant[] f, int i)
        {
            string s = AlarmTextValue(f, i);
            return s == null ? null : JsonValue.Create(s);
        }

        private static bool? AlarmBoolValue(Variant[] f, int i) => AlarmField(f, i) is bool b ? b : null;

        private static JsonNode AlarmBool(Variant[] f, int i)
        {
            bool? b = AlarmBoolValue(f, i);
            return b.HasValue ? JsonValue.Create(b.Value) : null;
        }

        private static JsonNode AlarmSeverity(Variant[] f, int i) => AlarmField(f, i) switch
        {
            ushort u => JsonValue.Create((int)u),
            uint u => JsonValue.Create(u),
            int n => JsonValue.Create(n),
            short s => JsonValue.Create((int)s),
            byte b => JsonValue.Create((int)b),
            _ => null
        };

        private static JsonNode AlarmTime(Variant[] f, int i) => AlarmField(f, i) switch
        {
            DateTimeUtc t when Canonical.HasTime(t) => JsonValue.Create(Canonical.Time(t)),
            DateTime d when Canonical.HasTime(new DateTimeUtc(d)) => JsonValue.Create(Canonical.Time(new DateTimeUtc(d))),
            _ => null
        };

        private static JsonNode AlarmBytes(Variant[] f, int i) => AlarmField(f, i) switch
        {
            byte[] b => JsonValue.Create(Convert.ToBase64String(b)),
            ByteString bs when !bs.IsNull => JsonValue.Create(Convert.ToBase64String(bs.Span)),
            _ => null
        };

        /// <summary>The ConditionEntry of the contract for one event field list.</summary>
        internal static JsonObject ConditionEntry(Variant[] f) => new()
        {
            ["conditionId"] = AlarmNodeJson(f, FConditionId),
            ["eventId"] = AlarmBytes(f, FEventId),
            ["eventType"] = AlarmNodeJson(f, FEventType),
            ["sourceNode"] = AlarmNodeJson(f, FSourceNode),
            ["sourceName"] = AlarmString(f, FSourceName),
            ["conditionName"] = AlarmString(f, FConditionName),
            ["time"] = AlarmTime(f, FTime),
            ["message"] = AlarmText(f, FMessage),
            ["severity"] = AlarmSeverity(f, FSeverity),
            ["retain"] = AlarmBool(f, FRetain),
            ["enabled"] = AlarmBool(f, FEnabled),
            ["acked"] = AlarmBool(f, FAcked),
            ["confirmed"] = AlarmBool(f, FConfirmed),
            ["active"] = AlarmBool(f, FActive),
            ["comment"] = AlarmText(f, FComment)
        };

        private static async Task<int> AlarmsAsync(ClientContext c)
        {
            string nodeStr = c.Args.Get("--node") ?? "i=2253";
            if (!nodeStr.StartsWith("nsu=", StringComparison.Ordinal))
            {
                NodeIds.Parse(nodeStr);
            }
            else if (nodeStr.IndexOf(';', 4) < 0)
            {
                throw new InputException("malformed NodeId: '" + nodeStr + "'");
            }
            string conditionName = c.Args.Get("--condition-name");
            bool doAck = PresenceFlag(c.Args, "--acknowledge");
            bool doConfirm = PresenceFlag(c.Args, "--confirm");
            bool doComment = PresenceFlag(c.Args, "--add-comment");
            string comment = c.Args.Get("--comment") ?? "interop-comment";
            int timeoutMs = c.Args.GetInt("--timeout-ms", 15000);
            double pi = c.Args.GetDouble("--publishing-interval-ms", 200);

            await c.ConnectAsync().ConfigureAwait(false);
            NodeId node = c.Node(nodeStr);
            var clock = Stopwatch.StartNew();
            int Remaining() => (int)Math.Max(0, timeoutMs - clock.ElapsedMilliseconds);

            var filter = new EventFilter
            {
                SelectClauses = new ArrayOf<SimpleAttributeOperand>(s_alarmClauses.Select(s => new SimpleAttributeOperand
                {
                    TypeDefinitionId = s.Type,
                    BrowsePath = new ArrayOf<QualifiedName>(s.Path.Select(p => new QualifiedName(p, 0)).ToArray()),
                    AttributeId = s.Attribute
                }).ToArray()),
                WhereClause = new ContentFilter { Elements = new ArrayOf<ContentFilterElement>(Array.Empty<ContentFilterElement>()) }
            };

            CreateSubscriptionResponse sub = await CreateSubscriptionAsync(c, pi).ConfigureAwait(false);
            var events = new List<Variant[]>();
            await using var loop = new PublishLoop(c);
            loop.Event += (subId, ev) =>
            {
                if (subId != sub.SubscriptionId || ev.ClientHandle != ClientHandle)
                {
                    return;
                }
                lock (events)
                {
                    events.Add(ev.EventFields.ToArray() ?? []);
                }
            };
            loop.Start();

            CreateMonitoredItemsResponse cmi = await c.Session.CreateMonitoredItemsAsync(c.Header(), sub.SubscriptionId, TimestampsToReturn.Both,
                new ArrayOf<MonitoredItemCreateRequest>(new[]
                {
                    new MonitoredItemCreateRequest
                    {
                        ItemToMonitor = new ReadValueId { NodeId = node, AttributeId = Attributes.EventNotifier },
                        MonitoringMode = MonitoringMode.Reporting,
                        RequestedParameters = new MonitoringParameters
                        {
                            ClientHandle = ClientHandle,
                            SamplingInterval = 0,
                            QueueSize = 1000,
                            DiscardOldest = true,
                            Filter = new ExtensionObject(filter)
                        }
                    }
                }), CancellationToken.None).ConfigureAwait(false);
            StatusCode monSc = cmi.Results[0].StatusCode;

            var item = new JsonObject
            {
                ["nodeId"] = Canonical.NodeId(node),
                ["subscriptionId"] = sub.SubscriptionId,
                ["monitoredItemStatusCode"] = StatusNames.Json(monSc)
            };
            var conditions = new List<string>();
            var conditionEvents = new Dictionary<string, Variant[]>();
            var latest = new Dictionary<string, Variant[]>();
            bool startSeen = false, endSeen = false;
            int processed = 0;
            int refreshFrom = int.MaxValue;

            async Task<int> Finish(bool ok, StatusCode sr, string category, string message, int code)
            {
                await DeleteSubscriptionQuietlyAsync(c, sub.SubscriptionId).ConfigureAwait(false);
                item["conditions"] ??= new JsonArray();
                foreach (string k in new[] { "target", "acknowledge", "confirm", "addComment" })
                {
                    if (!item.ContainsKey(k))
                    {
                        item[k] = null;
                    }
                }
                var r = new Result("alarms").Success(ok).ServiceResult(sr).Add(item);
                if (!ok)
                {
                    r.Error(category, message);
                }
                r.Print();
                return code;
            }

            if (!StatusCode.IsGood(monSc))
            {
                item["refresh"] = new JsonObject
                {
                    ["statusCode"] = StatusNames.Json(monSc),
                    ["startSeen"] = false,
                    ["endSeen"] = false
                };
                return await Finish(false, monSc, "service", "CreateMonitoredItems rejected the event monitored item", 4).ConfigureAwait(false);
            }

            // Processes the events received so far (in arrival order).
            void Drain()
            {
                lock (events)
                {
                    for (; processed < events.Count; processed++)
                    {
                        Variant[] f = events[processed];
                        NodeId type = AlarmNodeId(f, FEventType);
                        bool inRefresh = processed >= refreshFrom && !endSeen;
                        if (inRefresh && type == ObjectTypeIds.RefreshStartEventType)
                        {
                            startSeen = true;
                            continue;
                        }
                        if (inRefresh && type == ObjectTypeIds.RefreshEndEventType)
                        {
                            endSeen = true;
                            continue;
                        }
                        NodeId cond = AlarmNodeId(f, FConditionId);
                        if (cond.IsNull)
                        {
                            continue;
                        }
                        string key = Canonical.NodeId(cond);
                        latest[key] = f;
                        if (inRefresh)
                        {
                            if (!conditionEvents.ContainsKey(key))
                            {
                                conditions.Add(key);
                            }
                            conditionEvents[key] = f;
                        }
                    }
                }
            }

            int EventCount()
            {
                lock (events)
                {
                    return events.Count;
                }
            }

            // Waits for an event at index >= from that satisfies pred; null on timeout.
            async Task<Variant[]> WaitForAsync(int from, Func<Variant[], bool> pred)
            {
                int scanned = from;
                while (true)
                {
                    Drain();
                    lock (events)
                    {
                        for (; scanned < events.Count; scanned++)
                        {
                            if (pred(events[scanned]))
                            {
                                return events[scanned];
                            }
                        }
                    }
                    if (Remaining() <= 0)
                    {
                        return null;
                    }
                    await Task.Delay(Math.Min(20, Remaining())).ConfigureAwait(false);
                }
            }

            async Task<StatusCode> CallAsync1(NodeId objectId, NodeId methodId, params Variant[] inputs)
            {
                try
                {
                    CallResponse resp = await c.Session.CallAsync(c.Header(), new ArrayOf<CallMethodRequest>(new[]
                    {
                        new CallMethodRequest { ObjectId = objectId, MethodId = methodId, InputArguments = new ArrayOf<Variant>(inputs) }
                    }), CancellationToken.None).ConfigureAwait(false);
                    StatusCode svc = resp.ResponseHeader.ServiceResult;
                    if (StatusCode.IsBad(svc))
                    {
                        return svc;
                    }
                    return resp.Results.Count > 0 ? resp.Results[0].StatusCode : StatusCodes.BadUnexpectedError;
                }
                catch (ServiceResultException e) when (!IsTransport(e.StatusCode.Code))
                {
                    return e.StatusCode;
                }
            }

            // ConditionRefresh
            refreshFrom = EventCount();
            StatusCode refreshSc = await CallAsync1(ObjectTypeIds.ConditionType, MethodIds.ConditionType_ConditionRefresh,
                new Variant(sub.SubscriptionId)).ConfigureAwait(false);
            if (StatusCode.IsGood(refreshSc))
            {
                await WaitForAsync(refreshFrom, _ => endSeen).ConfigureAwait(false);
            }
            Drain();

            void PutRefresh()
            {
                item["refresh"] = new JsonObject
                {
                    ["statusCode"] = StatusNames.Json(refreshSc),
                    ["startSeen"] = startSeen,
                    ["endSeen"] = endSeen
                };
                var list = new JsonArray();
                foreach (string k in conditions)
                {
                    list.Add(ConditionEntry(conditionEvents[k]));
                }
                item["conditions"] = list;
            }
            PutRefresh();

            if (!StatusCode.IsGood(refreshSc))
            {
                return await Finish(false, refreshSc, "service", "ConditionRefresh failed", 4).ConfigureAwait(false);
            }
            if (!endSeen)
            {
                return await Finish(false, StatusCodes.BadTimeout, "timeout", "timeout waiting for the RefreshEndEvent", 7).ConfigureAwait(false);
            }

            string targetKey = null;
            foreach (string k in conditions)
            {
                Variant[] f = conditionEvents[k];
                if (conditionName != null ? AlarmField(f, FConditionName) as string == conditionName : AlarmBoolValue(f, FRetain) == true)
                {
                    targetKey = k;
                    break;
                }
            }
            item["target"] = targetKey == null ? null : ConditionEntry(conditionEvents[targetKey]);
            item["acknowledge"] = null;
            item["confirm"] = null;
            item["addComment"] = null;
            if (!doAck && !doConfirm && !doComment)
            {
                return await Finish(true, StatusCodes.Good, null, null, 0).ConfigureAwait(false);
            }
            if (targetKey == null)
            {
                return await Finish(false, StatusCodes.BadNodeIdUnknown, "service",
                    conditionName != null ? "no condition named " + conditionName + " in the refresh" : "no retained condition in the refresh", 4).ConfigureAwait(false);
            }
            NodeId targetId = AlarmNodeId(conditionEvents[targetKey], FConditionId);
            var commentText = new Variant(new LocalizedText("en", comment));

            bool OfTarget(Variant[] f) => AlarmNodeId(f, FConditionId) is { IsNull: false } n && Canonical.NodeId(n) == targetKey;

            // Runs one condition method with the latest EventId of the target and waits for its follow-up event.
            async Task<(StatusCode Status, Variant EventId, JsonObject Event, bool TimedOut)> ActionAsync(NodeId method, Func<Variant[], bool> pred)
            {
                Drain();
                Variant eventId = latest[targetKey][FEventId];
                int from = EventCount();
                StatusCode sc = await CallAsync1(targetId, method, eventId, commentText).ConfigureAwait(false);
                if (!StatusCode.IsGood(sc))
                {
                    return (sc, eventId, null, false);
                }
                Variant[] ev = await WaitForAsync(from, f => OfTarget(f) && pred(f)).ConfigureAwait(false);
                return (sc, eventId, ev == null ? null : ConditionEntry(ev), ev == null);
            }

            if (doAck)
            {
                var (sc, eventId, ev, timedOut) = await ActionAsync(MethodIds.AcknowledgeableConditionType_Acknowledge,
                    f => AlarmBoolValue(f, FAcked) == true).ConfigureAwait(false);
                var ack = new JsonObject { ["statusCode"] = StatusNames.Json(sc), ["event"] = ev, ["repeatStatusCode"] = null };
                item["acknowledge"] = ack;
                if (!StatusCode.IsGood(sc))
                {
                    return await Finish(false, sc, "service", "Acknowledge failed", 4).ConfigureAwait(false);
                }
                if (timedOut)
                {
                    return await Finish(false, StatusCodes.BadTimeout, "timeout", "timeout waiting for the acknowledged event", 7).ConfigureAwait(false);
                }
                StatusCode repeat = await CallAsync1(targetId, MethodIds.AcknowledgeableConditionType_Acknowledge, eventId, commentText).ConfigureAwait(false);
                ack["repeatStatusCode"] = StatusNames.Json(repeat);
            }
            if (doConfirm)
            {
                var (sc, _, ev, timedOut) = await ActionAsync(MethodIds.AcknowledgeableConditionType_Confirm,
                    f => AlarmBoolValue(f, FConfirmed) == true).ConfigureAwait(false);
                item["confirm"] = new JsonObject { ["statusCode"] = StatusNames.Json(sc), ["event"] = ev };
                if (!StatusCode.IsGood(sc))
                {
                    return await Finish(false, sc, "service", "Confirm failed", 4).ConfigureAwait(false);
                }
                if (timedOut)
                {
                    return await Finish(false, StatusCodes.BadTimeout, "timeout", "timeout waiting for the confirmed event", 7).ConfigureAwait(false);
                }
            }
            if (doComment)
            {
                var (sc, _, ev, timedOut) = await ActionAsync(MethodIds.ConditionType_AddComment,
                    f => AlarmTextValue(f, FComment) == comment).ConfigureAwait(false);
                item["addComment"] = new JsonObject { ["statusCode"] = StatusNames.Json(sc), ["event"] = ev };
                if (!StatusCode.IsGood(sc))
                {
                    return await Finish(false, sc, "service", "AddComment failed", 4).ConfigureAwait(false);
                }
                if (timedOut)
                {
                    return await Finish(false, StatusCodes.BadTimeout, "timeout", "timeout waiting for the commented event", 7).ConfigureAwait(false);
                }
            }
            return await Finish(true, StatusCodes.Good, null, null, 0).ConfigureAwait(false);
        }
    }
}
