// SPDX-License-Identifier: MIT
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;

namespace OpcUaInterop
{
    internal static partial class ClientCommand
    {
        private const uint ClientHandle = 1;

        private static async Task<CreateSubscriptionResponse> CreateSubscriptionAsync(
            ClientContext c, double interval, uint lifetime = 0, uint keepAlive = 0)
        {
            if (keepAlive == 0)
            {
                // keep-alives well inside the request timeout, so no Publish times out locally
                keepAlive = (uint)Math.Clamp(c.RequestTimeoutMs / 2 / Math.Max(interval, 1), 1, 20);
                lifetime = Math.Max(keepAlive * 10, 30);
            }
            return await c.Session.CreateSubscriptionAsync(c.Header(), interval, lifetime, keepAlive, 0, true, 0, CancellationToken.None).ConfigureAwait(false);
        }

        private static async Task DeleteSubscriptionQuietlyAsync(ClientContext c, uint id)
        {
            try
            {
                await c.Session.DeleteSubscriptionsAsync(c.Header(), new ArrayOf<uint>(new[] { id }), CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // ignore
            }
        }

        private static MonitoredItemCreateRequest ValueItem(NodeId node, double sampling, uint queue, bool discardOldest, ExtensionObject filter = default) => new()
        {
            ItemToMonitor = new ReadValueId { NodeId = node, AttributeId = Attributes.Value },
            MonitoringMode = MonitoringMode.Reporting,
            RequestedParameters = new MonitoringParameters
            {
                ClientHandle = ClientHandle,
                SamplingInterval = sampling,
                QueueSize = queue,
                DiscardOldest = discardOldest,
                Filter = filter
            }
        };

        private static JsonObject NotificationJson(int seq, DataValue dv)
        {
            var n = new JsonObject { ["sequenceNumber"] = seq };
            Canonical.PutValue(n, dv.WrappedValue, valueFirst: true);
            n["statusCode"] = StatusNames.Json(dv.StatusCode);
            if (Canonical.HasTime(dv.SourceTimestamp))
            {
                n["sourceTimestamp"] = Canonical.Time(dv.SourceTimestamp);
            }
            if (Canonical.HasTime(dv.ServerTimestamp))
            {
                n["serverTimestamp"] = Canonical.Time(dv.ServerTimestamp);
            }
            return n;
        }

        // ------------------------------------------------------------------
        // subscribe
        // ------------------------------------------------------------------

        private static async Task<int> SubscribeAsync(ClientContext c)
        {
            string nodeStr = c.Args.Get("--node") ?? throw new InputException("missing --node");
            if (!nodeStr.StartsWith("nsu=", StringComparison.Ordinal))
            {
                NodeIds.Parse(nodeStr);
            }
            double pi = c.Args.GetDouble("--publishing-interval-ms", 500);
            double si = c.Args.GetDouble("--sampling-interval-ms", 100);
            int wanted = c.Args.GetInt("--notifications", 5);
            int timeoutMs = c.Args.GetInt("--timeout-ms", 10000);
            uint queue = (uint)Math.Max(1, c.Args.GetInt("--queue-size", 1));
            bool discardOldest = c.Args.GetBool("--discard-oldest", true);
            TimestampsToReturn ts = Timestamps(c.Args);

            string dbAbs = c.Args.Get("--deadband-absolute");
            string dbPct = c.Args.Get("--deadband-percent");
            string trig = c.Args.Get("--trigger");
            bool useFilter = dbAbs != null || dbPct != null || trig != null;
            string triggerName = trig ?? "StatusValue";
            string deadbandName = dbAbs != null ? "Absolute" : dbPct != null ? "Percent" : "None";
            double deadbandValue = 0;
            ExtensionObject filter = default;
            if (useFilter)
            {
                if (dbAbs != null && dbPct != null)
                {
                    throw new InputException("--deadband-absolute and --deadband-percent are mutually exclusive");
                }
                DataChangeTrigger trigger = triggerName switch
                {
                    "Status" => DataChangeTrigger.Status,
                    "StatusValue" => DataChangeTrigger.StatusValue,
                    "StatusValueTimestamp" => DataChangeTrigger.StatusValueTimestamp,
                    _ => throw new InputException("--trigger must be Status, StatusValue or StatusValueTimestamp")
                };
                string dbText = dbAbs ?? dbPct;
                if (dbText != null && !double.TryParse(dbText, NumberStyles.Float, Inv.C, out deadbandValue))
                {
                    throw new InputException("invalid deadband value");
                }
                filter = new ExtensionObject(new DataChangeFilter
                {
                    Trigger = trigger,
                    DeadbandType = (uint)(dbAbs != null ? DeadbandType.Absolute : dbPct != null ? DeadbandType.Percent : DeadbandType.None),
                    DeadbandValue = deadbandValue
                });
            }

            await c.ConnectAsync().ConfigureAwait(false);
            NodeId node = c.Node(nodeStr);
            CreateSubscriptionResponse sub = await CreateSubscriptionAsync(c, pi).ConfigureAwait(false);
            var notifications = new List<JsonObject>();
            var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int seq = 0;
            await using var loop = new PublishLoop(c);
            loop.DataChange += (subId, mi) =>
            {
                if (subId != sub.SubscriptionId || mi.ClientHandle != ClientHandle)
                {
                    return;
                }
                lock (notifications)
                {
                    if (notifications.Count >= wanted)
                    {
                        return;
                    }
                    notifications.Add(NotificationJson(++seq, mi.Value));
                    if (notifications.Count >= wanted)
                    {
                        done.TrySetResult();
                    }
                }
            };
            loop.Start();

            CreateMonitoredItemsResponse cmi = await c.Session.CreateMonitoredItemsAsync(c.Header(), sub.SubscriptionId, ts,
                new ArrayOf<MonitoredItemCreateRequest>(new[] { ValueItem(node, si, queue, discardOldest, filter) }),
                CancellationToken.None).ConfigureAwait(false);
            MonitoredItemCreateResult mr = cmi.Results[0];
            StatusCode monSc = mr.StatusCode;
            bool timedOut = false;
            if (StatusCode.IsGood(monSc))
            {
                if (wanted <= 0)
                {
                    done.TrySetResult();
                }
                Task first = await Task.WhenAny(done.Task, Task.Delay(timeoutMs)).ConfigureAwait(false);
                timedOut = first != done.Task;
            }

            var item = new JsonObject
            {
                ["nodeId"] = Canonical.NodeId(node),
                ["subscriptionId"] = sub.SubscriptionId,
                ["revisedPublishingInterval"] = sub.RevisedPublishingInterval,
                ["revisedLifetimeCount"] = sub.RevisedLifetimeCount,
                ["revisedMaxKeepAliveCount"] = sub.RevisedMaxKeepAliveCount,
                ["monitoredItemStatusCode"] = StatusNames.Json(monSc)
            };
            if (useFilter)
            {
                item["monitoredItemId"] = mr.MonitoredItemId;
                item["revisedSamplingInterval"] = mr.RevisedSamplingInterval;
                item["revisedQueueSize"] = mr.RevisedQueueSize;
                item["filter"] = new JsonObject
                {
                    ["trigger"] = triggerName,
                    ["deadbandType"] = deadbandName,
                    ["deadbandValue"] = deadbandValue
                };
                item["filterResult"] = mr.FilterResult.IsNull
                    ? null
                    : new JsonObject { ["typeId"] = Canonical.ExpandedNodeId(mr.FilterResult.TypeId) };
            }
            var arr = new JsonArray();
            lock (notifications)
            {
                foreach (JsonObject n in notifications)
                {
                    arr.Add(n);
                }
            }
            item["notifications"] = arr;
            var r = new Result("subscribe").Success(StatusCode.IsGood(monSc) && !timedOut).ServiceResult(monSc).Add(item);
            if (timedOut)
            {
                r.Error("timeout", "timeout waiting for notifications");
            }
            else if (!StatusCode.IsGood(monSc))
            {
                r.Error("service", "CreateMonitoredItems rejected the monitored item");
            }
            r.Print();
            await DeleteSubscriptionQuietlyAsync(c, sub.SubscriptionId).ConfigureAwait(false);
            return timedOut ? 7 : StatusCode.IsGood(monSc) ? 0 : 4;
        }

        // ------------------------------------------------------------------
        // subscription-lifecycle
        // ------------------------------------------------------------------

        private static async Task<int> LifecycleAsync(ClientContext c)
        {
            string nodeStr = c.Args.Get("--node");
            string scenario = c.Args.Get("--scenario");
            if (nodeStr == null || scenario == null)
            {
                throw new InputException("missing --node or --scenario");
            }
            if (scenario is not ("revise" or "publishing-mode" or "monitoring-mode" or "delete"))
            {
                throw new InputException("unknown scenario: " + scenario);
            }
            int timeoutMs = c.Args.GetInt("--timeout-ms", 15000);
            await c.ConnectAsync().ConfigureAwait(false);
            NodeId node = c.Node(nodeStr);
            return scenario switch
            {
                "revise" => await ReviseAsync(c).ConfigureAwait(false),
                "publishing-mode" => await PublishingModeAsync(c, node, timeoutMs).ConfigureAwait(false),
                "monitoring-mode" => await MonitoringModeAsync(c, node, timeoutMs).ConfigureAwait(false),
                _ => await DeleteScenarioAsync(c, node).ConfigureAwait(false)
            };
        }

        private static async Task<int> ReviseAsync(ClientContext c)
        {
            CreateSubscriptionResponse sub = await CreateSubscriptionAsync(c, 1.0, 5, 10).ConfigureAwait(false);
            await DeleteSubscriptionQuietlyAsync(c, sub.SubscriptionId).ConfigureAwait(false);
            bool ok = sub.RevisedLifetimeCount >= 3L * sub.RevisedMaxKeepAliveCount && sub.RevisedPublishingInterval >= 10.0;
            new Result("subscription-lifecycle").Success(ok).Add(new JsonObject
            {
                ["subscriptionId"] = sub.SubscriptionId,
                ["requestedPublishingInterval"] = 1,
                ["requestedLifetimeCount"] = 5,
                ["requestedMaxKeepAliveCount"] = 10,
                ["revisedPublishingInterval"] = sub.RevisedPublishingInterval,
                ["revisedLifetimeCount"] = sub.RevisedLifetimeCount,
                ["revisedMaxKeepAliveCount"] = sub.RevisedMaxKeepAliveCount
            }).Print();
            return ok ? 0 : 4;
        }

        private static async Task WriteInt32Async(ClientContext c, NodeId node, int v)
        {
            await c.Session.WriteAsync(c.Header(), new ArrayOf<WriteValue>(new[]
            {
                new WriteValue { NodeId = node, AttributeId = Attributes.Value, Value = new DataValue(new Variant(v)) }
            }), CancellationToken.None).ConfigureAwait(false);
        }

        private static async Task<int> PublishingModeAsync(ClientContext c, NodeId node, int timeoutMs)
        {
            CreateSubscriptionResponse sub = await CreateSubscriptionAsync(c, 500).ConfigureAwait(false);
            var values = new List<int>();
            bool overflow = false;
            var initial = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            bool collecting = false;
            await using var loop = new PublishLoop(c);
            loop.DataChange += (subId, mi) =>
            {
                if (subId != sub.SubscriptionId || mi.ClientHandle != ClientHandle)
                {
                    return;
                }
                lock (values)
                {
                    if (!initial.Task.IsCompleted)
                    {
                        initial.TrySetResult();
                        return;
                    }
                    if (!collecting)
                    {
                        return;
                    }
                    if (mi.Value.WrappedValue.TypeInfo.BuiltInType == BuiltInType.Int32)
                    {
                        values.Add(mi.Value.WrappedValue.GetInt32());
                    }
                    if ((mi.Value.StatusCode.Code & 0x480) != 0)
                    {
                        overflow = true;
                    }
                }
            };
            loop.Start();
            CreateMonitoredItemsResponse cmi = await c.Session.CreateMonitoredItemsAsync(c.Header(), sub.SubscriptionId, TimestampsToReturn.Source,
                new ArrayOf<MonitoredItemCreateRequest>(new[] { ValueItem(node, 0, 3, true) }), CancellationToken.None).ConfigureAwait(false);
            StatusCode monSc = cmi.Results[0].StatusCode;
            if (!StatusCode.IsGood(monSc))
            {
                await DeleteSubscriptionQuietlyAsync(c, sub.SubscriptionId).ConfigureAwait(false);
                new Result("subscription-lifecycle").Success(false).ServiceResult(monSc).Error("service", "CreateMonitoredItem failed").Print();
                return 4;
            }
            await Task.WhenAny(initial.Task, Task.Delay(1500)).ConfigureAwait(false);
            initial.TrySetResult();

            await c.Session.SetPublishingModeAsync(c.Header(), false, new ArrayOf<uint>(new[] { sub.SubscriptionId }), CancellationToken.None).ConfigureAwait(false);
            lock (values)
            {
                values.Clear();
                collecting = true;
            }
            for (int v = 1; v <= 5; v++)
            {
                await WriteInt32Async(c, node, v).ConfigureAwait(false);
            }
            await Task.Delay(200).ConfigureAwait(false);
            await c.Session.SetPublishingModeAsync(c.Header(), true, new ArrayOf<uint>(new[] { sub.SubscriptionId }), CancellationToken.None).ConfigureAwait(false);
            await Task.Delay(Math.Max(2000, Math.Min(timeoutMs - 2000, 5000))).ConfigureAwait(false);
            await DeleteSubscriptionQuietlyAsync(c, sub.SubscriptionId).ConfigureAwait(false);

            List<int> got;
            lock (values)
            {
                got = values.ToList();
            }
            int nv = got.Count;
            if (nv < 5)
            {
                overflow = true;
            }
            bool ok = nv >= 3 ? got[nv - 3] == 3 && got[nv - 2] == 4 && got[nv - 1] == 5 : nv >= 1 && got[nv - 1] == 5;
            var arr = new JsonArray();
            foreach (int v in got)
            {
                arr.Add(JsonValue.Create(v));
            }
            new Result("subscription-lifecycle").Success(ok).Add(new JsonObject
            {
                ["subscriptionId"] = sub.SubscriptionId,
                ["revisedPublishingInterval"] = sub.RevisedPublishingInterval,
                ["revisedLifetimeCount"] = sub.RevisedLifetimeCount,
                ["revisedMaxKeepAliveCount"] = sub.RevisedMaxKeepAliveCount,
                ["overflow"] = overflow,
                ["values"] = arr
            }).Print();
            return ok ? 0 : 4;
        }

        private static async Task<int> MonitoringModeAsync(ClientContext c, NodeId node, int timeoutMs)
        {
            CreateSubscriptionResponse sub = await CreateSubscriptionAsync(c, 100).ConfigureAwait(false);
            int count = 0;
            var initial = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var loop = new PublishLoop(c);
            loop.DataChange += (subId, mi) =>
            {
                if (subId != sub.SubscriptionId || mi.ClientHandle != ClientHandle)
                {
                    return;
                }
                if (!initial.Task.IsCompleted)
                {
                    initial.TrySetResult();
                    return;
                }
                Interlocked.Increment(ref count);
            };
            loop.Start();
            CreateMonitoredItemsResponse cmi = await c.Session.CreateMonitoredItemsAsync(c.Header(), sub.SubscriptionId, TimestampsToReturn.Source,
                new ArrayOf<MonitoredItemCreateRequest>(new[] { ValueItem(node, 0, 5, true) }), CancellationToken.None).ConfigureAwait(false);
            MonitoredItemCreateResult mr = cmi.Results[0];
            if (!StatusCode.IsGood(mr.StatusCode))
            {
                await DeleteSubscriptionQuietlyAsync(c, sub.SubscriptionId).ConfigureAwait(false);
                new Result("subscription-lifecycle").Success(false).ServiceResult(mr.StatusCode).Error("service", "CreateMonitoredItem failed").Print();
                return 4;
            }
            await Task.WhenAny(initial.Task, Task.Delay(1500)).ConfigureAwait(false);
            initial.TrySetResult();
            var ids = new ArrayOf<uint>(new[] { mr.MonitoredItemId });

            int baseCount = Volatile.Read(ref count);
            await c.Session.SetMonitoringModeAsync(c.Header(), sub.SubscriptionId, MonitoringMode.Disabled, ids, CancellationToken.None).ConfigureAwait(false);
            await WriteInt32Async(c, node, 100).ConfigureAwait(false);
            await Task.Delay(300).ConfigureAwait(false);
            int disabled = Volatile.Read(ref count) - baseCount;

            int beforeSampling = Volatile.Read(ref count);
            await c.Session.SetMonitoringModeAsync(c.Header(), sub.SubscriptionId, MonitoringMode.Sampling, ids, CancellationToken.None).ConfigureAwait(false);
            await WriteInt32Async(c, node, 101).ConfigureAwait(false);
            await WriteInt32Async(c, node, 102).ConfigureAwait(false);
            await Task.Delay(300).ConfigureAwait(false);
            int sampling = Volatile.Read(ref count) - beforeSampling;

            int beforeReporting = Volatile.Read(ref count);
            await c.Session.SetMonitoringModeAsync(c.Header(), sub.SubscriptionId, MonitoringMode.Reporting, ids, CancellationToken.None).ConfigureAwait(false);
            await WriteInt32Async(c, node, 103).ConfigureAwait(false);
            await Task.Delay(Math.Max(2000, Math.Min(timeoutMs - 2000, 5000))).ConfigureAwait(false);
            int reporting = Volatile.Read(ref count) - beforeReporting;
            await DeleteSubscriptionQuietlyAsync(c, sub.SubscriptionId).ConfigureAwait(false);

            bool ok = disabled == 0 && reporting >= 1;
            new Result("subscription-lifecycle").Success(ok).Add(new JsonObject
            {
                ["subscriptionId"] = sub.SubscriptionId,
                ["modeSteps"] = new JsonArray(
                    new JsonObject { ["mode"] = "Disabled", ["notificationCount"] = disabled },
                    new JsonObject { ["mode"] = "Sampling", ["notificationCount"] = sampling },
                    new JsonObject { ["mode"] = "Reporting", ["notificationCount"] = reporting })
            }).Print();
            return ok ? 0 : 4;
        }

        private static async Task<int> DeleteScenarioAsync(ClientContext c, NodeId node)
        {
            CreateSubscriptionResponse sub = await CreateSubscriptionAsync(c, 500).ConfigureAwait(false);
            CreateMonitoredItemsResponse cmi = await c.Session.CreateMonitoredItemsAsync(c.Header(), sub.SubscriptionId, TimestampsToReturn.Source,
                new ArrayOf<MonitoredItemCreateRequest>(new[] { ValueItem(node, 100, 1, true) }), CancellationToken.None).ConfigureAwait(false);
            MonitoredItemCreateResult mr = cmi.Results[0];
            if (!StatusCode.IsGood(mr.StatusCode))
            {
                await DeleteSubscriptionQuietlyAsync(c, sub.SubscriptionId).ConfigureAwait(false);
                new Result("subscription-lifecycle").Success(false).ServiceResult(mr.StatusCode).Error("service", "CreateMonitoredItem failed").Print();
                return 4;
            }
            var ids = new ArrayOf<uint>(new[] { mr.MonitoredItemId });
            async Task<StatusCode> DelMon()
            {
                try
                {
                    DeleteMonitoredItemsResponse r = await c.Session.DeleteMonitoredItemsAsync(c.Header(), sub.SubscriptionId, ids, CancellationToken.None).ConfigureAwait(false);
                    return r.Results.Count > 0 ? r.Results[0] : StatusCodes.Good;
                }
                catch (ServiceResultException e)
                {
                    return e.StatusCode;
                }
            }
            async Task<StatusCode> DelSub()
            {
                try
                {
                    DeleteSubscriptionsResponse r = await c.Session.DeleteSubscriptionsAsync(c.Header(), new ArrayOf<uint>(new[] { sub.SubscriptionId }), CancellationToken.None).ConfigureAwait(false);
                    return r.Results.Count > 0 ? r.Results[0] : StatusCodes.Good;
                }
                catch (ServiceResultException e)
                {
                    return e.StatusCode;
                }
            }
            StatusCode m1 = await DelMon().ConfigureAwait(false);
            StatusCode m2 = await DelMon().ConfigureAwait(false);
            StatusCode s1 = await DelSub().ConfigureAwait(false);
            StatusCode s2 = await DelSub().ConfigureAwait(false);
            bool ok = StatusCode.IsBad(m2) && StatusCode.IsBad(s2);
            new Result("subscription-lifecycle").Success(ok).Add(new JsonObject
            {
                ["subscriptionId"] = sub.SubscriptionId,
                ["deleteMonitoredItem"] = new JsonObject { ["first"] = StatusNames.Json(m1), ["second"] = StatusNames.Json(m2) },
                ["deleteSubscription"] = new JsonObject { ["first"] = StatusNames.Json(s1), ["second"] = StatusNames.Json(s2) }
            }).Print();
            return ok ? 0 : 4;
        }

        // ------------------------------------------------------------------
        // event-subscribe
        // ------------------------------------------------------------------

        private static readonly string[] s_eventFields = ["EventId", "EventType", "SourceName", "Message", "Severity", "Time"];

        private static async Task<int> EventSubscribeAsync(ClientContext c)
        {
            string nodeStr = c.Args.Get("--node") ?? throw new InputException("missing --node");
            if (!nodeStr.StartsWith("nsu=", StringComparison.Ordinal))
            {
                NodeIds.Parse(nodeStr);
            }
            double pi = c.Args.GetDouble("--publishing-interval-ms", 500);
            int wanted = c.Args.GetInt("--events", 1);
            int timeoutMs = c.Args.GetInt("--timeout-ms", 10000);
            uint queue = (uint)Math.Max(1, c.Args.GetInt("--queue-size", 10));
            string ofType = c.Args.Get("--of-type");
            string minSev = c.Args.Get("--min-severity");
            ushort minSeverity = 0;
            if (minSev != null && !ushort.TryParse(minSev, NumberStyles.Integer, Inv.C, out minSeverity))
            {
                throw new InputException("invalid --min-severity " + minSev);
            }

            await c.ConnectAsync().ConfigureAwait(false);
            NodeId node = c.Node(nodeStr);

            var select = s_eventFields.Select(f => new SimpleAttributeOperand
            {
                TypeDefinitionId = ObjectTypeIds.BaseEventType,
                BrowsePath = new ArrayOf<QualifiedName>(new[] { new QualifiedName(f, 0) }),
                AttributeId = Attributes.Value
            }).ToArray();
            var elements = new List<ContentFilterElement>();
            if (!string.IsNullOrEmpty(ofType))
            {
                elements.Add(new ContentFilterElement
                {
                    FilterOperator = FilterOperator.OfType,
                    FilterOperands = new ArrayOf<ExtensionObject>(new[] { new ExtensionObject(new LiteralOperand { Value = new Variant(c.Node(ofType)) }) })
                });
            }
            if (minSev != null)
            {
                elements.Add(new ContentFilterElement
                {
                    FilterOperator = FilterOperator.GreaterThanOrEqual,
                    FilterOperands = new ArrayOf<ExtensionObject>(new[]
                    {
                        new ExtensionObject(new SimpleAttributeOperand
                        {
                            TypeDefinitionId = ObjectTypeIds.BaseEventType,
                            BrowsePath = new ArrayOf<QualifiedName>(new[] { new QualifiedName("Severity", 0) }),
                            AttributeId = Attributes.Value
                        }),
                        new ExtensionObject(new LiteralOperand { Value = new Variant(minSeverity) })
                    })
                });
            }
            if (elements.Count == 2)
            {
                elements.Add(new ContentFilterElement
                {
                    FilterOperator = FilterOperator.And,
                    FilterOperands = new ArrayOf<ExtensionObject>(new[]
                    {
                        new ExtensionObject(new ElementOperand { Index = 0 }),
                        new ExtensionObject(new ElementOperand { Index = 1 })
                    })
                });
            }
            var filter = new EventFilter
            {
                SelectClauses = new ArrayOf<SimpleAttributeOperand>(select),
                WhereClause = new ContentFilter { Elements = new ArrayOf<ContentFilterElement>(elements.ToArray()) }
            };

            CreateSubscriptionResponse sub = await CreateSubscriptionAsync(c, pi).ConfigureAwait(false);
            var events = new List<Variant[]>();
            var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var loop = new PublishLoop(c);
            loop.Event += (subId, ev) =>
            {
                if (subId != sub.SubscriptionId || ev.ClientHandle != ClientHandle)
                {
                    return;
                }
                lock (events)
                {
                    if (events.Count >= wanted)
                    {
                        return;
                    }
                    events.Add(ev.EventFields.ToArray() ?? []);
                    if (events.Count >= wanted)
                    {
                        done.TrySetResult();
                    }
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
                            QueueSize = queue,
                            DiscardOldest = true,
                            Filter = new ExtensionObject(filter)
                        }
                    }
                }), CancellationToken.None).ConfigureAwait(false);
            StatusCode monSc = cmi.Results[0].StatusCode;
            bool timedOut = false;
            if (StatusCode.IsGood(monSc))
            {
                if (wanted <= 0)
                {
                    done.TrySetResult();
                }
                timedOut = await Task.WhenAny(done.Task, Task.Delay(timeoutMs)).ConfigureAwait(false) != done.Task;
            }
            await DeleteSubscriptionQuietlyAsync(c, sub.SubscriptionId).ConfigureAwait(false);

            var list = new JsonArray();
            int seq = 0;
            lock (events)
            {
                foreach (Variant[] vs in events)
                {
                    var fields = new JsonArray();
                    for (int i = 0; i < Math.Min(vs.Length, s_eventFields.Length); i++)
                    {
                        var f = new JsonObject { ["name"] = s_eventFields[i] };
                        Canonical.PutValue(f, vs[i]);
                        fields.Add(f);
                    }
                    list.Add(new JsonObject { ["sequenceNumber"] = ++seq, ["fields"] = fields });
                }
            }
            var r = new Result("event-subscribe").Success(StatusCode.IsGood(monSc) && !timedOut).ServiceResult(monSc).Add(new JsonObject
            {
                ["nodeId"] = Canonical.NodeId(node),
                ["subscriptionId"] = sub.SubscriptionId,
                ["revisedPublishingInterval"] = sub.RevisedPublishingInterval,
                ["monitoredItemStatusCode"] = StatusNames.Json(monSc),
                ["selectClauses"] = Json.Strings(s_eventFields),
                ["events"] = list
            });
            if (timedOut)
            {
                r.Error("timeout", "timeout waiting for events");
            }
            else if (!StatusCode.IsGood(monSc))
            {
                r.Error("service", "CreateMonitoredItems rejected the event monitored item");
            }
            r.Print();
            return timedOut ? 7 : StatusCode.IsGood(monSc) ? 0 : 4;
        }

        // ------------------------------------------------------------------
        // history-read
        // ------------------------------------------------------------------

        private sealed record HistoryPage(StatusCode Service, StatusCode Item, string ContinuationPoint, JsonArray Values);

        private static async Task<int> HistoryReadAsync(ClientContext c)
        {
            string nodeStr = c.Args.Get("--node");
            string startStr = c.Args.Get("--start");
            string endStr = c.Args.Get("--end");
            if (nodeStr == null || startStr == null || endStr == null)
            {
                throw new InputException("missing --node, --start, or --end [--scenario continue]");
            }
            DateTime start = ParseTime(startStr, "--start");
            DateTime end = ParseTime(endStr, "--end");
            uint num = (uint)Math.Max(0, c.Args.GetInt("--num-values", 0));
            string cp = c.Args.Get("--continuation-point");
            bool release = c.Args.GetBool("--release-continuation-point", false);
            bool bounds = c.Args.GetBool("--return-bounds", false);
            string scenario = c.Args.Get("--scenario");
            if (scenario != null && scenario != "continue")
            {
                throw new InputException("unknown --scenario " + scenario);
            }
            TimestampsToReturn ts = Timestamps(c.Args);
            await c.ConnectAsync().ConfigureAwait(false);
            NodeId node = c.Node(nodeStr);

            async Task<HistoryPage> Page(string cpIn, bool rel, uint n)
            {
                var details = new ReadRawModifiedDetails
                {
                    IsReadModified = false,
                    StartTime = new DateTimeUtc(start),
                    EndTime = new DateTimeUtc(end),
                    NumValuesPerNode = n,
                    ReturnBounds = bounds
                };
                var hv = new HistoryReadValueId
                {
                    NodeId = node,
                    ContinuationPoint = string.IsNullOrEmpty(cpIn) ? default : ByteString.From(Convert.FromBase64String(cpIn))
                };
                HistoryReadResponse resp;
                try
                {
                    resp = await c.Session.HistoryReadAsync(c.Header(), new ExtensionObject(details), ts, rel,
                        new ArrayOf<HistoryReadValueId>(new[] { hv }), CancellationToken.None).ConfigureAwait(false);
                }
                catch (ServiceResultException e)
                {
                    return new HistoryPage(e.StatusCode, StatusCodes.Good, null, new JsonArray());
                }
                StatusCode svc = resp.ResponseHeader.ServiceResult;
                StatusCode item = StatusCodes.Good;
                string cpOut = null;
                var values = new JsonArray();
                if (StatusCode.IsGood(svc) && resp.Results.Count > 0)
                {
                    HistoryReadResult hr = resp.Results[0];
                    item = hr.StatusCode;
                    if (!hr.ContinuationPoint.IsNull && hr.ContinuationPoint.Length > 0)
                    {
                        cpOut = Convert.ToBase64String(hr.ContinuationPoint.Span);
                    }
                    if (!hr.HistoryData.IsNull && hr.HistoryData.TryGetValue(out HistoryData data, Codec.Context))
                    {
                        foreach (DataValue dv in data.DataValues)
                        {
                            var v = new JsonObject();
                            Canonical.PutValue(v, dv.WrappedValue, valueFirst: true);
                            v["statusCode"] = StatusNames.Json(dv.StatusCode);
                            if (Canonical.HasTime(dv.SourceTimestamp))
                            {
                                v["sourceTimestamp"] = Canonical.Time(dv.SourceTimestamp);
                            }
                            if (Canonical.HasTime(dv.ServerTimestamp))
                            {
                                v["serverTimestamp"] = Canonical.Time(dv.ServerTimestamp);
                            }
                            values.Add(v);
                        }
                    }
                }
                return new HistoryPage(svc, item, cpOut, values);
            }

            if (scenario == "continue")
            {
                uint n = num == 0 ? 2 : num;
                var pages = new JsonArray();
                string cur = null;
                string lastCp = null;
                StatusCode lastSvc = StatusCodes.Good, lastItem = StatusCodes.Good;
                for (int i = 0; i < 8; i++)
                {
                    HistoryPage p = await Page(cur, false, n).ConfigureAwait(false);
                    lastSvc = p.Service;
                    lastItem = p.Item;
                    pages.Add(new JsonObject
                    {
                        ["values"] = p.Values,
                        ["continuationPoint"] = p.ContinuationPoint,
                        ["statusCode"] = StatusNames.Json(p.Item)
                    });
                    if (!StatusCode.IsGood(p.Service) || !StatusCode.IsGood(p.Item) || string.IsNullOrEmpty(p.ContinuationPoint))
                    {
                        break;
                    }
                    cur = p.ContinuationPoint;
                    lastCp = cur;
                }
                StatusCode releaseSc = StatusCodes.Good, reuseSc = StatusCodes.Good;
                string toRelease = lastCp;
                HistoryPage released = await Page(toRelease, true, n).ConfigureAwait(false);
                releaseSc = StatusCode.IsGood(released.Service) ? released.Item : released.Service;
                if (toRelease != null)
                {
                    HistoryPage reuse = await Page(toRelease, false, n).ConfigureAwait(false);
                    reuseSc = StatusCode.IsGood(reuse.Service) ? reuse.Item : reuse.Service;
                }
                bool okc = StatusCode.IsGood(lastSvc) && StatusCode.IsGood(lastItem) && pages.Count > 0;
                new Result("history-read").Success(okc).ServiceResult(StatusCode.IsGood(lastSvc) ? lastItem : lastSvc).Add(new JsonObject
                {
                    ["scenario"] = "continue",
                    ["nodeId"] = Canonical.NodeId(node),
                    ["pages"] = pages,
                    ["releaseStatusCode"] = StatusNames.Json(releaseSc),
                    ["reuseAfterReleaseStatusCode"] = StatusNames.Json(reuseSc)
                }).Print();
                return okc ? 0 : 4;
            }

            HistoryPage page = await Page(cp, release, num).ConfigureAwait(false);
            bool ok = StatusCode.IsGood(page.Service) && StatusCode.IsGood(page.Item);
            new Result("history-read").Success(ok).ServiceResult(StatusCode.IsGood(page.Service) ? page.Item : page.Service).Add(new JsonObject
            {
                ["nodeId"] = Canonical.NodeId(node),
                ["statusCode"] = StatusNames.Json(page.Item),
                ["continuationPoint"] = page.ContinuationPoint,
                ["values"] = page.Values
            }).Print();
            return ok ? 0 : 4;
        }

        private static DateTime ParseTime(string s, string flag)
        {
            if (!DateTime.TryParse(s, Inv.C, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out DateTime t))
            {
                throw new InputException("invalid " + flag + " " + s);
            }
            return t;
        }

        // ------------------------------------------------------------------
        // republish / transfer-subscriptions
        // ------------------------------------------------------------------

        private static async Task<int> RepublishAsync(ClientContext c)
        {
            string subStr = c.Args.Get("--subscription-id");
            string seqStr = c.Args.Get("--sequence-number");
            if (subStr == null || seqStr == null)
            {
                throw new InputException("missing --subscription-id or --sequence-number");
            }
            uint subId = (uint)c.Args.GetLong("--subscription-id", 0);
            uint seq = (uint)c.Args.GetLong("--sequence-number", 0);
            await c.ConnectAsync().ConfigureAwait(false);
            StatusCode sc;
            NotificationMessage nm = null;
            try
            {
                RepublishResponse resp = await c.Session.RepublishAsync(c.Header(), subId, seq, CancellationToken.None).ConfigureAwait(false);
                sc = resp.ResponseHeader.ServiceResult;
                nm = resp.NotificationMessage;
            }
            catch (ServiceResultException e)
            {
                sc = e.StatusCode;
            }
            bool ok = StatusCode.IsGood(sc);
            var item = new JsonObject { ["subscriptionId"] = subId, ["retransmitSequenceNumber"] = seq };
            if (ok && nm != null)
            {
                item["sequenceNumber"] = nm.SequenceNumber;
                if (Canonical.HasTime(nm.PublishTime))
                {
                    item["publishTime"] = Canonical.Time(nm.PublishTime);
                }
                item["notificationDataCount"] = nm.NotificationData.Count;
            }
            var r = new Result("republish").Success(ok).ServiceResult(sc).Add(item);
            if (!ok)
            {
                r.Error("service", "Republish failed");
            }
            r.Print();
            return ok ? 0 : 4;
        }

        private static async Task<int> TransferAsync(ClientContext c)
        {
            List<string> subs = c.Args.All("--subscription-id");
            if (subs.Count == 0)
            {
                throw new InputException("missing --subscription-id");
            }
            uint[] ids = subs.Select(s => uint.TryParse(s, NumberStyles.Integer, Inv.C, out uint v) ? v : throw new InputException("invalid --subscription-id " + s)).ToArray();
            bool initial = c.Args.GetBool("--send-initial-values", false);
            await c.ConnectAsync().ConfigureAwait(false);
            StatusCode sc;
            TransferSubscriptionsResponse resp = null;
            try
            {
                resp = await c.Session.TransferSubscriptionsAsync(c.Header(), new ArrayOf<uint>(ids), initial, CancellationToken.None).ConfigureAwait(false);
                sc = resp.ResponseHeader.ServiceResult;
            }
            catch (ServiceResultException e)
            {
                sc = e.StatusCode;
            }
            bool ok = StatusCode.IsGood(sc);
            var r = new Result("transfer-subscriptions");
            if (ok && resp != null)
            {
                for (int i = 0; i < resp.Results.Count && i < ids.Length; i++)
                {
                    TransferResult tr = resp.Results[i];
                    if (!StatusCode.IsGood(tr.StatusCode))
                    {
                        ok = false;
                    }
                    var seqs = new JsonArray();
                    foreach (uint s in tr.AvailableSequenceNumbers)
                    {
                        seqs.Add(JsonValue.Create(s));
                    }
                    r.Add(new JsonObject
                    {
                        ["subscriptionId"] = ids[i],
                        ["statusCode"] = StatusNames.Json(tr.StatusCode),
                        ["availableSequenceNumbers"] = seqs
                    });
                }
            }
            r.Success(ok).ServiceResult(sc);
            if (!ok)
            {
                r.Error("service", "TransferSubscriptions failed");
            }
            r.Print();
            return ok ? 0 : 4;
        }
    }
}
