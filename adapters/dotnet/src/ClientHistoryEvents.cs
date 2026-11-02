// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>
    /// client history-read-events / history-update-events (docs/CONTAINER_CONTRACT.md §1, §4): HistoryRead
    /// with ReadEventDetails and HistoryUpdate with UpdateEventDetails / DeleteEventDetails, sent as raw
    /// session services so that every status code reaches the result unchanged.
    /// </summary>
    internal static partial class ClientCommand
    {
        /// <summary>The default SelectClauses of history-read-events (BaseEventType fields).</summary>
        internal static readonly string[] DefaultHistoryEventSelect =
            ["EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"];

        /// <summary>A `/`-separated browse path from BaseEventType; `ns:Name` for other namespaces.</summary>
        internal static SimpleAttributeOperand SelectOperand(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new InputException("empty --select path");
            }
            var names = new List<QualifiedName>();
            foreach (string seg in path.Split('/'))
            {
                if (seg.Length == 0)
                {
                    throw new InputException("invalid --select path " + path);
                }
                int colon = seg.IndexOf(':');
                if (colon > 0 && ushort.TryParse(seg.AsSpan(0, colon), NumberStyles.None, Inv.C, out ushort ns))
                {
                    names.Add(new QualifiedName(seg[(colon + 1)..], ns));
                }
                else
                {
                    names.Add(new QualifiedName(seg, 0));
                }
            }
            return new SimpleAttributeOperand
            {
                TypeDefinitionId = ObjectTypeIds.BaseEventType,
                BrowsePath = new ArrayOf<QualifiedName>(names.ToArray()),
                AttributeId = Attributes.Value
            };
        }

        /// <summary>The WhereClause of --of-type / --min-severity: one element, or [And(1, 2), OfType, GreaterThanOrEqual]; empty when neither is set.</summary>
        internal static ContentFilter EventWhere(NodeId ofType, ushort? minSeverity)
        {
            var elements = new List<ContentFilterElement>();
            if (!ofType.IsNull)
            {
                elements.Add(new ContentFilterElement
                {
                    FilterOperator = FilterOperator.OfType,
                    FilterOperands = new ArrayOf<ExtensionObject>(new[] { new ExtensionObject(new LiteralOperand { Value = new Variant(ofType) }) })
                });
            }
            if (minSeverity.HasValue)
            {
                elements.Add(new ContentFilterElement
                {
                    FilterOperator = FilterOperator.GreaterThanOrEqual,
                    FilterOperands = new ArrayOf<ExtensionObject>(new[]
                    {
                        new ExtensionObject(SelectOperand("Severity")),
                        new ExtensionObject(new LiteralOperand { Value = new Variant(minSeverity.Value) })
                    })
                });
            }
            if (elements.Count == 2)
            {
                // Part 4 §7.7.1: element 0 is the root, and an ElementOperand refers to a later
                // element (UA-.NETStandard answers BadEventFilterInvalid for an And at the end).
                elements.Insert(0, new ContentFilterElement
                {
                    FilterOperator = FilterOperator.And,
                    FilterOperands = new ArrayOf<ExtensionObject>(new[]
                    {
                        new ExtensionObject(new ElementOperand { Index = 1 }),
                        new ExtensionObject(new ElementOperand { Index = 2 })
                    })
                });
            }
            return new ContentFilter { Elements = new ArrayOf<ContentFilterElement>(elements.ToArray()) };
        }

        /// <summary>--timestamps source|server|both|neither (any case; default both).</summary>
        internal static TimestampsToReturn EventTimestamps(string v) => (v ?? "both").ToLowerInvariant() switch
        {
            "source" => TimestampsToReturn.Source,
            "server" => TimestampsToReturn.Server,
            "both" => TimestampsToReturn.Both,
            "neither" => TimestampsToReturn.Neither,
            _ => throw new InputException("invalid --timestamps " + v + " (source, server, both or neither)")
        };

        private sealed record EventPage(StatusCode Service, StatusCode Item, string ContinuationPoint, JsonArray Events);

        private static JsonArray EventsJson(HistoryEvent he, IReadOnlyList<string> names)
        {
            var list = new JsonArray();
            if (he == null)
            {
                return list;
            }
            foreach (HistoryEventFieldList fl in he.Events)
            {
                var fields = new JsonArray();
                Variant[] vs = fl?.EventFields.ToArray() ?? [];
                for (int i = 0; i < vs.Length; i++)
                {
                    var f = new JsonObject { ["name"] = i < names.Count ? names[i] : "field" + i };
                    Canonical.PutValue(f, vs[i]);
                    fields.Add(f);
                }
                list.Add(new JsonObject { ["fields"] = fields });
            }
            return list;
        }

        private static async Task<int> HistoryReadEventsAsync(ClientContext c)
        {
            List<string> nodeStrs = c.Args.All("--node");
            if (nodeStrs.Count == 0)
            {
                throw new InputException("missing --node");
            }
            ParseNodesOffline(c.Args);
            string startStr = c.Args.Get("--start"), endStr = c.Args.Get("--end");
            DateTimeUtc start = startStr == null ? DateTimeUtc.MinValue : new DateTimeUtc(ParseTime(startStr, "--start"));
            DateTimeUtc end = endStr == null ? DateTimeUtc.MinValue : new DateTimeUtc(ParseTime(endStr, "--end"));
            int numInt = c.Args.GetInt("--num-values", 0);
            if (numInt < 0)
            {
                throw new InputException("--num-values must be >= 0");
            }
            uint num = (uint)numInt;
            List<string> selectPaths = c.Args.All("--select");
            if (selectPaths.Count == 0)
            {
                selectPaths = [.. DefaultHistoryEventSelect];
            }
            SimpleAttributeOperand[] select = selectPaths.Select(SelectOperand).ToArray();
            string ofTypeStr = c.Args.Get("--of-type");
            if (ofTypeStr != null && !ofTypeStr.StartsWith("nsu=", StringComparison.Ordinal))
            {
                NodeIds.Parse(ofTypeStr);
            }
            string minSevStr = c.Args.Get("--min-severity");
            ushort? minSev = null;
            if (minSevStr != null)
            {
                if (!ushort.TryParse(minSevStr, NumberStyles.Integer, Inv.C, out ushort ms))
                {
                    throw new InputException("invalid --min-severity " + minSevStr);
                }
                minSev = ms;
            }
            string cpIn = c.Args.Get("--continuation-point");
            if (cpIn != null)
            {
                try
                {
                    Convert.FromBase64String(cpIn);
                }
                catch (FormatException)
                {
                    throw new InputException("--continuation-point must be Base64");
                }
                if (nodeStrs.Count != 1)
                {
                    throw new InputException("--continuation-point takes exactly one --node");
                }
            }
            bool release = PresenceFlag(c.Args, "--release-continuation-point");
            if (release && cpIn == null)
            {
                throw new InputException("--release-continuation-point needs --continuation-point");
            }
            string scenario = c.Args.Get("--scenario");
            if (scenario != null && scenario != "continue")
            {
                throw new InputException("unknown --scenario " + scenario);
            }
            int maxPages = c.Args.GetInt("--max-pages", 8);
            if (maxPages < 1)
            {
                throw new InputException("--max-pages must be >= 1");
            }
            TimestampsToReturn ts = EventTimestamps(c.Args.Get("--timestamps"));

            await c.ConnectAsync().ConfigureAwait(false);
            List<NodeId> nodes = nodeStrs.Select(c.Node).ToList();
            var filter = new EventFilter
            {
                SelectClauses = new ArrayOf<SimpleAttributeOperand>(select),
                WhereClause = EventWhere(ofTypeStr == null ? NodeId.Null : c.Node(ofTypeStr), minSev)
            };
            var details = new ExtensionObject(new ReadEventDetails
            {
                StartTime = start,
                EndTime = end,
                NumValuesPerNode = num,
                Filter = filter
            });

            async Task<EventPage[]> Request(IReadOnlyList<NodeId> ids, IReadOnlyList<string> cps, bool rel)
            {
                var toRead = new HistoryReadValueId[ids.Count];
                for (int i = 0; i < ids.Count; i++)
                {
                    toRead[i] = new HistoryReadValueId
                    {
                        NodeId = ids[i],
                        ContinuationPoint = string.IsNullOrEmpty(cps[i]) ? default : ByteString.From(Convert.FromBase64String(cps[i]))
                    };
                }
                var pages = new EventPage[ids.Count];
                HistoryReadResponse resp;
                try
                {
                    resp = await c.Session.HistoryReadAsync(c.Header(), details, ts, rel,
                        new ArrayOf<HistoryReadValueId>(toRead), CancellationToken.None).ConfigureAwait(false);
                }
                catch (ServiceResultException e) when (!IsTransport(e.StatusCode.Code))
                {
                    for (int i = 0; i < pages.Length; i++)
                    {
                        pages[i] = new EventPage(e.StatusCode, StatusCodes.Good, null, new JsonArray());
                    }
                    return pages;
                }
                StatusCode svc = resp.ResponseHeader.ServiceResult;
                for (int i = 0; i < pages.Length; i++)
                {
                    if (!StatusCode.IsGood(svc) || i >= resp.Results.Count)
                    {
                        pages[i] = new EventPage(svc, StatusCode.IsGood(svc) ? StatusCodes.BadUnexpectedError : StatusCodes.Good, null, new JsonArray());
                        continue;
                    }
                    HistoryReadResult hr = resp.Results[i];
                    string cpOut = !hr.ContinuationPoint.IsNull && hr.ContinuationPoint.Length > 0
                        ? Convert.ToBase64String(hr.ContinuationPoint.Span)
                        : null;
                    HistoryEvent he = null;
                    if (!hr.HistoryData.IsNull)
                    {
                        hr.HistoryData.TryGetValue(out he, Codec.Context);
                    }
                    pages[i] = new EventPage(svc, hr.StatusCode, cpOut, EventsJson(he, selectPaths));
                }
                return pages;
            }

            StatusCode serviceFault = StatusCodes.Good, firstBad = StatusCodes.Good;
            void Track(EventPage p)
            {
                if (!StatusCode.IsGood(p.Service) && StatusCode.IsGood(serviceFault))
                {
                    serviceFault = p.Service;
                }
                else if (StatusCode.IsBad(p.Item) && StatusCode.IsGood(firstBad))
                {
                    firstBad = p.Item;
                }
            }

            var r = new Result("history-read-events");
            if (scenario == "continue")
            {
                // Each node pages on its own: follow the continuation points until none is left (or
                // --max-pages), then release the last one received and try to reuse it.
                foreach (NodeId node in nodes)
                {
                    var pages = new JsonArray();
                    var all = new JsonArray();
                    string cur = cpIn, lastCp = null;
                    EventPage p = null;
                    for (int i = 0; i < maxPages; i++)
                    {
                        p = (await Request([node], [cur], false).ConfigureAwait(false))[0];
                        Track(p);
                        foreach (JsonNode e in p.Events)
                        {
                            all.Add(e.DeepClone());
                        }
                        pages.Add(new JsonObject
                        {
                            ["statusCode"] = StatusNames.Json(StatusCode.IsGood(p.Service) ? p.Item : p.Service),
                            ["continuationPoint"] = p.ContinuationPoint,
                            ["events"] = p.Events
                        });
                        if (!StatusCode.IsGood(p.Service) || StatusCode.IsBad(p.Item) || string.IsNullOrEmpty(p.ContinuationPoint))
                        {
                            break;
                        }
                        cur = p.ContinuationPoint;
                        lastCp = cur;
                    }
                    JsonNode releaseSc = null, reuseSc = null;
                    if (lastCp != null)
                    {
                        EventPage rel = (await Request([node], [lastCp], true).ConfigureAwait(false))[0];
                        releaseSc = StatusNames.Json(StatusCode.IsGood(rel.Service) ? rel.Item : rel.Service);
                        EventPage reuse = (await Request([node], [lastCp], false).ConfigureAwait(false))[0];
                        reuseSc = StatusNames.Json(StatusCode.IsGood(reuse.Service) ? reuse.Item : reuse.Service);
                    }
                    r.Add(new JsonObject
                    {
                        ["scenario"] = "continue",
                        ["nodeId"] = Canonical.NodeId(node),
                        ["statusCode"] = StatusNames.Json(StatusCode.IsGood(p.Service) ? p.Item : p.Service),
                        ["continuationPoint"] = p.ContinuationPoint,
                        ["selectClauses"] = Json.Strings(selectPaths),
                        ["events"] = all,
                        ["pages"] = pages,
                        ["releaseStatusCode"] = releaseSc,
                        ["reuseAfterReleaseStatusCode"] = reuseSc
                    });
                }
            }
            else
            {
                var cps = nodes.Select(_ => cpIn).ToList();
                EventPage[] pages = await Request(nodes, cps, release).ConfigureAwait(false);
                for (int i = 0; i < nodes.Count; i++)
                {
                    EventPage p = pages[i];
                    Track(p);
                    r.Add(new JsonObject
                    {
                        ["nodeId"] = Canonical.NodeId(nodes[i]),
                        ["statusCode"] = StatusNames.Json(StatusCode.IsGood(p.Service) ? p.Item : p.Service),
                        ["continuationPoint"] = p.ContinuationPoint,
                        ["selectClauses"] = Json.Strings(selectPaths),
                        ["events"] = p.Events
                    });
                }
            }
            if (!StatusCode.IsGood(serviceFault))
            {
                r.ServiceResult(serviceFault).Error("service", "HistoryRead failed");
                r.Print();
                return 4;
            }
            if (StatusCode.IsBad(firstBad))
            {
                r.ServiceResult(firstBad).Error("service", "HistoryRead returned a Bad result for a node");
                r.Print();
                return 4;
            }
            r.Print();
            return 0;
        }

        // ------------------------------------------------------------------
        // history-update-events
        // ------------------------------------------------------------------

        /// <summary>One --event field before NodeIds are resolved: the select path, its type and the JSON value.</summary>
        internal sealed record EventFieldInput(string Path, string Type, JsonElement Value);

        /// <summary>Parses one --event JSON object (keys are select paths, values §7 or {"type","value"}).</summary>
        internal static List<EventFieldInput> ParseEventJson(string json)
        {
            JsonElement root;
            try
            {
                using JsonDocument doc = JsonDocument.Parse(json);
                root = doc.RootElement.Clone();
            }
            catch (JsonException e)
            {
                throw new InputException("--event is not JSON: " + e.Message);
            }
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new InputException("--event must be a JSON object keyed by select path");
            }
            var list = new List<EventFieldInput>();
            foreach (JsonProperty p in root.EnumerateObject())
            {
                SelectOperand(p.Name);
                JsonElement v = p.Value;
                string type;
                JsonElement value;
                if (v.ValueKind == JsonValueKind.Object && v.TryGetProperty("type", out JsonElement t) && t.ValueKind == JsonValueKind.String)
                {
                    type = t.GetString();
                    value = v.TryGetProperty("value", out JsonElement inner) ? inner : default;
                }
                else
                {
                    type = v.ValueKind switch
                    {
                        JsonValueKind.String => "String",
                        JsonValueKind.True or JsonValueKind.False => "Boolean",
                        JsonValueKind.Number => v.TryGetInt32(out _) ? "Int32" : "Double",
                        JsonValueKind.Null => "Null",
                        JsonValueKind.Object when v.TryGetProperty("text", out _) => "LocalizedText",
                        _ => throw new InputException("--event field " + p.Name + ": give {\"type\":…,\"value\":…}")
                    };
                    value = v;
                }
                // syntax check of everything but NodeIds with a namespace URI
                EventFieldVariant(new EventFieldInput(p.Name, type, value), s => NodeIds.Parse(s.StartsWith("nsu=", StringComparison.Ordinal) ? "i=0" : s));
                list.Add(new EventFieldInput(p.Name, type, value));
            }
            return list;
        }

        /// <summary>The Variant of an --event field (§7 encodings).</summary>
        internal static Variant EventFieldVariant(EventFieldInput f, Func<string, NodeId> node)
        {
            JsonElement v = f.Value;
            if (f.Type == "Null" || v.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            {
                return Variant.Null;
            }
            try
            {
                switch (f.Type)
                {
                    case "LocalizedText":
                        if (v.ValueKind == JsonValueKind.String)
                        {
                            return new Variant(new LocalizedText(v.GetString()));
                        }
                        string locale = v.TryGetProperty("locale", out JsonElement l) && l.ValueKind == JsonValueKind.String ? l.GetString() : null;
                        string text = v.TryGetProperty("text", out JsonElement tx) && tx.ValueKind == JsonValueKind.String ? tx.GetString() : null;
                        return new Variant(new LocalizedText(string.IsNullOrEmpty(locale) ? null : locale, text));
                    case "QualifiedName":
                        if (v.ValueKind == JsonValueKind.Object)
                        {
                            ushort ns = v.TryGetProperty("ns", out JsonElement n) ? n.GetUInt16() : (ushort)0;
                            return new Variant(new QualifiedName(v.GetProperty("name").GetString(), ns));
                        }
                        return ValueParser.Parse("QualifiedName", v.GetString(), null);
                    case "NodeId":
                        return new Variant(node(v.GetString()));
                    case "StatusCode":
                        if (v.ValueKind == JsonValueKind.Object)
                        {
                            return new Variant(new StatusCode(v.GetProperty("code").GetUInt32()));
                        }
                        return ValueParser.Parse("StatusCode", v.ValueKind == JsonValueKind.Number ? v.GetRawText() : v.GetString(), null);
                    default:
                        string literal = v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText();
                        return ValueParser.Parse(f.Type, literal, null);
                }
            }
            catch (InputException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new InputException("--event field " + f.Path + " (" + f.Type + "): " + e.Message);
            }
        }

        private static async Task<int> HistoryUpdateEventsAsync(ClientContext c)
        {
            string nodeStr = c.Args.Get("--node") ?? throw new InputException("missing --node");
            ParseNodesOffline(c.Args);
            string perform = c.Args.Get("--perform") ?? throw new InputException("missing --perform insert|replace|update|delete");
            PerformUpdateType? type = perform.ToLowerInvariant() switch
            {
                "insert" => PerformUpdateType.Insert,
                "replace" => PerformUpdateType.Replace,
                "update" => PerformUpdateType.Update,
                "delete" => null,
                _ => throw new InputException("invalid --perform " + perform + " (insert, replace, update or delete)")
            };
            var events = c.Args.All("--event").Select(ParseEventJson).ToList();
            List<string> selectPaths = c.Args.All("--select");
            var eventIds = new List<ByteString>();
            if (type == null)
            {
                foreach (string id in c.Args.All("--event-id"))
                {
                    try
                    {
                        eventIds.Add(ByteString.From(Convert.FromBase64String(id)));
                    }
                    catch (FormatException)
                    {
                        throw new InputException("--event-id must be Base64: " + id);
                    }
                }
                if (eventIds.Count == 0)
                {
                    throw new InputException("--perform delete needs --event-id");
                }
            }
            else
            {
                if (events.Count == 0)
                {
                    throw new InputException("--perform " + perform + " needs --event");
                }
                if (selectPaths.Count == 0)
                {
                    // the paths of the --event objects, in order of appearance
                    selectPaths = events.SelectMany(e => e.Select(f => f.Path)).Distinct().ToList();
                }
                foreach (string p in selectPaths)
                {
                    SelectOperand(p);
                }
                foreach (List<EventFieldInput> e in events)
                {
                    foreach (EventFieldInput f in e)
                    {
                        if (!selectPaths.Contains(f.Path))
                        {
                            throw new InputException("--event field " + f.Path + " is not a --select path");
                        }
                    }
                }
            }

            await c.ConnectAsync().ConfigureAwait(false);
            NodeId node = c.Node(nodeStr);
            ExtensionObject details;
            if (type == null)
            {
                details = new ExtensionObject(new DeleteEventDetails
                {
                    NodeId = node,
                    EventIds = new ArrayOf<ByteString>(eventIds.ToArray())
                });
            }
            else
            {
                var data = new List<HistoryEventFieldList>();
                foreach (List<EventFieldInput> e in events)
                {
                    var fields = new Variant[selectPaths.Count];
                    for (int i = 0; i < selectPaths.Count; i++)
                    {
                        EventFieldInput f = e.FirstOrDefault(x => x.Path == selectPaths[i]);
                        fields[i] = f == null ? Variant.Null : EventFieldVariant(f, c.Node);
                    }
                    data.Add(new HistoryEventFieldList { EventFields = new ArrayOf<Variant>(fields) });
                }
                details = new ExtensionObject(new UpdateEventDetails
                {
                    NodeId = node,
                    PerformInsertReplace = type.Value,
                    Filter = new EventFilter
                    {
                        SelectClauses = new ArrayOf<SimpleAttributeOperand>(selectPaths.Select(SelectOperand).ToArray()),
                        WhereClause = new ContentFilter()
                    },
                    EventData = new ArrayOf<HistoryEventFieldList>(data.ToArray())
                });
            }

            string performName = type switch
            {
                PerformUpdateType.Insert => "Insert",
                PerformUpdateType.Replace => "Replace",
                PerformUpdateType.Update => "Update",
                _ => "Delete"
            };
            var r = new Result("history-update-events");
            HistoryUpdateResponse resp;
            try
            {
                resp = await c.Session.HistoryUpdateAsync(c.Header(), new ArrayOf<ExtensionObject>(new[] { details }),
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch (ServiceResultException e) when (!IsTransport(e.StatusCode.Code))
            {
                r.ServiceResult(e.StatusCode).Error("service", "HistoryUpdate failed: " + e.Message).Print();
                return 4;
            }
            StatusCode svc = resp.ResponseHeader.ServiceResult;
            if (!StatusCode.IsGood(svc) || resp.Results.Count == 0)
            {
                r.ServiceResult(StatusCode.IsGood(svc) ? StatusCodes.BadUnexpectedError : svc).Error("service", "HistoryUpdate failed").Print();
                return 4;
            }
            HistoryUpdateResult hr = resp.Results[0];
            var ops = new JsonArray();
            foreach (StatusCode sc in hr.OperationResults)
            {
                ops.Add(StatusNames.Json(sc));
            }
            r.Add(new JsonObject
            {
                ["nodeId"] = Canonical.NodeId(node),
                ["performUpdateType"] = performName,
                ["statusCode"] = StatusNames.Json(hr.StatusCode),
                ["operationResults"] = ops
            });
            if (StatusCode.IsBad(hr.StatusCode))
            {
                r.ServiceResult(hr.StatusCode).Error("service", "HistoryUpdate returned a Bad result for the node").Print();
                return 4;
            }
            r.Print();
            return 0;
        }
    }
}
