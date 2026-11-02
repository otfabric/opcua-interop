// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using Opc.Ua;
using Opc.Ua.Identity;
using Opc.Ua.Server;
using Opc.Ua.Server.Historian;
using Opc.Ua.Server.Historian.InMemory;

namespace OpcUaInterop
{
    /// <summary>
    /// The fixture address space (docs/FIXTURES.md) as a classic CustomNodeManager2:
    /// folders / objects, variables, methods, behaviours (counter / toggle / ramp / fixed-status),
    /// BaseEvent emission on Events.Source, raw history on History.Temperature and event history on
    /// History.Events (InteropNodeManager.HistoryEvents.cs).
    /// </summary>
    internal sealed partial class InteropNodeManager : AsyncCustomNodeManager
    {
        private const string EventsSourceId = "s=Events.Source";
        private const string HistoryTemperatureId = "s=History.Temperature";

        private readonly Fixture m_fixture;
        private readonly Dictionary<string, NodeState> m_nodes = new();
        private readonly List<Timer> m_timers = [];
        private readonly InMemoryHistorianProvider m_historian;
        private BaseObjectState m_eventsSource;
        private BaseDataVariableState m_historyTemperature;

        public InteropNodeManager(IServerInternal server, ApplicationConfiguration configuration, Fixture fixture)
            // useSamplingGroups: sample monitored values at their revised sampling interval.
            // Without it the stack reports every ClearChangeMasks as an exception and a
            // 1 s item on the 100 ms ramp got a value every 500 ms.
            : base(server, configuration, useSamplingGroups: true, fixture.Namespaces[0].Uri)
        {
            m_fixture = fixture;
            m_historian = new InMemoryHistorianProvider(new InMemoryHistorianOptions
            {
                RawDataRetentionPeriod = TimeSpan.Zero,
                DefaultCapabilities = HistorianNodeCapabilities.ReadOnly with { ServerTimestampSupported = true }
            });
        }

        /// <summary>AddNodes / DeleteNodes are served in this namespace.</summary>
        public override bool AllowNodeManagement => true;

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                foreach (Timer t in m_timers)
                {
                    t.Dispose();
                }
                m_timers.Clear();
                m_historian.Dispose();
                m_eventHistorian?.Dispose();
            }
            base.Dispose(disposing);
        }

        // ------------------------------------------------------------------
        // NodeId helpers
        // ------------------------------------------------------------------

        /// <summary>Resolves a fixture NodeId string (nsu= / ns= / i=) against the server namespace table.</summary>
        public NodeId Resolve(string s)
        {
            return NodeIds.Parse(s, uri =>
            {
                int idx = Server.NamespaceUris.GetIndex(uri);
                return idx;
            });
        }

        private static string Key(string fixtureId)
        {
            int semi = fixtureId.LastIndexOf(';');
            return semi >= 0 && fixtureId.StartsWith("nsu=", StringComparison.Ordinal) ? fixtureId[(semi + 1)..] : fixtureId;
        }

        private QualifiedName BrowseName(string s)
        {
            int colon = s.IndexOf(':');
            if (colon > 0 && ushort.TryParse(s.AsSpan(0, colon), out ushort ns))
            {
                // the fixture's namespace index 1 is the interop namespace, whatever its index here
                return new QualifiedName(s[(colon + 1)..], ns == 0 ? (ushort)0 : NamespaceIndex);
            }
            return new QualifiedName(s, NamespaceIndex);
        }

        private static NodeId ReferenceType(string name) => name switch
        {
            "HasComponent" => ReferenceTypeIds.HasComponent,
            "HasProperty" => ReferenceTypeIds.HasProperty,
            "HasSubtype" => ReferenceTypeIds.HasSubtype,
            "HasTypeDefinition" => ReferenceTypeIds.HasTypeDefinition,
            "Aggregates" => ReferenceTypeIds.Aggregates,
            _ => ReferenceTypeIds.Organizes
        };

        public static NodeId DataTypeId(string name) => name switch
        {
            "Boolean" => DataTypeIds.Boolean,
            "SByte" => DataTypeIds.SByte,
            "Byte" => DataTypeIds.Byte,
            "Int16" => DataTypeIds.Int16,
            "UInt16" => DataTypeIds.UInt16,
            "Int32" => DataTypeIds.Int32,
            "UInt32" => DataTypeIds.UInt32,
            "Int64" => DataTypeIds.Int64,
            "UInt64" => DataTypeIds.UInt64,
            "Float" => DataTypeIds.Float,
            "Double" => DataTypeIds.Double,
            "String" => DataTypeIds.String,
            "DateTime" => DataTypeIds.DateTime,
            "Guid" => DataTypeIds.Guid,
            "ByteString" => DataTypeIds.ByteString,
            "XmlElement" => DataTypeIds.XmlElement,
            "NodeId" => DataTypeIds.NodeId,
            "QualifiedName" => DataTypeIds.QualifiedName,
            "LocalizedText" => DataTypeIds.LocalizedText,
            "StatusCode" => DataTypeIds.StatusCode,
            _ => DataTypeIds.BaseDataType
        };

        private static byte AccessLevel(List<string> levels)
        {
            byte b = 0;
            foreach (string s in levels ?? [])
            {
                b |= s switch
                {
                    "CurrentRead" => AccessLevels.CurrentRead,
                    "CurrentWrite" => AccessLevels.CurrentWrite,
                    "HistoryRead" => AccessLevels.HistoryRead,
                    "HistoryWrite" => AccessLevels.HistoryWrite,
                    "SemanticChange" => AccessLevels.SemanticChange,
                    "StatusWrite" => AccessLevels.StatusWrite,
                    "TimestampWrite" => AccessLevels.TimestampWrite,
                    _ => (byte)0
                };
            }
            return b == 0 ? AccessLevels.CurrentRead : b;
        }

        // ------------------------------------------------------------------
        // Address space
        // ------------------------------------------------------------------

        public override async System.Threading.Tasks.ValueTask CreateAddressSpaceAsync(
            IDictionary<NodeId, IList<IReference>> externalReferences,
            CancellationToken cancellationToken = default)
        {
            {
                var defs = new List<(Fixture.NodeDef Def, NodeState State)>();
                foreach (Fixture.NodeDef nd in m_fixture.Nodes)
                {
                    NodeState state = nd.NodeClass switch
                    {
                        "Variable" => CreateVariable(nd),
                        "Method" => CreateMethod(nd),
                        _ => CreateObject(nd)
                    };
                    m_nodes[Key(nd.NodeId)] = state;
                    defs.Add((nd, state));
                }

                var children = new HashSet<NodeState>();
                foreach ((Fixture.NodeDef nd, NodeState state) in defs)
                {
                    if (string.IsNullOrEmpty(nd.ParentNodeId))
                    {
                        continue;
                    }
                    NodeId refType = ReferenceType(nd.ReferenceType);
                    if (m_nodes.TryGetValue(Key(nd.ParentNodeId), out NodeState parent))
                    {
                        if (state is BaseInstanceState instance &&
                            (refType == ReferenceTypeIds.HasComponent || refType == ReferenceTypeIds.HasProperty))
                        {
                            instance.ReferenceTypeId = refType;
                            parent.AddChild(instance);
                            children.Add(state);
                        }
                        else
                        {
                            parent.AddReference(refType, false, state.NodeId);
                            state.AddReference(refType, true, parent.NodeId);
                        }
                    }
                    else
                    {
                        // parent in another node manager (Objects folder)
                        NodeId parentId = Resolve(nd.ParentNodeId);
                        state.AddReference(refType, true, parentId);
                        if (!externalReferences.TryGetValue(parentId, out IList<IReference> refs))
                        {
                            externalReferences[parentId] = refs = new List<IReference>();
                        }
                        refs.Add(new NodeStateReference(refType, false, state.NodeId));
                    }
                }

                List<NodeState> alarmNodes = CreateAlarmNodes(externalReferences);
                alarmNodes.AddRange(CreateHistoryEventNodes(externalReferences));

                foreach ((Fixture.NodeDef _, NodeState state) in defs)
                {
                    if (!children.Contains(state))
                    {
                        await AddPredefinedNodeAsync(SystemContext, state, cancellationToken).ConfigureAwait(false);
                    }
                }
                foreach (NodeState state in alarmNodes)
                {
                    await AddPredefinedNodeAsync(SystemContext, state, cancellationToken).ConfigureAwait(false);
                }

                if (m_eventsSource != null)
                {
                    await AddRootNotifierAsync(m_eventsSource, cancellationToken).ConfigureAwait(false);
                }
                await RegisterAlarmNotifierAsync(cancellationToken).ConfigureAwait(false);

                SetupHistory();
                ResetHistoryEvents();
                SetupBehaviors();
                SetupEventEmission();
            }
        }

        private BaseObjectState CreateObject(Fixture.NodeDef nd)
        {
            NodeId typeDef = string.IsNullOrEmpty(nd.TypeDefinition) ? ObjectTypeIds.FolderType : Resolve(nd.TypeDefinition);
            BaseObjectState o = typeDef == ObjectTypeIds.FolderType ? new FolderState(null) : new BaseObjectState(null);
            o.NodeId = Resolve(nd.NodeId);
            o.BrowseName = BrowseName(nd.BrowseName);
            o.DisplayName = new LocalizedText("en", nd.DisplayName ?? o.BrowseName.Name);
            if (!string.IsNullOrEmpty(nd.Description))
            {
                o.Description = new LocalizedText("en", nd.Description);
            }
            o.TypeDefinitionId = typeDef;
            o.EventNotifier = EventNotifiers.None;
            if (Key(nd.NodeId) == EventsSourceId)
            {
                o.EventNotifier = EventNotifiers.SubscribeToEvents;
                m_eventsSource = o;
            }
            return o;
        }

        private BaseDataVariableState CreateVariable(Fixture.NodeDef nd)
        {
            NodeId typeDef = string.IsNullOrEmpty(nd.TypeDefinition)
                ? VariableTypeIds.BaseDataVariableType
                : Resolve(nd.TypeDefinition);
            var v = new BaseDataVariableState(null)
            {
                NodeId = Resolve(nd.NodeId),
                BrowseName = BrowseName(nd.BrowseName),
                TypeDefinitionId = typeDef,
                DataType = DataTypeId(nd.DataType),
                ValueRank = nd.ValueRank,
                AccessLevel = AccessLevel(nd.AccessLevel),
                MinimumSamplingInterval = 0,
                Historizing = false,
                StatusCode = StatusCodes.Good,
                Timestamp = DateTimeUtc.Now
            };
            v.UserAccessLevel = v.AccessLevel;
            v.DisplayName = new LocalizedText("en", nd.DisplayName ?? v.BrowseName.Name);
            if (!string.IsNullOrEmpty(nd.Description))
            {
                v.Description = new LocalizedText("en", nd.Description);
            }
            if (nd.ValueRank >= 1)
            {
                v.ArrayDimensions = new ArrayOf<uint>(
                    (nd.ArrayDimensions.Count > 0 ? nd.ArrayDimensions : Enumerable.Repeat(0, nd.ValueRank).ToList())
                    .Select(d => (uint)Math.Max(0, d)).ToArray());
            }
            v.Value = FixtureValue(nd);
            if (nd.EuRange != null)
            {
                PropertyState<Opc.Ua.Range> range = PropertyState<Opc.Ua.Range>.With<StructureBuilder<Opc.Ua.Range>>(v);
                {
                    range
                    .NodeId = new NodeId(Key(nd.NodeId)[2..] + ".EURange", NamespaceIndex);
                    range.BrowseName = QualifiedName.From(BrowseNames.EURange);
                    range.DisplayName = new LocalizedText("en", BrowseNames.EURange);
                    range.TypeDefinitionId = VariableTypeIds.PropertyType;
                    range.ReferenceTypeId = ReferenceTypeIds.HasProperty;
                    range.DataType = DataTypeIds.Range;
                    range.ValueRank = ValueRanks.Scalar;
                    range.AccessLevel = AccessLevels.CurrentRead;
                    range.UserAccessLevel = AccessLevels.CurrentRead;
                }
                range.Value = new Opc.Ua.Range { Low = nd.EuRange.Low, High = nd.EuRange.High };
                v.AddChild(range);
            }
            if (Key(nd.NodeId) == HistoryTemperatureId)
            {
                v.Historizing = true;
                m_historyTemperature = v;
            }
            return v;
        }

        /// <summary>The fixture initialValue as a Variant of the declared type / rank.</summary>
        internal static Variant FixtureValue(Fixture.NodeDef nd)
        {
            if (nd.InitialValue is not JsonElement json || json.ValueKind == JsonValueKind.Null)
            {
                return Variant.Null;
            }
            string type = nd.DataType ?? "String";
            if (nd.ValueRank >= 1 && json.ValueKind == JsonValueKind.Array)
            {
                var items = json.EnumerateArray().Select(Literal).ToList();
                string literal = System.Text.Json.JsonSerializer.Serialize(items);
                int[] dims = nd.ValueRank >= 2 && nd.ArrayDimensions.Count >= 2 ? nd.ArrayDimensions.ToArray() : null;
                return ValueParser.Parse(type + "[]", literal, dims);
            }
            string lit = Literal(json);
            if (type is "QualifiedName" or "NodeId")
            {
                // the fixture writes these in namespace-index form of the namespace table (0 here)
                return ValueParser.Parse(type, lit, null);
            }
            if (type == "StatusCode")
            {
                return new Variant(new StatusCode(uint.Parse(lit, Inv.C)));
            }
            return ValueParser.Parse(type, lit, null);
        }

        private static string Literal(JsonElement e) => e.ValueKind switch
        {
            JsonValueKind.String => e.GetString(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => e.GetRawText()
        };

        private MethodState CreateMethod(Fixture.NodeDef nd)
        {
            var m = new MethodState(null)
            {
                NodeId = Resolve(nd.NodeId),
                BrowseName = BrowseName(nd.BrowseName),
                Executable = true,
                UserExecutable = true,
                ReferenceTypeId = ReferenceTypeIds.HasComponent
            };
            m.DisplayName = new LocalizedText("en", nd.DisplayName ?? m.BrowseName.Name);
            if (!string.IsNullOrEmpty(nd.Description))
            {
                m.Description = new LocalizedText("en", nd.Description);
            }
            string id = Key(nd.NodeId)[2..];
            if (nd.InputArguments.Count > 0)
            {
                m.InputArguments = ArgumentsProperty(m, id + ".InputArguments", BrowseNames.InputArguments, nd.InputArguments);
            }
            if (nd.OutputArguments.Count > 0)
            {
                m.OutputArguments = ArgumentsProperty(m, id + ".OutputArguments", BrowseNames.OutputArguments, nd.OutputArguments);
            }
            m.OnCallMethod = MethodHandler(nd.MethodBehavior);
            return m;
        }

        private PropertyState<ArrayOf<Argument>> ArgumentsProperty(
            MethodState method, string id, string browseName, List<Fixture.ArgumentDef> args)
        {
            PropertyState<ArrayOf<Argument>> p = PropertyState<ArrayOf<Argument>>.With<StructureBuilder<Argument>>(method);
            p.NodeId = new NodeId(id, NamespaceIndex);
            p.BrowseName = QualifiedName.From(browseName);
            p.DisplayName = new LocalizedText(browseName);
            p.TypeDefinitionId = VariableTypeIds.PropertyType;
            p.ReferenceTypeId = ReferenceTypeIds.HasProperty;
            p.DataType = DataTypeIds.Argument;
            p.ValueRank = ValueRanks.OneDimension;
            p.ArrayDimensions = new ArrayOf<uint>(new uint[] { 0 });
            p.AccessLevel = AccessLevels.CurrentRead;
            p.UserAccessLevel = AccessLevels.CurrentRead;
            p.Value = new ArrayOf<Argument>(args.Select(a => new Argument
            {
                Name = a.Name ?? string.Empty,
                DataType = DataTypeId(a.DataType),
                ValueRank = a.ValueRank,
                Description = new LocalizedText("en", a.Description ?? string.Empty)
            }).ToArray());
            return p;
        }

        private static GenericMethodCalledEventHandler MethodHandler(string behavior)
        {
            return behavior switch
            {
                "Add" => (ctx, m, inputs, outputs) =>
                {
                    outputs[0] = new Variant(inputs[0].GetInt32() + inputs[1].GetInt32());
                    return ServiceResult.Good;
                },
                "Multiply" => (ctx, m, inputs, outputs) =>
                {
                    outputs[0] = new Variant(inputs[0].GetDouble() * inputs[1].GetDouble());
                    return ServiceResult.Good;
                },
                "Echo" => (ctx, m, inputs, outputs) =>
                {
                    outputs[0] = new Variant(inputs[0].GetString());
                    return ServiceResult.Good;
                },
                "NoArguments" => (ctx, m, inputs, outputs) =>
                {
                    outputs[0] = new Variant(true);
                    return ServiceResult.Good;
                },
                "MultipleOutputs" => (ctx, m, inputs, outputs) =>
                {
                    int x = inputs[0].GetInt32();
                    outputs[0] = new Variant(x * 2);
                    outputs[1] = new Variant(x.ToString(Inv.C));
                    return ServiceResult.Good;
                },
                "Fail" => (ctx, m, inputs, outputs) => new ServiceResult(StatusCodes.BadInternalError),
                _ => (ctx, m, inputs, outputs) => new ServiceResult(StatusCodes.BadNotImplemented)
            };
        }

        // ------------------------------------------------------------------
        // Behaviours
        // ------------------------------------------------------------------

        private void SetupBehaviors()
        {
            foreach (Fixture.BehaviorDef b in m_fixture.Behaviors)
            {
                if (!m_nodes.TryGetValue(Key(b.Target), out NodeState n) || n is not BaseDataVariableState v)
                {
                    Console.Error.WriteLine("[dotnet] warn: behavior target not found: " + b.Target);
                    continue;
                }
                switch (b.Kind)
                {
                    case "counter":
                        {
                            long next = (long)b.Initial;
                            long inc = (long)b.Increment;
                            Every(b.IntervalMs, () =>
                            {
                                long val = next;
                                next += inc;
                                Update(v, new Variant(val));
                            });
                            break;
                        }
                    case "toggle":
                        {
                            bool state = false;
                            Every(b.IntervalMs, () =>
                            {
                                state = !state;
                                Update(v, new Variant(state));
                            });
                            break;
                        }
                    case "ramp":
                        {
                            double cur = b.Initial;
                            Every(b.IntervalMs, () =>
                            {
                                double val = cur;
                                cur += b.Increment;
                                if (cur > b.Maximum)
                                {
                                    cur = b.Minimum;
                                }
                                Update(v, new Variant(val));
                            });
                            break;
                        }
                    case "fixed-status":
                        v.StatusCode = new StatusCode((uint)b.Initial);
                        break;
                    default:
                        Console.Error.WriteLine("[dotnet] warn: unknown behavior kind: " + b.Kind);
                        break;
                }
            }
        }

        private void Every(int intervalMs, Action action)
        {
            int period = Math.Max(10, intervalMs);
            var timer = new Timer(_ =>
            {
                try
                {
                    action();
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("[dotnet] warn: behavior failed: " + e.Message);
                }
            }, null, 0, period);
            m_timers.Add(timer);
        }

        private void Update(BaseDataVariableState v, Variant value)
        {
            v.Value = value;
            v.Timestamp = DateTimeUtc.Now;
            v.ClearChangeMasks(SystemContext, false);
        }

        // ------------------------------------------------------------------
        // PubSub (§14): published fields and TargetVariables
        // ------------------------------------------------------------------

        /// <summary>The fixture variable with this NodeId, or null.</summary>
        public BaseDataVariableState FindVariable(NodeId id)
        {
            foreach (NodeState n in m_nodes.Values)
            {
                if (n is BaseDataVariableState v && v.NodeId == id)
                {
                    return v;
                }
            }
            return null;
        }

        /// <summary>The current Value attribute of a variable, as a PublishedVariable samples it.</summary>
        public DataValue ReadValue(NodeId id)
        {
            BaseDataVariableState v = FindVariable(id);
            if (v == null)
            {
                return new DataValue(Variant.Null, StatusCodes.BadNodeIdUnknown, DateTimeUtc.MinValue, DateTimeUtc.Now);
            }
            lock (v)
            {
                return new DataValue(v.Value, v.StatusCode, v.Timestamp, DateTimeUtc.Now);
            }
        }

        /// <summary>
        /// Writes a received field into a TargetVariable (Value attribute only). The value must have the
        /// variable's built-in type and rank, as for a Write service call.
        /// </summary>
        public StatusCode WriteValue(NodeId id, uint attributeId, DataValue value)
        {
            if (attributeId != Attributes.Value)
            {
                return StatusCodes.BadAttributeIdInvalid;
            }
            BaseDataVariableState v = FindVariable(id);
            if (v == null)
            {
                return StatusCodes.BadNodeIdUnknown;
            }
            Variant incoming = value.WrappedValue;
            lock (v)
            {
                Variant current = v.Value;
                if (!current.IsNull && !incoming.IsNull &&
                    (current.TypeInfo.BuiltInType != incoming.TypeInfo.BuiltInType ||
                     current.TypeInfo.IsScalar != incoming.TypeInfo.IsScalar))
                {
                    return StatusCodes.BadTypeMismatch;
                }
                v.Value = incoming;
                v.StatusCode = value.StatusCode;
                v.Timestamp = Canonical.HasTime(value.SourceTimestamp) ? value.SourceTimestamp : DateTimeUtc.Now;
                v.ClearChangeMasks(SystemContext, false);
            }
            return StatusCodes.Good;
        }

        // ------------------------------------------------------------------
        // Events
        // ------------------------------------------------------------------

        private void SetupEventEmission()
        {
            if (m_eventsSource == null)
            {
                Console.Error.WriteLine("[dotnet] warn: Events.Source not present; BaseEvent emission disabled");
                return;
            }
            var timer = new Timer(_ => EmitPeerEvent(), null, 500, 2000);
            m_timers.Add(timer);
        }

        private void EmitPeerEvent()
        {
            try
            {
                var e = new BaseEventState(null);
                e.Initialize(SystemContext, m_eventsSource, EventSeverity.Medium, new LocalizedText("en", "peer-event"));
                m_eventsSource.ReportEvent(SystemContext, e);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[dotnet] warn: BaseEvent emission failed: " + ex.Message);
            }
        }

        // ------------------------------------------------------------------
        // History (raw, in-memory historian of the stack)
        // ------------------------------------------------------------------

        private void SetupHistory()
        {
            if (m_historyTemperature == null)
            {
                return;
            }
            m_historian.Register(m_historyTemperature.NodeId, HistorianNodeCapabilities.ReadOnly with { ServerTimestampSupported = true });
            var baseTime = new DateTime(2026, 7, 24, 10, 0, 0, DateTimeKind.Utc);
            var samples = new DataValue[5];
            for (int i = 0; i < 5; i++)
            {
                var ts = new DateTimeUtc(baseTime.AddSeconds(5 * i));
                samples[i] = new DataValue(new Variant(20.0 + i), StatusCodes.Good, ts, ts);
            }
            var ctx = new HistorianOperationContext(
                SystemContext,
                new OperationContext(new RequestHeader(), null, RequestType.HistoryUpdate, RequestLifetime.None),
                m_historyTemperature,
                HistoryUpdateType.Insert);
            HistorianUpdateOutcome<DataValue> outcome = m_historian
                .InsertAsync(ctx, m_historyTemperature.NodeId, new ArrayOf<DataValue>(samples), CancellationToken.None)
                .AsTask().GetAwaiter().GetResult();
            Console.Error.WriteLine("[dotnet] info: History.Temperature seeded: " + outcome);
        }

        protected override IHistorianProvider GetHistorianProvider(NodeState node)
        {
            if (m_historyTemperature != null && node.NodeId == m_historyTemperature.NodeId)
            {
                return m_historian;
            }
            if (m_historyEvents != null && node.NodeId == m_historyEvents.NodeId)
            {
                return m_eventHistorian;
            }
            return null;
        }
    }
}
