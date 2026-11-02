// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using Opc.Ua;
using Opc.Ua.Server;
using Opc.Ua.Server.Historian;
using Opc.Ua.Server.Historian.InMemory;

namespace OpcUaInterop
{
    /// <summary>
    /// The event history fixture (docs/FIXTURES.md "History (events)", serverFeatures
    /// "history-events" and "history-events-update"): the notifier s=History.Events, EventNotifier
    /// SubscribeToEvents | HistoryRead | HistoryWrite, seeded with five events, and the method
    /// s=History.ResetEvents. HistoryRead (ReadEventDetails) and HistoryUpdate (UpdateEventDetails,
    /// DeleteEventDetails) are the stack's historian dispatcher on its InMemoryHistorianProvider; the
    /// dispatcher evaluates the WhereClause and projects the SelectClauses.
    /// </summary>
    internal sealed partial class InteropNodeManager
    {
        private const string HistoryFolderId = "s=History";
        internal static readonly DateTime HistoryEventsBase = new(2026, 7, 24, 10, 0, 0, DateTimeKind.Utc);

        private BaseObjectState m_historyEvents;
        private InMemoryHistorianProvider m_eventHistorian;

        /// <summary>One seed event of the fixture (README "History (events)").</summary>
        internal sealed record SeedEvent(string EventId, NodeId EventType, DateTime Time, ushort Severity, string Message);

        /// <summary>The five seed events: hist-evt-0 … hist-evt-4, 5 s apart, Severity 100 … 500, #3 a SystemEventType.</summary>
        internal static IReadOnlyList<SeedEvent> HistoryEventSeed()
        {
            var list = new List<SeedEvent>(5);
            for (int i = 0; i < 5; i++)
            {
                list.Add(new SeedEvent(
                    "hist-evt-" + i,
                    i == 3 ? ObjectTypeIds.SystemEventType : ObjectTypeIds.BaseEventType,
                    HistoryEventsBase.AddSeconds(5 * i),
                    (ushort)(100 * (i + 1)),
                    "history-event-" + i));
            }
            return list;
        }

        /// <summary>Builds s=History.Events (Organizes from s=History) with its ResetEvents method.</summary>
        private List<NodeState> CreateHistoryEventNodes(IDictionary<NodeId, IList<IReference>> externalReferences)
        {
            var notifier = new BaseObjectState(null)
            {
                NodeId = new NodeId("History.Events", NamespaceIndex),
                BrowseName = new QualifiedName("History.Events", NamespaceIndex),
                DisplayName = new LocalizedText("en", "History.Events"),
                Description = new LocalizedText("en", "Historical events: five seeded events from 2026-07-24T10:00:00Z, 5 s apart."),
                TypeDefinitionId = ObjectTypeIds.BaseObjectType,
                EventNotifier = (byte)(EventNotifiers.SubscribeToEvents | EventNotifiers.HistoryRead | EventNotifiers.HistoryWrite)
            };
            if (m_nodes.TryGetValue(HistoryFolderId, out NodeState history))
            {
                history.AddReference(ReferenceTypeIds.Organizes, false, notifier.NodeId);
                notifier.AddReference(ReferenceTypeIds.Organizes, true, history.NodeId);
            }
            else
            {
                notifier.AddReference(ReferenceTypeIds.Organizes, true, ObjectIds.ObjectsFolder);
                if (!externalReferences.TryGetValue(ObjectIds.ObjectsFolder, out IList<IReference> refs))
                {
                    externalReferences[ObjectIds.ObjectsFolder] = refs = new List<IReference>();
                }
                refs.Add(new NodeStateReference(ReferenceTypeIds.Organizes, false, notifier.NodeId));
            }

            var reset = new MethodState(notifier)
            {
                NodeId = new NodeId("History.ResetEvents", NamespaceIndex),
                BrowseName = new QualifiedName("ResetEvents", NamespaceIndex),
                DisplayName = new LocalizedText("en", "ResetEvents"),
                Description = new LocalizedText("en", "Restores the five seed events of History.Events."),
                ReferenceTypeId = ReferenceTypeIds.HasComponent,
                Executable = true,
                UserExecutable = true
            };
            reset.OnCallMethod = (ctx, m, inputs, outputs) =>
            {
                ResetHistoryEvents();
                return ServiceResult.Good;
            };
            notifier.AddChild(reset);
            m_historyEvents = notifier;
            return [notifier];
        }

        /// <summary>A fresh in-memory event archive with the seed (initial state and ResetEvents).</summary>
        private void ResetHistoryEvents()
        {
            if (m_historyEvents == null)
            {
                return;
            }
            var provider = new InMemoryHistorianProvider(new InMemoryHistorianOptions
            {
                RawDataRetentionPeriod = TimeSpan.Zero,
                DefaultCapabilities = HistorianNodeCapabilities.EventReadWrite
            });
            provider.Register(m_historyEvents.NodeId, HistorianNodeCapabilities.EventReadWrite);
            var records = new List<HistorianEventRecord>();
            foreach (SeedEvent e in HistoryEventSeed())
            {
                records.Add(SeedRecord(e));
            }
            var ctx = new HistorianOperationContext(
                SystemContext,
                new OperationContext(new RequestHeader(), null, RequestType.HistoryUpdate, RequestLifetime.None),
                m_historyEvents,
                HistoryUpdateType.Insert);
            HistorianUpdateOutcome<HistorianEventRecord> outcome = provider
                .InsertEventsAsync(ctx, m_historyEvents.NodeId, new ArrayOf<HistorianEventRecord>(records.ToArray()), CancellationToken.None)
                .AsTask().GetAwaiter().GetResult();
            InMemoryHistorianProvider old = Interlocked.Exchange(ref m_eventHistorian, provider);
            old?.Dispose();
            Console.Error.WriteLine("[dotnet] info: History.Events seeded: " + outcome);
        }

        /// <summary>
        /// A seed event as a historian record. The fields are stored both by name (legacy lookup) and
        /// keyed by the BaseEventType SimpleAttributeOperand, so a later Replace / Update (which
        /// stores qualified fields) keeps the fields it does not touch.
        /// </summary>
        private HistorianEventRecord SeedRecord(SeedEvent e)
        {
            var time = new DateTimeUtc(e.Time);
            var eventId = ByteString.From(Encoding.ASCII.GetBytes(e.EventId));
            var fields = new (string Name, Variant Value)[]
            {
                (BrowseNames.EventId, new Variant(eventId)),
                (BrowseNames.EventType, new Variant(e.EventType)),
                (BrowseNames.SourceNode, new Variant(m_historyEvents.NodeId)),
                (BrowseNames.SourceName, new Variant("History.Events")),
                (BrowseNames.Time, new Variant(time)),
                (BrowseNames.ReceiveTime, new Variant(time)),
                (BrowseNames.Message, new Variant(new LocalizedText("en", e.Message))),
                (BrowseNames.Severity, new Variant(e.Severity))
            };
            var named = new KeyValuePair<string, Variant>[fields.Length];
            var qualified = new KeyValuePair<HistorianEventFieldKey, Variant>[fields.Length];
            for (int i = 0; i < fields.Length; i++)
            {
                named[i] = new KeyValuePair<string, Variant>(fields[i].Name, fields[i].Value);
                qualified[i] = new KeyValuePair<HistorianEventFieldKey, Variant>(
                    new HistorianEventFieldKey(
                        ObjectTypeIds.BaseEventType,
                        new ArrayOf<QualifiedName>(new[] { new QualifiedName(fields[i].Name) }),
                        Attributes.Value,
                        null),
                    fields[i].Value);
            }
            return new HistorianEventRecord(eventId, e.EventType, time, new ArrayOf<KeyValuePair<string, Variant>>(named))
            {
                QualifiedFields = new ArrayOf<KeyValuePair<HistorianEventFieldKey, Variant>>(qualified)
            };
        }
    }
}
