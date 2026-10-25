// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>
    /// The Alarms &amp; Conditions fixture (fixtures/baseline/README.md "Alarms", serverFeatures "alarms"):
    /// s=Alarms / s=Alarms.Source (root notifier) with the AlarmConditionType instance
    /// s=Alarms.InteropAlarm (ConfirmedState included) and the s=Alarms.Reset method.
    /// Acknowledge / Confirm / AddComment / Enable / Disable / ConditionRefresh are the stack's own
    /// AlarmConditionState handling.
    /// </summary>
    internal sealed partial class InteropNodeManager
    {
        private const string CompatibilityId = "s=Compatibility";
        private const ushort AlarmSeverity = 500;

        private AlarmConditionState m_alarm;
        private BaseObjectState m_alarmsSource;

        /// <summary>Builds the alarm nodes; returns the nodes to register as predefined nodes.</summary>
        private List<NodeState> CreateAlarmNodes(IDictionary<NodeId, IList<IReference>> externalReferences)
        {
            var folder = new FolderState(null)
            {
                NodeId = new NodeId("Alarms", NamespaceIndex),
                BrowseName = new QualifiedName("Alarms", NamespaceIndex),
                DisplayName = new LocalizedText("en", "Alarms"),
                Description = new LocalizedText("en", "Alarms & Conditions (Part 9) interoperability fixture."),
                TypeDefinitionId = ObjectTypeIds.FolderType,
                EventNotifier = EventNotifiers.None
            };
            if (m_nodes.TryGetValue(CompatibilityId, out NodeState compat))
            {
                compat.AddReference(ReferenceTypeIds.Organizes, false, folder.NodeId);
                folder.AddReference(ReferenceTypeIds.Organizes, true, compat.NodeId);
            }
            else
            {
                folder.AddReference(ReferenceTypeIds.Organizes, true, ObjectIds.ObjectsFolder);
                if (!externalReferences.TryGetValue(ObjectIds.ObjectsFolder, out IList<IReference> refs))
                {
                    externalReferences[ObjectIds.ObjectsFolder] = refs = new List<IReference>();
                }
                refs.Add(new NodeStateReference(ReferenceTypeIds.Organizes, false, folder.NodeId));
            }

            var source = new BaseObjectState(null)
            {
                NodeId = new NodeId("Alarms.Source", NamespaceIndex),
                BrowseName = new QualifiedName("Alarms.Source", NamespaceIndex),
                DisplayName = new LocalizedText("en", "Alarm Source"),
                Description = new LocalizedText("en", "SourceNode of the InteropAlarm condition."),
                TypeDefinitionId = ObjectTypeIds.BaseObjectType,
                EventNotifier = EventNotifiers.SubscribeToEvents
            };
            folder.AddReference(ReferenceTypeIds.Organizes, false, source.NodeId);
            source.AddReference(ReferenceTypeIds.Organizes, true, folder.NodeId);

            // The optional ConfirmedState / Confirm have to exist before Create, which assigns
            // their NodeIds and wires the Part 9 method handlers.
            var alarm = new AlarmConditionState(Server.Telemetry, source);
            alarm.ConfirmedState = new TwoStateVariableState(alarm);
            alarm.Confirm = new AddCommentMethodState(alarm);
            alarm.Create(
                SystemContext,
                new NodeId("Alarms.InteropAlarm", NamespaceIndex),
                new QualifiedName("InteropAlarm", NamespaceIndex),
                new LocalizedText("en", "InteropAlarm"),
                assignNodeIds: true);
            alarm.ReferenceTypeId = ReferenceTypeIds.HasComponent;
            source.AddChild(alarm);
            source.AddReference(ReferenceTypeIds.HasCondition, false, alarm.NodeId);
            alarm.AddReference(ReferenceTypeIds.HasCondition, true, source.NodeId);

            // BaseEventType.EventType of the condition's events (not set by Create)
            alarm.EventType.Value = ObjectTypeIds.AlarmConditionType;
            alarm.SourceNode.Value = source.NodeId;
            alarm.SourceName.Value = "Alarms.Source";
            alarm.ConditionName.Value = "InteropAlarm";
            alarm.AutoReportStateChanges = true;

            var reset = new MethodState(source)
            {
                NodeId = new NodeId("Alarms.Reset", NamespaceIndex),
                BrowseName = new QualifiedName("Reset", NamespaceIndex),
                DisplayName = new LocalizedText("en", "Reset"),
                Description = new LocalizedText("en", "Re-arms InteropAlarm: enabled, active, unacknowledged, unconfirmed, retained."),
                ReferenceTypeId = ReferenceTypeIds.HasComponent,
                Executable = true,
                UserExecutable = true
            };
            reset.OnCallMethod = (ctx, m, inputs, outputs) =>
            {
                ArmAlarm(ctx, report: true);
                return ServiceResult.Good;
            };
            source.AddChild(reset);

            m_alarm = alarm;
            m_alarmsSource = source;
            ArmAlarm(SystemContext, report: false);
            return [folder, source];
        }

        private async ValueTask RegisterAlarmNotifierAsync(CancellationToken ct)
        {
            if (m_alarmsSource != null)
            {
                await AddRootNotifierAsync(m_alarmsSource, ct).ConfigureAwait(false);
            }
        }

        /// <summary>The initial / Reset state: Enabled, Active, not acked, not confirmed, Retain, Severity 500.</summary>
        private void ArmAlarm(ISystemContext ctx, bool report)
        {
            AlarmConditionState a = m_alarm;
            if (!a.EnabledState.Id.Value)
            {
                a.SetEnableState(ctx, enabled: true);
            }
            a.SetActiveState(ctx, active: true);
            a.SetSeverity(ctx, (EventSeverity)AlarmSeverity);
            a.SetAcknowledgedState(ctx, acknowledged: false);
            a.SetConfirmedState(ctx, confirmed: false);
            a.Message.Value = new LocalizedText("en", "interop-alarm");
            if (a.Comment != null)
            {
                a.Comment.Value = new LocalizedText("en", string.Empty);
            }
            a.Retain.Value = true;
            a.EventId.Value = Uuid.NewUuid().ToByteString();
            a.Time.Value = DateTimeUtc.Now;
            a.ReceiveTime.Value = a.Time.Value;
            a.ClearChangeMasks(ctx, includeChildren: true);
            if (report)
            {
                var snapshot = new InstanceStateSnapshot();
                snapshot.Initialize(ctx, a);
                a.ReportEvent(ctx, snapshot);
            }
        }
    }
}
