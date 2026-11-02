// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>
    /// The Part 9 1.05 extension of the alarm fixture (docs/FIXTURES.md "Alarms (1.05)",
    /// serverFeatures "alarms-105"), next to InteropAlarm under s=Alarms.Source:
    /// <list type="bullet">
    /// <item>s=Alarms.ExtAlarm: an AlarmConditionType with SuppressedState, OutOfServiceState,
    /// SilenceState, LatchedState, ShelvingState, AudibleEnabled / AudibleSound and the methods
    /// Silence, Suppress(2), Unsuppress(2), RemoveFromService(2), PlaceInService(2), Reset(2),
    /// GetGroupMemberships (no ConfirmedState: an acknowledged branch ends);</item>
    /// <item>s=Alarms.Dialog: a DialogConditionType with the ResponseOptionSet [Yes, No];</item>
    /// <item>s=Alarms.Group: an AlarmGroupType with an AlarmGroupMember reference to ExtAlarm;</item>
    /// <item>the methods s=Alarms.ResetExt (re-arms ExtAlarm and the dialog), s=Alarms.Deactivate
    /// (ExtAlarm inactive, still latched) and s=Alarms.Branch (a new branch of ExtAlarm; output:
    /// its EventId).</item>
    /// </list>
    /// Every method of the conditions is the stack's own handler; the adapter only answers
    /// OnShelve (SetShelvingState) and OnRespond (SetResponse).
    /// </summary>
    internal sealed partial class InteropNodeManager
    {
        private const ushort ExtAlarmSeverity = 400;
        private const string ExtSoundListId = "interop-sounds";

        private AlarmConditionState m_extAlarm;
        private DialogConditionState m_dialog;

        /// <summary>Builds the 1.05 nodes below folder / source; returns the extra root nodes.</summary>
        private List<NodeState> CreateAlarm105Nodes(FolderState folder, BaseObjectState source)
        {
            // The optional children have to exist before Create, which assigns their NodeIds and
            // wires the stack's method handlers (AlarmConditionState.OnAfterCreate).
            var alarm = new AlarmConditionState(Server.Telemetry, source);
            alarm.AddSuppressedState(SystemContext)
                 .AddOutOfServiceState(SystemContext)
                 .AddSilenceState(SystemContext)
                 .AddLatchedState(SystemContext)
                 .AddShelvingState(SystemContext)
                 .AddAudibleEnabled(SystemContext)
                 .AddAudibleSound(SystemContext)
                 .AddSilence(SystemContext)
                 .AddSuppress(SystemContext)
                 .AddSuppress2(SystemContext)
                 .AddUnsuppress(SystemContext)
                 .AddUnsuppress2(SystemContext)
                 .AddRemoveFromService(SystemContext)
                 .AddRemoveFromService2(SystemContext)
                 .AddPlaceInService(SystemContext)
                 .AddPlaceInService2(SystemContext)
                 .AddReset(SystemContext)
                 .AddReset2(SystemContext)
                 .AddGetGroupMemberships(SystemContext);
            alarm.AudibleSound.AddListId(SystemContext);
            alarm.Create(
                SystemContext,
                new NodeId("Alarms.ExtAlarm", NamespaceIndex),
                new QualifiedName("ExtAlarm", NamespaceIndex),
                new LocalizedText("en", "ExtAlarm"),
                assignNodeIds: true);
            alarm.ReferenceTypeId = ReferenceTypeIds.HasComponent;
            source.AddChild(alarm);
            source.AddReference(ReferenceTypeIds.HasCondition, false, alarm.NodeId);
            alarm.AddReference(ReferenceTypeIds.HasCondition, true, source.NodeId);
            alarm.EventType.Value = ObjectTypeIds.AlarmConditionType;
            alarm.SourceNode.Value = source.NodeId;
            alarm.SourceName.Value = "Alarms.Source";
            alarm.ConditionName.Value = "ExtAlarm";
            alarm.AutoReportStateChanges = true;
            alarm.OnShelve = (ctx, a, shelving, oneShot, shelvingTime) =>
            {
                a.SetShelvingState(ctx, shelving, oneShot, shelvingTime);
                return ServiceResult.Good;
            };
            alarm.AudibleSound.ListId.Value = ExtSoundListId;
            alarm.AudibleSound.Value = new ByteString(System.Text.Encoding.ASCII.GetBytes("interop-horn"));

            var dialog = new DialogConditionState(source);
            dialog.Create(
                SystemContext,
                new NodeId("Alarms.Dialog", NamespaceIndex),
                new QualifiedName("Dialog", NamespaceIndex),
                new LocalizedText("en", "Dialog"),
                assignNodeIds: true);
            dialog.ReferenceTypeId = ReferenceTypeIds.HasComponent;
            source.AddChild(dialog);
            source.AddReference(ReferenceTypeIds.HasCondition, false, dialog.NodeId);
            dialog.AddReference(ReferenceTypeIds.HasCondition, true, source.NodeId);
            dialog.EventType.Value = ObjectTypeIds.DialogConditionType;
            dialog.SourceNode.Value = source.NodeId;
            dialog.SourceName.Value = "Alarms.Source";
            dialog.ConditionName.Value = "InteropDialog";
            dialog.AutoReportStateChanges = true;
            dialog.Prompt.Value = new LocalizedText("en", "interop-dialog");
            dialog.ResponseOptionSet.Value = new ArrayOf<LocalizedText>(new[]
            {
                new LocalizedText("en", "Yes"), new LocalizedText("en", "No")
            });
            dialog.DefaultResponse.Value = 0;
            dialog.OkResponse.Value = 0;
            dialog.CancelResponse.Value = 1;
            dialog.OnRespond = (ctx, d, selected) =>
            {
                d.SetResponse(ctx, selected);
                return ServiceResult.Good;
            };

            var group = new AlarmGroupState(null);
            group.Create(
                SystemContext,
                new NodeId("Alarms.Group", NamespaceIndex),
                new QualifiedName("Group", NamespaceIndex),
                new LocalizedText("en", "Group"),
                assignNodeIds: true);
            group.Description = new LocalizedText("en", "AlarmGroup with the member ExtAlarm.");
            folder.AddReference(ReferenceTypeIds.Organizes, false, group.NodeId);
            group.AddReference(ReferenceTypeIds.Organizes, true, folder.NodeId);
            group.AddReference(ReferenceTypeIds.AlarmGroupMember, false, alarm.NodeId);
            alarm.AddReference(ReferenceTypeIds.AlarmGroupMember, true, group.NodeId);

            source.AddChild(FixtureMethod(source, "Alarms.ResetExt", "ResetExt",
                "Re-arms ExtAlarm (enabled, active, unacknowledged, latched, not suppressed / silenced / out of service / shelved, no branches) and re-activates the dialog.",
                null, (ctx, m, inputs, outputs) =>
                {
                    ArmExt(ctx, report: true);
                    return ServiceResult.Good;
                }));
            source.AddChild(FixtureMethod(source, "Alarms.Deactivate", "Deactivate",
                "ExtAlarm becomes inactive; it stays latched until Reset.",
                null, (ctx, m, inputs, outputs) =>
                {
                    m_extAlarm.SetActiveState(ctx, active: false);
                    m_extAlarm.EventId.Value = Uuid.NewUuid().ToByteString();
                    m_extAlarm.Time.Value = DateTimeUtc.Now;
                    m_extAlarm.ReceiveTime.Value = m_extAlarm.Time.Value;
                    m_extAlarm.ClearChangeMasks(ctx, includeChildren: true);
                    var snapshot = new InstanceStateSnapshot();
                    snapshot.Initialize(ctx, m_extAlarm);
                    m_extAlarm.ReportEvent(ctx, snapshot);
                    return ServiceResult.Good;
                }));
            source.AddChild(FixtureMethod(source, "Alarms.Branch", "Branch",
                "Creates a branch of ExtAlarm; returns the EventId of the branch.",
                "EventId", (ctx, m, inputs, outputs) =>
                {
                    ConditionState branch = m_extAlarm.CreateBranch(ctx, new NodeId(Guid.NewGuid(), NamespaceIndex));
                    if (branch == null)
                    {
                        return StatusCodes.BadInternalError;
                    }
                    outputs[0] = new Variant(branch.EventId.Value);
                    return ServiceResult.Good;
                }));

            m_extAlarm = alarm;
            m_dialog = dialog;
            ArmExt(SystemContext, report: false);
            return [group];
        }

        private MethodState FixtureMethod(NodeState parent, string id, string name, string description,
            string byteStringOutput, GenericMethodCalledEventHandler handler)
        {
            var m = new MethodState(parent)
            {
                NodeId = new NodeId(id, NamespaceIndex),
                BrowseName = new QualifiedName(name, NamespaceIndex),
                DisplayName = new LocalizedText("en", name),
                Description = new LocalizedText("en", description),
                ReferenceTypeId = ReferenceTypeIds.HasComponent,
                Executable = true,
                UserExecutable = true
            };
            if (byteStringOutput != null)
            {
                m.OutputArguments = ArgumentsProperty(m, id + ".OutputArguments", BrowseNames.OutputArguments,
                    [new Fixture.ArgumentDef { Name = byteStringOutput, DataType = "ByteString", ValueRank = -1 }]);
            }
            m.OnCallMethod = handler;
            return m;
        }

        /// <summary>The initial / ResetExt state of ExtAlarm and the dialog.</summary>
        private void ArmExt(ISystemContext ctx, bool report)
        {
            AlarmConditionState a = m_extAlarm;
            a.ClearBranches();
            if (!a.EnabledState.Id.Value)
            {
                a.SetEnableState(ctx, enabled: true);
            }
            if (a.ShelvingState.CurrentState.Id.Value != ObjectIds.ShelvedStateMachineType_Unshelved)
            {
                a.SetShelvingState(ctx, false, false, 0);
            }
            a.SetSuppressedState(ctx, false);
            a.SetSilenceState(ctx, false);
            a.SetOutOfServiceState(ctx, false);
            a.SetActiveState(ctx, active: true);
            a.SetLatchedState(ctx, true);
            a.SetSeverity(ctx, (EventSeverity)ExtAlarmSeverity);
            a.SetAcknowledgedState(ctx, acknowledged: false);
            a.AudibleEnabled.Value = true;
            a.Message.Value = new LocalizedText("en", "ext-alarm");
            if (a.Comment != null)
            {
                a.Comment.Value = new LocalizedText("en", string.Empty);
            }
            a.Retain.Value = true;
            a.EventId.Value = Uuid.NewUuid().ToByteString();
            a.Time.Value = DateTimeUtc.Now;
            a.ReceiveTime.Value = a.Time.Value;
            a.ClearChangeMasks(ctx, includeChildren: true);

            DialogConditionState d = m_dialog;
            if (!d.EnabledState.Id.Value)
            {
                d.SetEnableState(ctx, enabled: true);
            }
            d.Activate(ctx);
            d.LastResponse.Value = -1;
            d.SetSeverity(ctx, (EventSeverity)ExtAlarmSeverity);
            d.Message.Value = new LocalizedText("en", "interop-dialog");
            if (d.Comment != null)
            {
                d.Comment.Value = new LocalizedText("en", string.Empty);
            }
            d.Retain.Value = true;
            d.EventId.Value = Uuid.NewUuid().ToByteString();
            d.Time.Value = DateTimeUtc.Now;
            d.ReceiveTime.Value = d.Time.Value;
            d.ClearChangeMasks(ctx, includeChildren: true);

            if (report)
            {
                foreach (ConditionState c in new ConditionState[] { a, d })
                {
                    var snapshot = new InstanceStateSnapshot();
                    snapshot.Initialize(ctx, c);
                    c.ReportEvent(ctx, snapshot);
                }
            }
        }
    }
}
