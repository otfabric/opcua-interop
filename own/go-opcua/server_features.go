// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// What the contract builds in code, not from fixture.json: the alarm fixture
// (docs/FIXTURES.md "Alarms"), the event history (§17) and the events of
// Events.Source. They exist only in the baseline fixture, whose folders they join.

const (
	historyTemperature = "History.Temperature"
	historyEventsNode  = "History.Events"
	historyReset       = "History.ResetEvents"
	alarmsFolder       = "Alarms"
	alarmsSource       = "Alarms.Source"
	alarmsCondition    = "Alarms.InteropAlarm"
	alarmsReset        = "Alarms.Reset"
	eventsSource       = "Events.Source"
	eventIntervalMS    = 2000
)

// historyBase is the time of the first sample and of the first event.
var historyBase = time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)

func (a *addressSpace) stringID(name string) *ua.NodeID {
	return ua.NewStringNodeID(a.ns.ID(), name)
}

// addMethodNode is a method without arguments below parent.
func (a *addressSpace) addMethodNode(parent *server.Node, name, browse string, handler func() ua.StatusCode) {
	nodeID := a.stringID(name)
	method := server.NewFolderNode(nodeID, browse)
	method.SetNodeClass(ua.NodeClassMethod)
	_ = method.SetAttribute(ua.AttributeIDExecutable, server.DataValueFromValue(true))
	_ = method.SetAttribute(ua.AttributeIDUserExecutable, server.DataValueFromValue(true))
	a.ns.AddNode(method)
	parent.AddRef(method, id.HasComponent, true)
	a.s.RegisterMethod(parent.ID(), nodeID, func(context.Context, *ua.NodeID, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, handler()
	})
}

// addFeatures builds what the contract creates in code.
func (a *addressSpace) addFeatures() error {
	if err := a.addHistory(); err != nil {
		return err
	}
	return a.addAlarms(a.stringID("Compatibility"))
}

// addHistory gives History.Temperature its five samples and creates History.Events
// with its seed (§17.1).
func (a *addressSpace) addHistory() error {
	hist := server.NewHistorian()
	a.s.SetHistorian(hist)

	temperature := a.stringID(historyTemperature)
	if a.s.Node(temperature) == nil {
		return fmt.Errorf("no node %s", historyTemperature)
	}
	hist.EnableNode(temperature, 100)
	for n := range 5 {
		at := historyBase.Add(time.Duration(n) * 5 * time.Second)
		hist.RecordValue(temperature, &ua.DataValue{
			EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
			Value:        ua.MustVariant(float64(20 + n)), SourceTimestamp: at, ServerTimestamp: at,
		})
	}

	notifier := a.stringID(historyEventsNode)
	folder := a.s.Node(a.stringID("History"))
	if folder == nil {
		return fmt.Errorf("no node History")
	}
	obj := server.NewFolderNode(notifier, historyEventsNode)
	a.ns.AddNode(obj)
	folder.AddRef(obj, id.Organizes, true)
	if typ := a.s.Node(ua.NewNumericNodeID(0, id.BaseObjectType)); typ != nil {
		obj.AddRef(typ, id.HasTypeDefinition, true)
	}
	seed := func() {
		hist.EnableEvents(notifier, 1000)
		for n := range 5 {
			hist.RecordEvent(notifier, seedEvent(notifier, n))
		}
	}
	a.addMethodNode(obj, historyReset, "ResetEvents", func() ua.StatusCode {
		seed()
		return ua.StatusOK
	})
	if err := a.s.EnableEventHistory(notifier, server.EventHistoryOptions{Writable: true}); err != nil {
		return err
	}
	seed()
	return nil
}

// seedEvent is event n of the table of docs/FIXTURES.md "History (events)".
func seedEvent(notifier *ua.NodeID, n int) *server.HistoricalEvent {
	at := historyBase.Add(time.Duration(n) * 5 * time.Second)
	eventType := uint32(id.BaseEventType)
	if n == 3 {
		eventType = id.SystemEventType
	}
	return &server.HistoricalEvent{Fields: map[string]*ua.Variant{
		"EventId":     ua.MustVariant([]byte("hist-evt-" + strconv.Itoa(n))),
		"EventType":   ua.MustVariant(ua.NewNumericNodeID(0, eventType)),
		"SourceNode":  ua.MustVariant(notifier),
		"SourceName":  ua.MustVariant(historyEventsNode),
		"Time":        ua.MustVariant(at),
		"ReceiveTime": ua.MustVariant(at),
		"Message":     ua.MustVariant(ua.NewLocalizedTextWithLocale("history-event-"+strconv.Itoa(n), "en")),
		"Severity":    ua.MustVariant(uint16(100 * (n + 1))),
	}}
}

// addAlarms creates the alarm fixture: an active, unacknowledged, confirmable
// AlarmConditionType on Alarms.Source, and the method that re-arms it.
func (a *addressSpace) addAlarms(compatibility *ua.NodeID) error {
	parent := a.s.Node(compatibility)
	if parent == nil {
		return fmt.Errorf("no folder for the alarms")
	}
	folder := server.NewFolderNode(a.stringID(alarmsFolder), alarmsFolder)
	a.ns.AddNode(folder)
	parent.AddRef(folder, id.Organizes, true)
	source := server.NewFolderNode(a.stringID(alarmsSource), alarmsSource)
	a.ns.AddNode(source)
	folder.AddRef(source, id.Organizes, true)

	cond, err := a.s.AddCondition(server.ConditionConfig{
		NodeID: a.stringID(alarmsCondition), Name: "InteropAlarm",
		Type:   ua.NewNumericNodeID(0, id.AlarmConditionType),
		Source: source.ID(), SourceName: alarmsSource, Severity: 500, Message: "interop-alarm",
		Confirmable: true,
	})
	if err != nil {
		return err
	}
	rearm := func() error {
		if !cond.State().Enabled {
			if err := cond.Enable(); err != nil {
				return err
			}
		}
		active, acked, confirmed := true, false, false
		severity, message := uint16(500), "interop-alarm"
		return cond.Update(server.ConditionUpdate{Active: &active, Acked: &acked, Confirmed: &confirmed, Severity: &severity, Message: &message})
	}
	a.addMethodNode(source, alarmsReset, "Reset", func() ua.StatusCode {
		if err := rearm(); err != nil {
			return ua.StatusBadInternalError
		}
		return ua.StatusOK
	})
	return cond.SetActive(true)
}

// emitEvents reports the BaseEvents of Events.Source, on it and on the Server object,
// until ctx ends (§1 event-subscribe).
func (a *addressSpace) emitEvents(ctx context.Context) error {
	source := a.stringID(eventsSource)
	node := a.s.Node(source)
	if node == nil {
		return fmt.Errorf("no node %s", eventsSource)
	}
	if err := node.SetAttribute(ua.AttributeIDEventNotifier, server.DataValueFromValue(uint8(ua.EventNotifierTypeSubscribeToEvents))); err != nil {
		return err
	}
	serverObject := ua.NewNumericNodeID(0, id.Server)
	go func() {
		ticker := time.NewTicker(eventIntervalMS * time.Millisecond)
		defer ticker.Stop()
		sequence := 0
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				sequence++
				event := &server.BaseEvent{
					EventID:    []byte(fmt.Sprintf("peer-event-%d", sequence)),
					EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
					SourceNode: source, SourceName: eventsSource, Time: now,
					Message: ua.NewLocalizedTextWithLocale("peer-event", "en"), Severity: 500,
				}
				_ = a.s.EmitBaseEvent(source, event)
				_ = a.s.EmitBaseEvent(serverObject, event)
			}
		}
	}()
	return nil
}
