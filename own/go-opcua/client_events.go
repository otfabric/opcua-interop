// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// operand is a SimpleAttributeOperand of the Value of a field of an event type.
func operand(eventType uint32, path ...string) *ua.SimpleAttributeOperand {
	names := make([]*ua.QualifiedName, len(path))
	for i, name := range path {
		names[i] = &ua.QualifiedName{Name: name}
	}
	return &ua.SimpleAttributeOperand{TypeDefinitionID: ua.NewNumericNodeID(0, eventType), BrowsePath: names, AttributeID: ua.AttributeIDValue}
}

// selectOperand is a --select path (§1 history-read-events): names separated by /,
// each `ns:Name` in another namespace.
func selectOperand(path string) (*ua.SimpleAttributeOperand, error) {
	var names []*ua.QualifiedName
	for _, part := range strings.Split(path, "/") {
		q := &ua.QualifiedName{Name: part}
		if ns, name, ok := strings.Cut(part, ":"); ok {
			n, err := strconv.ParseUint(ns, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("--select %q: %w", path, err)
			}
			q = &ua.QualifiedName{NamespaceIndex: uint16(n), Name: name}
		}
		names = append(names, q)
	}
	return &ua.SimpleAttributeOperand{TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType), BrowsePath: names, AttributeID: ua.AttributeIDValue}, nil
}

// whereClause is the WhereClause of --of-type and --min-severity: empty, one element,
// or an And in front of both, since element 0 is the root of a ContentFilter and an
// ElementOperand refers to a later element (§1 history-read-events, Part 4 §7.7.1).
func whereClause(ctx context.Context, c *opcua.Client, ofType string, minSeverity int) (*ua.ContentFilter, *outcome) {
	var elements []*ua.ContentFilterElement
	if ofType != "" {
		ref, err := parseNodeRef(ofType)
		if err != nil {
			res := inputError(err.Error())
			return nil, &res
		}
		nodeID, failed := resolve(ctx, c, ref)
		if failed != nil {
			return nil, failed
		}
		elements = append(elements, &ua.ContentFilterElement{
			FilterOperator: ua.FilterOperatorOfType,
			FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(nodeID)})},
		})
	}
	if minSeverity >= 0 {
		elements = append(elements, &ua.ContentFilterElement{
			FilterOperator: ua.FilterOperatorGreaterThanOrEqual,
			FilterOperands: []*ua.ExtensionObject{
				ua.NewExtensionObject(operand(id.BaseEventType, "Severity")),
				ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(uint16(minSeverity))}),
			},
		})
	}
	if len(elements) == 2 {
		elements = append([]*ua.ContentFilterElement{{
			FilterOperator: ua.FilterOperatorAnd,
			FilterOperands: []*ua.ExtensionObject{
				ua.NewExtensionObject(&ua.ElementOperand{Index: 1}),
				ua.NewExtensionObject(&ua.ElementOperand{Index: 2}),
			},
		}}, elements...)
	}
	return &ua.ContentFilter{Elements: elements}, nil
}

// eventItem is the monitored item of a notifier with an EventFilter.
func eventItem(nodeID *ua.NodeID, filter *ua.EventFilter, queue uint32) *ua.MonitoredItemCreateRequest {
	return &ua.MonitoredItemCreateRequest{
		ItemToMonitor:  &ua.ReadValueID{NodeID: nodeID, AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle: 1, QueueSize: queue, DiscardOldest: true, Filter: ua.NewExtensionObject(filter),
		},
	}
}

// eventField is one selected field of an event in a result (§4 event-subscribe).
func eventField(name string, v *ua.Variant) map[string]any {
	field := map[string]any{"name": name, "dataType": "Null", "builtInType": 0, "value": nil}
	if v != nil && v.Value() != nil {
		field["dataType"], field["builtInType"], field["value"] = typeName(uint32(v.Type())), int(v.Type()), encodeValue(v)
	}
	return field
}

func eventFields(names []string, values []*ua.Variant) []any {
	fields := make([]any, 0, len(values))
	for i, v := range values {
		if i < len(names) {
			fields = append(fields, eventField(names[i], v))
		}
	}
	return fields
}

// eventSubscribeNames are the SelectClauses of event-subscribe (§1).
var eventSubscribeNames = []string{"EventId", "EventType", "SourceName", "Message", "Severity", "Time"}

func eventSubscribeCommand(fs *flag.FlagSet) command {
	node := fs.String("node", "", "EventNotifier")
	count := fs.Int("events", 1, "events to collect")
	timeoutMS := fs.Int64("timeout-ms", 10000, "command timeout")
	publishing := fs.Int64("publishing-interval-ms", 500, "publishing interval")
	queue := fs.Uint("queue-size", 10, "queue size")
	ofType := fs.String("of-type", "", "OfType element")
	minSeverity := fs.Int("min-severity", -1, "Severity threshold")
	var ref nodeRef
	return command{
		validate: func() (err error) { ref, err = parseNodeRef(*node); return err },
		run: func(ctx context.Context, c *opcua.Client) outcome {
			nodeID, failed := resolve(ctx, c, ref)
			if failed != nil {
				return *failed
			}
			where, failed := whereClause(ctx, c, *ofType, *minSeverity)
			if failed != nil {
				return *failed
			}
			clauses := make([]*ua.SimpleAttributeOperand, len(eventSubscribeNames))
			for i, name := range eventSubscribeNames {
				clauses[i] = operand(id.BaseEventType, name)
			}
			notify := make(chan *opcua.PublishNotificationData, 64)
			sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Duration(*publishing) * time.Millisecond}, notify)
			if err != nil {
				return classify(err)
			}
			defer cancelSubscription(sub)
			resp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, eventItem(nodeID, &ua.EventFilter{SelectClauses: clauses, WhereClause: where}, uint32(*queue)))
			if err != nil {
				return classify(err)
			}
			result := map[string]any{
				"nodeId": nodeIDString(nodeID), "subscriptionId": sub.SubscriptionID,
				"revisedPublishingInterval": float64(sub.RevisedPublishingInterval / time.Millisecond),
				"monitoredItemStatusCode":   statusOf(resp.Results[0].StatusCode),
				"selectClauses":             eventSubscribeNames,
				"events":                    []any{},
			}
			if !isGood(resp.Results[0].StatusCode) {
				return serviceBad(resp.Results[0].StatusCode, []any{result})
			}
			events, res := collectEvents(notify, *count, time.Duration(*timeoutMS)*time.Millisecond)
			result["events"] = events
			res.results = []any{result}
			return res
		},
	}
}

func collectEvents(notify <-chan *opcua.PublishNotificationData, count int, timeout time.Duration) ([]any, outcome) {
	deadline := time.After(timeout)
	events := []any{}
	for len(events) < count {
		select {
		case msg := <-notify:
			if msg.Error != nil {
				return events, classify(msg.Error)
			}
			list, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			for _, ev := range list.Events {
				if len(events) < count {
					events = append(events, map[string]any{"sequenceNumber": len(events) + 1, "fields": eventFields(eventSubscribeNames, ev.EventFields)})
				}
			}
		case <-deadline:
			return events, failure(exitTimeout, "timeout", fmt.Sprintf("%d of %d events after %v", len(events), count, timeout), ua.StatusBadTimeout)
		}
	}
	return events, outcome{status: ua.StatusOK}
}

func cancelSubscription(sub *opcua.Subscription) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = sub.Cancel(ctx)
}

// conditionEntry is a condition in the result of `alarms` (§4), keys in this order.
// A field the event does not carry as the expected type is null.
type conditionEntry struct {
	ConditionID   string  `json:"conditionId"`
	EventID       string  `json:"eventId"`
	EventType     *string `json:"eventType"`
	SourceNode    *string `json:"sourceNode"`
	SourceName    *string `json:"sourceName"`
	ConditionName *string `json:"conditionName"`
	Time          *string `json:"time"`
	Message       *string `json:"message"`
	Severity      *uint16 `json:"severity"`
	Retain        *bool   `json:"retain"`
	Enabled       *bool   `json:"enabled"`
	Acked         *bool   `json:"acked"`
	Confirmed     *bool   `json:"confirmed"`
	Active        *bool   `json:"active"`
	Comment       *string `json:"comment"`

	eventBytes []byte
}

// alarmClauses are the SelectClauses of `alarms`, in the order of §1.
func alarmClauses() []*ua.SimpleAttributeOperand {
	conditionID := &ua.SimpleAttributeOperand{TypeDefinitionID: ua.NewNumericNodeID(0, id.ConditionType), AttributeID: ua.AttributeIDNodeID}
	return []*ua.SimpleAttributeOperand{
		operand(id.BaseEventType, "EventId"),
		operand(id.BaseEventType, "EventType"),
		operand(id.BaseEventType, "SourceNode"),
		operand(id.BaseEventType, "SourceName"),
		operand(id.BaseEventType, "Time"),
		operand(id.BaseEventType, "Message"),
		operand(id.BaseEventType, "Severity"),
		operand(id.ConditionType, "ConditionName"),
		operand(id.ConditionType, "BranchId"),
		operand(id.ConditionType, "Retain"),
		operand(id.ConditionType, "EnabledState", "Id"),
		operand(id.ConditionType, "Comment"),
		operand(id.AcknowledgeableConditionType, "AckedState", "Id"),
		operand(id.AcknowledgeableConditionType, "ConfirmedState", "Id"),
		operand(id.AlarmConditionType, "ActiveState", "Id"),
		conditionID,
	}
}

func fieldString(v *ua.Variant) *string {
	if v == nil {
		return nil
	}
	var s string
	switch x := v.Value().(type) {
	case string:
		s = x
	case *ua.LocalizedText:
		if x == nil {
			return nil
		}
		s = x.Text
	case *ua.NodeID:
		s = nodeIDString(x)
	case time.Time:
		if x.IsZero() {
			return nil
		}
		s = timeString(x)
	default:
		return nil
	}
	return &s
}

func fieldBool(v *ua.Variant) *bool {
	if v != nil {
		if b, ok := v.Value().(bool); ok {
			return &b
		}
	}
	return nil
}

// parseCondition is the entry of an event with a ConditionId, or nil.
func parseCondition(fields []*ua.Variant) *conditionEntry {
	if len(fields) < 16 {
		return nil
	}
	conditionID, ok := fields[15].Value().(*ua.NodeID)
	if !ok || conditionID == nil {
		return nil
	}
	e := &conditionEntry{
		ConditionID: nodeIDString(conditionID), EventType: fieldString(fields[1]), SourceNode: fieldString(fields[2]),
		SourceName: fieldString(fields[3]), Time: fieldString(fields[4]), Message: fieldString(fields[5]),
		ConditionName: fieldString(fields[7]), Retain: fieldBool(fields[9]), Enabled: fieldBool(fields[10]),
		Comment: fieldString(fields[11]), Acked: fieldBool(fields[12]), Confirmed: fieldBool(fields[13]), Active: fieldBool(fields[14]),
	}
	if b, ok := fields[0].Value().([]byte); ok {
		e.eventBytes = b
		e.EventID, _ = encodeAny(b).(string)
	}
	if severity, ok := fields[6].Value().(uint16); ok {
		e.Severity = &severity
	}
	return e
}

// alarmRun is one `alarms` command: its subscription and the condition events seen.
type alarmRun struct {
	c        *opcua.Client
	notify   chan *opcua.PublishNotificationData
	deadline <-chan time.Time
	latest   map[string]*conditionEntry
}

var errNoEvent = errors.New("the event did not arrive in time")

// next returns the next event of a condition, or nil for one without a ConditionId,
// with its type.
func (r *alarmRun) next() (*conditionEntry, *ua.NodeID, error) {
	for {
		select {
		case msg := <-r.notify:
			if msg.Error != nil {
				return nil, nil, msg.Error
			}
			list, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || len(list.Events) == 0 {
				continue
			}
			ev := list.Events[0]
			// A list with several events is handed out one by one.
			if len(list.Events) > 1 {
				rest := &ua.EventNotificationList{Events: list.Events[1:]}
				r.notify <- &opcua.PublishNotificationData{Value: rest}
			}
			var eventType *ua.NodeID
			if len(ev.EventFields) > 1 {
				eventType, _ = ev.EventFields[1].Value().(*ua.NodeID)
			}
			entry := parseCondition(ev.EventFields)
			if entry != nil {
				r.latest[entry.ConditionID] = entry
			}
			return entry, eventType, nil
		case <-r.deadline:
			return nil, nil, errNoEvent
		}
	}
}

// waitFor returns the next event of the condition that matches.
func (r *alarmRun) waitFor(conditionID string, match func(*conditionEntry) bool) (*conditionEntry, error) {
	for {
		entry, _, err := r.next()
		if err != nil {
			return nil, err
		}
		if entry != nil && entry.ConditionID == conditionID && match(entry) {
			return entry, nil
		}
	}
}

// action calls a method of the condition with EventId and comment (§1 step 5).
func (r *alarmRun) action(ctx context.Context, target *conditionEntry, method uint32, eventID []byte, comment string) (ua.StatusCode, error) {
	ref, err := parseNodeRef(target.ConditionID)
	if err != nil {
		return ua.StatusBad, err
	}
	res, err := r.c.Call(ctx, &ua.CallMethodRequest{
		ObjectID: ref.id, MethodID: ua.NewNumericNodeID(0, method),
		InputArguments: []*ua.Variant{ua.MustVariant(eventID), ua.MustVariant(ua.NewLocalizedTextWithLocale(comment, "en"))},
	})
	if err != nil {
		return ua.StatusBad, err
	}
	return res.StatusCode, nil
}

// actionResult is `acknowledge`, `confirm` or `addComment` of the result.
type actionResult struct {
	StatusCode statusJSON      `json:"statusCode"`
	Event      *conditionEntry `json:"event"`
	Repeat     *statusJSON     `json:"repeatStatusCode,omitempty"`
}

// perform calls one action and waits for its event. It says the status the command
// ends with: OK while nothing failed.
func (r *alarmRun) perform(ctx context.Context, target *conditionEntry, method uint32, comment string, match func(*conditionEntry) bool) (*actionResult, ua.StatusCode) {
	latest := r.latest[target.ConditionID]
	status, err := r.action(ctx, target, method, latest.eventBytes, comment)
	if err != nil {
		res := classify(err)
		return &actionResult{StatusCode: statusOf(res.status)}, res.status
	}
	result := &actionResult{StatusCode: statusOf(status)}
	if !isGood(status) {
		return result, status
	}
	event, err := r.waitFor(target.ConditionID, match)
	if err != nil {
		return result, ua.StatusBadTimeout
	}
	result.Event = event
	return result, ua.StatusOK
}

func alarmsCommand(fs *flag.FlagSet) command {
	node := fs.String("node", "i=2253", "EventNotifier")
	name := fs.String("condition-name", "", "ConditionName of the target")
	acknowledge := fs.Bool("acknowledge", false, "Acknowledge the target")
	confirm := fs.Bool("confirm", false, "Confirm the target")
	addComment := fs.Bool("add-comment", false, "AddComment on the target")
	comment := fs.String("comment", "interop-comment", "comment of the methods")
	timeoutMS := fs.Int64("timeout-ms", 15000, "command budget")
	publishing := fs.Int64("publishing-interval-ms", 200, "publishing interval")
	var ref nodeRef
	return command{
		validate: func() (err error) { ref, err = parseNodeRef(*node); return err },
		run: func(_ context.Context, c *opcua.Client) outcome {
			timeout := time.Duration(*timeoutMS) * time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			nodeID, failed := resolve(ctx, c, ref)
			if failed != nil {
				return *failed
			}
			r := &alarmRun{c: c, notify: make(chan *opcua.PublishNotificationData, 4096), deadline: time.After(timeout), latest: map[string]*conditionEntry{}}
			sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Duration(*publishing) * time.Millisecond}, r.notify)
			if err != nil {
				return classify(err)
			}
			defer cancelSubscription(sub)
			item := eventItem(nodeID, &ua.EventFilter{SelectClauses: alarmClauses(), WhereClause: &ua.ContentFilter{}}, 1000)
			resp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, item)
			if err != nil {
				return classify(err)
			}
			result := map[string]any{
				"nodeId": nodeIDString(nodeID), "subscriptionId": sub.SubscriptionID,
				"monitoredItemStatusCode": statusOf(resp.Results[0].StatusCode),
				"refresh":                 map[string]any{"statusCode": statusOf(resp.Results[0].StatusCode), "startSeen": false, "endSeen": false},
				"conditions":              []any{}, "target": nil, "acknowledge": nil, "confirm": nil, "addComment": nil,
			}
			results := []any{result}
			if !isGood(resp.Results[0].StatusCode) {
				return serviceBad(resp.Results[0].StatusCode, results)
			}
			return r.run(ctx, c, sub, result, results, alarmActions{*name, *comment, *acknowledge, *confirm, *addComment})
		},
	}
}

// alarmActions is what `alarms` was asked to do.
type alarmActions struct {
	name, comment                string
	acknowledge, confirm, addCom bool
}

// refresh is steps 2 and 3 of §1: ConditionRefresh, then the conditions up to the
// RefreshEnd.
func (r *alarmRun) refresh(ctx context.Context, c *opcua.Client, sub *opcua.Subscription, result map[string]any) ([]*conditionEntry, ua.StatusCode) {
	status := ua.StatusOK
	if err := c.ConditionRefresh(ctx, sub.SubscriptionID); err != nil {
		status = classify(err).status
	}
	refresh := map[string]any{"statusCode": statusOf(status), "startSeen": false, "endSeen": false}
	result["refresh"] = refresh
	if !isGood(status) {
		return nil, status
	}
	var conditions []*conditionEntry
	byID := map[string]int{}
	for {
		entry, eventType, err := r.next()
		if err != nil {
			return conditions, ua.StatusBadTimeout
		}
		if eventType != nil && eventType.Namespace() == 0 {
			switch eventType.IntID() {
			case id.RefreshStartEventType:
				refresh["startSeen"] = true
				continue
			case id.RefreshEndEventType:
				refresh["endSeen"] = true
				return conditions, ua.StatusOK
			}
		}
		if entry == nil {
			continue
		}
		if i, ok := byID[entry.ConditionID]; ok {
			conditions[i] = entry
		} else {
			byID[entry.ConditionID] = len(conditions)
			conditions = append(conditions, entry)
		}
	}
}

// run is everything after the event monitored item exists.
func (r *alarmRun) run(ctx context.Context, c *opcua.Client, sub *opcua.Subscription, result map[string]any, results []any, do alarmActions) outcome {
	conditions, status := r.refresh(ctx, c, sub, result)
	entries := make([]any, len(conditions))
	for i, entry := range conditions {
		entries[i] = entry
	}
	result["conditions"] = entries
	if !isGood(status) {
		return r.failed(status, results)
	}
	var target *conditionEntry
	for _, entry := range conditions {
		if (do.name != "" && entry.ConditionName != nil && *entry.ConditionName == do.name) ||
			(do.name == "" && entry.Retain != nil && *entry.Retain) {
			target = entry
			break
		}
	}
	if target != nil {
		result["target"] = target
	}
	if !do.acknowledge && !do.confirm && !do.addCom {
		return outcome{status: ua.StatusOK, results: results}
	}
	if target == nil {
		return serviceBad(ua.StatusBadNodeIDUnknown, results)
	}

	if do.acknowledge {
		stale := r.latest[target.ConditionID].eventBytes
		res, status := r.perform(ctx, target, 9111, do.comment, func(e *conditionEntry) bool { return e.Acked != nil && *e.Acked })
		result["acknowledge"] = res
		if !isGood(status) {
			return r.failed(status, results)
		}
		// The EventId is stale now: what the server says is reported, never judged.
		if repeat, err := r.action(ctx, target, 9111, stale, do.comment); err == nil {
			s := statusOf(repeat)
			res.Repeat = &s
		}
	}
	if do.confirm {
		res, status := r.perform(ctx, target, 9113, do.comment, func(e *conditionEntry) bool { return e.Confirmed != nil && *e.Confirmed })
		result["confirm"] = res
		if !isGood(status) {
			return r.failed(status, results)
		}
	}
	if do.addCom {
		res, status := r.perform(ctx, target, 9029, do.comment, func(e *conditionEntry) bool { return e.Comment != nil && *e.Comment == do.comment })
		result["addComment"] = res
		if !isGood(status) {
			return r.failed(status, results)
		}
	}
	return outcome{status: ua.StatusOK, results: results}
}

func (r *alarmRun) failed(status ua.StatusCode, results []any) outcome {
	if status == ua.StatusBadTimeout {
		res := failure(exitTimeout, "timeout", "no event in time", status)
		res.results = results
		return res
	}
	return serviceBad(status, results)
}
