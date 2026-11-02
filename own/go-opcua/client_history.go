// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// historyTime is a --start or --end. Without one, the null DateTime.
func historyTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}

// continuationJSON is a continuation point in a result: Base64 or null.
func continuationJSON(cp []byte) any {
	if len(cp) == 0 {
		return nil
	}
	return base64.StdEncoding.EncodeToString(cp)
}

// historyPages is one HistoryRead of a node, whatever its details are.
type historyReader struct {
	c       *opcua.Client
	details any
	nodeID  *ua.NodeID
	read    func(ctx context.Context, nodes []*ua.HistoryReadValueID) (*ua.HistoryReadResponse, error)
	items   func(r *ua.HistoryReadResult) ([]any, string)
	// itemsKey names the items in the result: values or events.
	itemsKey string
}

// page reads one page. A fault of the service is the error; the status of the node
// is in the result.
func (h *historyReader) page(ctx context.Context, cp []byte) (*ua.HistoryReadResult, error) {
	resp, err := h.read(ctx, []*ua.HistoryReadValueID{{NodeID: h.nodeID, ContinuationPoint: cp}})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) != 1 || resp.Results[0] == nil {
		return nil, ua.StatusBadUnknownResponse
	}
	return resp.Results[0], nil
}

// nodeResult is the result of one node without a scenario.
func (h *historyReader) nodeResult(ctx context.Context, cp []byte, release bool) (map[string]any, ua.StatusCode, error) {
	result := map[string]any{"nodeId": nodeIDString(h.nodeID), "continuationPoint": nil, h.itemsKey: []any{}}
	if release {
		statuses, err := h.c.HistoryReleaseContinuationPoints(ctx, h.details, &ua.HistoryReadValueID{NodeID: h.nodeID, ContinuationPoint: cp})
		if err != nil {
			return nil, ua.StatusOK, err
		}
		result["statusCode"] = statusOf(statuses[0])
		return result, statuses[0], nil
	}
	r, err := h.page(ctx, cp)
	if err != nil {
		return nil, ua.StatusOK, err
	}
	items, errText := h.items(r)
	if errText != "" {
		return nil, ua.StatusOK, errors.New(errText)
	}
	result["statusCode"] = statusOf(r.StatusCode)
	result["continuationPoint"] = continuationJSON(r.ContinuationPoint)
	result[h.itemsKey] = items
	return result, r.StatusCode, nil
}

// continueScenario pages to the end, releases the last continuation point the server
// returned and sends it once more (§1, --scenario continue).
func (h *historyReader) continueScenario(ctx context.Context, maxPages int) (map[string]any, ua.StatusCode, error) {
	pages := []any{}
	all := []any{}
	var cp, last []byte
	status := ua.StatusOK
	for n := 0; n < maxPages; n++ {
		r, err := h.page(ctx, cp)
		if err != nil {
			return nil, ua.StatusOK, err
		}
		items, errText := h.items(r)
		if errText != "" {
			return nil, ua.StatusOK, errors.New(errText)
		}
		status = r.StatusCode
		pages = append(pages, map[string]any{"statusCode": statusOf(r.StatusCode), "continuationPoint": continuationJSON(r.ContinuationPoint), h.itemsKey: items})
		all = append(all, items...)
		cp = r.ContinuationPoint
		if len(cp) == 0 {
			break
		}
		last = cp
	}
	result := map[string]any{
		"nodeId": nodeIDString(h.nodeID), "statusCode": statusOf(status), "continuationPoint": continuationJSON(cp),
		h.itemsKey: all, "scenario": "continue", "pages": pages, "releaseStatusCode": nil, "reuseAfterReleaseStatusCode": nil,
	}
	if h.itemsKey == "values" { // raw: the pages are the result (§ history-read flags)
		delete(result, "statusCode")
		delete(result, "continuationPoint")
		delete(result, h.itemsKey)
	}
	if len(last) == 0 {
		return result, status, nil
	}
	statuses, err := h.c.HistoryReleaseContinuationPoints(ctx, h.details, &ua.HistoryReadValueID{NodeID: h.nodeID, ContinuationPoint: last})
	if err != nil {
		return nil, ua.StatusOK, err
	}
	result["releaseStatusCode"] = statusOf(statuses[0])
	r, err := h.page(ctx, last)
	if err != nil {
		return nil, ua.StatusOK, err
	}
	result["reuseAfterReleaseStatusCode"] = statusOf(r.StatusCode)
	return result, status, nil
}

// historyEnd is the outcome of a read: 4 for a Bad node, and the results either way.
func historyEnd(bad ua.StatusCode, results []any) outcome {
	if !isGood(bad) && uint32(bad)>>30 != 1 {
		return serviceBad(bad, results)
	}
	return outcome{status: ua.StatusOK, results: results}
}

// dataValues are the items of a raw read (§4 history-read).
func dataValues(r *ua.HistoryReadResult) ([]any, string) {
	values := []any{}
	if r.HistoryData == nil || r.HistoryData.Value == nil {
		return values, ""
	}
	data, ok := r.HistoryData.Value.(*ua.HistoryData)
	if !ok {
		return nil, fmt.Sprintf("HistoryData of type %T", r.HistoryData.Value)
	}
	for _, dv := range data.DataValues {
		v := map[string]any{"value": encodeValue(dv.Value), "statusCode": statusOf(dv.Status)}
		if dv.Value != nil && dv.Value.Value() != nil {
			v["dataType"], v["builtInType"] = typeName(uint32(dv.Value.Type())), int(dv.Value.Type())
		}
		if !dv.SourceTimestamp.IsZero() {
			v["sourceTimestamp"] = timeString(dv.SourceTimestamp)
		}
		if !dv.ServerTimestamp.IsZero() {
			v["serverTimestamp"] = timeString(dv.ServerTimestamp)
		}
		values = append(values, v)
	}
	return values, ""
}

func historyReadCommand(fs *flag.FlagSet) command {
	node := fs.String("node", "", "node to read")
	start := fs.String("start", "", "start time")
	end := fs.String("end", "", "end time")
	numValues := fs.Uint("num-values", 0, "NumValuesPerNode")
	continuation := fs.String("continuation-point", "", "continuation point")
	release := fs.Bool("release-continuation-point", false, "release it instead of reading")
	bounds := fs.Bool("return-bounds", false, "ReturnBounds")
	timestamps := fs.String("timestamps", "Both", "TimestampsToReturn")
	scenario := fs.String("scenario", "", "continue")
	var ref nodeRef
	var cp []byte
	var details *ua.ReadRawModifiedDetails
	return command{
		validate: func() (err error) {
			// HistoryReadRawModified of go-opcua always asks for both.
			if *timestamps != "Both" {
				return errors.New("--timestamps " + *timestamps + " is not provided by this image: go-opcua always requests Both")
			}
			if *scenario != "" && *scenario != "continue" {
				return errors.New("--scenario: " + *scenario)
			}
			if *scenario == "continue" && *numValues == 0 {
				*numValues = 2
			}
			details = &ua.ReadRawModifiedDetails{NumValuesPerNode: uint32(*numValues), ReturnBounds: *bounds}
			if details.StartTime, err = historyTime(*start); err != nil {
				return fmt.Errorf("--start: %w", err)
			}
			if details.EndTime, err = historyTime(*end); err != nil {
				return fmt.Errorf("--end: %w", err)
			}
			if *continuation != "" { // none is null on the wire, not empty: node-opcua tells them apart
				if cp, err = base64.StdEncoding.DecodeString(*continuation); err != nil {
					return fmt.Errorf("--continuation-point: %w", err)
				}
			}
			ref, err = parseNodeRef(*node)
			return err
		},
		run: func(ctx context.Context, c *opcua.Client) outcome {
			nodeID, failed := resolve(ctx, c, ref)
			if failed != nil {
				return *failed
			}
			h := &historyReader{c: c, details: details, nodeID: nodeID, items: dataValues, itemsKey: "values",
				read: func(ctx context.Context, nodes []*ua.HistoryReadValueID) (*ua.HistoryReadResponse, error) {
					return c.HistoryReadRawModified(ctx, nodes, details)
				}}
			var result map[string]any
			var status ua.StatusCode
			var err error
			if *scenario == "continue" {
				result, status, err = h.continueScenario(ctx, 64)
			} else {
				result, status, err = h.nodeResult(ctx, cp, *release)
			}
			if err != nil {
				return classify(err)
			}
			return historyEnd(status, []any{result})
		},
	}
}

// defaultEventSelect are the SelectClauses of history-read-events without --select.
var defaultEventSelect = []string{"EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"}

// selectOperands turns --select paths into operands.
func selectOperands(paths []string) ([]*ua.SimpleAttributeOperand, error) {
	clauses := make([]*ua.SimpleAttributeOperand, len(paths))
	for i, path := range paths {
		clause, err := selectOperand(path)
		if err != nil {
			return nil, err
		}
		clauses[i] = clause
	}
	return clauses, nil
}

func historyReadEventsCommand(fs *flag.FlagSet) command {
	var nodes, selects repeated
	fs.Var(&nodes, "node", "event notifier, repeatable")
	fs.Var(&selects, "select", "SelectClause, repeatable")
	start := fs.String("start", "", "start time")
	end := fs.String("end", "", "end time")
	numValues := fs.Uint("num-values", 0, "NumValuesPerNode")
	ofType := fs.String("of-type", "", "OfType element")
	minSeverity := fs.Int("min-severity", -1, "Severity threshold")
	continuation := fs.String("continuation-point", "", "continuation point")
	release := fs.Bool("release-continuation-point", false, "release it instead of reading")
	_ = fs.String("timestamps", "both", "TimestampsToReturn: Part 11 ignores it for events, and go-opcua sends Both")
	scenario := fs.String("scenario", "", "continue")
	maxPages := fs.Int("max-pages", 8, "most requests of the scenario")
	var refs []nodeRef
	var cp []byte
	details := &ua.ReadEventDetails{}
	var clauses []*ua.SimpleAttributeOperand
	return command{
		validate: func() (err error) {
			if len(selects) == 0 {
				selects = defaultEventSelect
			}
			if clauses, err = selectOperands(selects); err != nil {
				return err
			}
			if *scenario != "" && *scenario != "continue" {
				return errors.New("--scenario: " + *scenario)
			}
			details.NumValuesPerNode = uint32(*numValues)
			if details.StartTime, err = historyTime(*start); err != nil {
				return fmt.Errorf("--start: %w", err)
			}
			if details.EndTime, err = historyTime(*end); err != nil {
				return fmt.Errorf("--end: %w", err)
			}
			if *continuation != "" { // none is null on the wire, not empty: node-opcua tells them apart
				if cp, err = base64.StdEncoding.DecodeString(*continuation); err != nil {
					return fmt.Errorf("--continuation-point: %w", err)
				}
			}
			if *release && len(cp) == 0 {
				return errors.New("--release-continuation-point needs --continuation-point")
			}
			if len(cp) > 0 && len(nodes) != 1 {
				return errors.New("--continuation-point needs one --node")
			}
			refs, err = parseRefs(nodes)
			return err
		},
		run: func(ctx context.Context, c *opcua.Client) outcome {
			where, failed := whereClause(ctx, c, *ofType, *minSeverity)
			if failed != nil {
				return *failed
			}
			details.Filter = &ua.EventFilter{SelectClauses: clauses, WhereClause: where}
			ids, failed := resolveAll(ctx, c, refs)
			if failed != nil {
				return *failed
			}
			events := func(r *ua.HistoryReadResult) ([]any, string) { return historyEvents(selects, r) }
			read := func(ctx context.Context, nodes []*ua.HistoryReadValueID) (*ua.HistoryReadResponse, error) {
				return c.HistoryReadEvent(ctx, nodes, details)
			}
			results := make([]any, 0, len(ids))
			bad := ua.StatusOK
			for _, nodeID := range ids {
				h := &historyReader{c: c, details: details, nodeID: nodeID, read: read, items: events, itemsKey: "events"}
				var result map[string]any
				var status ua.StatusCode
				var err error
				if *scenario == "continue" {
					result, status, err = h.continueScenario(ctx, *maxPages)
				} else {
					result, status, err = h.nodeResult(ctx, cp, *release)
				}
				if err != nil {
					return classify(err)
				}
				result["selectClauses"] = selects
				results = append(results, result)
				if bad == ua.StatusOK && !isGood(status) && uint32(status)>>30 != 1 {
					bad = status
				}
			}
			return historyEnd(bad, results)
		},
	}
}

// historyEvents are the items of an event read (§4 history-read-events).
func historyEvents(names []string, r *ua.HistoryReadResult) ([]any, string) {
	events := []any{}
	if r.HistoryData == nil || r.HistoryData.Value == nil {
		return events, ""
	}
	data, ok := r.HistoryData.Value.(*ua.HistoryEvent)
	if !ok {
		return nil, fmt.Sprintf("HistoryData of type %T", r.HistoryData.Value)
	}
	for _, ev := range data.Events {
		events = append(events, map[string]any{"fields": eventFields(names, ev.EventFields)})
	}
	return events, ""
}

// orderedKeys are the keys of a JSON object in the order of the document, for the
// default SelectClauses of history-update-events.
func orderedKeys(doc string) ([]string, error) {
	dec := json.NewDecoder(strings.NewReader(doc))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("--event: not a JSON object: %q", doc)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// eventValue is a field of --event (§1 history-update-events) as a Variant.
func eventValue(ctx context.Context, c *opcua.Client, raw json.RawMessage) (*ua.Variant, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	switch x := v.(type) {
	case string:
		return ua.NewVariant(x)
	case bool:
		return ua.NewVariant(x)
	case json.Number:
		if n, err := strconv.ParseInt(x.String(), 10, 32); err == nil {
			return ua.NewVariant(int32(n))
		}
		f, err := x.Float64()
		if err != nil {
			return nil, err
		}
		return ua.NewVariant(f)
	case map[string]any:
		if typ, ok := x["type"].(string); ok {
			return typedEventValue(ctx, c, typ, x["value"])
		}
		locale, _ := x["locale"].(string)
		text, _ := x["text"].(string)
		return ua.NewVariant(ua.NewLocalizedTextWithLocale(text, locale))
	}
	return nil, fmt.Errorf("--event: cannot read the value %s", raw)
}

// typedEventValue is a {"type", "value"} field.
func typedEventValue(ctx context.Context, c *opcua.Client, typ string, value any) (*ua.Variant, error) {
	switch typ {
	case "NodeId":
		s, _ := value.(string)
		ref, err := parseNodeRef(s)
		if err != nil {
			return nil, err
		}
		nodeID, failed := resolve(ctx, c, ref)
		if failed != nil {
			return nil, errors.New(failed.err.Message)
		}
		return ua.NewVariant(nodeID)
	case "LocalizedText":
		switch x := value.(type) {
		case string:
			return ua.NewVariant(ua.NewLocalizedText(x))
		case map[string]any:
			locale, _ := x["locale"].(string)
			text, _ := x["text"].(string)
			return ua.NewVariant(ua.NewLocalizedTextWithLocale(text, locale))
		}
	case "QualifiedName":
		if x, ok := value.(map[string]any); ok {
			ns, _ := x["ns"].(json.Number)
			name, _ := x["name"].(string)
			value = ns.String() + ":" + name
		}
	case "StatusCode":
		if x, ok := value.(map[string]any); ok {
			value = x["code"]
		}
	}
	parsed, err := parseLiteral(typ, fmt.Sprint(value))
	if err != nil {
		return nil, fmt.Errorf("--event: %s: %w", typ, err)
	}
	return ua.NewVariant(parsed)
}

// eventData is the UpdateEventDetails content of the --event documents. The fields
// are in --select order; a path an event does not have is a null Variant.
func eventData(ctx context.Context, c *opcua.Client, selects []string, events []string) ([]*ua.HistoryEventFieldList, *outcome) {
	lists := make([]*ua.HistoryEventFieldList, len(events))
	for i, doc := range events {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(doc), &fields); err != nil {
			res := inputError("--event: " + err.Error())
			return nil, &res
		}
		values := make([]*ua.Variant, len(selects))
		for j, path := range selects {
			values[j] = ua.MustVariant(nil)
			raw, ok := fields[path]
			if !ok {
				continue
			}
			v, err := eventValue(ctx, c, raw)
			if err != nil {
				res := inputError(err.Error())
				return nil, &res
			}
			values[j] = v
		}
		lists[i] = &ua.HistoryEventFieldList{EventFields: values}
	}
	return lists, nil
}

var performTypes = map[string]ua.PerformUpdateType{
	"insert": ua.PerformUpdateTypeInsert, "replace": ua.PerformUpdateTypeReplace, "update": ua.PerformUpdateTypeUpdate,
}

func historyUpdateEventsCommand(fs *flag.FlagSet) command {
	node := fs.String("node", "", "historizing notifier")
	perform := fs.String("perform", "", "insert, replace, update or delete")
	var selects, events, eventIDs repeated
	fs.Var(&selects, "select", "SelectClause, repeatable")
	fs.Var(&events, "event", "EventData entry, repeatable")
	fs.Var(&eventIDs, "event-id", "EventId, repeatable")
	var ref nodeRef
	var clauses []*ua.SimpleAttributeOperand
	var ids [][]byte
	return command{
		validate: func() (err error) {
			if ref, err = parseNodeRef(*node); err != nil {
				return err
			}
			if *perform == "delete" {
				for _, s := range eventIDs {
					b, err := base64.StdEncoding.DecodeString(s)
					if err != nil {
						return fmt.Errorf("--event-id: %w", err)
					}
					ids = append(ids, b)
				}
				return nil
			}
			if _, ok := performTypes[*perform]; !ok {
				return errors.New("--perform: " + *perform)
			}
			for _, doc := range events {
				keys, err := orderedKeys(doc)
				if err != nil {
					return err
				}
				for _, key := range keys {
					if !containsPath(selects, key) {
						if !isDefaultSelect(fs) {
							return fmt.Errorf("--event: %s is not a --select path", key)
						}
						selects = append(selects, key)
					}
				}
			}
			clauses, err = selectOperands(selects)
			return err
		},
		run: func(ctx context.Context, c *opcua.Client) outcome {
			nodeID, failed := resolve(ctx, c, ref)
			if failed != nil {
				return *failed
			}
			var resp *ua.HistoryUpdateResponse
			var err error
			name := "Delete"
			if *perform == "delete" {
				resp, err = c.HistoryDeleteEvents(ctx, &ua.DeleteEventDetails{NodeID: nodeID, EventIDs: ids})
			} else {
				name = strings.ToUpper((*perform)[:1]) + (*perform)[1:]
				data, failed := eventData(ctx, c, selects, events)
				if failed != nil {
					return *failed
				}
				resp, err = c.HistoryUpdateEvents(ctx, &ua.UpdateEventDetails{
					NodeID: nodeID, PerformInsertReplace: performTypes[*perform],
					Filter: &ua.EventFilter{SelectClauses: clauses, WhereClause: &ua.ContentFilter{}}, EventData: data,
				})
			}
			if err != nil {
				return classify(err)
			}
			if len(resp.Results) != 1 || resp.Results[0] == nil {
				return failure(exitInternal, "internal", "no result for the update", ua.StatusBadUnexpectedError)
			}
			r := resp.Results[0]
			operations := make([]any, len(r.OperationResults))
			for i, status := range r.OperationResults {
				operations[i] = statusOf(status)
			}
			results := []any{map[string]any{"nodeId": nodeIDString(nodeID), "performUpdateType": name, "statusCode": statusOf(r.StatusCode), "operationResults": operations}}
			return historyEnd(r.StatusCode, results)
		},
	}
}

func containsPath(paths []string, path string) bool {
	for _, p := range paths {
		if p == path {
			return true
		}
	}
	return false
}

// isDefaultSelect says that --select was not given: the paths come from the events.
func isDefaultSelect(fs *flag.FlagSet) bool {
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == "select" })
	return !given
}
