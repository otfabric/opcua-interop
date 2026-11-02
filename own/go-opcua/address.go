// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// addressSpace builds the fixture's nodes. Everything in the fixture exists, but
// only what print-capabilities declares has behaviour: Events.Source, for example,
// is an object that emits nothing.
type addressSpace struct {
	s   *server.Server
	ns  *server.NodeNameSpace
	uri string
	// values are the current values of the nodes with a behaviour.
	mu     sync.Mutex
	values map[string]*ua.DataValue
}

// nodeID resolves a fixture NodeId: nsu= of the model namespace, or namespace 0.
func (a *addressSpace) nodeID(s string) (*ua.NodeID, error) {
	if rest, ok := strings.CutPrefix(s, "nsu="+a.uri+";"); ok {
		return ua.ParseNodeID(fmt.Sprintf("ns=%d;%s", a.ns.ID(), rest))
	}
	return ua.ParseNodeID(s)
}

func (a *addressSpace) build(fx *fixture) error {
	for i := range fx.Nodes {
		if err := a.addNode(fx, &fx.Nodes[i]); err != nil {
			return fmt.Errorf("node %s: %w", fx.Nodes[i].NodeID, err)
		}
	}
	return nil
}

func (a *addressSpace) addNode(fx *fixture, n *fixtureNode) error {
	nodeID, err := a.nodeID(n.NodeID)
	if err != nil {
		return err
	}
	_, name, ok := strings.Cut(n.BrowseName, ":")
	if !ok {
		name = n.BrowseName
	}

	var node *server.Node
	switch n.NodeClass {
	case "Object":
		node = server.NewFolderNode(nodeID, name)
	case "Method":
		node = server.NewFolderNode(nodeID, name)
		node.SetNodeClass(ua.NodeClassMethod)
		_ = node.SetAttribute(ua.AttributeIDExecutable, server.DataValueFromValue(true))
		_ = node.SetAttribute(ua.AttributeIDUserExecutable, server.DataValueFromValue(true))
	case "Variable":
		if node, err = a.newVariable(fx, nodeID, name, n); err != nil {
			return err
		}
	default:
		return errors.New("unknown node class " + n.NodeClass)
	}
	if n.DisplayName != "" {
		node.SetDisplayName(n.DisplayName, "en")
	}
	node.SetDescription(n.Description, "en")
	a.ns.AddNode(node)

	parentID, err := a.nodeID(n.ParentNodeID)
	if err != nil {
		return err
	}
	parent := a.s.Node(parentID)
	if parent == nil {
		return errors.New("no parent node " + n.ParentNodeID)
	}
	var refType server.RefType = server.RefTypeIDOrganizes
	if n.ReferenceType == "HasComponent" {
		refType = server.RefTypeIDHasComponent
	}
	parent.AddRef(node, refType, true)
	if n.TypeDefinition != "" {
		typeID, err := a.nodeID(n.TypeDefinition)
		if err != nil {
			return err
		}
		if typ := a.s.Node(typeID); typ != nil {
			node.AddRef(typ, id.HasTypeDefinition, true)
		}
	}
	if n.EURange != nil {
		a.addEURange(node, n.EURange)
	}
	if n.NodeClass == "Method" {
		a.addMethod(parentID, nodeID, node, n)
	}
	return nil
}

func (a *addressSpace) newVariable(fx *fixture, nodeID *ua.NodeID, name string, n *fixtureNode) (*server.Node, error) {
	var value any
	var err error
	key := nodeID.StringID()
	switch {
	case key == "Diagnostics.AdapterName":
		value = adapterName
	case key == "Diagnostics.StackVersion":
		value = upstreamVersion
	case key == "Diagnostics.FixtureId":
		value = fx.ID
	case key == "DataValues.GoodWithTimestamps":
		v, parseErr := initialValue(n)
		if parseErr != nil {
			return nil, parseErr
		}
		value = func() *ua.DataValue {
			now := time.Now()
			return &ua.DataValue{
				EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
				Value:        ua.MustVariant(v), SourceTimestamp: now, ServerTimestamp: now,
			}
		}
	default:
		if value, err = initialValue(n); err != nil {
			return nil, err
		}
	}
	if a.hasBehavior(fx, n.NodeID) {
		initial := server.DataValueFromValue(value)
		a.setValue(key, initial)
		value = func() *ua.DataValue { return a.value(key) }
	}
	node := server.NewVariableNode(nodeID, name, value)
	set := func(attr ua.AttributeID, v any) error { return node.SetAttribute(attr, server.DataValueFromValue(v)) }
	var access byte
	for _, level := range n.AccessLevel {
		switch level {
		case "CurrentRead":
			access |= byte(ua.AccessLevelTypeCurrentRead)
		case "CurrentWrite":
			access |= byte(ua.AccessLevelTypeCurrentWrite)
		case "HistoryRead":
			access |= byte(ua.AccessLevelTypeHistoryRead)
			if err := set(ua.AttributeIDHistorizing, true); err != nil {
				return nil, err
			}
		}
	}
	dataType, ok := builtInTypes[n.DataType]
	if !ok {
		return nil, errors.New("unknown data type " + n.DataType)
	}
	for attr, v := range map[ua.AttributeID]any{
		ua.AttributeIDAccessLevel:     access,
		ua.AttributeIDUserAccessLevel: access,
		ua.AttributeIDValueRank:       n.ValueRank,
		ua.AttributeIDDataType:        ua.NewNumericExpandedNodeID(0, dataType),
	} {
		if err := set(attr, v); err != nil {
			return nil, err
		}
	}
	return node, nil
}

func (a *addressSpace) hasBehavior(fx *fixture, target string) bool {
	for _, b := range fx.Behaviors {
		if b.Target == target {
			return true
		}
	}
	return false
}

func (a *addressSpace) setValue(key string, dv *ua.DataValue) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.values[key] = dv
}

func (a *addressSpace) value(key string) *ua.DataValue {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.values[key]
}

// addEURange is the EURange property of an analog item: what makes the server
// accept a percent deadband (Part 8 §5.3.2.3, §7.2).
func (a *addressSpace) addEURange(node *server.Node, r *ua.Range) {
	value := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(ua.NewExtensionObject(r))}
	prop := server.NewNode(
		ua.NewStringNodeID(a.ns.ID(), node.ID().StringID()+".EURange"),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:   server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:  server.DataValueFromValue(attrs.BrowseName("EURange")),
			ua.AttributeIDDisplayName: server.DataValueFromValue(attrs.DisplayName("EURange", "en")),
			ua.AttributeIDDataType:    server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Range)),
		},
		nil,
		func() *ua.DataValue { return value },
	)
	a.ns.AddNode(prop)
	node.AddRef(prop, id.HasProperty, true)
}

// addMethod registers the handler of a fixture method, and its argument properties.
func (a *addressSpace) addMethod(object, method *ua.NodeID, node *server.Node, n *fixtureNode) {
	a.addArguments(node, "InputArguments", n.InputArguments)
	a.addArguments(node, "OutputArguments", n.OutputArguments)
	a.s.RegisterMethod(object, method, methodHandler(n.MethodBehavior, len(n.InputArguments)))
}

func (a *addressSpace) addArguments(method *server.Node, prop string, args []fixtureArg) {
	if len(args) == 0 {
		return
	}
	objects := make([]*ua.ExtensionObject, len(args))
	for i, arg := range args {
		objects[i] = ua.NewExtensionObject(&ua.Argument{
			Name: arg.Name, DataType: ua.NewNumericNodeID(0, builtInTypes[arg.DataType]), ValueRank: arg.ValueRank,
			Description: ua.NewLocalizedTextWithLocale(arg.Description, "en"),
		})
	}
	value := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(objects)}
	node := server.NewNode(
		ua.NewStringNodeID(a.ns.ID(), method.ID().StringID()+"."+prop),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName(prop)),
			ua.AttributeIDDataType:   server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Argument)),
		},
		nil,
		func() *ua.DataValue { return value },
	)
	a.ns.AddNode(node)
	method.AddRef(node, id.HasProperty, true)
}

// methodHandler is the method of docs/FIXTURES.md "Methods".
func methodHandler(behavior string, inputs int) server.MethodHandler {
	return func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		if len(args) != inputs {
			return nil, ua.StatusBadArgumentsMissing
		}
		switch behavior {
		case "Add":
			a, okA := args[0].Value().(int32)
			b, okB := args[1].Value().(int32)
			if okA && okB {
				return []*ua.Variant{ua.MustVariant(a + b)}, ua.StatusOK
			}
		case "Multiply":
			a, okA := args[0].Value().(float64)
			b, okB := args[1].Value().(float64)
			if okA && okB {
				return []*ua.Variant{ua.MustVariant(a * b)}, ua.StatusOK
			}
		case "Echo":
			if s, ok := args[0].Value().(string); ok {
				return []*ua.Variant{ua.MustVariant(s)}, ua.StatusOK
			}
		case "NoArguments":
			return []*ua.Variant{ua.MustVariant(true)}, ua.StatusOK
		case "MultipleOutputs":
			if v, ok := args[0].Value().(int32); ok {
				return []*ua.Variant{ua.MustVariant(v * 2), ua.MustVariant(fmt.Sprint(v))}, ua.StatusOK
			}
		case "Fail":
			return nil, ua.StatusBadInternalError
		}
		return nil, ua.StatusBadInvalidArgument
	}
}

// startBehaviors runs the value generators of the fixture until ctx ends.
func (a *addressSpace) startBehaviors(ctx context.Context, fx *fixture) error {
	for _, b := range fx.Behaviors {
		nodeID, err := a.nodeID(b.Target)
		if err != nil {
			return err
		}
		key := nodeID.StringID()
		current := a.value(key)
		if current == nil {
			return errors.New("behavior of a node that is not a variable: " + b.Target)
		}
		switch b.Kind {
		case "fixed-status":
			status, err := b.Initial.Int64()
			if err != nil {
				return err
			}
			a.setValue(key, &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueStatusCode, Value: current.Value, Status: ua.StatusCode(status)})
			continue
		case "counter", "toggle", "ramp":
		default:
			return errors.New("unknown behavior " + b.Kind)
		}
		value := current.Value.Value()
		var step func() any
		switch b.Kind {
		case "counter":
			step = func() any { value = value.(int64) + int64(b.Increment); return value }
		case "toggle":
			step = func() any { value = !value.(bool); return value }
		case "ramp":
			step = func() any {
				next := value.(float64) + b.Increment
				if next > b.Maximum {
					next = b.Minimum
				}
				value = next
				return value
			}
		}
		go func() {
			ticker := time.NewTicker(time.Duration(b.Interval) * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					now := time.Now()
					a.setValue(key, &ua.DataValue{
						EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
						Value:        ua.MustVariant(step()), SourceTimestamp: now, ServerTimestamp: now,
					})
					a.s.ChangeNotification(nodeID)
				}
			}
		}()
	}
	return nil
}
