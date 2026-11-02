// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"flag"
	"strings"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func readResult(nodeID string, dv *ua.DataValue) map[string]any {
	r := map[string]any{"nodeId": nodeID, "statusCode": statusOf(dv.Status)}
	if dv.Value != nil && dv.Value.Value() != nil {
		r["dataType"] = typeName(uint32(dv.Value.Type()))
		r["builtInType"] = int(dv.Value.Type())
	}
	r["value"] = encodeValue(dv.Value)
	if !dv.SourceTimestamp.IsZero() {
		r["sourceTimestamp"] = timeString(dv.SourceTimestamp)
	}
	return r
}

func readCommand(fs *flag.FlagSet) command {
	var nodes repeated
	var refs []nodeRef
	fs.Var(&nodes, "node", "NodeId, repeatable")
	indexRange := fs.String("index-range", "", "NumericRange")
	return command{
		validate: func() (err error) { refs, err = parseRefs(nodes); return err },
		run: func(ctx context.Context, c *opcua.Client) outcome {
			ids, failed := resolveAll(ctx, c, refs)
			if failed != nil {
				return *failed
			}
			req := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnBoth}
			for _, nodeID := range ids {
				req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{NodeID: nodeID, AttributeID: ua.AttributeIDValue, IndexRange: *indexRange})
			}
			resp, err := c.Read(ctx, req)
			if err != nil {
				return classify(err)
			}
			results := make([]any, len(resp.Results))
			bad := ua.StatusOK
			for i, dv := range resp.Results {
				results[i] = readResult(nodeIDString(ids[i]), dv)
				if !isGood(dv.Status) && bad == ua.StatusOK {
					bad = dv.Status
				}
			}
			if bad != ua.StatusOK {
				return serviceBad(bad, results)
			}
			return outcome{status: ua.StatusOK, results: results}
		},
	}
}

func writeCommand(fs *flag.FlagSet) command {
	node := fs.String("node", "", "NodeId")
	typ := fs.String("type", "", "type name")
	value := fs.String("value", "", "value literal")
	indexRange := fs.String("index-range", "", "NumericRange")
	var ref nodeRef
	return command{
		validate: func() (err error) {
			if *typ == "" {
				return errors.New("--type is required")
			}
			ref, err = parseNodeRef(*node)
			return err
		},
		run: func(ctx context.Context, c *opcua.Client) outcome {
			nodeID, failed := resolve(ctx, c, ref)
			if failed != nil {
				return *failed
			}
			resp, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
				NodeID: nodeID, AttributeID: ua.AttributeIDValue, IndexRange: *indexRange,
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: literalVariant(*typ, *value)},
			}}})
			if err != nil {
				return classify(err)
			}
			if len(resp.Results) != 1 {
				return failure(exitInternal, "internal", "no result for the write", ua.StatusBadUnexpectedError)
			}
			results := []any{map[string]any{"nodeId": nodeIDString(nodeID), "statusCode": statusOf(resp.Results[0])}}
			if !isGood(resp.Results[0]) {
				return serviceBad(resp.Results[0], results)
			}
			return outcome{status: ua.StatusOK, results: results}
		},
	}
}

func browseCommand(fs *flag.FlagSet) command {
	node := fs.String("node", "i=85", "starting node")
	maxRefs := fs.Uint("max-refs", 0, "maximum references per Browse request")
	var ref nodeRef
	return command{
		validate: func() (err error) { ref, err = parseNodeRef(*node); return err },
		run: func(ctx context.Context, c *opcua.Client) outcome {
			nodeID, failed := resolve(ctx, c, ref)
			if failed != nil {
				return *failed
			}
			resp, err := c.Browse(ctx, &ua.BrowseRequest{
				RequestedMaxReferencesPerNode: uint32(*maxRefs),
				NodesToBrowse: []*ua.BrowseDescription{{
					NodeID: nodeID, BrowseDirection: ua.BrowseDirectionForward,
					ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences), IncludeSubtypes: true,
					NodeClassMask: uint32(ua.NodeClassAll), ResultMask: uint32(ua.BrowseResultMaskAll),
				}},
			})
			if err != nil {
				return classify(err)
			}
			if len(resp.Results) != 1 {
				return failure(exitInternal, "internal", "no result for the browse", ua.StatusBadUnexpectedError)
			}
			result := resp.Results[0]
			if !isGood(result.StatusCode) {
				return serviceBad(result.StatusCode, nil)
			}
			results := browseRefs(nil, result.References)
			for point := result.ContinuationPoint; len(point) > 0; {
				next, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{ContinuationPoints: [][]byte{point}})
				if err != nil {
					return classify(err)
				}
				if len(next.Results) != 1 {
					return failure(exitInternal, "internal", "no result for the browse", ua.StatusBadUnexpectedError)
				}
				if !isGood(next.Results[0].StatusCode) {
					return serviceBad(next.Results[0].StatusCode, results)
				}
				results = browseRefs(results, next.Results[0].References)
				point = next.Results[0].ContinuationPoint
			}
			return outcome{status: ua.StatusOK, results: results}
		},
	}
}

func browseRefs(results []any, refs []*ua.ReferenceDescription) []any {
	for _, ref := range refs {
		nodeID := ""
		if ref.NodeID != nil {
			nodeID = nodeIDString(ref.NodeID.NodeID)
		}
		var name map[string]any
		if ref.BrowseName != nil {
			name = map[string]any{"ns": ref.BrowseName.NamespaceIndex, "name": ref.BrowseName.Name}
		}
		results = append(results, map[string]any{
			"referenceTypeId": nodeIDString(ref.ReferenceTypeID),
			"isForward":       ref.IsForward,
			"nodeId":          nodeID,
			"browseName":      name,
			"displayName":     localizedText(ref.DisplayName),
			"nodeClass":       strings.TrimPrefix(ref.NodeClass.String(), "NodeClass"),
		})
	}
	return results
}

func callCommand(fs *flag.FlagSet) command {
	object := fs.String("object", "", "NodeId of the object")
	method := fs.String("method", "", "NodeId of the method")
	var inputs repeated
	fs.Var(&inputs, "input", "input argument Type:value, repeatable")
	var objectRef, methodRef nodeRef
	return command{
		validate: func() (err error) {
			if objectRef, err = parseNodeRef(*object); err != nil {
				return err
			}
			methodRef, err = parseNodeRef(*method)
			return err
		},
		run: func(ctx context.Context, c *opcua.Client) outcome {
			ids, failed := resolveAll(ctx, c, []nodeRef{objectRef, methodRef})
			if failed != nil {
				return *failed
			}
			args := make([]*ua.Variant, len(inputs))
			for i, input := range inputs {
				typ, lit, _ := strings.Cut(input, ":")
				args[i] = literalVariant(typ, lit)
			}
			res, err := c.Call(ctx, &ua.CallMethodRequest{ObjectID: ids[0], MethodID: ids[1], InputArguments: args})
			if err != nil {
				return classify(err)
			}
			outputs := make([]any, len(res.OutputArguments))
			for i, v := range res.OutputArguments {
				outputs[i] = encodeValue(v)
			}
			results := []any{map[string]any{
				"objectNodeId": nodeIDString(ids[0]), "methodNodeId": nodeIDString(ids[1]),
				"statusCode": statusOf(res.StatusCode), "outputArguments": outputs,
			}}
			if !isGood(res.StatusCode) {
				return serviceBad(res.StatusCode, results)
			}
			return outcome{status: ua.StatusOK, results: results}
		},
	}
}

func registerCommand(fs *flag.FlagSet) command {
	var nodes repeated
	var refs []nodeRef
	fs.Var(&nodes, "node", "NodeId, repeatable")
	return command{
		validate: func() (err error) { refs, err = parseRefs(nodes); return err },
		run: func(ctx context.Context, c *opcua.Client) outcome {
			ids, failed := resolveAll(ctx, c, refs)
			if failed != nil {
				return *failed
			}
			reg, err := c.RegisterNodes(ctx, &ua.RegisterNodesRequest{NodesToRegister: ids})
			if err != nil {
				return classify(err)
			}
			if len(reg.RegisteredNodeIDs) != len(ids) {
				return failure(exitInternal, "internal", "RegisterNodes returned another number of nodes", ua.StatusBadUnexpectedError)
			}
			req := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnBoth}
			for _, alias := range reg.RegisteredNodeIDs {
				req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{NodeID: alias, AttributeID: ua.AttributeIDValue})
			}
			read, err := c.Read(ctx, req)
			if err != nil {
				return classify(err)
			}
			unregStatus := ua.StatusOK
			if _, err := c.UnregisterNodes(ctx, &ua.UnregisterNodesRequest{NodesToUnregister: reg.RegisteredNodeIDs}); err != nil {
				out := classify(err)
				unregStatus = out.status
			}
			results := make([]any, len(ids))
			bad := unregStatus
			for i := range ids {
				r := map[string]any{"nodeId": nodeIDString(ids[i]), "registeredNodeId": nodeIDString(reg.RegisteredNodeIDs[i])}
				dv := read.Results[i]
				r["statusCode"] = statusOf(dv.Status)
				if isGood(dv.Status) {
					r["dataType"] = typeName(uint32(dv.Value.Type()))
					r["builtInType"] = int(dv.Value.Type())
					r["value"] = encodeValue(dv.Value)
				} else if bad == ua.StatusOK {
					bad = dv.Status
				}
				r["unregisterStatusCode"] = statusOf(unregStatus)
				results[i] = r
			}
			if bad != ua.StatusOK {
				return serviceBad(bad, results)
			}
			return outcome{status: ua.StatusOK, results: results}
		},
	}
}
