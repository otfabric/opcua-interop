// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// codecFlags are the flags of `codec` (§1).
type codecFlags struct {
	action, format, decodeShort, typ, value, dims, document, input, jsonMode string
	status, sourceTS, serverTS                                               string
	sourcePico, serverPico                                                   uint
	nodes                                                                    repeated
}

func (f *codecFlags) define(fs *flag.FlagSet) {
	fs.StringVar(&f.format, "format", "", "json or xml")
	fs.StringVar(&f.decodeShort, "decode", "", "short form of decode: json or xml")
	fs.StringVar(&f.typ, "type", "", "type")
	fs.StringVar(&f.value, "value", "", "literal")
	fs.StringVar(&f.dims, "dimensions", "", "matrix dimensions")
	fs.StringVar(&f.document, "document", "", "document to decode")
	fs.StringVar(&f.input, "input", "", "file to decode")
	fs.StringVar(&f.jsonMode, "json-mode", "compact", "compact or verbose")
	fs.StringVar(&f.status, "status", "", "StatusCode of the DataValue")
	fs.StringVar(&f.sourceTS, "source-timestamp", "", "SourceTimestamp of the DataValue")
	fs.StringVar(&f.serverTS, "server-timestamp", "", "ServerTimestamp of the DataValue")
	fs.UintVar(&f.sourcePico, "source-picoseconds", 0, "SourcePicoseconds of the DataValue")
	fs.UintVar(&f.serverPico, "server-picoseconds", 0, "ServerPicoseconds of the DataValue")
	fs.Var(&f.nodes, "node", "NodeId, repeatable")
}

// codecCommand is `codec`; its first word may be the action.
func codecCommand(fs *flag.FlagSet, g *globals) command {
	f := &codecFlags{}
	f.define(fs)
	cmd := command{
		offline: func() bool { return len(f.nodes) == 0 && f.action != "" || f.decodeShort != "" },
		validate: func() error {
			if f.decodeShort != "" {
				f.action, f.format = "decode", f.decodeShort
			}
			switch f.jsonMode {
			case "compact", "verbose":
			default:
				return errors.New("--json-mode: " + f.jsonMode)
			}
			if len(f.nodes) > 0 {
				return nil
			}
			if f.format != "json" && f.format != "xml" {
				return errors.New("--format json|xml is required")
			}
			if f.typ == "" {
				return errors.New("--type is required")
			}
			return nil
		},
		local: func() outcome {
			if f.action == "decode" {
				return f.decodeDocument()
			}
			return f.encodeLiteral()
		},
		run: func(ctx context.Context, c *opcua.Client) outcome {
			if f.action == "encode" {
				return f.encodeNode(ctx, c)
			}
			return f.nodeDocuments(ctx, c)
		},
	}
	g.positional = func(word string) bool {
		if word != "encode" && word != "decode" {
			return false
		}
		f.action = word
		return true
	}
	return cmd
}

func (f *codecFlags) codecOptions() []ua.CodecOption {
	if f.jsonMode == "verbose" {
		return []ua.CodecOption{ua.WithJSONForm(ua.JSONVerbose)}
	}
	return nil
}

// encodeDoc is the document of v in format, and the status that goes with it.
func (f *codecFlags) encodeDoc(format string, v any) (any, statusJSON) {
	var b []byte
	var err error
	if format == "xml" {
		b, err = ua.EncodeXML(v)
	} else {
		b, err = ua.EncodeJSON(v, f.codecOptions()...)
	}
	if err != nil {
		return nil, statusOf(ua.StatusBadEncodingError)
	}
	return string(b), statusOf(ua.StatusOK)
}

// binaryOf is the OPC UA Binary encoding in Base64.
func binaryOf(v any) any {
	b, err := ua.Encode(v)
	if err != nil {
		return nil
	}
	return base64.StdEncoding.EncodeToString(b)
}

// valueRank is what §4 reports for a Variant.
func valueRank(v *ua.Variant) (int, []int) {
	dims := v.ArrayDimensions()
	switch {
	case len(dims) > 1:
		out := make([]int, len(dims))
		for i, d := range dims {
			out[i] = int(d)
		}
		return len(dims), out
	case v.Has(ua.VariantArrayValues):
		return 1, nil
	}
	return -1, nil
}

// describe are the members that say what a Variant holds.
func describe(result map[string]any, v *ua.Variant) {
	result["dataType"], result["builtInType"] = typeName(uint32(v.Type())), int(v.Type())
	rank, dims := valueRank(v)
	result["valueRank"] = rank
	if dims != nil {
		result["arrayDimensions"] = dims
	}
	result["value"] = flatten(encodeValue(v))
}

// flatten lays out a matrix in row-major order (§4).
func flatten(value any) any {
	rows, ok := value.([]any)
	if !ok {
		return value
	}
	var out []any
	for _, row := range rows {
		inner, ok := row.([]any)
		if !ok {
			return value
		}
		out = append(out, inner...)
	}
	return out
}

// dataValueJSON is the canonical DataValue object (§7).
func dataValueJSON(dv *ua.DataValue) map[string]any {
	out := map[string]any{"dataType": "Null", "builtInType": 0, "value": nil}
	if dv.Value != nil && dv.Value.Value() != nil {
		rank, dims := valueRank(dv.Value)
		out["dataType"], out["builtInType"], out["value"] = typeName(uint32(dv.Value.Type())), int(dv.Value.Type()), flatten(encodeValue(dv.Value))
		if rank > 1 {
			out["arrayDimensions"] = dims
		}
	}
	if dv.EncodingMask&ua.DataValueStatusCode != 0 {
		out["statusCode"] = statusOf(dv.Status)
	}
	if !dv.SourceTimestamp.IsZero() {
		out["sourceTimestamp"] = timeString(dv.SourceTimestamp)
	}
	if !dv.ServerTimestamp.IsZero() {
		out["serverTimestamp"] = timeString(dv.ServerTimestamp)
	}
	return out
}

// literal builds the Variant and DataValue of --type, --value and the DataValue flags.
func (f *codecFlags) literal() (*ua.Variant, *ua.DataValue, error) {
	parsed, err := parseLiteral(f.typ, f.value)
	if err != nil {
		return nil, nil, err
	}
	if f.dims != "" {
		items := strings.Split(f.value, ",")
		var dims []int
		for _, s := range strings.Split(f.dims, ",") {
			d, err := strconv.Atoi(s)
			if err != nil {
				return nil, nil, fmt.Errorf("--dimensions: %w", err)
			}
			dims = append(dims, d)
		}
		if len(dims) != 2 {
			return nil, nil, errors.New("--dimensions: this image has two-dimensional matrices")
		}
		base, _ := strings.CutSuffix(f.typ, "[]")
		if parsed, err = matrix(base, items, dims); err != nil {
			return nil, nil, err
		}
	}
	v, err := ua.NewVariant(parsed)
	if err != nil {
		return nil, nil, err
	}
	dv := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v}
	if f.status != "" {
		n, err := strconv.ParseUint(f.status, 0, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("--status: %w", err)
		}
		dv.Status = ua.StatusCode(n)
		dv.EncodingMask |= ua.DataValueStatusCode
	}
	for flagName, set := range map[string]func(time.Time){
		f.sourceTS: func(t time.Time) { dv.SourceTimestamp = t; dv.EncodingMask |= ua.DataValueSourceTimestamp },
		f.serverTS: func(t time.Time) { dv.ServerTimestamp = t; dv.EncodingMask |= ua.DataValueServerTimestamp },
	} {
		if flagName != "" {
			t, err := time.Parse(time.RFC3339Nano, flagName)
			if err != nil {
				return nil, nil, fmt.Errorf("timestamp: %w", err)
			}
			set(t)
		}
	}
	if f.sourcePico != 0 {
		dv.SourcePicoseconds = uint16(f.sourcePico)
		dv.EncodingMask |= ua.DataValueSourcePicoseconds
	}
	if f.serverPico != 0 {
		dv.ServerPicoseconds = uint16(f.serverPico)
		dv.EncodingMask |= ua.DataValueServerPicoseconds
	}
	return v, dv, nil
}

// encodeResult is the item of `codec encode` (§4).
func (f *codecFlags) encodeResult(source string, v *ua.Variant, dv *ua.DataValue) (map[string]any, ua.StatusCode) {
	result := map[string]any{"action": "encode", "format": f.format, "source": source}
	if f.format == "json" {
		result["jsonMode"] = f.jsonMode
	}
	describe(result, v)
	result["dataValue"] = dataValueJSON(dv)
	variantDoc, variantStatus := f.encodeDoc(f.format, v)
	dvDoc, dvStatus := f.encodeDoc(f.format, dv)
	result["encoded"] = map[string]any{"variant": variantDoc, "dataValue": dvDoc}
	result["statusCodes"] = map[string]any{"variant": variantStatus, "dataValue": dvStatus}
	result["binary"] = map[string]any{"variant": binaryOf(v), "dataValue": binaryOf(dv)}
	return result, ua.StatusCode(variantStatus.Code)
}

func (f *codecFlags) encodeLiteral() outcome {
	v, dv, err := f.literal()
	if err != nil {
		return inputError(err.Error())
	}
	result, status := f.encodeResult("literal", v, dv)
	if !isGood(status) {
		return serviceBad(status, []any{result})
	}
	return outcome{status: ua.StatusOK, results: []any{result}}
}

// readNode reads the Value attribute with both timestamps.
func readNode(ctx context.Context, c *opcua.Client, nodeID *ua.NodeID) (*ua.DataValue, error) {
	resp, err := c.Read(ctx, &ua.ReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead:        []*ua.ReadValueID{{NodeID: nodeID, AttributeID: ua.AttributeIDValue}},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) != 1 {
		return nil, ua.StatusBadUnknownResponse
	}
	return resp.Results[0], nil
}

// encodeNode is `codec encode --node`: what the server returned, one item per node.
func (f *codecFlags) encodeNode(ctx context.Context, c *opcua.Client) outcome {
	refs, err := parseRefs(f.nodes)
	if err != nil {
		return inputError(err.Error())
	}
	ids, failed := resolveAll(ctx, c, refs)
	if failed != nil {
		return *failed
	}
	results := make([]any, len(ids))
	bad := ua.StatusOK
	for i, nodeID := range ids {
		dv, err := readNode(ctx, c, nodeID)
		if err != nil {
			return classify(err)
		}
		result, status := f.encodeResult("node", dv.Value, dv)
		result["nodeId"] = nodeIDString(nodeID)
		results[i] = result
		if bad == ua.StatusOK {
			bad = status
		}
	}
	if !isGood(bad) {
		return serviceBad(bad, results)
	}
	return outcome{status: ua.StatusOK, results: results}
}

// nodeDocuments is the short form `codec --endpoint --node` (§4): both formats.
func (f *codecFlags) nodeDocuments(ctx context.Context, c *opcua.Client) outcome {
	refs, err := parseRefs(f.nodes)
	if err != nil {
		return inputError(err.Error())
	}
	ids, failed := resolveAll(ctx, c, refs)
	if failed != nil {
		return *failed
	}
	results := make([]any, len(ids))
	bad := ua.StatusOK
	for i, nodeID := range ids {
		result := map[string]any{"nodeId": nodeIDString(nodeID), "json": nil, "xml": nil}
		results[i] = result
		dv, err := readNode(ctx, c, nodeID)
		if err != nil {
			return classify(err)
		}
		result["statusCode"] = statusOf(dv.Status)
		if !isGood(dv.Status) {
			if bad == ua.StatusOK {
				bad = dv.Status
			}
			continue
		}
		describe(result, dv.Value)
		result["json"], _ = f.encodeDoc("json", dv.Value)
		result["xml"], _ = f.encodeDoc("xml", dv.Value)
		result["dataValueJson"], _ = f.encodeDoc("json", dv)
		result["dataValueXml"], _ = f.encodeDoc("xml", dv)
		result["binary"], result["dataValueBinary"] = binaryOf(dv.Value), binaryOf(dv)
	}
	if !isGood(bad) {
		return serviceBad(bad, results)
	}
	return outcome{status: ua.StatusOK, results: results}
}

// document is what to decode: --document, --input, else stdin. Trailing whitespace
// is ignored.
func (f *codecFlags) readDocument() ([]byte, error) {
	var b []byte
	var err error
	switch {
	case f.document != "":
		b = []byte(f.document)
	case f.input != "":
		b, err = os.ReadFile(f.input)
	default:
		b, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(b), " \t\r\n")), nil
}

// decodeTarget is a pointer to the value of --type, or nil for an unknown type.
func decodeTarget(typ string) any {
	switch typ {
	case "Variant":
		return &ua.Variant{}
	case "DataValue":
		return &ua.DataValue{}
	}
	zero := map[string]any{
		"Boolean": false, "SByte": int8(0), "Byte": uint8(0), "Int16": int16(0), "UInt16": uint16(0),
		"Int32": int32(0), "UInt32": uint32(0), "Int64": int64(0), "UInt64": uint64(0),
		"Float": float32(0), "Double": float64(0), "String": "", "DateTime": time.Time{},
		"Guid": &ua.GUID{}, "ByteString": []byte(nil), "NodeId": &ua.NodeID{}, "StatusCode": ua.StatusCode(0),
		"QualifiedName": &ua.QualifiedName{}, "LocalizedText": &ua.LocalizedText{},
	}[typ]
	if zero == nil {
		return nil
	}
	if reflect.TypeOf(zero).Kind() == reflect.Pointer {
		return zero
	}
	return reflect.New(reflect.TypeOf(zero)).Interface()
}

func (f *codecFlags) decodeDocument() outcome {
	target := decodeTarget(f.typ)
	if target == nil {
		return inputError("--type " + f.typ + " cannot be decoded by this image")
	}
	doc, err := f.readDocument()
	if err != nil {
		return inputError(err.Error())
	}
	head := map[string]any{"action": "decode", "format": f.format, "type": f.typ}
	if f.format == "json" {
		head["jsonMode"] = f.jsonMode
	}
	if f.format == "xml" {
		err = ua.DecodeXML(doc, target)
	} else {
		err = ua.DecodeJSON(doc, target)
	}
	if err != nil {
		head["statusCode"] = statusOf(ua.StatusBadDecodingError)
		res := failure(exitService, "service", err.Error(), ua.StatusBadDecodingError)
		res.results = []any{head}
		return res
	}
	head["statusCode"] = statusOf(ua.StatusOK)
	value := target
	switch x := target.(type) {
	case *ua.Variant:
		describe(head, x)
	case *ua.DataValue:
		if x.Value != nil {
			describe(head, x.Value)
		}
		head["dataValue"] = dataValueJSON(x)
	default:
		elem := reflect.ValueOf(target)
		if elem.Kind() == reflect.Pointer && reflect.TypeOf(decodeTarget(f.typ)).Elem().Kind() != reflect.Struct {
			value = elem.Elem().Interface()
		}
		if v, err := ua.NewVariant(value); err == nil {
			describe(head, v)
		}
	}
	head["binary"] = binaryOf(value)
	head["reencoded"], _ = f.encodeDoc(f.format, value)
	return outcome{status: ua.StatusOK, results: []any{head}}
}

// codecInfo is `codec` of the capability document.
func codecInfo() map[string]any {
	return map[string]any{
		"formats": []string{"json", "xml"}, "jsonVersion": "1.05", "jsonModes": []string{"compact", "verbose"},
		"xmlEncodeUnsupported": []string{}, "xmlDecodeUnsupported": []string{},
	}
}
