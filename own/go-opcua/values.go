// SPDX-License-Identifier: MIT

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// builtInTypes are the OPC UA built-in types by name. The number is both the
// Variant type (Part 6 Table 1) and the NodeId of the DataType in namespace 0.
var builtInTypes = map[string]uint32{
	"Boolean": 1, "SByte": 2, "Byte": 3, "Int16": 4, "UInt16": 5, "Int32": 6, "UInt32": 7,
	"Int64": 8, "UInt64": 9, "Float": 10, "Double": 11, "String": 12, "DateTime": 13, "Guid": 14,
	"ByteString": 15, "XmlElement": 16, "NodeId": 17, "ExpandedNodeId": 18, "StatusCode": 19,
	"QualifiedName": 20, "LocalizedText": 21, "ExtensionObject": 22, "DataValue": 23, "Variant": 24,
	"DiagnosticInfo": 25,
}

func typeName(id uint32) string {
	for name, n := range builtInTypes {
		if n == id {
			return name
		}
	}
	return "Null"
}

// statusJSON is a StatusCode in a result (§3).
type statusJSON struct {
	Name     string `json:"name"`
	Code     uint32 `json:"code"`
	Severity string `json:"severity"`
}

func statusOf(s ua.StatusCode) statusJSON {
	name := ua.StatusCodes[s&0xFFFF0000].Symbol
	if name == "" {
		name = s.Symbol()
	}
	severity := "Good"
	switch uint32(s) >> 30 {
	case 1:
		severity = "Uncertain"
	case 2, 3:
		severity = "Bad"
	}
	return statusJSON{Name: name, Code: uint32(s), Severity: severity}
}

func isGood(s ua.StatusCode) bool { return uint32(s)>>30 == 0 }

// nodeIDString is the canonical form (§6). go-opcua writes a GUID in upper case.
func nodeIDString(n *ua.NodeID) string {
	if n == nil {
		return ""
	}
	if n.Type() == ua.NodeIDTypeGUID {
		return strings.ToLower(n.String())
	}
	return n.String()
}

func timeString(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// encodeValue is a Variant's value in a result (§7).
func encodeValue(v *ua.Variant) any {
	if v == nil || v.Value() == nil {
		return nil
	}
	if b, ok := v.Value().([]byte); ok && v.Type() == ua.TypeIDByte {
		out := make([]int, len(b))
		for i, x := range b {
			out[i] = int(x)
		}
		return out
	}
	return encodeAny(v.Value())
}

func encodeAny(x any) any {
	switch v := x.(type) {
	case nil:
		return nil
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float32:
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			return nil
		}
		return v
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil
		}
		return v
	case time.Time:
		return timeString(v)
	case *ua.GUID:
		return strings.ToLower(v.String())
	case []byte:
		return base64.StdEncoding.EncodeToString(v)
	case ua.ByteArray:
		return base64.StdEncoding.EncodeToString(v)
	case ua.XMLElement:
		return string(v)
	case *ua.NodeID:
		return nodeIDString(v)
	case *ua.ExpandedNodeID:
		return v.String()
	case ua.StatusCode:
		return statusOf(v)
	case *ua.QualifiedName:
		return map[string]any{"ns": v.NamespaceIndex, "name": v.Name}
	case *ua.LocalizedText:
		return localizedText(v)
	case *ua.Variant:
		return map[string]any{"dataType": typeName(uint32(v.Type())), "builtInType": int(v.Type()), "value": encodeValue(v)}
	case *ua.ExtensionObject:
		if v == nil || v.TypeID == nil {
			return nil
		}
		return map[string]any{"typeId": v.TypeID.String()}
	}
	if rv := reflect.ValueOf(x); rv.Kind() == reflect.Slice {
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = encodeAny(rv.Index(i).Interface())
		}
		return out
	}
	return x
}

func localizedText(t *ua.LocalizedText) map[string]string {
	if t == nil {
		return map[string]string{"locale": "", "text": ""}
	}
	return map[string]string{"locale": t.Locale, "text": t.Text}
}

// parseLiteral turns a value literal (§12) into a Go value for a Variant. It
// covers the types of the fixture, as scalars and one-dimensional arrays.
func parseLiteral(typ, lit string) (any, error) {
	if base, ok := strings.CutSuffix(typ, "[]"); ok {
		var items []string
		switch {
		case strings.HasPrefix(lit, "["):
			if err := json.Unmarshal([]byte(lit), &items); err != nil {
				return nil, err
			}
		case lit != "":
			items = strings.Split(lit, ",")
		}
		return parseArray(base, items)
	}
	switch typ {
	case "Boolean":
		switch lit {
		case "true", "1":
			return true, nil
		case "false", "0":
			return false, nil
		}
		return nil, fmt.Errorf("not a Boolean: %q", lit)
	case "SByte":
		n, err := strconv.ParseInt(lit, 10, 8)
		return int8(n), err
	case "Byte":
		n, err := strconv.ParseUint(lit, 10, 8)
		return uint8(n), err
	case "Int16":
		n, err := strconv.ParseInt(lit, 10, 16)
		return int16(n), err
	case "UInt16":
		n, err := strconv.ParseUint(lit, 10, 16)
		return uint16(n), err
	case "Int32":
		n, err := strconv.ParseInt(lit, 10, 32)
		return int32(n), err
	case "UInt32":
		n, err := strconv.ParseUint(lit, 10, 32)
		return uint32(n), err
	case "Int64":
		return strconv.ParseInt(lit, 10, 64)
	case "UInt64":
		return strconv.ParseUint(lit, 10, 64)
	case "Float":
		n, err := strconv.ParseFloat(lit, 32)
		return float32(n), err
	case "Double":
		return strconv.ParseFloat(lit, 64)
	case "String":
		return lit, nil
	case "DateTime":
		return time.Parse(time.RFC3339Nano, lit)
	case "Guid":
		if g := ua.NewGUID(lit); g != nil {
			return g, nil
		}
		return nil, fmt.Errorf("not a Guid: %q", lit)
	case "ByteString":
		return base64.StdEncoding.DecodeString(lit)
	case "XmlElement":
		return ua.XMLElement(lit), nil
	case "NodeId":
		return ua.ParseNodeID(lit)
	case "StatusCode":
		n, err := strconv.ParseUint(lit, 0, 32)
		return ua.StatusCode(n), err
	case "QualifiedName":
		ns, name, ok := strings.Cut(lit, ":")
		if !ok {
			return nil, fmt.Errorf("not a QualifiedName: %q", lit)
		}
		n, err := strconv.ParseUint(ns, 10, 16)
		return &ua.QualifiedName{NamespaceIndex: uint16(n), Name: name}, err
	case "LocalizedText":
		locale, text, ok := strings.Cut(lit, ":")
		if !ok {
			return nil, fmt.Errorf("not a LocalizedText: %q", lit)
		}
		return ua.NewLocalizedTextWithLocale(text, locale), nil
	}
	return nil, fmt.Errorf("unknown type %q", typ)
}

// parseArray makes a typed slice, so that the Variant has the right type also
// when it is empty.
func parseArray(base string, items []string) (any, error) {
	zero := map[string]any{
		"Boolean": false, "SByte": int8(0), "Byte": uint8(0), "Int16": int16(0), "UInt16": uint16(0),
		"Int32": int32(0), "UInt32": uint32(0), "Int64": int64(0), "UInt64": uint64(0),
		"Float": float32(0), "Double": float64(0), "String": "", "ByteString": []byte(nil),
	}[base]
	if zero == nil {
		return nil, fmt.Errorf("no arrays of %q in this adapter", base)
	}
	out := reflect.MakeSlice(reflect.SliceOf(reflect.TypeOf(zero)), len(items), len(items))
	for i, item := range items {
		v, err := parseLiteral(base, item)
		if err != nil {
			return nil, err
		}
		out.Index(i).Set(reflect.ValueOf(v))
	}
	return out.Interface(), nil
}

// literalVariant keeps the leniency of `write` and `call` (§12): an unknown type
// or a malformed literal goes out as a String, and the server answers.
func literalVariant(typ, lit string) *ua.Variant {
	if v, err := parseLiteral(typ, lit); err == nil {
		if variant, err := ua.NewVariant(v); err == nil {
			return variant
		}
	}
	return ua.MustVariant(lit)
}

var nodeIDForm = regexp.MustCompile(`^(ns=[0-9]+;)?[isgb]=.`)

// nodeRef is a --node argument (§8). A namespace URI is resolved once connected.
type nodeRef struct {
	uri string
	id  *ua.NodeID
}

func parseNodeRef(s string) (nodeRef, error) {
	if rest, ok := strings.CutPrefix(s, "nsu="); ok {
		uri, ident, ok := strings.Cut(rest, ";")
		if !ok || uri == "" {
			return nodeRef{}, fmt.Errorf("malformed NodeId: %q", s)
		}
		id, err := ua.ParseNodeID("ns=1;" + ident)
		if err != nil {
			return nodeRef{}, fmt.Errorf("malformed NodeId: %q", s)
		}
		return nodeRef{uri: uri, id: id}, nil
	}
	// go-opcua also reads a bare word as a string NodeId; §8 does not.
	if !nodeIDForm.MatchString(s) {
		return nodeRef{}, fmt.Errorf("malformed NodeId: %q", s)
	}
	id, err := ua.ParseNodeID(s)
	if err != nil {
		return nodeRef{}, fmt.Errorf("malformed NodeId: %q", s)
	}
	return nodeRef{id: id}, nil
}

// readDER returns the DER of a certificate file, PEM or DER.
func readDER(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(b); block != nil {
		return block.Bytes, nil
	}
	return b, nil
}

// readRSAKey reads an RSA private key, PEM or DER, PKCS#8 or PKCS#1.
func readRSAKey(path string) (*rsa.PrivateKey, error) {
	der, err := readDER(path)
	if err != nil {
		return nil, err
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if rk, ok := k.(*rsa.PrivateKey); ok {
		return rk, nil
	}
	return nil, errors.New(path + ": not an RSA key; this adapter has the RSA policies only")
}

// repeated is a flag that may be given several times.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(s string) error { *r = append(*r, s); return nil }
