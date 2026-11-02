// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"github.com/otfabric/go-opcua/ua"
)

// fixture is the part of fixtures/schema/opcua-fixture.schema.json this adapter
// realises.
type fixture struct {
	ID     string `json:"id"`
	Server struct {
		ApplicationURI  string `json:"applicationUri"`
		ProductURI      string `json:"productUri"`
		ApplicationName string `json:"applicationName"`
	} `json:"server"`
	Endpoint struct {
		Path string `json:"path"`
		Port int    `json:"port"`
	} `json:"endpoint"`
	Namespaces []struct {
		URI string `json:"uri"`
	} `json:"namespaces"`
	Nodes     []fixtureNode `json:"nodes"`
	Behaviors []struct {
		Target    string      `json:"target"`
		Kind      string      `json:"kind"`
		Initial   json.Number `json:"initial"`
		Increment float64     `json:"increment"`
		Minimum   float64     `json:"minimum"`
		Maximum   float64     `json:"maximum"`
		Interval  int64       `json:"intervalMs"`
	} `json:"behaviors"`
	Users []struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		Roles    []string `json:"roles"`
	} `json:"users"`
	SecurityProfiles []struct {
		Policy string `json:"securityPolicy"`
		Mode   string `json:"securityMode"`
	} `json:"securityProfiles"`
}

type fixtureNode struct {
	NodeClass       string       `json:"nodeClass"`
	NodeID          string       `json:"nodeId"`
	BrowseName      string       `json:"browseName"`
	DisplayName     string       `json:"displayName"`
	Description     string       `json:"description"`
	ParentNodeID    string       `json:"parentNodeId"`
	ReferenceType   string       `json:"referenceType"`
	TypeDefinition  string       `json:"typeDefinition"`
	DataType        string       `json:"dataType"`
	ValueRank       int32        `json:"valueRank"`
	ArrayDimensions []int        `json:"arrayDimensions"`
	AccessLevel     []string     `json:"accessLevel"`
	InitialValue    any          `json:"initialValue"`
	MethodBehavior  string       `json:"methodBehavior"`
	InputArguments  []fixtureArg `json:"inputArguments"`
	OutputArguments []fixtureArg `json:"outputArguments"`
	EURange         *ua.Range    `json:"euRange"`
}

type fixtureArg struct {
	Name        string `json:"name"`
	DataType    string `json:"dataType"`
	ValueRank   int32  `json:"valueRank"`
	Description string `json:"description"`
}

func loadFixture(path string) (*fixture, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	dec.UseNumber() // 64-bit integers keep their digits.
	var fx fixture
	if err := dec.Decode(&fx); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(fx.Namespaces) == 0 {
		return nil, fmt.Errorf("%s: no namespace", path)
	}
	return &fx, nil
}

// initialValue converts a fixture value to a Go value of the node's type.
func initialValue(n *fixtureNode) (any, error) {
	if arr, ok := n.InitialValue.([]any); ok {
		items := make([]string, len(arr))
		for i, item := range arr {
			items[i] = fmt.Sprint(item)
		}
		if len(n.ArrayDimensions) == 2 {
			return matrix(n.DataType, items, n.ArrayDimensions)
		}
		return parseArray(n.DataType, items)
	}
	return parseLiteral(n.DataType, fmt.Sprint(n.InitialValue))
}

// matrix is a two-dimensional array in row-major order, which is how the fixture
// and go-opcua lay it out.
func matrix(dataType string, items []string, dims []int) (any, error) {
	if dims[0]*dims[1] != len(items) {
		return nil, fmt.Errorf("matrix of %d %s, dimensions %v", len(items), dataType, dims)
	}
	rows := make([]reflect.Value, dims[0])
	for r := range rows {
		row, err := parseArray(dataType, items[r*dims[1]:(r+1)*dims[1]])
		if err != nil {
			return nil, err
		}
		rows[r] = reflect.ValueOf(row)
	}
	out := reflect.MakeSlice(reflect.SliceOf(rows[0].Type()), dims[0], dims[0])
	for r, row := range rows {
		out.Index(r).Set(row)
	}
	return out.Interface(), nil
}
