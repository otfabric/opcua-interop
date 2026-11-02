// SPDX-License-Identifier: MIT

package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otfabric/go-opcua/ua"
)

func TestPubSubFileIsStrict(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"unknown member": `{"configuration":{},"nonsense":1}`,
		"no config":      `{}`,
		"not json":       `{`,
		"bad mqtt":       `{"configuration":{},"mqtt":{"protocolVersion":"3.1"}}`,
	} {
		path := filepath.Join(dir, "f.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPubSubFile(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResolveNamespaces(t *testing.T) {
	raw := `{"PublishedDataSets":[{"Name":"d","DataSetSource":{"UaTypeId":"i=15581","UaBody":{"PublishedData":[{"PublishedVariable":"nsu=urn:x;s=A","AttributeId":13}]}}}]}`
	cfg, err := parsePubSubConfiguration([]byte(raw), map[string]uint16{"urn:x": 7})
	if err != nil {
		t.Fatal(err)
	}
	items, ok := cfg.PublishedDataSets[0].DataSetSource.Value.(*ua.PublishedDataItemsDataType)
	if !ok || items.PublishedData[0].PublishedVariable.Namespace() != 7 {
		t.Fatalf("source %+v", cfg.PublishedDataSets[0].DataSetSource.Value)
	}
	if _, err := parsePubSubConfiguration([]byte(`{"Name":"nsu=urn:other;s=A"}`), map[string]uint16{"urn:x": 7}); err == nil {
		t.Error("an unknown namespace was accepted")
	}
}

func unicastGroup(url string) *ua.WriterGroupDataType {
	return &ua.WriterGroupDataType{Name: "g" + url, TransportSettings: ua.NewExtensionObject(&ua.DatagramWriterGroupTransport2DataType{
		Address: ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: url})})}
}

func TestMoveUnicastAddress(t *testing.T) {
	conn := &ua.PubSubConnectionDataType{Name: "c", WriterGroups: []*ua.WriterGroupDataType{unicastGroup("opc.udp://peer:1")},
		Address: ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: "opc.udp://localhost:2"})}
	if err := moveUnicastAddress(conn); err != nil {
		t.Fatal(err)
	}
	if got := conn.Address.Value.(*ua.NetworkAddressURLDataType).URL; got != "opc.udp://peer:1" {
		t.Errorf("connection address %s", got)
	}
	if conn.WriterGroups[0].TransportSettings != nil {
		t.Error("the address stays on the writer group")
	}
	two := &ua.PubSubConnectionDataType{Name: "c", WriterGroups: []*ua.WriterGroupDataType{unicastGroup("opc.udp://a:1"), unicastGroup("opc.udp://b:1")}}
	if err := moveUnicastAddress(two); err == nil {
		t.Error("two destinations were accepted")
	}
	readers := &ua.PubSubConnectionDataType{Name: "c", WriterGroups: []*ua.WriterGroupDataType{unicastGroup("opc.udp://a:1")}, ReaderGroups: []*ua.ReaderGroupDataType{{Name: "r"}}}
	if err := moveUnicastAddress(readers); err == nil {
		t.Error("a destination next to readers was accepted")
	}
}

func TestCheckGroups(t *testing.T) {
	conn := &ua.PubSubConnectionDataType{WriterGroups: []*ua.WriterGroupDataType{{Name: "g", SecurityGroupID: "unknown"}}}
	if err := checkGroups(conn, map[string]bool{"known": true}); err == nil {
		t.Error("an unknown SecurityGroupId was accepted")
	}
}

// The message of the example of §14.9, byte for byte.
func TestPubSubCodecExample(t *testing.T) {
	const want = "8SG6CAlkAAcAAU30hyYcRNVi3QEJAwAEAAb7////DAIAAABoaQn//////////4YDAAAAAQAAAAIAAAADAAAA"
	raw, err := base64.StdEncoding.DecodeString(want)
	if err != nil {
		t.Fatal(err)
	}
	f := &codecFlags{action: "pubsub-uadp-decode", document: want}
	res := f.pubsubCodec()
	if res.exit != 0 || res.err != nil {
		t.Fatalf("decode: %+v", res.err)
	}
	head := res.results[0].(map[string]any)
	if head["reencoded"] != want {
		t.Errorf("reencoded %v, want %s (%d bytes)", head["reencoded"], want, len(raw))
	}
}

func TestPubSubCodecRefuses(t *testing.T) {
	for name, f := range map[string]*codecFlags{
		"not json":     {action: "pubsub-uadp-encode", document: "{"},
		"bad type":     {action: "pubsub-uadp-encode", document: `{"messages":[{"messageType":"Nope"}]}`},
		"bad encoding": {action: "pubsub-uadp-encode", document: `{"messages":[{"messageType":"KeyFrame","fieldEncoding":"Nope"}]}`},
		"bad value":    {action: "pubsub-uadp-encode", document: `{"messages":[{"fields":[{"dataType":"Int64","value":1}]}]}`},
		"bad type id":  {action: "pubsub-json-encode", document: `{"messages":[{"fields":[{"dataType":"Nope","value":1}]}]}`},
		"not base64":   {action: "pubsub-uadp-decode", document: "%%%"},
		"bad metadata": {action: "pubsub-uadp-decode", document: "AA==", metadata: "{"},
	} {
		if res := f.pubsubCodec(); res.exit != exitInput {
			t.Errorf("%s: exit %d, want %d", name, res.exit, exitInput)
		}
	}
	if res := (&codecFlags{action: "pubsub-uadp-decode", document: "AA=="}).pubsubCodec(); res.exit != exitService {
		t.Errorf("truncated message: exit %d, want %d", res.exit, exitService)
	}
	if res := (&codecFlags{action: "pubsub-json-decode", document: "not json"}).pubsubCodec(); res.exit != exitService {
		t.Errorf("not JSON: exit %d, want %d", res.exit, exitService)
	}
}

func TestDiscoverInputIsRefused(t *testing.T) {
	for _, f := range []*discoverFlags{
		{},
		{url: "mqtt://x:1", typ: "DataSetMetaData", timeoutMS: 1},
		{url: "opc.udp://x:1", typ: "Nope", timeoutMS: 1},
		{url: "opc.udp://x:1", typ: "DataSetMetaData"},
		{url: "opc.udp://x:1", typ: "DataSetMetaData", timeoutMS: 1, writerIDs: "a"},
		{url: "opc.udp://x:1", typ: "DataSetMetaData", timeoutMS: 1, publisherID: "70000"},
	} {
		if err := f.validate(); err == nil || strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%+v: accepted", f)
		}
	}
}
