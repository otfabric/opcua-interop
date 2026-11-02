// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

const model = "nsu=urn:otfabric:opcua-interop:model;s="

// fixturePath is /fixtures in the image build, the repository's otherwise.
func fixturePath(t *testing.T) string {
	t.Helper()
	for _, dir := range []string{"/fixtures", "../../fixtures"} {
		path := filepath.Join(dir, "baseline", "fixture.json")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Fatal("no baseline fixture")
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// startFixtureServer runs the server role in this process and returns its URL.
func startFixtureServer(t *testing.T) string {
	t.Helper()
	fx, err := loadFixture(fixturePath(t))
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &serverFlags{bindAddress: "127.0.0.1", bindPort: port, advertisedHost: "127.0.0.1"}
	_, cleanup, code := startServer(ctx, f, fx)
	if code != exitOK {
		t.Fatalf("startServer: exit %d", code)
	}
	t.Cleanup(cleanup)
	return fmt.Sprintf("opc.tcp://127.0.0.1:%d/opcua-interop", port)
}

// client runs a client command and returns its exit code and envelope.
func client(t *testing.T, args ...string) (int, map[string]any) {
	t.Helper()
	var out bytes.Buffer
	code := run(append([]string{"client"}, args...), &out)
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("%v: output %q: %v", args, out.String(), err)
	}
	for _, key := range []string{"schemaVersion", "adapter", "operation", "success", "serviceResult", "results", "error"} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("%v: envelope without %s: %s", args, key, out.String())
		}
	}
	return code, doc
}

func first(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	results := doc["results"].([]any)
	if len(results) == 0 {
		t.Fatalf("no results: %v", doc)
	}
	return results[0].(map[string]any)
}

func TestCapabilitiesAreNotIndependent(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"print-capabilities"}, &out); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["upstream"].(map[string]any)["independentEngine"] != false {
		t.Errorf("upstream: %v", doc["upstream"])
	}
	if doc["adapter"].(map[string]any)["name"] != "otfabric" {
		t.Errorf("adapter: %v", doc["adapter"])
	}
}

func TestLiterals(t *testing.T) {
	for _, c := range []struct {
		typ, lit string
		want     any
	}{
		{"Boolean", "1", true},
		{"SByte", "-100", int8(-100)},
		{"UInt64", "18446744073709551615", uint64(math.MaxUint64)},
		{"Float", "12.5", float32(12.5)},
		{"String", "x", "x"},
		{"XmlElement", "<a/>", ua.XMLElement("<a/>")},
		{"StatusCode", "0x80340000", ua.StatusCode(0x80340000)},
	} {
		got, err := parseLiteral(c.typ, c.lit)
		if err != nil || got != c.want {
			t.Errorf("parseLiteral(%s, %q) = %v, %v; want %v", c.typ, c.lit, got, err, c.want)
		}
	}
	got, err := parseLiteral("Int32[]", "1,2,3")
	if err != nil || len(got.([]int32)) != 3 {
		t.Errorf("Int32[]: %v, %v", got, err)
	}
	got, err = parseLiteral("String[]", `["a,b","c"]`)
	if err != nil || len(got.([]string)) != 2 {
		t.Errorf("String[]: %v, %v", got, err)
	}
	if empty, err := parseLiteral("Double[]", ""); err != nil || len(empty.([]float64)) != 0 {
		t.Errorf("empty array: %v, %v", empty, err)
	}
	if _, err := parseLiteral("Int32", "x"); err == nil {
		t.Error("a malformed literal has no error")
	}
	if v := literalVariant("NoSuchType", "x"); v.Type() != ua.TypeIDString {
		t.Errorf("leniency of §12: %v", v.Type())
	}
}

func TestEncodeValue(t *testing.T) {
	when := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		value, want any
	}{
		{int64(-5), "-5"},
		{uint64(5), "5"},
		{math.NaN(), nil},
		{[]byte("a"), "YQ=="},
		{when, "2024-01-01T00:00:00.000Z"},
		{ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63"), "72962b91-fa75-4ae6-8d28-b404dc7daf63"},
		{ua.NewNumericNodeID(0, 85), "i=85"},
	} {
		if got := encodeAny(c.value); got != c.want {
			t.Errorf("encodeAny(%v) = %v, want %v", c.value, got, c.want)
		}
	}
	matrix := encodeValue(ua.MustVariant([][]int32{{1}, {2}})).([]any)
	if len(matrix) != 2 || len(matrix[0].([]any)) != 1 {
		t.Errorf("matrix: %v", matrix)
	}
}

func TestStatusNames(t *testing.T) {
	if got := statusOf(ua.StatusOK); got != (statusJSON{"Good", 0, "Good"}) {
		t.Errorf("Good: %+v", got)
	}
	if got := statusOf(ua.StatusBadNodeIDUnknown); got != (statusJSON{"BadNodeIdUnknown", 2150891520, "Bad"}) {
		t.Errorf("BadNodeIdUnknown: %+v", got)
	}
	if got := statusOf(ua.StatusUncertain); got.Severity != "Uncertain" {
		t.Errorf("Uncertain: %+v", got)
	}
}

func TestInputIsRefusedWithoutANetworkRequest(t *testing.T) {
	const nowhere = "opc.tcp://192.0.2.1:4840"
	for _, args := range [][]string{
		{"read", "--endpoint", nowhere, "--node", "nsu=missing"},
		{"read", "--endpoint", nowhere, "--node", "garbage"},
		{"read", "--endpoint", nowhere},
		{"read", "--node", "i=85"},
		{"read", "--endpoint", nowhere, "--node", "i=85", "--no-such-flag"},
		{"read", "--endpoint", nowhere, "--node", "i=85", "--security-policy", "ECC_nistP256", "--security-mode", "Sign"},
		{"read", "--endpoint", nowhere, "--node", "i=85", "--security-policy", "Basic256Sha256", "--security-mode", "Sign"},
		{"subscribe", "--endpoint", nowhere, "--node", "i=85", "--deadband-absolute", "1", "--deadband-percent", "1"},
		// Not in the subset: refused, never faked.
		{"history-read", "--endpoint", nowhere, "--node", "i=85"},
		{"codec", "encode", "--format", "json"},
	} {
		code, doc := client(t, args...)
		if code != exitInput || doc["success"] != false {
			t.Errorf("%v: exit %d: %v", args, code, doc)
		}
		if doc["error"].(map[string]any)["category"] != "input" {
			t.Errorf("%v: %v", args, doc["error"])
		}
	}
}

func TestNoServerIsATransportFailure(t *testing.T) {
	code, doc := client(t, "read", "--endpoint", fmt.Sprintf("opc.tcp://127.0.0.1:%d", freePort(t)), "--node", "i=85", "--connect-timeout", "2")
	if code != exitConnect || doc["error"].(map[string]any)["category"] != "transport" {
		t.Errorf("exit %d: %v", code, doc)
	}
}

func TestClientAgainstServer(t *testing.T) {
	ep := startFixtureServer(t)

	t.Run("endpoints", func(t *testing.T) {
		code, doc := client(t, "endpoints", "--endpoint", ep)
		if code != exitOK || first(t, doc)["securityMode"] != "None" {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("find-servers", func(t *testing.T) {
		code, doc := client(t, "find-servers", "--endpoint", ep)
		if code != exitOK || first(t, doc)["applicationUri"] != "urn:otfabric:opcua-interop:server" {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("no such endpoint", func(t *testing.T) {
		code, doc := client(t, "read", "--endpoint", ep, "--node", "i=85", "--security-policy", "Basic256Sha256", "--security-mode", "Sign", "--certificate", "x", "--private-key", "x")
		if code != exitConnect {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("browse", func(t *testing.T) {
		code, doc := client(t, "browse", "--endpoint", ep)
		found := false
		for _, r := range doc["results"].([]any) {
			name := r.(map[string]any)["browseName"].(map[string]any)["name"]
			found = found || name == "Compatibility"
		}
		if code != exitOK || !found {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	for node, want := range map[string]any{
		"Scalar.Int32":          float64(-123456789),
		"Scalar.Int64":          "-1234567890123456789",
		"Scalar.Guid":           "72962b91-fa75-4ae6-8d28-b404dc7daf63",
		"Access.ReadOnly":       "immutable",
		"Diagnostics.FixtureId": "baseline",
	} {
		t.Run("read "+node, func(t *testing.T) {
			code, doc := client(t, "read", "--endpoint", ep, "--node", model+node)
			if code != exitOK || first(t, doc)["value"] != want {
				t.Errorf("exit %d: %v", code, doc)
			}
		})
	}
	t.Run("read an unknown node", func(t *testing.T) {
		code, doc := client(t, "read", "--endpoint", ep, "--node", model+"NoSuchNode")
		if code != exitService || doc["serviceResult"].(map[string]any)["name"] != "BadNodeIdUnknown" {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("read an unknown namespace", func(t *testing.T) {
		code, doc := client(t, "read", "--endpoint", ep, "--node", "nsu=urn:none;s=x")
		if code != exitInput {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("read write-only", func(t *testing.T) {
		// go-opcua answers BadUserAccessDenied here, not the BadNotReadable of
		// docs/FIXTURES.md: README.md "What it cannot do".
		code, doc := client(t, "read", "--endpoint", ep, "--node", model+"Access.WriteOnly")
		if code != exitService || first(t, doc)["statusCode"].(map[string]any)["severity"] != "Bad" {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("write", func(t *testing.T) {
		code, doc := client(t, "write", "--endpoint", ep, "--node", model+"Access.ReadWrite", "--type", "Int32", "--value", "999")
		if code != exitOK {
			t.Fatalf("exit %d: %v", code, doc)
		}
		_, doc = client(t, "read", "--endpoint", ep, "--node", model+"Access.ReadWrite")
		if first(t, doc)["value"] != float64(999) {
			t.Errorf("read back: %v", doc)
		}
	})
	t.Run("write read-only", func(t *testing.T) {
		code, doc := client(t, "write", "--endpoint", ep, "--node", model+"Access.ReadOnly", "--type", "String", "--value", "x")
		if code != exitService {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("call", func(t *testing.T) {
		code, doc := client(t, "call", "--endpoint", ep, "--object", model+"Methods", "--method", model+"Methods.Add", "--input", "Int32:10", "--input", "Int32:20")
		if code != exitOK || first(t, doc)["outputArguments"].([]any)[0] != float64(30) {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("call Fail", func(t *testing.T) {
		code, doc := client(t, "call", "--endpoint", ep, "--object", model+"Methods", "--method", model+"Methods.Fail")
		if code != exitService || first(t, doc)["statusCode"].(map[string]any)["name"] != "BadInternalError" {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("register-nodes", func(t *testing.T) {
		code, doc := client(t, "register-nodes", "--endpoint", ep, "--node", model+"Scalar.Int32")
		if code != exitOK || first(t, doc)["value"] != float64(-123456789) {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("username", func(t *testing.T) {
		code, doc := client(t, "read", "--endpoint", ep, "--node", model+"Scalar.Int32", "--username", "test-user", "--password", "test-password")
		if code != exitOK {
			t.Errorf("exit %d: %v", code, doc)
		}
		code, doc = client(t, "read", "--endpoint", ep, "--node", model+"Scalar.Int32", "--username", "test-user", "--password", "wrong")
		if code != exitService {
			t.Errorf("wrong password: exit %d: %v", code, doc)
		}
	})
	t.Run("subscribe", func(t *testing.T) {
		code, doc := client(t, "subscribe", "--endpoint", ep, "--node", model+"Dynamic.Counter", "--notifications", "3", "--timeout-ms", "15000")
		if code != exitOK || len(first(t, doc)["notifications"].([]any)) != 3 {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("subscribe past the request timeout", func(t *testing.T) {
		code, doc := client(t, "subscribe", "--endpoint", ep, "--node", model+"Dynamic.Counter", "--notifications", "6", "--timeout-ms", "15000", "--request-timeout", "1")
		if code != exitOK || len(first(t, doc)["notifications"].([]any)) != 6 {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("subscribe runs out of time", func(t *testing.T) {
		code, doc := client(t, "subscribe", "--endpoint", ep, "--node", model+"Access.ReadOnly", "--notifications", "3", "--timeout-ms", "1500")
		if code != exitTimeout || doc["success"] != false {
			t.Errorf("exit %d: %v", code, doc)
		}
	})
	t.Run("deadband", func(t *testing.T) {
		code, doc := client(t, "subscribe", "--endpoint", ep, "--node", model+"Analog.Level", "--publishing-interval-ms", "200", "--notifications", "3", "--timeout-ms", "15000", "--deadband-absolute", "10")
		if code != exitOK || first(t, doc)["filter"].(map[string]any)["deadbandType"] != "Absolute" {
			t.Errorf("exit %d: %v", code, doc)
		}
		code, doc = client(t, "subscribe", "--endpoint", ep, "--node", model+"Dynamic.Ramp", "--notifications", "1", "--deadband-percent", "10")
		if code != exitService || first(t, doc)["monitoredItemStatusCode"].(map[string]any)["severity"] != "Bad" {
			t.Errorf("percent without EURange: exit %d: %v", code, doc)
		}
	})
}
