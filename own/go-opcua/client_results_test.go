// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// The results of `read` and `register-nodes` follow the request: a response with
// another number of results is an internal failure, an empty result is
// BadUnknownResponse, and a Good result without a value has the type Null.
func TestResultsFollowTheRequest(t *testing.T) {
	ids := []*ua.NodeID{ua.NewNumericNodeID(1, 1), ua.NewNumericNodeID(1, 2)}
	good := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(5))}
	noValue := &ua.DataValue{}
	for _, c := range []struct {
		name     string
		results  []*ua.DataValue
		exit     int
		category string
	}{
		{"one result per node", []*ua.DataValue{good, good}, exitOK, ""},
		{"no results", nil, exitInternal, "internal"},
		{"one result less", []*ua.DataValue{good}, exitInternal, "internal"},
		{"one result more", []*ua.DataValue{good, good, good}, exitInternal, "internal"},
		{"an empty result", []*ua.DataValue{good, nil}, exitService, "service"},
		{"Good without a value", []*ua.DataValue{good, noValue}, exitOK, ""},
	} {
		for op, mapping := range map[string]func() outcome{
			"read":           func() outcome { return readResults(ids, c.results) },
			"register-nodes": func() outcome { return registerResults(ids, ids, c.results, ua.StatusOK) },
		} {
			t.Run(op+"/"+c.name, func(t *testing.T) {
				res := mapping()
				if res.exit != c.exit {
					t.Fatalf("exit %d, want %d: %+v", res.exit, c.exit, res.err)
				}
				if c.exit == exitOK {
					if res.err != nil {
						t.Fatalf("error %+v", res.err)
					}
				} else if res.err == nil || res.err.Category != c.category {
					t.Fatalf("error %+v, want category %s", res.err, c.category)
				}
				if c.exit == exitInternal {
					return
				}
				if len(res.results) != len(ids) {
					t.Fatalf("%d results for %d nodes", len(res.results), len(ids))
				}
				second := res.results[1].(map[string]any)
				switch c.name {
				case "an empty result":
					if got := second["statusCode"].(statusJSON).Name; got != "BadUnknownResponse" {
						t.Errorf("statusCode %s", got)
					}
				case "Good without a value":
					if second["dataType"] != "Null" || second["builtInType"] != 0 || second["value"] != nil {
						t.Errorf("result %v", second)
					}
				}
			})
		}
	}
	if res := registerResults(ids, ids[:1], []*ua.DataValue{good, good}, ua.StatusOK); res.exit != exitInternal {
		t.Errorf("another number of aliases: exit %d", res.exit)
	}
}

// A command that stops with a runtime error ends as an internal failure, with a
// document, instead of ending the process.
func TestARuntimeErrorIsAnInternalFailure(t *testing.T) {
	cmd := command{
		validate: func() error { return nil },
		offline:  func() bool { return true },
		local: func() outcome {
			var results []any
			return outcome{results: results[:len(results)+1]}
		},
	}
	res := execute(cmd, &globals{})
	if res.exit != exitInternal || res.err == nil || res.err.Category != "internal" {
		t.Fatalf("exit %d: %+v", res.exit, res.err)
	}
}

func conditionEvent(name string) *ua.EventFieldList {
	fields := make([]*ua.Variant, 16)
	for i := range fields {
		fields[i] = &ua.Variant{}
	}
	fields[15] = ua.MustVariant(ua.NewStringNodeID(1, name))
	return &ua.EventFieldList{EventFields: fields}
}

func eventNotification(names ...string) *opcua.PublishNotificationData {
	list := &ua.EventNotificationList{}
	for _, name := range names {
		list.Events = append(list.Events, conditionEvent(name))
	}
	return &opcua.PublishNotificationData{Value: list}
}

// nextNames reads the conditions of r up to the deadline.
func nextNames(t *testing.T, r *alarmRun) []string {
	t.Helper()
	var names []string
	for {
		entry, _, err := r.next()
		if errors.Is(err, errNoEvent) {
			return names
		}
		if err != nil || entry == nil {
			t.Fatalf("next: %v, %v", entry, err)
		}
		names = append(names, strings.TrimPrefix(entry.ConditionID, "ns=1;s="))
	}
}

// The events of one notification are handed out in the order of the server, before
// those of the next notification, and then the deadline ends the wait.
func TestAlarmEventsKeepTheServerOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		notify := make(chan *opcua.PublishNotificationData, 2)
		notify <- eventNotification("a", "b", "c")
		notify <- eventNotification("d")
		r := &alarmRun{notify: notify, deadline: time.After(time.Second), latest: map[string]*conditionEntry{}}
		if got := nextNames(t, r); !slices.Equal(got, []string{"a", "b", "c", "d"}) {
			t.Errorf("events %v", got)
		}
		if len(r.latest) != 4 {
			t.Errorf("latest %v", r.latest)
		}
	})
}

// With the channel full and the subscription waiting to send the next notification,
// the reader still hands out every event and returns at the deadline.
func TestAlarmEventsOfAFullChannel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		notify := make(chan *opcua.PublishNotificationData, 1)
		notify <- eventNotification("a", "b", "c")
		go func() { notify <- eventNotification("d") }()
		synctest.Wait()
		r := &alarmRun{notify: notify, deadline: time.After(time.Second), latest: map[string]*conditionEntry{}}
		start := time.Now()
		if got := nextNames(t, r); !slices.Equal(got, []string{"a", "b", "c", "d"}) {
			t.Errorf("events %v", got)
		}
		if waited := time.Since(start); waited != time.Second {
			t.Errorf("returned after %v, want the deadline of 1s", waited)
		}
	})
}

// schemaCategories are the error categories of schemas/client-result.schema.json.
func schemaCategories(t *testing.T) []string {
	t.Helper()
	var raw []byte
	for _, path := range []string{"/schemas/client-result.schema.json", "../../schemas/client-result.schema.json"} {
		if b, err := os.ReadFile(path); err == nil {
			raw = b
			break
		}
	}
	if raw == nil {
		t.Skip("no schemas/client-result.schema.json (the image build copies only fixtures)")
	}
	var schema struct {
		Defs struct {
			ErrorObject struct {
				Properties struct {
					Category struct {
						Enum []string `json:"enum"`
					} `json:"category"`
				} `json:"properties"`
			} `json:"errorObject"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	enum := schema.Defs.ErrorObject.Properties.Category.Enum
	if len(enum) == 0 {
		t.Fatal("no category enum in $defs.errorObject of schemas/client-result.schema.json")
	}
	return enum
}

// Every category a failure of this adapter can have is one of the schema (§3).
func TestFailureCategoriesAreInTheSchema(t *testing.T) {
	enum := schemaCategories(t)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "failure" {
				return true
			}
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s: the category of failure is not a string literal", fset.Position(call.Pos()))
				return true
			}
			category, _ := strconv.Unquote(lit.Value)
			seen++
			if !slices.Contains(enum, category) {
				t.Errorf("%s: category %q is not in %v", fset.Position(call.Pos()), category, enum)
			}
			return true
		})
	}
	if seen == 0 {
		t.Fatal("no call of failure found")
	}
}

// dialFixture connects a client to an in-process fixture server.
func dialFixture(t *testing.T) *opcua.Client {
	t.Helper()
	g := &globals{endpoint: startFixtureServer(t), policy: "None", mode: "None", connect: 5, request: 5, disconnect: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, res := g.dial(ctx)
	if res != nil {
		t.Fatalf("dial: exit %d: %+v", res.exit, res.err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// A namespace URI the server does not have is input (§8, exit 2); a NamespaceArray
// that cannot be read in time is a timeout (exit 7), not input.
func TestNamespaceFailuresByCause(t *testing.T) {
	c := dialFixture(t)
	ref := func(s string) nodeRef {
		r, err := parseNodeRef(s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, res := resolve(ctx, c, ref("nsu=urn:none;s=x")); res == nil || res.exit != exitInput || res.err.Category != "input" {
		t.Errorf("unknown URI: %+v", res)
	}
	if id, res := resolve(ctx, c, ref(model+"Scalar.Int32")); res != nil || id.Namespace() == 0 {
		t.Errorf("known URI: %v, %+v", id, res)
	}
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if _, res := resolve(expired, c, ref(model+"Scalar.Int32")); res == nil || res.exit != exitTimeout || res.err.Category != "timeout" {
		t.Errorf("no time left: %+v", res)
	}
}

// dropOnRequest is a TCP proxy to a fixture server. Once armed, it closes a
// connection on the next bytes the client sends, without forwarding them: the
// request after arm fails on the connection.
func dropOnRequest(t *testing.T) (endpoint string, arm func()) {
	t.Helper()
	_, rest, _ := strings.Cut(startFixtureServer(t), "opc.tcp://")
	target, path, _ := strings.Cut(rest, "/")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var armed atomic.Bool
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				go func() { _, _ = io.Copy(conn, up) }()
				buf := make([]byte, 64*1024)
				for {
					n, err := conn.Read(buf)
					if err != nil || armed.Load() {
						return
					}
					if _, err := up.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return fmt.Sprintf("opc.tcp://%s/%s", l.Addr(), path), func() { armed.Store(true) }
}

// dialThrough connects a client to endpoint.
func dialThrough(t *testing.T, endpoint string) *opcua.Client {
	t.Helper()
	g := &globals{endpoint: endpoint, policy: "None", mode: "None", connect: 5, request: 5, disconnect: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, res := g.dial(ctx)
	if res != nil {
		t.Fatalf("dial: exit %d: %+v", res.exit, res.err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// A ConditionRefresh or a method call that fails on the connection is a transport
// failure (§5, exit 3), as for any other request, not a service failure.
func TestAlarmsKeepTheClassOfAFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	newRun := func(c *opcua.Client) *alarmRun {
		return &alarmRun{c: c, notify: make(chan *opcua.PublishNotificationData, 1), deadline: time.After(10 * time.Second), latest: map[string]*conditionEntry{}}
	}

	endpoint, arm := dropOnRequest(t)
	c := dialThrough(t, endpoint)
	arm()
	result := map[string]any{}
	res := newRun(c).run(ctx, c, &opcua.Subscription{SubscriptionID: 1}, result, []any{result}, alarmActions{})
	if res.exit != exitConnect || res.err == nil || res.err.Category != "transport" || len(res.results) != 1 {
		t.Fatalf("refresh: exit %d: %+v", res.exit, res.err)
	}

	endpoint, arm = dropOnRequest(t)
	c = dialThrough(t, endpoint)
	arm()
	r := newRun(c)
	target := &conditionEntry{ConditionID: "ns=1;s=Alarm"}
	r.latest[target.ConditionID] = target
	act, stop := r.perform(ctx, target, 9111, "x", func(*conditionEntry) bool { return true })
	if act == nil || stop == nil || stop.exit != exitConnect || stop.err.Category != "transport" {
		t.Fatalf("perform: %+v, %+v", act, stop)
	}
}

// A word that is not a flag is refused (§5, exit 2): the flags after it would be
// ignored.
func TestStrayArgumentsAreRefused(t *testing.T) {
	const nowhere = "opc.tcp://192.0.2.1:4840"
	for _, args := range [][]string{
		{"read", "--endpoint", nowhere, "--node", "i=85", "stray"},
		{"alarms", "--endpoint", nowhere, "--acknowledge", "yes", "--condition-name", "X", "--timeout-ms", "2000"},
	} {
		code, doc := client(t, args...)
		if code != exitInput || doc["error"].(map[string]any)["category"] != "input" {
			t.Errorf("%v: exit %d: %v", args, code, doc)
		}
	}
	if _, _, err := parseServerFlags([]string{"--fixture", "fixture.json", "stray", "--bind-port", "4841"}); err == nil {
		t.Error("server: a stray word was accepted")
	}
}

// §10: the ready file of a previous run is removed on startup, also when the
// server then does not start.
func TestStaleReadyFileIsRemoved(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	if err := os.WriteFile(ready, []byte(`{"ready":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := run([]string{"server", "--fixture", filepath.Join(t.TempDir(), "none.json"), "--ready-file", ready}, &out); code != exitFixture {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(ready); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ready file: %v", err)
	}
}
