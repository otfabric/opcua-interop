// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// cliError is the `error` member of the envelope (§3).
type cliError struct {
	Category string `json:"category"`
	Message  string `json:"message"`
}

// envelope is the one JSON object a client command writes (§3).
type envelope struct {
	SchemaVersion string     `json:"schemaVersion"`
	Adapter       string     `json:"adapter"`
	Operation     string     `json:"operation"`
	Success       bool       `json:"success"`
	ServiceResult statusJSON `json:"serviceResult"`
	Results       []any      `json:"results"`
	Error         *cliError  `json:"error"`
}

// outcome is what an operation ends with.
type outcome struct {
	status  ua.StatusCode
	results []any
	exit    int
	err     *cliError
}

func failure(exit int, category, message string, status ua.StatusCode) outcome {
	return outcome{status: status, exit: exit, err: &cliError{category, message}}
}

func inputError(message string) outcome {
	return failure(exitInput, "input", message, ua.StatusBadInvalidArgument)
}

// classify maps an error of the stack to an outcome. Whatever the server answered
// with a status is a service failure, also while connecting, except the status
// codes that mean the connection is gone.
func classify(err error) outcome {
	var status ua.StatusCode
	if errors.As(err, &status) {
		switch status {
		case ua.StatusBadTimeout, ua.StatusBadRequestTimeout:
			return failure(exitTimeout, "timeout", err.Error(), status)
		case ua.StatusBadCommunicationError, ua.StatusBadConnectionRejected, ua.StatusBadConnectionClosed,
			ua.StatusBadNotConnected, ua.StatusBadSecureChannelClosed, ua.StatusBadTCPEndpointURLInvalid:
			return failure(exitConnect, "transport", err.Error(), status)
		}
		return failure(exitService, "service", err.Error(), status)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return failure(exitTimeout, "timeout", err.Error(), ua.StatusBadTimeout)
	}
	return failure(exitConnect, "transport", err.Error(), ua.StatusBadCommunicationError)
}

// globals are the flags of every command (§1).
type globals struct {
	endpoint, policy, mode, cert, key, user string
	password                                string
	userSet                                 bool
	trust                                   repeated
	connect, request, disconnect            float64
	lifetimeMS                              int64
	userCert, userKey                       string
	reverseListen                           int
	reverseTimeoutMS                        int64
	reverseServerURI                        string
	listener                                *uacp.ReverseListener
	// positional takes the first word after the operation (`codec encode`).
	positional func(word string) bool
}

func (g *globals) define(fs *flag.FlagSet) {
	fs.StringVar(&g.endpoint, "endpoint", "", "OPC UA endpoint URL")
	fs.StringVar(&g.policy, "security-policy", "None", "security policy")
	fs.StringVar(&g.mode, "security-mode", "None", "security mode")
	fs.StringVar(&g.cert, "certificate", "", "application certificate")
	fs.StringVar(&g.key, "private-key", "", "private key")
	fs.Var(&g.trust, "trust-list", "trusted certificate, repeatable")
	fs.StringVar(&g.user, "username", "", "user name")
	fs.StringVar(&g.password, "password", "", "password")
	fs.Float64Var(&g.connect, "connect-timeout", 5, "connection timeout in seconds")
	fs.Float64Var(&g.request, "request-timeout", 5, "request timeout in seconds")
	fs.Float64Var(&g.disconnect, "disconnect-timeout", 2, "disconnect timeout in seconds")
	fs.Int64Var(&g.lifetimeMS, "channel-lifetime-ms", 0, "requested SecureChannel lifetime")
	fs.StringVar(&g.userCert, "user-certificate", "", "certificate of an X509IdentityToken")
	fs.StringVar(&g.userKey, "user-private-key", "", "private key of the user certificate")
	fs.IntVar(&g.reverseListen, "reverse-listen", 0, "wait for the server's ReverseHello on this port")
	fs.Int64Var(&g.reverseTimeoutMS, "reverse-timeout-ms", 30000, "how long to wait for the reverse connection")
	fs.StringVar(&g.reverseServerURI, "reverse-server-uri", "", "required ServerArray[0] of the server that dials in")
}

func seconds(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// validate checks what needs no network.
func (g *globals) validate() error {
	if g.endpoint == "" {
		return errors.New("--endpoint is required")
	}
	if g.isReverse() && g.isTLS() {
		return errors.New("--reverse-listen is for opc.tcp")
	}
	if !slices.Contains(securityProfiles, securityProfile{g.policy, g.mode}) {
		return fmt.Errorf("security policy %s with mode %s is not declared by this image", g.policy, g.mode)
	}
	if g.policy != "None" && (g.cert == "" || g.key == "") {
		return errors.New("--certificate and --private-key are required with a security policy")
	}
	if (g.userCert == "") != (g.userKey == "") {
		return errors.New("--user-certificate and --user-private-key go together")
	}
	if g.userCert != "" && g.userSet {
		return errors.New("--user-certificate and --username exclude each other")
	}
	return nil
}

// command is one client operation.
type command struct {
	validate func() error
	run      func(ctx context.Context, c *opcua.Client) outcome
	// discovery runs without a session.
	discovery func(ctx context.Context) outcome
	// offline says that this call needs no server, and local runs it.
	offline func() bool
	local   func() outcome
	// budget replaces the request timeout as the time of the whole command, for a
	// command of many requests. The timeout still applies to each request.
	budget func() time.Duration
}

func runClient(args []string, out io.Writer) int {
	op := ""
	if len(args) > 0 {
		op = args[0]
	}
	g := &globals{}
	fs := flag.NewFlagSet("client "+op, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	g.define(fs)
	var res outcome
	cmd, ok := commandFor(op, g, fs)
	var words []string
	if len(args) > 1 {
		words = presenceFlags(args[1:])
		if g.positional != nil && len(words) > 0 && g.positional(words[0]) {
			words = words[1:]
		}
	}
	if !ok {
		res = inputError("operation " + op + " is not provided by this image (print-capabilities)")
	} else if err := fs.Parse(words); err != nil {
		res = inputError(err.Error())
	} else {
		fs.Visit(func(f *flag.Flag) { g.userSet = g.userSet || f.Name == "username" })
		res = execute(cmd, g)
	}

	results := res.results
	if results == nil {
		results = []any{}
	}
	if err := writeJSON(out, envelope{"1.0", adapterName, op, res.err == nil, statusOf(res.status), results, res.err}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitInternal
	}
	return res.exit
}

func commandFor(op string, g *globals, fs *flag.FlagSet) (command, bool) {
	switch op {
	case "endpoints":
		return command{discovery: g.endpoints}, true
	case "find-servers":
		return command{discovery: g.findServers}, true
	case "read":
		return readCommand(fs), true
	case "write":
		return writeCommand(fs), true
	case "browse":
		return browseCommand(fs), true
	case "call":
		return callCommand(fs), true
	case "subscribe":
		return subscribeCommand(fs), true
	case "register-nodes":
		return registerCommand(fs), true
	case "event-subscribe":
		return eventSubscribeCommand(fs), true
	case "alarms":
		return alarmsCommand(fs), true
	case "history-read":
		return historyReadCommand(fs), true
	case "history-read-events":
		return historyReadEventsCommand(fs), true
	case "history-update-events":
		return historyUpdateEventsCommand(fs), true
	case "codec":
		return codecCommand(fs, g), true
	case "push":
		return pushCommand(fs), true
	case "gds-pull":
		return gdsCommand(fs), true
	}
	return command{}, false
}

// presenceFlags writes the presence flags that may be followed by true or false
// (§1) in the one form the flag package reads.
func presenceFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		out = append(out, args[i])
		switch args[i] {
		case "--acknowledge", "--confirm", "--add-comment", "--release-continuation-point":
			if i+1 < len(args) {
				switch args[i+1] {
				case "true", "false", "1", "0":
					out[len(out)-1] = args[i] + "=" + args[i+1]
					i++
				}
			}
		}
	}
	return out
}

func execute(cmd command, g *globals) outcome {
	defer g.close()
	if cmd.validate != nil && cmd.offline != nil {
		if err := cmd.validate(); err != nil {
			return inputError(err.Error())
		}
		if cmd.offline() {
			return cmd.local()
		}
	}
	if err := g.validate(); err != nil {
		return inputError(err.Error())
	}
	if cmd.validate != nil && cmd.offline == nil {
		if err := cmd.validate(); err != nil {
			return inputError(err.Error())
		}
	}
	connectCtx, cancel := context.WithTimeout(context.Background(), g.connectTime())
	defer cancel()
	if cmd.discovery != nil {
		return cmd.discovery(connectCtx)
	}
	c, res := g.dial(connectCtx)
	if res != nil {
		return *res
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), seconds(g.disconnect))
		defer cancel()
		logClose(c.Close(ctx))
	}()
	limit := seconds(g.request)
	if cmd.budget != nil {
		limit = cmd.budget()
	}
	ctx, cancel2 := context.WithTimeout(context.Background(), limit)
	defer cancel2()
	return cmd.run(ctx, c)
}

// resolve gives the NodeId on this server, or the failure of §8.
func resolve(ctx context.Context, c *opcua.Client, ref nodeRef) (*ua.NodeID, *outcome) {
	if ref.uri == "" {
		return ref.id, nil
	}
	ns, err := c.FindNamespace(ctx, ref.uri)
	if err != nil {
		res := inputError("unknown namespace URI " + ref.uri + ": " + err.Error())
		return nil, &res
	}
	if err := ref.id.SetNamespace(ns); err != nil {
		res := inputError(err.Error())
		return nil, &res
	}
	return ref.id, nil
}

func resolveAll(ctx context.Context, c *opcua.Client, refs []nodeRef) ([]*ua.NodeID, *outcome) {
	ids := make([]*ua.NodeID, len(refs))
	for i, ref := range refs {
		id, res := resolve(ctx, c, ref)
		if res != nil {
			return nil, res
		}
		ids[i] = id
	}
	return ids, nil
}

// parseRefs is the flag parser of a list of --node arguments.
func parseRefs(args []string) ([]nodeRef, error) {
	if len(args) == 0 {
		return nil, errors.New("--node is required")
	}
	refs := make([]nodeRef, len(args))
	for i, arg := range args {
		ref, err := parseNodeRef(arg)
		if err != nil {
			return nil, err
		}
		refs[i] = ref
	}
	return refs, nil
}

// serviceBad is the outcome of an item that is not Good while the service was.
func serviceBad(status ua.StatusCode, results []any) outcome {
	res := failure(exitService, "service", status.Error(), status)
	res.results = results
	return res
}
