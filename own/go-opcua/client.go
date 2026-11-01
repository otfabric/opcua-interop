// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
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
}

func seconds(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// validate checks what needs no network.
func (g *globals) validate() error {
	if g.endpoint == "" {
		return errors.New("--endpoint is required")
	}
	if !slices.Contains(securityProfiles, securityProfile{g.policy, g.mode}) {
		return fmt.Errorf("security policy %s with mode %s is not declared by this image", g.policy, g.mode)
	}
	if g.policy != "None" && (g.cert == "" || g.key == "") {
		return errors.New("--certificate and --private-key are required with a security policy")
	}
	return nil
}

// command is one client operation.
type command struct {
	validate func() error
	run      func(ctx context.Context, c *opcua.Client) outcome
	// discovery runs without a session.
	discovery func(ctx context.Context) outcome
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
	if cmd, ok := commandFor(op, g, fs); !ok {
		res = inputError("operation " + op + " is not provided by this image (print-capabilities)")
	} else if err := fs.Parse(args[1:]); err != nil {
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
	}
	return command{}, false
}

func execute(cmd command, g *globals) outcome {
	if err := g.validate(); err != nil {
		return inputError(err.Error())
	}
	if cmd.validate != nil {
		if err := cmd.validate(); err != nil {
			return inputError(err.Error())
		}
	}
	connectCtx, cancel := context.WithTimeout(context.Background(), seconds(g.connect))
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
		if err := c.Close(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "close:", err)
		}
	}()
	ctx, cancel2 := context.WithTimeout(context.Background(), seconds(g.request))
	defer cancel2()
	return cmd.run(ctx, c)
}

// dial selects the endpoint of exactly the requested policy and mode (§9) and
// connects to --endpoint, not to the URL the server advertises: a server behind a
// published port knows itself under another name.
func (g *globals) dial(ctx context.Context) (*opcua.Client, *outcome) {
	endpoints, err := opcua.GetEndpoints(ctx, g.endpoint, opcua.DialTimeout(seconds(g.connect)))
	if err != nil {
		res := classifyConnect(err)
		return nil, &res
	}
	wantPolicy, wantMode := ua.FormatSecurityPolicyURI(g.policy), ua.MessageSecurityModeFromString(g.mode)
	var chosen *ua.EndpointDescription
	for _, ep := range endpoints {
		if ep.SecurityPolicyURI == wantPolicy && ep.SecurityMode == wantMode &&
			(ep.TransportProfileURI == "" || ep.TransportProfileURI == ua.TransportProfileUATCP) {
			chosen = ep
			break
		}
	}
	if chosen == nil {
		res := failure(exitConnect, "transport", fmt.Sprintf("the server has no endpoint %s/%s", g.policy, g.mode), ua.StatusBadSecurityPolicyRejected)
		return nil, &res
	}
	chosen.EndpointURL = g.endpoint

	opts := []opcua.Option{
		opcua.DialTimeout(seconds(g.connect)),
		opcua.RequestTimeout(seconds(g.request)),
		opcua.AutoReconnect(false),
	}
	if g.lifetimeMS > 0 {
		opts = append(opts, opcua.Lifetime(time.Duration(g.lifetimeMS)*time.Millisecond))
	}
	if g.policy == "None" {
		opts = append(opts, opcua.InsecureNoSecurity())
	}
	if g.cert != "" && g.key != "" {
		cert, err := readDER(g.cert)
		if err != nil {
			res := failure(exitInternal, "internal", err.Error(), ua.StatusBadInternalError)
			return nil, &res
		}
		key, err := readRSAKey(g.key)
		if err != nil {
			res := failure(exitInternal, "internal", err.Error(), ua.StatusBadInternalError)
			return nil, &res
		}
		opts = append(opts, opcua.Certificate(cert), opcua.PrivateKey(key))
	}
	if len(g.trust) > 0 {
		certs := make([]*x509.Certificate, 0, len(g.trust))
		for _, path := range g.trust {
			der, err := readDER(path)
			if err == nil {
				var cert *x509.Certificate
				if cert, err = x509.ParseCertificate(der); err == nil {
					certs = append(certs, cert)
				}
			}
			if err != nil {
				res := failure(exitInternal, "internal", path+": "+err.Error(), ua.StatusBadInternalError)
				return nil, &res
			}
		}
		opts = append(opts, opcua.TrustedCertificates(certs...))
	} else {
		// §9: without --trust-list every certificate is accepted.
		opts = append(opts, opcua.InsecureSkipVerify())
	}
	if g.userSet {
		opts = append(opts, opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeUserName), opcua.AuthUsername(g.user, g.password))
	} else {
		opts = append(opts, opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeAnonymous), opcua.AuthAnonymous())
	}

	c, err := opcua.NewClient(g.endpoint, opts...)
	if err != nil {
		res := failure(exitInternal, "internal", err.Error(), ua.StatusBadInternalError)
		return nil, &res
	}
	if err := c.Connect(ctx); err != nil {
		res := classifyConnect(err)
		return nil, &res
	}
	return c, nil
}

// classifyConnect is classify for the time before a session exists, where running
// out of time is a transport failure (§3: hello timeout).
func classifyConnect(err error) outcome {
	res := classify(err)
	if res.exit == exitTimeout {
		return failure(exitConnect, "transport", err.Error(), res.status)
	}
	return res
}

func (g *globals) endpoints(ctx context.Context) outcome {
	eps, err := opcua.GetEndpoints(ctx, g.endpoint, opcua.DialTimeout(seconds(g.connect)))
	if err != nil {
		return classifyConnect(err)
	}
	results := make([]any, len(eps))
	for i, ep := range eps {
		results[i] = map[string]any{"url": ep.EndpointURL, "securityPolicy": ep.SecurityPolicyURI, "securityMode": modeName(ep.SecurityMode)}
	}
	return outcome{status: ua.StatusOK, results: results}
}

func modeName(m ua.MessageSecurityMode) string {
	return strings.TrimPrefix(m.String(), "MessageSecurityMode")
}

func (g *globals) findServers(ctx context.Context) outcome {
	apps, err := opcua.FindServers(ctx, g.endpoint, opcua.DialTimeout(seconds(g.connect)))
	if err != nil {
		return classifyConnect(err)
	}
	results := make([]any, len(apps))
	for i, app := range apps {
		urls := app.DiscoveryURLs
		if urls == nil {
			urls = []string{}
		}
		results[i] = map[string]any{"applicationUri": app.ApplicationURI, "applicationName": localizedText(app.ApplicationName), "productUri": app.ProductURI, "discoveryUrls": urls}
	}
	return outcome{status: ua.StatusOK, results: results}
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

func subscribeCommand(fs *flag.FlagSet) command {
	node := fs.String("node", "", "node to monitor")
	publishing := fs.Int64("publishing-interval-ms", 500, "publishing interval")
	sampling := fs.Int64("sampling-interval-ms", 100, "sampling interval")
	count := fs.Int("notifications", 5, "notifications to collect")
	timeoutMS := fs.Int64("timeout-ms", 10000, "command timeout")
	queueSize := fs.Uint("queue-size", 1, "queue size")
	discardOldest := fs.String("discard-oldest", "true", "queue overflow policy")
	timestamps := fs.String("timestamps", "Both", "TimestampsToReturn")
	absolute := fs.Float64("deadband-absolute", 0, "absolute deadband")
	percent := fs.Float64("deadband-percent", 0, "percent deadband")
	trigger := fs.String("trigger", "StatusValue", "DataChangeFilter trigger")
	set := map[string]bool{}
	var ref nodeRef
	var ts ua.TimestampsToReturn
	var triggerValue ua.DataChangeTrigger
	return command{
		validate: func() (err error) {
			fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
			if set["deadband-absolute"] && set["deadband-percent"] {
				return errors.New("--deadband-absolute and --deadband-percent exclude each other")
			}
			var ok bool
			if ts, ok = map[string]ua.TimestampsToReturn{"Source": ua.TimestampsToReturnSource, "Server": ua.TimestampsToReturnServer, "Both": ua.TimestampsToReturnBoth, "Neither": ua.TimestampsToReturnNeither}[*timestamps]; !ok {
				return errors.New("--timestamps: " + *timestamps)
			}
			if triggerValue, ok = map[string]ua.DataChangeTrigger{"Status": ua.DataChangeTriggerStatus, "StatusValue": ua.DataChangeTriggerStatusValue, "StatusValueTimestamp": ua.DataChangeTriggerStatusValueTimestamp}[*trigger]; !ok {
				return errors.New("--trigger: " + *trigger)
			}
			ref, err = parseNodeRef(*node)
			return err
		},
		run: func(requestCtx context.Context, c *opcua.Client) outcome {
			nodeID, failed := resolve(requestCtx, c, ref)
			if failed != nil {
				return *failed
			}
			notify := make(chan *opcua.PublishNotificationData, 64)
			sub, err := c.Subscribe(requestCtx, &opcua.SubscriptionParameters{Interval: time.Duration(*publishing) * time.Millisecond}, notify)
			if err != nil {
				return classify(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = sub.Cancel(ctx)
			}()

			// A filter only when one was asked for: the result then says so (§4).
			var filter *ua.DataChangeFilter
			deadbandName := "None"
			if set["deadband-absolute"] || set["deadband-percent"] || set["trigger"] {
				filter = &ua.DataChangeFilter{Trigger: triggerValue, DeadbandType: uint32(ua.DeadbandTypeNone)}
				switch {
				case set["deadband-absolute"]:
					filter.DeadbandType, filter.DeadbandValue, deadbandName = uint32(ua.DeadbandTypeAbsolute), *absolute, "Absolute"
				case set["deadband-percent"]:
					filter.DeadbandType, filter.DeadbandValue, deadbandName = uint32(ua.DeadbandTypePercent), *percent, "Percent"
				}
			}
			params := &ua.MonitoringParameters{
				ClientHandle: 1, SamplingInterval: float64(*sampling),
				QueueSize: uint32(*queueSize), DiscardOldest: *discardOldest != "false",
			}
			if filter != nil {
				params.Filter = ua.NewExtensionObject(filter)
			}
			resp, err := sub.Monitor(requestCtx, ts, &ua.MonitoredItemCreateRequest{
				ItemToMonitor:       &ua.ReadValueID{NodeID: nodeID, AttributeID: ua.AttributeIDValue},
				MonitoringMode:      ua.MonitoringModeReporting,
				RequestedParameters: params,
			})
			if err != nil {
				return classify(err)
			}
			item := resp.Results[0]

			result := map[string]any{
				"nodeId":                    nodeIDString(nodeID),
				"subscriptionId":            sub.SubscriptionID,
				"revisedPublishingInterval": float64(sub.RevisedPublishingInterval / time.Millisecond),
				"revisedLifetimeCount":      sub.RevisedLifetimeCount,
				"revisedMaxKeepAliveCount":  sub.RevisedMaxKeepAliveCount,
				"monitoredItemStatusCode":   statusOf(item.StatusCode),
			}
			if filter != nil {
				result["monitoredItemId"] = item.MonitoredItemID
				result["revisedSamplingInterval"] = item.RevisedSamplingInterval
				result["revisedQueueSize"] = item.RevisedQueueSize
				result["filter"] = map[string]any{"trigger": *trigger, "deadbandType": deadbandName, "deadbandValue": filter.DeadbandValue}
				result["filterResult"] = nil
				if item.FilterResult != nil && item.FilterResult.TypeID != nil {
					result["filterResult"] = map[string]any{"typeId": item.FilterResult.TypeID.String()}
				}
			}
			result["notifications"] = []any{}
			results := []any{result}
			if !isGood(item.StatusCode) {
				return serviceBad(item.StatusCode, results)
			}

			notifications, res := collect(notify, *count, time.Duration(*timeoutMS)*time.Millisecond)
			result["notifications"] = notifications
			res.results = results
			return res
		},
	}
}

// collect reads data-change notifications until there are enough, or the timeout
// has passed. The sequence number is the position in the result: go-opcua does not
// hand out the one of the NotificationMessage.
func collect(notify <-chan *opcua.PublishNotificationData, count int, timeout time.Duration) ([]any, outcome) {
	deadline := time.After(timeout)
	notifications := []any{}
	for len(notifications) < count {
		select {
		case msg := <-notify:
			if msg.Error != nil {
				return notifications, classify(msg.Error)
			}
			change, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, item := range change.MonitoredItems {
				if len(notifications) == count {
					break
				}
				notifications = append(notifications, notification(len(notifications)+1, item.Value))
			}
		case <-deadline:
			res := failure(exitTimeout, "timeout", fmt.Sprintf("%d of %d notifications after %v", len(notifications), count, timeout), ua.StatusBadTimeout)
			return notifications, res
		}
	}
	return notifications, outcome{status: ua.StatusOK}
}

func notification(sequence int, dv *ua.DataValue) map[string]any {
	n := map[string]any{"sequenceNumber": sequence, "statusCode": statusOf(dv.Status), "value": encodeValue(dv.Value)}
	if dv.Value != nil && dv.Value.Value() != nil {
		n["dataType"] = typeName(uint32(dv.Value.Type()))
		n["builtInType"] = int(dv.Value.Type())
	}
	if !dv.SourceTimestamp.IsZero() {
		n["sourceTimestamp"] = timeString(dv.SourceTimestamp)
	}
	if !dv.ServerTimestamp.IsZero() {
		n["serverTimestamp"] = timeString(dv.ServerTimestamp)
	}
	return n
}
