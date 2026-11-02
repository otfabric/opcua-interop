// SPDX-License-Identifier: MIT

// Command opcua-interop is the opcua-interop-otfabric image: go-opcua behind the
// client command contract (docs/CONTAINER_CONTRACT.md).
//
// It is OT Fabric's own stack, not an independent implementation: results
// against it are never independent evidence for go-opcua (README.md). It covers a
// core subset of the contract, and print-capabilities declares which.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const adapterName = "otfabric"

// Set with -ldflags by the Dockerfile.
var (
	adapterVersion   = "dev"
	upstreamVersion  = "dev"
	upstreamRevision = "dev"
)

// Exit codes (docs/CONTAINER_CONTRACT.md §5).
const (
	exitOK       = 0
	exitInput    = 2
	exitConnect  = 3
	exitService  = 4
	exitFixture  = 5
	exitInternal = 6
	exitTimeout  = 7
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: opcua-interop server|client|print-capabilities|version")
		return exitInput
	}
	switch args[0] {
	case "server":
		return runServer(args[1:])
	case "client":
		return runClient(args[1:], out)
	case "print-capabilities":
		if err := writeJSON(out, capabilities()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitInternal
		}
		return exitOK
	case "version":
		fmt.Fprintf(out, "%s %s (go-opcua %s, commit %s)\n", adapterName, adapterVersion, upstreamVersion, upstreamRevision)
		return exitOK
	}
	fmt.Fprintln(os.Stderr, "opcua-interop: unknown command", args[0])
	return exitInput
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
