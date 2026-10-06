// Command canary is the Agent Canary sensor entry point.
//
// The binary reads one config file: "canary <path>" loads it and starts, and
// "canary --check <path>" only validates it (FR-12). Both modes use the same
// load function. --check opens no socket and does no DNS lookup (SEC-11).
// The run loop is not part of the binary yet. The binary writes no files.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/cybagard/cyba-phantom/internal/config"
)

func main() {
	os.Exit(run(os.Args[1:], os.Environ(), os.Stdout, os.Stderr))
}

// run returns the exit code: 0 for a valid config, 1 for an invalid config, 2 for a usage error.
func run(args, env []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("canary", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "validate the config file and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: canary [--check] <config-path>")
		return 2
	}
	nw := config.Net{Dialer: &net.Dialer{}, Resolver: net.DefaultResolver}
	if *check {
		nw = config.Net{Dialer: noNet{}, Resolver: noNet{}}
	}
	if _, err := config.LoadWith(fs.Arg(0), env, nw); err != nil {
		fmt.Fprintln(stderr, err) // Each Error escapes its text and holds no secret value.
		return 1
	}
	if *check {
		fmt.Fprintln(stdout, "canary: config is valid")
		return 0
	}
	fmt.Fprintln(stdout, "canary: config loaded — no listeners yet")
	return 0
}

// noNet is the Dialer and the Resolver of --check: each call fails and uses no network.
type noNet struct{}

var errNoNet = errors.New("network access is not allowed with --check")

func (noNet) DialContext(context.Context, string, string) (net.Conn, error) { return nil, errNoNet }

func (noNet) LookupHost(context.Context, string) ([]string, error) { return nil, errNoNet }
