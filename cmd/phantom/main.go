// Command phantom is the Phantom sensor entry point.
//
// The binary reads one config file: "phantom <path>" loads it and exits, and
// "phantom --check <path>" only validates it (FR-12). Both modes use the same
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
	fs := flag.NewFlagSet("phantom", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // The flag package prints a flag name raw, so run prints a fixed usage line.
	check := fs.Bool("check", false, "validate the config file and exit")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: phantom[--check] <config-path>")
		return 2
	}
	if _, err := loadWith(fs.Arg(0), env, netFor(*check)); err != nil {
		// The error is a joined list of *config.Error. Each one escapes its text and holds no secret value.
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *check {
		fmt.Fprintln(stdout, "phantom: config is valid")
		return 0
	}
	fmt.Fprintln(stdout, "phantom: config loaded — no listeners yet")
	return 0
}

// loadWith is the one load function of both modes. A test replaces it to see the Net.
var loadWith = config.LoadWith

// netFor returns the Net of the load: the system Net, or noNet for --check.
func netFor(check bool) config.Net {
	if check {
		return config.Net{Dialer: noNet{}, Resolver: noNet{}}
	}
	return config.SystemNet()
}

// noNet is the Dialer and the Resolver of --check: each call fails and uses no network.
type noNet struct{}

var errNoNet = errors.New("network access is not allowed with --check")

func (noNet) DialContext(context.Context, string, string) (net.Conn, error) { return nil, errNoNet }

func (noNet) LookupHost(context.Context, string) ([]string, error) { return nil, errNoNet }
