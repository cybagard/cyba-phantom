// Command phantom is the Phantom sensor entry point.
//
// The binary reads one config file. "phantom <path>" loads it and binds the two listen sockets.
// It starts the store, the writer and the checkpointer. It starts the certificate client
// and the decoy listener. Then it waits for SIGINT or SIGTERM.
// "phantom --check <path>" only validates the file (FR-12). Both modes use the same load function.
// Both modes read acme.ca_root and the tls.certs files and name a bad key.
// --check prints each private list entry with its key path.
// --check opens no socket, no state directory, no store and no log, and does no DNS lookup (SEC-11).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/listener"
	"github.com/cybagard/cyba-phantom/internal/safefile"
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
		fmt.Fprintln(stderr, "usage: phantom [--check] <config-path>")
		return 2
	}
	cfg, err := loadWith(fs.Arg(0), env, netFor(*check))
	if err != nil {
		// The error is a joined list of *config.Error. Each one escapes
		// its text and holds no secret value. LoadWith gives a plain
		// error when the Dialer or the Resolver of the Net is nil.
		// netFor always sets both.
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !checkContent(cfg, time.Now(), stderr) {
		return 1
	}
	if *check {
		printPrivateLists(cfg, stdout)
		fmt.Fprintln(stdout, "phantom: config is valid")
		return 0
	}
	return serve(cfg, stdout, stderr)
}

// serve runs the sensor until SIGINT or SIGTERM (see serveWith). A test replaces it.
// serve sets the signal handler before the start, so it catches a signal
// during the start.
var serve = func(cfg *config.Config, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	p, d := serveSetup(paramsOf(cfg))
	return serveWith(ctx, stop, cfg, p, d, stdout, stderr)
}

// printPrivateLists writes one line for each entry of each private list.
// The line has the key path and the canonical prefix of the entry.
func printPrivateLists(cfg *config.Config, w io.Writer) {
	paths := []string{"acme.ca_private", "bundle.fetch_private"}
	for _, list := range []string{"tlog.publish", "alerts.sinks"} {
		for i := 0; ; i++ {
			item := fmt.Sprintf("%s[%d]", list, i)
			if _, ok := cfg.Get(item + ".type"); !ok {
				break
			}
			paths = append(paths, item+".private")
		}
	}
	for _, path := range paths {
		for i, pfx := range cfg.PrivateList(path) {
			fmt.Fprintf(w, "%s[%d]: %s\n", path, i, pfx)
		}
	}
}

// The rules of the files. They are the rules of the config loader. The key
// file also has no other read. checkContent applies them again to the file
// that it reads.
var (
	parentRule  = safefile.Rule{Type: safefile.Dir, Owner: safefile.OwnerSelfOrRoot, Forbid: 0o022}
	pemRule     = safefile.Rule{Type: safefile.Regular, Owner: safefile.OwnerSelfOrRoot, FollowEnd: true, MaxSize: 64 << 10, Forbid: 0o022}
	keyFileRule = safefile.Rule{Type: safefile.Regular, Owner: safefile.OwnerSelfOrRoot, FollowEnd: true, MaxSize: 64 << 10, Forbid: 0o026}
)

// readPEM reads a file with the rules of the loader. Its error has no path.
func readPEM(path string, rule safefile.Rule) ([]byte, error) {
	if err := safefile.CheckPathParents(path, parentRule); err != nil {
		return nil, err
	}
	f, fi, err := safefile.OpenPath(path, rule)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return safefile.ReadAll(f, fi, rule)
}

// keyForms is the text of the accepted key forms.
const keyForms = "the key file has one block of type PRIVATE KEY (PKCS8), RSA PRIVATE KEY (PKCS1) or EC PRIVATE KEY (SEC1)"

// staticLine returns the line for an error of ParseStatic. It names the key
// that can cause the error: one file, or the entry when both files can.
func staticLine(entry string, err error) string {
	switch {
	case errors.Is(err, listener.ErrStaticKey):
		return "phantom: " + entry + ".key_file: " + err.Error() + "; " + keyForms
	case errors.Is(err, listener.ErrStaticCert), errors.Is(err, listener.ErrStaticCA),
		errors.Is(err, listener.ErrStaticKeyKind), errors.Is(err, listener.ErrStaticName),
		errors.Is(err, listener.ErrStaticNotYet), errors.Is(err, listener.ErrStaticExpired):
		return "phantom: " + entry + ".cert_file: " + err.Error()
	}
	return "phantom: " + entry + ": " + err.Error()
}

// checkContent reads acme.ca_root and the files of each tls.certs entry and
// parses them at now. For each failing key it writes one line to stderr with
// the key path and a fixed text. It does not stop at the first failure.
// It returns false when one key failed. It keeps no parsed value.
func checkContent(cfg *config.Config, now time.Time, stderr io.Writer) bool {
	ok := true
	fail := func(line string) {
		fmt.Fprintln(stderr, line)
		ok = false
	}
	read := func(key, path string, rule safefile.Rule) ([]byte, bool) {
		b, err := readPEM(path, rule)
		if err != nil {
			fail("phantom: " + key + ": the file cannot be read")
		}
		return b, err == nil
	}
	if v, _ := cfg.Get("acme.ca_root"); v.Str != "" {
		if data, got := read("acme.ca_root", v.Str, pemRule); got {
			if _, err := listener.ParseACMERoots(data); err != nil {
				fail("phantom: acme.ca_root: " + err.Error())
			}
		}
	}
	for i := 0; ; i++ {
		entry := fmt.Sprintf("tls.certs[%d]", i)
		name, found := cfg.Get(entry + ".name")
		if !found {
			break
		}
		cf, _ := cfg.Get(entry + ".cert_file")
		kf, _ := cfg.Get(entry + ".key_file")
		certPEM, certOK := read(entry+".cert_file", cf.Str, pemRule)
		keyPEM, keyOK := read(entry+".key_file", kf.Str, keyFileRule)
		if !certOK || !keyOK {
			continue
		}
		if _, err := listener.ParseStatic(name.Str, certPEM, keyPEM, now); err != nil {
			fail(staticLine(entry, err))
		}
	}
	return ok
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
