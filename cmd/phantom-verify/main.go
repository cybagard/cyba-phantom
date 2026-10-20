// Command phantom-verify checks a signed checkpoint of the Phantom log, and
// optionally that an event is in the log (SEC-18, 04 §7).
//
// The command keeps the last accepted checkpoint of the key as its state. It
// refuses a checkpoint that is not consistent with the state. The command opens
// no network connection. Of the packages of this repository, it imports only
// internal/verify and internal/tlog/verifier. It also imports
// golang.org/x/mod/sumdb/note. Exit code 0 means verified. Exit code 1 means
// not verified. Exit code 2 means a usage error, an input error, a state fault,
// an output error, or an internal error. Error text is fixed and holds no input bytes: no path, no
// flag value, no file content.
package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/tlog/verifier"
	"github.com/cybagard/cyba-phantom/internal/verify"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `usage: phantom-verify --key <vkey file> --checkpoint <note file>
                      [--event <event file> --proof <proof file>]
                      [--prior <note file>] [--consistency <proof file>]...
                      [--state <dir>]`

// errSameSizes is the error for two --consistency files with the same sizes.
// The check for a proof uses the first file whose sizes match, so a second file
// with the same sizes is not allowed.
var errSameSizes = errors.New(sameSizesText)

// sameSizesText is the text of errSameSizes. The refusal for it uses the same
// text.
const sameSizesText = "two consistency proof files have the same sizes"

// refusals maps each error to its exit code and its fixed message. The message
// holds no input bytes. Only ErrFork says "fork". The message of ErrFork says
// that a fork is one cause, because a bad consistency proof file gives the same
// error.
var refusals = []struct {
	err  error
	code int
	msg  string
}{
	{verify.ErrNotVerified, 1, "not verified: the event is not in the tree of the checkpoint"},
	{verify.ErrFork, 1, "not consistent: a fork of the log, or a bad consistency proof"},
	{verify.ErrTreeSize, 1, "not verified: the proof tree size is larger than the checkpoint size"},
	{verify.ErrSignature, 1, "not verified: the checkpoint signature does not verify with the key"},
	{verify.ErrTooLarge, 2, "input error: an input is larger than its size cap"},
	{verify.ErrRead, 2, "input error: an input cannot be read"},
	{verify.ErrKey, 2, "input error: the key file is not a valid key"},
	{verify.ErrCheckpoint, 2, "input error: a checkpoint note is not valid"},
	{verify.ErrEvent, 2, "input error: the event is not one canonical JSON object"},
	{verify.ErrProof, 2, "input error: a proof file is not valid"},
	{verify.ErrRange, 2, "input error: a size or an index is outside 0 to 2^48"},
	{verify.ErrNoProof, 2, "input error: no consistency proof file has the needed sizes"},
	{errSameSizes, 2, "input error: " + sameSizesText},
	{verify.ErrStateLocked, 2, "state fault: another run holds the state lock"},
	{verify.ErrStateSync, 2, "state fault: the state was written, but the directory sync failed"},
	{verify.ErrState, 2, "state fault: the state cannot be used"},
	{verify.ErrStateChanged, 2, "state fault: the state changed during the run"},
}

// list is a flag that can repeat.
type list []string

func (l *list) String() string     { return "" }
func (l *list) Set(s string) error { *l = append(*l, s); return nil }

// run is the command. It returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("phantom-verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // The flag package prints a flag name raw, so run prints a fixed usage text.
	keyPath := fs.String("key", "", "")
	cpPath := fs.String("checkpoint", "", "")
	eventPath := fs.String("event", "", "")
	proofPath := fs.String("proof", "", "")
	priorPath := fs.String("prior", "", "")
	var consPaths list
	fs.Var(&consPaths, "consistency", "")
	statePath := fs.String("state", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *keyPath == "" || *cpPath == "" ||
		(*eventPath == "") != (*proofPath == "") {
		fmt.Fprintln(stderr, usage)
		return 2
	}

	out, stateLine, err := verifyAll(inputs{
		key: *keyPath, checkpoint: *cpPath, event: *eventPath, proof: *proofPath,
		prior: *priorPath, stateDir: *statePath, consistency: consPaths,
	})
	if err != nil {
		if stateLine != "" {
			// The state changed before a later check refused, or the directory
			// sync failed after the write. Stdout stays empty.
			fmt.Fprintln(stderr, stateLine)
		}
		for _, r := range refusals {
			if errors.Is(err, r.err) {
				fmt.Fprintln(stderr, "phantom-verify: "+r.msg)
				return r.code
			}
		}
		fmt.Fprintln(stderr, "phantom-verify: internal error")
		return 2
	}
	if _, err := stdout.Write(out); err != nil {
		// The state is already written. The user must still see its line.
		fmt.Fprintln(stderr, stateLine)
		fmt.Fprintln(stderr, "phantom-verify: output error: stdout cannot be written")
		return 2
	}
	return 0
}

// stateLines are the fixed lines for the state.
var stateLines = map[verify.StateChange]string{
	verify.StateFirstUse:  "no earlier checkpoint was known; the checkpoint is now the state",
	verify.StateUpdated:   "updated",
	verify.StateUnchanged: "unchanged",
}

// inputs holds the paths that the flags name. An empty path is a flag that is
// not set.
type inputs struct {
	key, checkpoint, event, proof, prior, stateDir string
	consistency                                    []string
}

// sizePair is the old size and the new size of a consistency proof.
type sizePair struct{ oldSize, newSize int64 }

// verifyAll reads and checks the inputs. It returns the text for stdout. The
// text is empty unless every check passes. The state line is not empty once the
// state is checked and written. If a later check refuses, or the directory sync
// fails after the write, run prints it to stderr.
func verifyAll(in inputs) ([]byte, string, error) {
	v, err := load(in.key, verify.ReadKey)
	if err != nil {
		return nil, "", err
	}
	var latest bytes.Buffer
	c, err := loadNote(in.checkpoint, v, &latest)
	if err != nil {
		return nil, "", err
	}
	var out bytes.Buffer
	line := func(name, value string) { fmt.Fprintf(&out, "%s: %s\n", name, value) }
	b64 := func(h [32]byte) string { return base64.StdEncoding.EncodeToString(h[:]) }
	line("origin", escape(c.Origin))
	line("size", fmt.Sprint(c.Size))
	line("root", b64(c.Root))

	// The prior note is read before the proof files. The list of proofs is read
	// once. It serves the prior check and the state check.
	var prior bytes.Buffer
	if in.prior != "" {
		if _, err := loadNote(in.prior, v, &prior); err != nil {
			return nil, "", err
		}
	}
	var proofs []verify.ConsistencyProof
	seen := map[sizePair]bool{}
	for _, p := range in.consistency {
		cons, err := load(p, verify.ReadConsistencyProof)
		if err != nil {
			return nil, "", err
		}
		sizes := sizePair{cons.OldSize, cons.NewSize}
		if seen[sizes] {
			return nil, "", errSameSizes
		}
		seen[sizes] = true
		proofs = append(proofs, cons)
	}
	if in.prior != "" {
		if err := verify.Consistency(v, prior.Bytes(), latest.Bytes(), proofs); err != nil {
			return nil, "", err
		}
		line("prior consistency", "verified")
	}

	stateDir := in.stateDir
	if stateDir == "" {
		if stateDir, err = verify.DefaultStateDir(); err != nil {
			return nil, "", err
		}
	}
	change, err := updateState(stateDir, v, c.Size, latest.Bytes(), proofs)
	if err != nil && !errors.Is(err, verify.ErrStateSync) {
		return nil, "", err
	}
	stateLine := "state: " + stateLines[change]
	if err != nil {
		// The state is written, but the directory sync failed. The user must see
		// what the state is.
		return nil, stateLine, err
	}
	line("state", stateLines[change])

	if in.event != "" {
		e, err := load(in.event, verify.ReadEvent)
		if err != nil {
			return nil, stateLine, err
		}
		p, err := load(in.proof, verify.ReadInclusionProof)
		if err != nil {
			return nil, stateLine, err
		}
		res, err := verify.Inclusion(v, latest.Bytes(), e, p)
		if err != nil {
			return nil, stateLine, err
		}
		line("event hash", b64(res.EventHash))
		line("leaf index", fmt.Sprint(res.LeafIndex))
		for _, h := range res.Proof {
			line("proof hash", b64(h))
		}
		for _, h := range res.Consistency {
			line("consistency hash", b64(h))
		}
	}
	return out.Bytes(), stateLine, nil
}

// stateLockWait and stateDirSync are the lock wait and the directory sync of the
// state. Only tests change them. No flag, no environment variable, and no other
// input sets them. The zero value of each gives the production behavior.
var (
	stateLockWait time.Duration
	stateDirSync  func(*os.File) error
)

// updateState loads the state, checks the checkpoint against it, and updates the
// state with the checkpoint. It closes the state before it returns. Thus the
// command does not hold the lock while it reads the event and proof files. If
// the directory sync fails after the write, it returns the change together with
// verify.ErrStateSync.
func updateState(dir string, v note.Verifier, size uint64, latest []byte, proofs []verify.ConsistencyProof) (verify.StateChange, error) {
	st, err := verify.LoadState(dir, v, verify.StateOptions{LockWait: stateLockWait, DirSync: stateDirSync})
	if err != nil {
		return 0, err
	}
	defer st.Close()
	if prev := st.Bytes(); prev != nil {
		if err := verify.Consistency(v, prev, latest, proofs); err != nil {
			return 0, err
		}
	}
	if size == 0 {
		// A note of size 0 needs no proof, but its root must be the empty root.
		// With no state and no --prior, no check above has looked at the root.
		if err := verify.Consistency(v, latest, latest, nil); err != nil {
			return 0, err
		}
	}
	return st.Update(latest)
}

// loadNote reads a checkpoint note with the key v. The raw bytes that
// ReadCheckpoint read, at most one byte more than the cap, go to raw. The
// checks of internal/verify need these bytes.
func loadNote(path string, v note.Verifier, raw *bytes.Buffer) (verifier.Checkpoint, error) {
	return load(path, func(r io.Reader) (verifier.Checkpoint, error) {
		return verify.ReadCheckpoint(io.TeeReader(r, raw), v)
	})
}

// load opens a file and gives it to a Read function of internal/verify, which
// applies the size cap. A failure to open the file gives ErrRead, because an
// error from the os package holds the path.
func load[T any](path string, read func(io.Reader) (T, error)) (T, error) {
	f, err := os.Open(path)
	if err != nil {
		var zero T
		return zero, verify.ErrRead
	}
	defer f.Close()
	return read(f)
}
