package tlog

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// fakeSink records the notes. onAdd runs before the record.
type fakeSink struct {
	mu    sync.Mutex
	sizes []uint64
	msgs  [][]byte
	err   error
	onAdd func(size uint64, msg []byte)
}

func (f *fakeSink) Add(size uint64, msg []byte) error {
	if f.onAdd != nil {
		f.onAdd(size, msg)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sizes = append(f.sizes, size)
	f.msgs = append(f.msgs, slices.Clone(msg))
	return f.err
}

func (f *fakeSink) added() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sizes)
}

// ckEnv is a log with leaves leaves, a state directory, and a key pair. The
// signer state is the note of the empty tree, as after the first start.
type ckEnv struct {
	l        *Log
	state    *os.Root
	dir      string
	sink     *fakeSink
	signer   note.Signer
	verifier note.Verifier
}

func newEnv(t *testing.T, leaves int) *ckEnv {
	t.Helper()
	withoutSync(t)
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, leaves)
	s, v := noteKeys(t, testOrigin, 1)
	e := &ckEnv{l, state, dir, &fakeSink{}, s, v}
	e.put(t, e.signed(t, 0, emptyRoot))
	return e
}

func (e *ckEnv) start() (*Checkpointer, error) {
	return NewCheckpointer(e.l, e.signer, e.verifier, e.sink, e.state, testOrigin, time.Minute, nil)
}

// dropState removes the signer state and leaves the key.
func (e *ckEnv) dropState(t *testing.T) {
	t.Helper()
	must(t, os.Remove(filepath.Join(e.dir, stateName)))
}

func (e *ckEnv) mustStart(t *testing.T) *Checkpointer {
	t.Helper()
	c, err := e.start()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *ckEnv) put(t *testing.T, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.dir, stateName), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// saved returns the state file, or nil if there is none.
func (e *ckEnv) saved() []byte {
	b, _ := os.ReadFile(filepath.Join(e.dir, stateName))
	return b
}

func (e *ckEnv) signed(t *testing.T, size uint64, root tlog.Hash) []byte {
	t.Helper()
	b, err := SignCheckpoint(e.signer, size, root)
	must(t, err)
	return b
}

// refused checks that c is not healthy and that nothing was signed after the
// state before.
func (e *ckEnv) refused(t *testing.T, c *Checkpointer, before []byte) {
	t.Helper()
	if c.Healthy() || c.Err() == nil {
		t.Fatal("the checkpointer is healthy")
	}
	if got := e.sink.added(); len(got) != 0 || !bytes.Equal(e.saved(), before) {
		t.Fatalf("signed %v, state changed %v", got, !bytes.Equal(e.saved(), before))
	}
}

func TestTU12SignsAtEachTickOnlyWhenTheSizeChanged(t *testing.T) {
	e := newEnv(t, 3)
	ticks := make(chan time.Time)
	c, err := e.start()
	must(t, err)
	c.ticks = ticks
	// tick runs the goroutine for one tick. It returns after the goroutine ended,
	// so no sign runs while the test appends.
	ctx, cancel := context.WithCancel(context.Background())
	tick := func() {
		done := make(chan struct{})
		run, stop := context.WithCancel(ctx)
		go func() { c.Run(run); close(done) }()
		ticks <- time.Time{}
		stop()
		<-done
	}
	tick()
	if got := e.sink.added(); !slices.Equal(got, []uint64{3}) {
		t.Fatalf("after the first tick: %v", got)
	}
	tick() // the size did not change
	if got := e.sink.added(); !slices.Equal(got, []uint64{3}) {
		t.Fatalf("after the second tick: %v", got)
	}
	appendTo(t, e.l, 3, 8)
	tick()
	if got := e.sink.added(); !slices.Equal(got, []uint64{3, 8}) || !c.Healthy() {
		t.Fatalf("signed %v, healthy %v", got, c.Healthy())
	}
	root, _ := e.l.RootAt(8)
	if cp, err := ParseCheckpoint(e.saved(), testOrigin, e.verifier); err != nil || cp.Size != 8 || cp.Root != root {
		t.Fatalf("state %+v, error %v", cp, err)
	}
	// A cancelled context ends Run with the default ticker.
	cancel()
	c2 := e.mustStart(t)
	c2.Run(ctx)
}

// A second Run call returns at once while the first Run is active.
func TestTU12SecondRunReturnsAtOnce(t *testing.T) {
	e := newEnv(t, 3)
	ticks := make(chan time.Time)
	c := e.mustStart(t)
	c.ticks = ticks
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan struct{})
	go func() { c.Run(ctx); close(first) }()
	ticks <- time.Time{} // the first Run takes this tick, so it is active
	second := make(chan struct{})
	go func() { c.Run(ctx); close(second) }()
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Fatal("the second Run did not return")
	}
	select {
	case <-first:
		t.Fatal("the first Run ended with the second")
	default:
	}
	cancel()
	<-first
	if got := e.sink.added(); !slices.Equal(got, []uint64{3}) || !c.Healthy() {
		t.Fatalf("signed %v, healthy %v", got, c.Healthy())
	}
}

func TestTU12StartRefusals(t *testing.T) {
	e := newEnv(t, 3)
	other, otherV := noteKeys(t, "other/origin", 2)
	_, sameNameV := noteKeys(t, testOrigin, 2) // the right name, another key
	for _, c := range []struct {
		name     string
		signer   note.Signer
		verifier note.Verifier
		origin   string
		interval time.Duration
	}{
		{"no interval", e.signer, e.verifier, testOrigin, 0},
		{"negative interval", e.signer, e.verifier, testOrigin, -time.Second},
		{"no origin", e.signer, e.verifier, "", time.Minute},
		{"signer of another name", other, e.verifier, testOrigin, time.Minute},
		{"verifier of another name", e.signer, otherV, testOrigin, time.Minute},
		{"verifier of another key", e.signer, sameNameV, testOrigin, time.Minute},
	} {
		if got, err := NewCheckpointer(e.l, c.signer, c.verifier, e.sink, e.state, c.origin, c.interval, nil); err == nil || got != nil {
			t.Errorf("%s: checkpointer %v, error %v", c.name, got, err)
		}
	}
	root, _ := e.l.RootAt(3)
	foreign, err := note.Sign(&note.Note{Text: checkpointBody(Checkpoint{Origin: "other/origin", Size: 3, Root: root})}, e.signer)
	must(t, err)
	otherKey, err := SignCheckpoint(other, 3, root)
	must(t, err)
	// Both states have an origin line that is not the origin. A note of another
	// key with the same origin line is not a start error (TestTS13BadStoredNoteIsNotHealthy).
	for name, state := range map[string][]byte{"note body of another origin": foreign, "note of a signer with another name": otherKey} {
		e.put(t, state)
		if got, err := e.start(); err == nil || got != nil || !strings.Contains(err.Error(), "another origin") {
			t.Errorf("%s: checkpointer %v, error %v", name, got, err)
		}
	}
	if got := e.sink.added(); len(got) != 0 {
		t.Fatalf("signed %v", got)
	}
}

// An empty or corrupt state file is a start error with its own text. It is not
// "another origin".
func TestTS13CorruptStateHasItsOwnError(t *testing.T) {
	for name, state := range map[string][]byte{
		"empty file":         nil,
		"no newline":         []byte("garbage"),
		"garbage first line": []byte("garbage\nnot a size\nAAAA\n"),
	} {
		e := newEnv(t, 3)
		e.put(t, state)
		got, err := e.start()
		if err == nil || got != nil || strings.Contains(err.Error(), "another origin") || !strings.HasPrefix(err.Error(), "checkpointer: ") {
			t.Errorf("%s: checkpointer %v, error %v", name, got, err)
		}
	}
}

// A temporary file that Remove cannot delete stops the signing. The error
// names that rule.
func TestTS13UndeletableTemporaryFileNamesTheRule(t *testing.T) {
	e := newEnv(t, 3)
	must(t, os.MkdirAll(filepath.Join(e.dir, stateName+".tmp", "x"), 0o700))
	c := e.mustStart(t)
	c.sign()
	if err := c.Err(); err == nil || !strings.Contains(err.Error(), "temporary file") || !strings.Contains(err.Error(), "cannot be removed") || !errors.As(err, new(*fs.PathError)) {
		t.Fatalf("error %v; want the rule and the OS error as cause", err)
	}
	if got := e.sink.added(); len(got) != 0 {
		t.Fatalf("signed %v", got)
	}
}

func TestTS13GuardRefusesAndStopsUntilRestart(t *testing.T) {
	bogus := tlog.Hash{1}
	for _, tc := range []struct {
		name string
		last Checkpoint
	}{
		{"smaller size", Checkpoint{Origin: testOrigin, Size: 12, Root: bogus}},
		{"same size, other root", Checkpoint{Origin: testOrigin, Size: 10, Root: bogus}},
		{"larger tree, no consistency proof", Checkpoint{Origin: testOrigin, Size: 3, Root: bogus}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, 10)
			c := e.mustStart(t)
			c.last = tc.last
			before := e.saved()
			c.sign()
			e.refused(t, c, before)
			appendTo(t, e.l, 10, 20)
			c.sign() // no retry on a later tick
			e.refused(t, c, before)
		})
	}
}

func TestTS13BadStoredNoteIsNotHealthy(t *testing.T) {
	for _, tc := range []struct {
		name string
		mk   func(e *ckEnv, root tlog.Hash) []byte
	}{
		{"bad signature", func(e *ckEnv, r tlog.Hash) []byte { b := e.signed(t, 10, r); b[len(b)-5] ^= 1; return b }},
		{"root that the tiles do not give", func(e *ckEnv, _ tlog.Hash) []byte { return e.signed(t, 10, tlog.Hash{1}) }},
		{"size above the log", func(e *ckEnv, r tlog.Hash) []byte { return e.signed(t, 11, r) }},
		{"size too large", func(e *ckEnv, r tlog.Hash) []byte { return e.signed(t, math.MaxUint64, r) }},
		{"not a note", func(*ckEnv, tlog.Hash) []byte { return []byte(testOrigin + "\ngarbage") }},
		{"other key", func(e *ckEnv, r tlog.Hash) []byte {
			other, _ := noteKeys(t, "other/origin", 2)
			b, err := note.Sign(&note.Note{Text: checkpointBody(Checkpoint{Origin: testOrigin, Size: 10, Root: r})}, other)
			must(t, err)
			return b
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, 10)
			root, _ := e.l.RootAt(10)
			stored := tc.mk(e, root)
			e.put(t, stored)
			c := e.mustStart(t)
			appendTo(t, e.l, 10, 15)
			c.sign()
			e.refused(t, c, stored)
		})
	}
}

func TestTS13StoredNoteThatVerifiesStarts(t *testing.T) {
	e := newEnv(t, 10)
	if size, ok, err := SignerState(e.state); size != 0 || !ok || err != nil {
		t.Fatalf("state of the empty tree: %d %v %v", size, ok, err)
	}
	e.dropState(t)
	if size, ok, err := SignerState(e.state); size != 0 || ok || err != nil {
		t.Fatalf("no state: %d %v %v", size, ok, err)
	}
	root, _ := e.l.RootAt(4)
	e.put(t, e.signed(t, 4, root))
	if size, ok, err := SignerState(e.state); size != 4 || !ok || err != nil {
		t.Fatalf("state: %d %v %v", size, ok, err)
	}
	c := e.mustStart(t)
	c.sign()
	// The tree grew before the first tick: the stored note goes first.
	if got := e.sink.added(); !c.Healthy() || !slices.Equal(got, []uint64{4, 10}) {
		t.Fatalf("healthy %v, signed %v", c.Healthy(), got)
	}
}

// T-S-13: the first start of the key writes the state of the empty tree. The
// checkpointer accepts it and gives nothing to the sink. The first tick with
// leaves signs with no proof: the empty tree is a prefix. Only RootAt runs.
func TestTS13FirstStartStateStartsTheCheckpointer(t *testing.T) {
	withoutSync(t)
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	signer, err := LoadOrCreateSigner(state, nil, testOrigin, false, 0)
	must(t, err)
	vkey, err := os.ReadFile(filepath.Join(dir, vkeyName))
	must(t, err)
	verifier, err := note.NewVerifier(strings.TrimSpace(string(vkey)))
	must(t, err)
	root0, err := l.RootAt(0)
	must(t, err)
	e := &ckEnv{l, state, dir, &fakeSink{}, signer, verifier}
	if cp, err := ParseCheckpoint(e.saved(), testOrigin, verifier); err != nil || cp.Size != 0 || cp.Root != root0 {
		t.Fatalf("state %+v, error %v", cp, err)
	}
	c := e.mustStart(t)
	c.sign() // the tree is empty
	if got := e.sink.added(); !c.Healthy() || len(got) != 0 {
		t.Fatalf("healthy %v, signed %v", c.Healthy(), got)
	}
	appendTo(t, l, 0, 5)
	c.sign()
	root5, _ := l.RootAt(5)
	if cp, err := ParseCheckpoint(e.saved(), testOrigin, verifier); err != nil || cp.Size != 5 || cp.Root != root5 || !c.Healthy() {
		t.Fatalf("state %+v, error %v, healthy %v", cp, err, c.Healthy())
	}
	if got := e.sink.added(); !slices.Equal(got, []uint64{5}) {
		t.Fatalf("signed %v", got)
	}
}

// T-S-13: a key with no signer state is a fault. The checkpointer does not
// sign, is not healthy, and writes no state, whatever the tree size.
func TestTS13MissingStateIsAFault(t *testing.T) {
	for _, leaves := range []int{0, 3} {
		e := newEnv(t, leaves)
		e.dropState(t)
		c := e.mustStart(t)
		c.sign()
		appendTo(t, e.l, leaves, leaves+2)
		c.sign()
		e.refused(t, c, nil)
		if _, err := os.Lstat(filepath.Join(e.dir, stateName)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%d leaves: state file made: %v", leaves, err)
		}
	}
}

// T-S-13: the fork case. The sensor signs at 10. Then the state file goes and
// another tree replaces the log. The checkpointer does not sign.
func TestTS13MissingStateAndForkedLogDoesNotSign(t *testing.T) {
	e := newEnv(t, 10)
	e.mustStart(t).sign()
	if got := e.sink.added(); !slices.Equal(got, []uint64{10}) {
		t.Fatalf("signed %v", got)
	}
	e.dropState(t)
	e.l.Close()
	must(t, os.RemoveAll(filepath.Join(e.dir, "tlog")))
	l, err := OpenLog(e.state, "tlog")
	must(t, err)
	t.Cleanup(func() { l.Close() })
	for i := range 12 {
		_, err := l.Append(sha256.Sum256(fmt.Appendf(nil, "forged %d", i)))
		must(t, err)
	}
	e.l, e.sink = l, &fakeSink{}
	c := e.mustStart(t)
	c.sign()
	e.refused(t, c, nil)
}

// T-S-13: a note that is durable but did not reach the sink is added again at
// each tick with an unchanged size, until the sink takes it. A new tick after
// that adds nothing.
func TestTS13PendingNoteGoesToTheSinkAgain(t *testing.T) {
	e := newEnv(t, 3)
	e.sink.err = errors.New("spool is full")
	c := e.mustStart(t)
	c.sign()
	c.sign() // fails again
	e.sink.err = nil
	c.sign()
	c.sign() // the sink has the note: no more calls
	if got := e.sink.added(); !slices.Equal(got, []uint64{3, 3, 3}) || !c.Healthy() {
		t.Fatalf("signed %v, healthy %v", got, c.Healthy())
	}
	for i, m := range e.sink.msgs {
		if !bytes.Equal(m, e.saved()) {
			t.Errorf("call %d: the note is not the stored note", i)
		}
	}
}

// T-S-13: the constructor does not call the sink. The first tick gives it the
// stored note, except the empty-tree note. A failed Add is tried again. The
// stored note also goes to the sink when the log stops before the first tick.
func TestTS13ConstructorLeavesTheStoredNoteToTheFirstTick(t *testing.T) {
	e := newEnv(t, 0)
	e.mustStart(t).sign() // the stored note is the empty tree
	if got := e.sink.added(); len(got) != 0 {
		t.Fatalf("empty tree: sink took %v", got)
	}
	appendTo(t, e.l, 0, 3)
	root, _ := e.l.RootAt(3)
	stored := e.signed(t, 3, root)
	e.put(t, stored) // a crash after the state write, before the Add
	c := e.mustStart(t)
	if got := e.sink.added(); len(got) != 0 {
		t.Fatalf("the constructor called the sink: %v", got)
	}
	c.sign()
	c.sign()
	if got := e.sink.added(); !slices.Equal(got, []uint64{3}) || !bytes.Equal(e.sink.msgs[0], stored) {
		t.Fatalf("sink took %v", got)
	}
	e2 := newEnv(t, 3)
	e2.put(t, stored)
	e2.sink.err = errors.New("spool is full")
	c2 := e2.mustStart(t)
	c2.sign() // the first Add fails
	e2.sink.err = nil
	c2.sign()
	if got := e2.sink.added(); !slices.Equal(got, []uint64{3, 3}) {
		t.Fatalf("sink took %v", got)
	}
	e3 := newEnv(t, 600)
	root600, _ := e3.l.RootAt(600)
	stored600 := e3.signed(t, 600, root600)
	e3.put(t, stored600)
	c3 := e3.mustStart(t)
	file := filepath.Join(e3.dir, "tlog", "tile", "8", "0", "000")
	b, err := os.ReadFile(file)
	must(t, err)
	b[len(b)/2] ^= 1
	must(t, os.WriteFile(file, b, 0o600))
	if _, err := e3.l.ProveInclusion(5, 600); err == nil { // the log stops
		t.Fatal("no error for the changed tile")
	}
	c3.sign()
	if got := e3.sink.added(); !slices.Equal(got, []uint64{600}) || !bytes.Equal(e3.sink.msgs[0], stored600) {
		t.Fatalf("log stopped: sink took %v", got)
	}
	if c3.Healthy() || !bytes.Equal(e3.saved(), stored600) {
		t.Fatalf("log stopped: healthy %v, state changed %v", c3.Healthy(), !bytes.Equal(e3.saved(), stored600))
	}
}

// The symlink points to a valid note in a directory outside the root. If the
// code followed the link, the checkpointer would start. It must give an error,
// and the outside file must stay as it was.
func TestTS13StateThatIsNotAPlainFileIsAnError(t *testing.T) {
	for name, mk := range map[string]func(e *ckEnv, p, outside string) error{
		"symlink to a file outside the root": func(_ *ckEnv, p, outside string) error { return os.Symlink(outside, p) },
		"directory":                          func(_ *ckEnv, p, _ string) error { return os.Mkdir(p, 0o700) },
		"too large":                          func(_ *ckEnv, p, _ string) error { return os.WriteFile(p, make([]byte, 2048), 0o600) },
		"no size":                            func(_ *ckEnv, p, _ string) error { return os.WriteFile(p, []byte("garbage"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 3)
			outside := filepath.Join(t.TempDir(), "outside.note") // another directory than the root
			valid := e.signed(t, 0, emptyRoot)
			must(t, os.WriteFile(outside, valid, 0o600))
			e.dropState(t)
			must(t, mk(e, filepath.Join(e.dir, stateName), outside))
			_, ok, err := SignerState(e.state)
			if ok || err == nil {
				t.Fatalf("SignerState: %v, %v", ok, err)
			}
			if got, err := e.start(); err == nil || got != nil {
				t.Fatalf("checkpointer %v, error %v", got, err)
			}
			if b, _ := os.ReadFile(outside); !bytes.Equal(b, valid) {
				t.Fatal("the outside file changed")
			}
		})
	}
}

func TestTS13StoppedLogDoesNotSign(t *testing.T) {
	for _, preStop := range []bool{true, false} {
		e := newEnv(t, 600)
		c := e.mustStart(t)
		root, _ := e.l.RootAt(100)
		c.last = Checkpoint{Origin: testOrigin, Size: 100, Root: root}
		before := e.saved()
		file := filepath.Join(e.dir, "tlog", "tile", "8", "0", "000")
		b, err := os.ReadFile(file)
		must(t, err)
		b[len(b)/2] ^= 1
		must(t, os.WriteFile(file, b, 0o600))
		if preStop { // a proof call finds the changed byte, and the log stops
			if _, err := e.l.ProveInclusion(5, 600); err == nil {
				t.Fatal("no error for the changed tile")
			}
		}
		c.sign() // without preStop, the consistency proof of the guard finds it
		e.refused(t, c, before)
		if _, err := e.l.RootAt(600); err == nil {
			t.Fatal("the log is not stopped")
		}
	}
}

func TestTS13StateIsDurableBeforeTheSpool(t *testing.T) {
	e := newEnv(t, 3)
	e.sink.onAdd = func(size uint64, msg []byte) {
		fi, err := os.Stat(filepath.Join(e.dir, stateName))
		if got := e.saved(); !bytes.Equal(got, msg) || err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("state not written before the spool: %v %v", err, !bytes.Equal(got, msg))
		}
		if _, err := os.Stat(filepath.Join(e.dir, stateName+".tmp")); err == nil {
			t.Error("temporary file stays")
		}
	}
	c := e.mustStart(t)
	e.sink.err = errors.New("spool is full") // a sink error does not stop the signing
	c.sign()
	appendTo(t, e.l, 3, 5)
	c.sign() // note 3 is pending and goes first, then note 5
	e.sink.err = nil
	c.sign() // note 5 is pending and goes again
	if got := e.sink.added(); !slices.Equal(got, []uint64{3, 3, 5, 5}) || !c.Healthy() {
		t.Fatalf("signed %v, healthy %v", got, c.Healthy())
	}
	// A state file that cannot be replaced: no note goes to the spool.
	must(t, os.Remove(filepath.Join(e.dir, stateName)))
	must(t, os.Mkdir(filepath.Join(e.dir, stateName), 0o700))
	appendTo(t, e.l, 5, 7)
	c.sign()
	if got := e.sink.added(); len(got) != 4 || c.Healthy() {
		t.Fatalf("signed %v, healthy %v", got, c.Healthy())
	}
}

func TestTS13SizeConversions(t *testing.T) {
	if _, ok := toUint(-1); ok {
		t.Error("negative size")
	}
	if u, ok := toUint(5); !ok || u != 5 {
		t.Error("size 5")
	}
	for _, u := range []uint64{maxSize + 1, 1 << 63, math.MaxUint64} {
		if _, ok := toSize(u); ok {
			t.Errorf("size %d", u)
		}
	}
	if n, ok := toSize(maxSize); !ok || n != maxSize {
		t.Error("largest size")
	}
	e := newEnv(t, 3)
	c := e.mustStart(t)
	c.last = Checkpoint{Origin: testOrigin, Size: 1 << 63, Root: tlog.Hash{}}
	if err := c.consistent(3, tlog.Hash{}); err == nil {
		t.Error("last signed size above the limit")
	}
}

func TestTS13NoKeyTextInLogsOrErrors(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	must(t, err)
	signer, err := note.NewSigner(skey)
	must(t, err)
	verifier, err := note.NewVerifier(vkey)
	must(t, err)
	b64 := strings.SplitN(skey, "+", 5)[4] // PRIVATE+KEY+name+hash+key; base64 can hold a plus
	raw, err := base64.StdEncoding.DecodeString(b64)
	must(t, err)
	seed := raw[1:]
	markers := []string{skey, b64, string(seed), base64.StdEncoding.EncodeToString(seed), hex.EncodeToString(seed)}

	lg, logs := testLogger()
	e := newEnv(t, 5)
	e.signer, e.verifier = signer, verifier
	e.put(t, e.signed(t, 0, emptyRoot)) // the state of the new key
	c, err := NewCheckpointer(e.l, signer, verifier, e.sink, e.state, testOrigin, time.Minute, lg)
	must(t, err)
	c.sign()
	appendTo(t, e.l, 5, 6)
	c.last.Root = tlog.Hash{1}
	c.last.Size = 3
	c.sign() // a guard fault: the error goes to the log
	errs := []error{c.Err()}
	e.dropState(t)
	missing, err := NewCheckpointer(e.l, signer, verifier, e.sink, e.state, testOrigin, time.Minute, lg)
	must(t, err)
	errs = append(errs, missing.Err())
	other, _ := noteKeys(t, "other/origin", 2)
	for _, s := range []note.Signer{other, signer} {
		b, err := SignCheckpoint(s, 1, tlog.Hash{})
		must(t, err)
		e.put(t, b)
		got, err := NewCheckpointer(e.l, signer, verifier, e.sink, e.state, testOrigin, time.Minute, lg)
		if err == nil {
			err = got.Err() // the root in the state is wrong: not healthy
		}
		errs = append(errs, err)
	}
	if !strings.Contains(logs.String(), "not healthy") || c.Err() == nil || len(e.sink.added()) != 1 {
		t.Fatalf("the sign path did not run as planned: %q", logs.String())
	}
	for _, m := range markers {
		if strings.Contains(logs.String(), m) {
			t.Errorf("log holds key material %.8q", m)
		}
		for _, err := range errs {
			if err != nil && strings.Contains(err.Error(), m) {
				t.Errorf("error holds key material %.8q", m)
			}
		}
	}
}
