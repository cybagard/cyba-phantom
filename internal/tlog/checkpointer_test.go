package tlog

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
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
	return f.err
}

func (f *fakeSink) added() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sizes)
}

// ckEnv is a log with leaves leaves, a state directory, and a key pair.
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
	return &ckEnv{l, state, dir, &fakeSink{}, s, v}
}

func (e *ckEnv) start(opts ...CheckpointOption) (*Checkpointer, error) {
	return NewCheckpointer(e.l, e.signer, e.verifier, e.sink, e.state, testOrigin, time.Minute, nil, opts...)
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
	c, err := e.start(func(c *Checkpointer) { c.ticks = ticks })
	must(t, err)
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

func TestTU12StartRefusals(t *testing.T) {
	e := newEnv(t, 3)
	other, otherV := noteKeys(t, "other/origin", 2)
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
	} {
		if got, err := NewCheckpointer(e.l, c.signer, c.verifier, e.sink, e.state, c.origin, c.interval, nil); err == nil || got != nil {
			t.Errorf("%s: checkpointer %v, error %v", c.name, got, err)
		}
	}
	root, _ := e.l.RootAt(3)
	foreign, err := note.Sign(&note.Note{Text: checkpointBody(Checkpoint{"other/origin", 3, root})}, e.signer)
	must(t, err)
	otherKey, err := SignCheckpoint(other, 3, root)
	must(t, err)
	for name, state := range map[string][]byte{"origin line of another origin": foreign, "note of another key": otherKey} {
		e.put(t, state)
		if got, err := e.start(); err == nil || got != nil {
			t.Errorf("%s: checkpointer %v, error %v", name, got, err)
		}
	}
	if got := e.sink.added(); len(got) != 0 {
		t.Fatalf("signed %v", got)
	}
}

func TestTS13GuardRefusesAndStopsForGood(t *testing.T) {
	bogus := tlog.Hash{1}
	for _, tc := range []struct {
		name string
		last Checkpoint
	}{
		{"smaller size", Checkpoint{testOrigin, 12, bogus}},
		{"same size, other root", Checkpoint{testOrigin, 10, bogus}},
		{"larger tree, no consistency proof", Checkpoint{testOrigin, 3, bogus}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, 10)
			c := e.mustStart(t)
			c.last, c.hasLast = tc.last, true
			c.sign()
			e.refused(t, c, nil)
			appendTo(t, e.l, 10, 20)
			c.sign() // no retry on a later tick
			e.refused(t, c, nil)
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
			b, err := note.Sign(&note.Note{Text: checkpointBody(Checkpoint{testOrigin, 10, r})}, other)
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
	if got := e.sink.added(); !c.Healthy() || !slices.Equal(got, []uint64{10}) {
		t.Fatalf("healthy %v, signed %v", c.Healthy(), got)
	}
}

func TestTS13StateThatIsNotAPlainFileIsAnError(t *testing.T) {
	for name, mk := range map[string]func(e *ckEnv, p string) error{
		"symlink":   func(e *ckEnv, p string) error { return os.Symlink(filepath.Join(e.dir, "outside"), p) },
		"directory": func(_ *ckEnv, p string) error { return os.Mkdir(p, 0o700) },
		"too large": func(_ *ckEnv, p string) error { return os.WriteFile(p, make([]byte, 2048), 0o600) },
		"no size":   func(_ *ckEnv, p string) error { return os.WriteFile(p, []byte("garbage"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 3)
			must(t, os.WriteFile(filepath.Join(e.dir, "outside"), []byte("outside"), 0o600))
			must(t, mk(e, filepath.Join(e.dir, stateName)))
			_, ok, err := SignerState(e.state)
			if ok || err == nil {
				t.Fatalf("SignerState: %v, %v", ok, err)
			}
			if got, err := e.start(); err == nil || got != nil {
				t.Fatalf("checkpointer %v, error %v", got, err)
			}
			if b, _ := os.ReadFile(filepath.Join(e.dir, "outside")); string(b) != "outside" {
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
		c.last, c.hasLast = Checkpoint{testOrigin, 100, root}, true
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
		e.refused(t, c, nil)
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
	c.sign()
	if got := e.sink.added(); !slices.Equal(got, []uint64{3, 5}) || !c.Healthy() {
		t.Fatalf("signed %v, healthy %v", got, c.Healthy())
	}
	// A state file that cannot be replaced: no note goes to the spool.
	must(t, os.Remove(filepath.Join(e.dir, stateName)))
	must(t, os.Mkdir(filepath.Join(e.dir, stateName), 0o700))
	appendTo(t, e.l, 5, 7)
	c.sign()
	if got := e.sink.added(); len(got) != 2 || c.Healthy() {
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
	c.last = Checkpoint{testOrigin, 1 << 63, tlog.Hash{}}
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
	c, err := NewCheckpointer(e.l, signer, verifier, e.sink, e.state, testOrigin, time.Minute, lg)
	must(t, err)
	c.sign()
	appendTo(t, e.l, 5, 6)
	c.last.Root = tlog.Hash{1}
	c.last.Size = 3
	c.sign() // a guard fault: the error goes to the log
	errs := []error{c.Err()}
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
