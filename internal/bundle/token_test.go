package bundle

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/token"
)

// trapEntsWith gives the files of a bundle with traps of these ids, in this
// order, and this seed file.
func trapEntsWith(seed ent, ids ...string) []ent {
	objs := make([]string, len(ids))
	for i, id := range ids {
		objs[i] = tj(id, "x")
	}
	return append(trapEnts(arr(objs...)), seed)
}

// loadTokens writes a bundle of version v that key k signs and loads it.
func (e *env) loadTokens(l *Loader, k rkey, v int, seed ent, ids ...string) *Bundle {
	e.t.Helper()
	e.putSeeded(k, ver(v), trapEntsWith(seed, ids...)...)
	b, err := l.Load(false)
	must(e.t, err)
	return b
}

// T-S-29: the key set of a bundle of each class has the traps in file order.
// It has the flag of the class. A key set built from the seed, the SHA-256
// and the ids verifies its tokens.
func TestTS29_BundleTokens(t *testing.T) {
	ids := []string{"b", "c", "a"} // not sorted
	for _, k := range []func(*env) rkey{keyOne, keyTwo} {
		e, install := newEnv(t), testInstall(t, 1)
		key := k(e)
		ref := key.id == "k2"
		b := e.loadTokens(e.seedLoader(install), key, 2, e.good(install, key, ver(2), seedA), ids...)
		own, err := token.NewKeySet(seedA, b.SHA256(), ids, ref)
		must(t, err)
		for i, id := range ids {
			tok, err := b.Tokens().Mint(i, testNow)
			got := token.Verify([]*token.KeySet{own}, tok)
			if err != nil || !got.OK || got.Trap != id {
				t.Errorf("%s, index %d: %v, %+v", key.id, i, err, got)
			}
			if got := token.Verify([]*token.KeySet{b.Tokens()}, tok); got.Reference != ref || got.Trap != id {
				t.Errorf("%s, index %d: own set gives %+v", key.id, i, got)
			}
		}
		if _, err := b.Tokens().Mint(len(ids), testNow); !errors.Is(err, token.ErrIndex) {
			t.Errorf("%s: index %d gives %v", key.id, len(ids), err)
		}
	}
}

// T-S-29: a rejected candidate does not replace the key set of the running
// bundle. Tokens gives the same pointer.
func TestTS29_BundleTokensRejected(t *testing.T) {
	e, install := newEnv(t), testInstall(t, 1)
	key, l := keyOne(e), e.seedLoader(install)
	run := e.loadTokens(l, key, 2, e.good(install, key, ver(2), seedA), "a")
	e.putSeeded(key, ver(3), trapEntsWith(e.good(install, key, ver(3), seedB), "x", "y")...)
	must(t, os.MkdirAll(filepath.Join(e.state, "bundle", StateName+".tmp", "x"), 0o700))
	if _, err := l.Load(false); err != ErrStateFault {
		t.Fatalf("got %v", err)
	}
	if l.Current() != run || run.Tokens() == nil || l.Current().Tokens() != run.Tokens() {
		t.Error("the key set of the running bundle changed")
	}
	if _, err := l.Current().Tokens().Mint(1, testNow); !errors.Is(err, token.ErrIndex) {
		t.Errorf("the running key set holds the traps of the candidate: %v", err)
	}
}

// T-S-29: with the seed step off (a test seam), a bundle has no key set. A
// bundle with a seed and no trap file has none and loads. With the real seed
// step, a bundle with traps and no seed file gives ErrSeedInvalid.
func TestTS29_BundleNoTokens(t *testing.T) {
	e0 := newEnv(t)
	e0.putSeeded(keyTwo(e0), ver(2), trapEnts(arr(tj("a", "x")))...)
	if b, err := e0.seedLoader(nil).Load(false); b != nil || err != ErrSeedInvalid {
		t.Errorf("no seed file: %v, %v", b, err)
	}
	e := newEnv(t)
	e.putSeeded(keyOne(e), ver(2), trapEnts(arr(tj("a", "x")))...)
	b, err := e.l.Load(false)
	must(t, err)
	e2 := newEnv(t)
	e2.putSeeded(keyTwo(e2), ver(2), plainEnt(seedA))
	b2, err := e2.seedLoader(nil).Load(false)
	must(t, err)
	for name, ks := range map[string]*token.KeySet{"seed step off": b.Tokens(), "no trap": b2.Tokens()} {
		if ks != nil {
			t.Errorf("%s: key set %v", name, ks)
		}
		if _, err := ks.Mint(0, testNow); !errors.Is(err, token.ErrNoKeySet) {
			t.Errorf("%s: Mint gives %v", name, err)
		}
		if got := token.Verify([]*token.KeySet{ks}, [token.Size]byte{}); got != (token.Result{}) {
			t.Errorf("%s: Verify gives %+v", name, got)
		}
	}
}

// T-S-29: the key set of the running bundle mints while a new bundle loads.
// The mints overlap the load. The tokens still verify under the old key set.
func TestTS29_BundleTokensRace(t *testing.T) {
	e := newEnv(t)
	l, two := e.seedLoader(nil), keyTwo(e)
	old := e.loadTokens(l, two, 2, plainEnt(seedA), "a", "b").Tokens()
	e.putSeeded(two, ver(3), trapEntsWith(plainEnt(seedB), "c", "d")...)
	started, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var late atomic.Int64 // mints that began after the load read the file
	var toks [][token.Size]byte
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			after := false
			select {
			case <-started:
				after = true
			default:
			}
			tok, err := old.Mint(1, testNow)
			if err != nil {
				t.Error(err)
				return
			}
			toks = append(toks, tok)
			if after {
				late.Add(1)
			}
		}
	}()
	// The load waits here until the goroutine has minted after the read.
	l.afterRead = func() {
		close(started)
		for late.Load() == 0 {
			select {
			case <-done:
				return
			default:
				runtime.Gosched()
			}
		}
	}
	b, err := l.Load(false)
	close(stop)
	<-done
	must(t, err)
	if late.Load() == 0 {
		t.Error("no mint overlapped the load")
	}
	if l.Current() != b || b.Manifest().Version != ver(3) || b.Tokens() == old {
		t.Error("the running bundle is not the new bundle")
	}
	for _, tok := range toks {
		if got := token.Verify([]*token.KeySet{old}, tok); !got.OK || got.Trap != "b" {
			t.Fatalf("Verify gives %+v", got)
		}
	}
}

// T-S-29: a key set step that fails refuses the candidate with ErrSeedInvalid.
// The running bundle stays. The seed that the step kept is zero after Load.
func TestTS29_BundleKeySetFails(t *testing.T) {
	e := newEnv(t)
	l, two := e.seedLoader(nil), keyTwo(e)
	run := e.loadTokens(l, two, 2, plainEnt(seedA), "a")
	var kept, seen []byte
	l.keySet = func(seed []byte, _ [32]byte, _ []string, _ bool) (*token.KeySet, error) {
		kept, seen = seed, bytes.Clone(seed)
		return nil, errors.New("stub")
	}
	e.putSeeded(two, ver(3), trapEntsWith(plainEnt(seedB), "c")...)
	if b, err := l.Load(false); b != nil || err != ErrSeedInvalid {
		t.Fatalf("got %v, %v", b, err)
	}
	if l.Current() != run || run.Tokens() == nil {
		t.Error("the running bundle changed")
	}
	if !bytes.Equal(seen, seedB) || !bytes.Equal(kept, make([]byte, len(seedB))) {
		t.Errorf("seed seen %x, kept seed after Load %x", seen, kept)
	}
}

// T-U-01: two bundles have the same seed and other trap order. Each has its
// own key set. The token for index 0 gives the first id of its own trap file.
// It does not verify under the other key set.
func TestTU01_BundleTrapIndex(t *testing.T) {
	e := newEnv(t)
	l, two := e.seedLoader(nil), keyTwo(e)
	first := e.loadTokens(l, two, 2, plainEnt(seedA), "a", "b").Tokens()
	second := e.loadTokens(l, two, 3, plainEnt(seedA), "b", "a").Tokens()
	t1, err1 := first.Mint(0, testNow)
	t2, err2 := second.Mint(0, testNow)
	must(t, errors.Join(err1, err2))
	for _, c := range []struct {
		name string
		ring *token.KeySet
		tok  [token.Size]byte
		want string
	}{{"first", first, t1, "a"}, {"second", second, t2, "b"}} {
		if got := token.Verify([]*token.KeySet{c.ring}, c.tok); !got.OK || got.Trap != c.want {
			t.Errorf("%s: Verify gives %+v", c.name, got)
		}
	}
	// The two bundles have another SHA-256, so another salt and key. This check
	// shows the key of each bundle, not the trap order.
	if token.Verify([]*token.KeySet{second}, t1).OK || token.Verify([]*token.KeySet{first}, t2).OK {
		t.Error("a token verifies under the key set of the other bundle")
	}
}

// ringCheck checks the position of the matching key set of a token in the
// ring of the loader. want is -1 for no match.
func ringCheck(t *testing.T, l *Loader, what string, tok [token.Size]byte, want int) {
	t.Helper()
	got := l.Ring().Verify(tok)
	if (want < 0) == got.OK || (got.OK && got.Set != want) {
		t.Errorf("%s: Verify gives %+v, want position %d", what, got, want)
	}
}

// T-U-22: each accepted load swaps the ring. A token of the replaced bundle
// verifies as the second key set. A rejected load leaves the ring. The
// replaced key set leaves the ring 25 h after the load.
func TestTU22_BundleRing(t *testing.T) {
	e := newEnv(t)
	l, two := e.seedLoader(nil), keyTwo(e)
	now := testNow
	l.now = func() time.Time { return now }
	if l.Ring().Len() != 0 {
		t.Fatal("a new loader has a ring that is not empty")
	}
	t1, _ := e.loadTokens(l, two, 2, plainEnt(seedA), "a").Tokens().Mint(0, now)
	ringCheck(t, l, "one bundle", t1, token.First)
	if l.Ring().Len() != 1 {
		t.Errorf("ring holds %d key sets after one load", l.Ring().Len())
	}
	t2, _ := e.loadTokens(l, two, 3, plainEnt(seedB), "b").Tokens().Mint(0, now)
	ringCheck(t, l, "replaced bundle", t1, token.Second)
	ringCheck(t, l, "running bundle", t2, token.First)
	e.putSeeded(two, ver(4), trapEntsWith(plainEnt(seedA), "c")...)
	must(t, os.MkdirAll(filepath.Join(e.state, "bundle", StateName+".tmp", "x"), 0o700))
	if _, err := l.Load(false); err != ErrStateFault {
		t.Fatalf("got %v", err)
	}
	ringCheck(t, l, "after a rejected load", t1, token.Second)
	now = now.Add(25 * time.Hour)
	ringCheck(t, l, "25 h after the load", t1, -1)
	ringCheck(t, l, "running bundle after 25 h", t2, token.First)
}

// T-U-22: a load of a bundle with no key set puts no key set in the current
// place. The ring keeps the replaced key set. A second such load empties it.
func TestTU22_BundleRingNoKeySet(t *testing.T) {
	e := newEnv(t)
	l, two := e.seedLoader(nil), keyTwo(e)
	t1, _ := e.loadTokens(l, two, 2, plainEnt(seedA), "a").Tokens().Mint(0, testNow)
	l.seed = nil // a bundle with no seed has no key set
	for v, want := range []int{token.Second, -1} {
		e.putSeeded(two, ver(3+v), trapEnts(arr(tj("b", "x")))...)
		b, err := l.Load(false)
		must(t, err)
		if b.Tokens() != nil {
			t.Fatal("the bundle has a key set")
		}
		ringCheck(t, l, "load without key set", t1, want)
	}
}
