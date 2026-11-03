package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

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

// T-S-29: a bundle with no seed has no key set. A bundle with a seed and no
// trap file has none and loads.
func TestTS29_BundleNoTokens(t *testing.T) {
	e := newEnv(t)
	e.putSeeded(keyOne(e), ver(2), trapEnts(arr(tj("a", "x")))...)
	b, err := e.l.Load(false)
	must(t, err)
	e2 := newEnv(t)
	e2.putSeeded(keyTwo(e2), ver(2), plainEnt(seedA))
	b2, err := e2.seedLoader(nil).Load(false)
	must(t, err)
	for name, ks := range map[string]*token.KeySet{"no seed": b.Tokens(), "no trap": b2.Tokens()} {
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

// T-S-29: the key set of the running bundle mints while a new bundle loads
// and its seed is zero. The tokens still verify under the old key set.
func TestTS29_BundleTokensRace(t *testing.T) {
	e := newEnv(t)
	l, two := e.seedLoader(nil), keyTwo(e)
	old := e.loadTokens(l, two, 2, plainEnt(seedA), "a", "b").Tokens()
	var toks [][token.Size]byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 500 {
			tok, err := old.Mint(1, testNow)
			if err != nil {
				t.Error(err)
				return
			}
			toks = append(toks, tok)
		}
	}()
	e.loadTokens(l, two, 3, plainEnt(seedB), "c", "d")
	<-done
	for _, tok := range toks {
		if got := token.Verify([]*token.KeySet{old}, tok); !got.OK || got.Trap != "b" {
			t.Fatalf("Verify gives %+v", got)
		}
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
	t1, _ := first.Mint(0, testNow)
	t2, _ := second.Mint(0, testNow)
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
	if token.Verify([]*token.KeySet{second}, t1).OK || token.Verify([]*token.KeySet{first}, t2).OK {
		t.Error("a token verifies under the key set of the other bundle")
	}
}
