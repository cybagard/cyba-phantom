package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rkey is a test key with its private part.
type rkey struct {
	id   string
	priv ed25519.PrivateKey
	pub  [32]byte
}

func newKey(seed byte, id string) rkey {
	priv, tk := testKey(seed, id)
	return rkey{id, priv, tk.PublicKey}
}

// keys gives the two keys of the compiled set, k1 and k2.
func (e *env) keys() [2]rkey {
	return [2]rkey{{"k1", e.priv, e.trust[0].PublicKey}, {"k2", e.priv2, e.trust[1].PublicKey}}
}

// transition makes the archive of a transition bundle in which key to replaces
// key from. repl is pairs of old and new manifest text.
func transition(from, to rkey, version string, repl ...string) []byte {
	rotation := q(to.id) + `,"rotation":` + rot(from.id, base64.StdEncoding.EncodeToString(to.pub[:]))
	return build(ent{name: "manifest.json", data: []byte(mf(version, append([]string{`"k1"`, rotation}, repl...)...))})
}

// lineOf makes the signature line of key k over the archive.
func lineOf(k rkey, arch []byte) string { return sigRow(k.id, ed25519.Sign(k.priv, SigMessage(arch))) }

// put writes the archive and a signature file of these lines at the path.
func (e *env) put(arch []byte, lines ...string) {
	e.t.Helper()
	e.write("bundle/current.cbnd", arch)
	e.write("bundle/current.sig", []byte(strings.Join(lines, "")))
}

// putBy writes a bundle of this version that one key signs.
func (e *env) putBy(k rkey, version string) {
	e.t.Helper()
	arch := build(ent{name: "manifest.json", data: []byte(mf(version, `"k1"`, q(k.id)))})
	e.put(arch, lineOf(k, arch))
}

// rotates writes a transition bundle that both keys sign, and loads it.
func (e *env) rotates(from, to rkey, version string) *Bundle {
	e.t.Helper()
	arch := transition(from, to, version)
	e.put(arch, lineOf(from, arch), lineOf(to, arch))
	b, err := e.l.Load(false)
	must(e.t, err)
	return b
}

func (e *env) absent(name string) {
	e.t.Helper()
	if _, err := os.Lstat(filepath.Join(e.state, "bundle", name)); err == nil {
		e.t.Errorf("%s exists", name)
	}
}

// T-S-20, SEC-24: a transition bundle with both lines loads and writes its
// record. Then the old key is not trusted, also after a restart. The new key
// is trusted. The transition bundle loads again and writes no second record.
func TestTS20RotationAccepted(t *testing.T) {
	e := running(t)
	k1, k3 := e.keys()[0], newKey(3, "k3")
	arch := transition(k1, k3, ver(3))
	e.put(arch, lineOf(k1, arch), lineOf(k3, arch))
	sig, err := os.ReadFile(filepath.Join(e.state, "bundle/current.sig"))
	must(t, err)
	b, err := e.l.Load(false)
	must(t, err)
	raw, _ := b.File("manifest.json")
	json, _ := os.ReadFile(filepath.Join(e.state, "bundle/rotation-1.json"))
	rec, _ := os.ReadFile(filepath.Join(e.state, "bundle/rotation-1.sig"))
	if b.Manifest().Rotation == nil || b.Class() != ClassProprietary || !bytes.Equal(json, raw) ||
		string(rec) != fmt.Sprintf("%x\n", b.SHA256())+string(sig) {
		t.Errorf("bundle %+v; record %q %q", b.Manifest(), json, rec)
	}
	if !e.l.Healthy() {
		t.Error("not healthy")
	}
	e.putBy(k1, ver(4))
	e.rejects(e.l, false, ErrBadSig)
	l2 := e.loader("bundle/current.cbnd")
	e.rejects(l2, false, ErrBadSig)
	e.put(arch, lineOf(k1, arch), lineOf(k3, arch))
	if b2, err := l2.Load(true); err != nil || b2.SHA256() != b.SHA256() {
		t.Fatalf("again: %v, %v", b2, err)
	}
	e.absent("rotation-2.json")
	e.absent("rotation-2.sig")
	e.putBy(k3, ver(4))
	if _, err := l2.Load(false); err != nil || !l2.Healthy() {
		t.Fatalf("new key: %v", err)
	}
	e.putBy(k1, ver(5))
	e.rejects(l2, false, ErrBadSig)
}

// T-S-20: the new key has the class of the old key. A transition from the
// reference key after a proprietary bundle is a rollback. After a restart, a
// bundle of the new key has class reference.
func TestTS20RotationKeepsClass(t *testing.T) {
	e := running(t)
	k2, k3 := e.keys()[1], newKey(3, "k3")
	arch := transition(k2, k3, ver(3))
	e.put(arch, lineOf(k2, arch), lineOf(k3, arch))
	e.rejects(e.l, false, ErrRollback)

	e = newEnv(t)
	b := e.rotates(k2, k3, ver(1))
	st, err := readState(mustRoot(t, e))
	if b.Class() != ClassReference || err != nil || st.Class != ClassReference {
		t.Errorf("class %v, state %+v, %v", b.Class(), st, err)
	}
	e.putBy(k3, ver(2))
	if b, err := e.loader("bundle/current.cbnd").Load(false); err != nil || b.Class() != ClassReference {
		t.Errorf("after restart: %v, %v", b, err)
	}
}

// mustRoot opens the bundle directory of the env.
func mustRoot(t *testing.T, e *env) *os.Root {
	t.Helper()
	d, err := e.root.OpenRoot("bundle")
	must(t, err)
	t.Cleanup(func() { d.Close() })
	return d
}

// T-S-20: a transition bundle needs a valid line of the old key and of the
// new key. It is refused with a key ID that is the old key ID, or that is in
// the trust set. It is refused with an old key that is not in the set.
func TestTS20RotationRefused(t *testing.T) {
	cases := []struct {
		name string
		do   func(e *env, k1, k2, k3 rkey)
	}{
		{"old key line only", func(e *env, k1, _, k3 rkey) { a := transition(k1, k3, ver(3)); e.put(a, lineOf(k1, a)) }},
		{"new key line only", func(e *env, k1, _, k3 rkey) { a := transition(k1, k3, ver(3)); e.put(a, lineOf(k3, a)) }},
		{"other trusted key in place of the old key", func(e *env, k1, k2, k3 rkey) {
			a := transition(k1, k3, ver(3))
			e.put(a, lineOf(k2, a), lineOf(k3, a))
		}},
		{"new key line of another key", func(e *env, k1, k2, k3 rkey) {
			a := transition(k1, k3, ver(3))
			e.put(a, lineOf(k1, a), lineOf(rkey{"k3", k2.priv, k3.pub}, a))
		}},
		{"from equals key_id", func(e *env, k1, _, _ rkey) { a := transition(k1, k1, ver(3)); e.put(a, lineOf(k1, a)) }},
		{"key_id in the trust set", func(e *env, k1, k2, _ rkey) {
			a := transition(k1, k2, ver(3))
			e.put(a, lineOf(k1, a), lineOf(k2, a))
		}},
		{"from not in the trust set", func(e *env, k1, _, k3 rkey) {
			a := transition(newKey(9, "k9"), k3, ver(3))
			e.put(a, lineOf(k1, a), lineOf(k3, a))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			k := e.keys()
			c.do(e, k[0], k[1], newKey(3, "k3"))
			e.rejects(e.l, false, ErrBadSig)
		})
	}
}

// T-S-20: the rotation checks come before the engine and rollback checks.
// A bundle with both lines gets the engine or version error only after it
// passes the rotation checks. Nothing is written.
func TestTS20RotationCheckOrder(t *testing.T) {
	for _, c := range []struct {
		name    string
		version string
		repl    []string
		both    bool
		want    error
	}{
		{"no old key line, lower version", ver(1), nil, false, ErrBadSig},
		{"no old key line, min_engine", ver(3), engineRepl, false, ErrBadSig},
		{"both lines, lower version", ver(1), nil, true, ErrRollback},
		{"both lines, min_engine", ver(3), engineRepl, true, ErrMinEngine},
		{"both lines, expired", ver(3), expiredRepl, true, ErrExpired},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			k := e.keys()
			k3 := newKey(3, "k3")
			arch := transition(k[0], k3, c.version, c.repl...)
			// The line of k2 is valid but it is not the line of the old key.
			old := lineOf(k[1], arch)
			if c.both {
				old = lineOf(k[0], arch)
			}
			e.put(arch, old, lineOf(k3, arch))
			e.rejects(e.l, false, c.want)
		})
	}
	t.Run("template_parse", func(t *testing.T) {
		e := running(t)
		e.l.template = stubParse
		arch := transition(e.keys()[0], newKey(3, "k3"), ver(3))
		e.put(arch, lineOf(e.keys()[0], arch), lineOf(newKey(3, "k3"), arch))
		e.rejects(e.l, false, ErrTemplateParse)
	})
}

// T-S-20: eight transitions load, and the ninth is refused with no write.
// After a restart the records apply in order. The key of the last record is
// trusted and the first key is not.
func TestTS20NinthTransition(t *testing.T) {
	e := running(t)
	cur := e.keys()[0]
	for i := 1; i <= 8; i++ {
		next := newKey(byte(10+i), fmt.Sprintf("r%d", i))
		e.rotates(cur, next, ver(2+i))
		cur = next
	}
	e.absent("rotation-9.json")
	next := newKey(30, "r9")
	arch := transition(cur, next, ver(11))
	e.put(arch, lineOf(cur, arch), lineOf(next, arch))
	e.rejects(e.l, false, ErrBadSig)
	l2 := e.loader("bundle/current.cbnd")
	e.putBy(cur, ver(11))
	if _, err := l2.Load(false); err != nil {
		t.Fatalf("last key: %v", err)
	}
	e.putBy(e.keys()[0], ver(12))
	e.rejects(l2, false, ErrBadSig)
	e.putBy(rkey{"r7", newKey(17, "r7").priv, [32]byte{}}, ver(12))
	e.rejects(l2, false, ErrBadSig)
}

// T-S-20: a failed write of a record gives a state fault. The version state
// and the files stay as they were. A failure of the second file removes the
// first.
func TestTS20RotationWriteFails(t *testing.T) {
	for _, name := range []string{"rotation-1.json", "rotation-1.sig"} {
		t.Run(name, func(t *testing.T) {
			e := running(t)
			k1, k3 := e.keys()[0], newKey(3, "k3")
			arch := transition(k1, k3, ver(3))
			e.put(arch, lineOf(k1, arch), lineOf(k3, arch))
			must(t, os.MkdirAll(filepath.Join(e.state, "bundle", name+".tmp", "x"), 0o700))
			st := mustRoot(t, e)
			before, err := readState(st)
			must(t, err)
			if _, err := e.l.Load(false); err != ErrStateFault {
				t.Fatalf("got %v", err)
			}
			if after, err := readState(st); err != nil || *after != *before {
				t.Errorf("state %+v, %v", after, err)
			}
			e.absent("rotation-1.json")
			if name == "rotation-1.json" {
				e.absent("rotation-1.sig")
			}
		})
	}
}

// T-S-20: a record that changed, or that is not whole, gives a state fault. The
// load refuses, Healthy is false, also after a restart, and no file changes.
func TestTS20RotationRecordFaults(t *testing.T) {
	edit := func(name string, f func(b []byte) []byte) func(e *env) {
		return func(e *env) {
			p := filepath.Join(e.state, "bundle", name)
			b, err := os.ReadFile(p)
			must(e.t, err)
			c := f(append([]byte(nil), b...))
			if bytes.Equal(b, c) {
				e.t.Fatal("the file did not change")
			}
			must(e.t, os.WriteFile(p, c, 0o600))
		}
	}
	file := func(f func(p string) error, names ...string) func(e *env) {
		return func(e *env) {
			for _, n := range names {
				must(e.t, f(filepath.Join(e.state, "bundle", n)))
			}
		}
	}
	chmod := func(p string) error { return os.Chmod(p, 0o644) }
	rename := func(p string) error { return os.Rename(p, strings.Replace(p, "rotation-1", "rotation-2", 1)) }
	swap := func(b []byte, i int, from, to byte) []byte {
		if b[i] == from {
			b[i] = to
		} else {
			b[i] = from
		}
		return b
	}
	cases := []struct {
		name string
		do   func(e *env)
	}{
		{"manifest byte", edit("rotation-1.json", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"from":"k1"`), []byte(`"from":"k2"`), 1)
		})},
		{"manifest without rotation", edit("rotation-1.json", func([]byte) []byte { return []byte(mf(ver(3))) })},
		{"sha line byte", edit("rotation-1.sig", func(b []byte) []byte { return swap(b, 0, '0', '1') })},
		{"sha line upper case", edit("rotation-1.sig", func(b []byte) []byte {
			i := bytes.IndexAny(b[:64], "abcdef")
			b[i] -= 'a' - 'A'
			return b
		})},
		{"sha line short", edit("rotation-1.sig", func(b []byte) []byte { return append(b[:63], b[64:]...) })},
		{"signature line byte", edit("rotation-1.sig", func(b []byte) []byte { return swap(b, 65+3+5, 'A', 'B') })},
		{"no .sig", file(os.Remove, "rotation-1.sig")},
		{"no .json", file(os.Remove, "rotation-1.json")},
		{"gap", file(rename, "rotation-1.json", "rotation-1.sig")},
		{"json mode 0644", file(chmod, "rotation-1.json")},
		{"sig mode 0644", file(chmod, "rotation-1.sig")},
		{"version state mode 0644", file(chmod, StateName)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			e.rotates(e.keys()[0], newKey(3, "k3"), ver(3))
			if !e.l.Healthy() {
				t.Fatal("not healthy before the change")
			}
			c.do(e)
			before := dirListing(t, e.state)
			l2 := e.loader("bundle/current.cbnd")
			if e.l.Healthy() || l2.Healthy() || dirListing(t, e.state) != before {
				t.Error("healthy, or a file changed")
			}
			e.rejects(e.l, false, ErrStateFault)
			e.rejects(l2, false, ErrStateFault)
		})
	}
}
