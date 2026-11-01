package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
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
	return build(transitionEnt(from, to, version, repl...))
}

func transitionEnt(from, to rkey, version string, repl ...string) ent {
	rotation := q(to.id) + `,"rotation":` + rot(from.id, base64.StdEncoding.EncodeToString(to.pub[:]))
	return ent{name: "manifest.json", data: []byte(mf(version, append([]string{`"k1"`, rotation}, repl...)...))}
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

// putBoth writes a transition bundle that both keys sign.
func (e *env) putBoth(from, to rkey, version string, repl ...string) []byte {
	e.t.Helper()
	arch := transition(from, to, version, repl...)
	e.put(arch, lineOf(from, arch), lineOf(to, arch))
	return arch
}

// rotates writes a transition bundle that both keys sign, and loads it.
func (e *env) rotates(from, to rkey, version string) *Bundle {
	e.t.Helper()
	e.putBoth(from, to, version)
	b, err := e.l.Load(false)
	must(e.t, err)
	return b
}

// fault loads, expects a state fault, and expects a loader that is not healthy.
func (e *env) fault(l *Loader, start bool) {
	e.t.Helper()
	if e.rejects(l, start, ErrStateFault); l.Healthy() {
		e.t.Error("healthy")
	}
}

// record writes transition record n with these signature lines.
func (e *env) record(n int, arch []byte, lines ...string) {
	e.t.Helper()
	e.write("bundle/"+recordName(n, "cbnd"), arch)
	e.write("bundle/"+recordName(n, "sig"), []byte(strings.Join(lines, "")))
}

// read gives the bytes of a file of the bundle directory.
func (e *env) read(name string) []byte {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.state, "bundle", name))
	must(e.t, err)
	return b
}

// absent expects that the files of record n do not exist.
func (e *env) absent(n int) {
	e.t.Helper()
	for _, ext := range []string{"cbnd", "sig"} {
		if _, err := os.Lstat(filepath.Join(e.state, "bundle", recordName(n, ext))); err == nil {
			e.t.Errorf("record %d exists", n)
		}
	}
}

// T-S-20, SEC-24: a transition bundle with both lines loads and writes its
// record. Then the old key is not trusted, also after a restart. The new key
// is trusted. The transition bundle loads again and writes no second record.
func TestTS20RotationAccepted(t *testing.T) {
	e := running(t)
	k1, k3 := e.keys()[0], newKey(3, "k3")
	// The pad makes the archive larger than the cap of a signature file.
	pad := make([]byte, 5000)
	rand.NewChaCha8([32]byte{1}).Read(pad)
	arch := build(transitionEnt(k1, k3, ver(3)), ent{name: "traps/pad", data: pad})
	e.put(arch, lineOf(k1, arch), lineOf(k3, arch))
	sig := e.read("current.sig")
	b, err := e.l.Load(false)
	must(t, err)
	if b.Manifest().Rotation == nil || b.Class() != ClassProprietary ||
		!bytes.Equal(e.read("rotation-1.cbnd"), arch) || !bytes.Equal(e.read("rotation-1.sig"), sig) || !e.l.Healthy() {
		t.Errorf("bundle %+v, or not healthy", b.Manifest())
	}
	e.putBy(k1, ver(4))
	e.rejects(e.l, false, ErrBadSig)
	l2 := e.loader("bundle/current.cbnd")
	e.rejects(l2, false, ErrBadSig)
	e.put(arch, lineOf(k1, arch), lineOf(k3, arch))
	if b2, err := l2.Load(true); err != nil || b2.SHA256() != b.SHA256() || !l2.Healthy() {
		t.Fatalf("again: %v, %v", b2, err)
	}
	e.absent(2)
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
	e.putBoth(k2, k3, ver(3))
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

// T-S-20: the loader refuses a transition bundle without a valid line of the
// old key or of the new key. It also refuses a key ID that is the old key ID.
// It refuses a key ID in the trust set and an old key that is not in the set.
func TestTS20RotationRefused(t *testing.T) {
	cases := []struct {
		name string
		do   func(e *env, k1, k2, k3 rkey)
	}{
		{"old key line only", func(e *env, k1, _, k3 rkey) { a := transition(k1, k3, ver(3)); e.put(a, lineOf(k1, a)) }},
		{"new key line only", func(e *env, k1, _, k3 rkey) { a := transition(k1, k3, ver(3)); e.put(a, lineOf(k3, a)) }},
		{"other trusted key in place of the old key", func(e *env, k1, k2, k3 rkey) { a := transition(k1, k3, ver(3)); e.put(a, lineOf(k2, a), lineOf(k3, a)) }},
		{"new key line of another key", func(e *env, k1, k2, k3 rkey) {
			a := transition(k1, k3, ver(3))
			e.put(a, lineOf(k1, a), lineOf(rkey{"k3", k2.priv, k3.pub}, a))
		}},
		{"from equals key_id", func(e *env, k1, _, _ rkey) { a := transition(k1, k1, ver(3)); e.put(a, lineOf(k1, a)) }},
		{"key_id in the trust set", func(e *env, k1, k2, _ rkey) { e.putBoth(k1, k2, ver(3)) }},
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

// T-S-20, SEC-24: a small-order key as the new key of a transition bundle is
// refused. This holds also when the line of that key verifies. The line has R
// as the base point and S as 1. It verifies for some archives, so the test
// changes the version until it does. The old key signs. No record is written.
func TestTS20SmallOrderRotationKey(t *testing.T) {
	sig := append([]byte{0x58}, bytes.Repeat([]byte{0x66}, 31)...)
	sig = append(sig, 1)
	sig = append(sig, make([]byte, 31)...)
	for _, key := range smallOrderKeys(t) {
		t.Run(fmt.Sprintf("%x", key[:2]), func(t *testing.T) {
			e := running(t)
			k1, evil := e.keys()[0], rkey{id: "k3", pub: key}
			var arch []byte
			for n := 3; n < 3+256 && arch == nil; n++ {
				if a := transition(k1, evil, ver(n)); ed25519.Verify(key[:], SigMessage(a), sig) {
					arch = a
				}
			}
			if arch == nil {
				t.Fatal("no archive of 256 verifies with the forged line")
			}
			e.put(arch, lineOf(k1, arch), sigRow("k3", sig))
			e.rejects(e.l, false, ErrBadSig)
			e.absent(1)
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
		e.putBoth(e.keys()[0], newKey(3, "k3"), ver(3))
		e.rejects(e.l, false, ErrTemplateParse)
	})
}

// T-S-20: the loader accepts eight transitions and refuses the ninth, with no
// write. After a restart, it applies the records in order. It trusts the key of
// the last record and does not trust the first key.
func TestTS20NinthTransition(t *testing.T) {
	e := running(t)
	cur := e.keys()[0]
	for i := 1; i <= 8; i++ {
		next := newKey(byte(10+i), fmt.Sprintf("r%d", i))
		e.rotates(cur, next, ver(2+i))
		cur = next
	}
	e.absent(9)
	e.putBoth(cur, newKey(30, "r9"), ver(11))
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

// T-S-20: a failed write of a record or of the version state gives a state
// fault. No record stays. The loader keeps the old key, also after a restart.
func TestTS20RotationWriteFails(t *testing.T) {
	for _, name := range []string{"rotation-1.cbnd", "rotation-1.sig", StateName} {
		t.Run(name, func(t *testing.T) {
			e := running(t)
			k1, k3 := e.keys()[0], newKey(3, "k3")
			e.putBoth(k1, k3, ver(3))
			blocker := filepath.Join(e.state, "bundle", name+".tmp")
			must(t, os.MkdirAll(filepath.Join(blocker, "x"), 0o700))
			st := mustRoot(t, e)
			before, err := readState(st)
			must(t, err)
			if _, err := e.l.Load(false); err != ErrStateFault {
				t.Fatalf("got %v", err)
			}
			if after, err := readState(st); err != nil || *after != *before {
				t.Errorf("state %+v, %v", after, err)
			}
			e.absent(1)
			must(t, os.RemoveAll(blocker))
			e.putBy(k1, ver(4))
			if _, err := e.l.Load(false); err != nil {
				t.Errorf("old key in memory: %v", err)
			}
			if _, err := e.loader("bundle/current.cbnd").Load(true); err != nil {
				t.Errorf("old key after a restart: %v", err)
			}
		})
	}
}

// T-S-20: a failed chain check after the write of a record removes the record
// and gives a state fault. The fault stays: Healthy is false and a later load
// gives a state fault.
func TestTS20RotationRecordCheckFails(t *testing.T) {
	e := running(t)
	k1, k3 := e.keys()[0], newKey(3, "k3")
	e.putBoth(k1, k3, ver(3))
	calls := 0
	e.l.decompress = func(b []byte) (*Archive, error) {
		if calls++; calls > 1 {
			return nil, ErrArchiveInvalid
		}
		return ReadArchive(b)
	}
	if _, err := e.l.Load(false); err != ErrStateFault {
		t.Fatalf("got %v", err)
	}
	e.absent(1)
	e.fault(e.l, false)
}

// T-S-20: a forged record gives a state fault at the next start. It holds the
// installed normal bundle and a line of another key. The loader is not healthy.
func TestTS20RotationForgedRecord(t *testing.T) {
	e := running(t)
	kx := newKey(9, "kx")
	arch := e.read("current.cbnd")
	e.record(1, arch, string(e.read("current.sig"))+lineOf(kx, arch))
	l2 := e.loader("bundle/current.cbnd")
	e.fault(l2, true)
	e.putBy(kx, ver(3))
	e.rejects(l2, false, ErrStateFault)
}

// T-S-20: a record archive with no line of a key of the set gives a state fault
// before the decompress. The archive of one transition with the signature file
// of another gives a state fault.
func TestTS20RotationRecordSignatures(t *testing.T) {
	e := running(t)
	k1, k3, k4 := e.keys()[0], newKey(3, "k3"), newKey(4, "k4")
	arch := transition(k1, k3, ver(3))
	e.record(1, arch, lineOf(k3, arch))
	if n := e.rejects(e.loader("bundle/current.cbnd"), true, ErrStateFault); n != 0 {
		t.Errorf("%d decompress calls", n)
	}
	e = running(t)
	e.rotates(k1, k3, ver(3))
	e.rotates(k3, k4, ver(4))
	e.write("bundle/rotation-2.sig", e.read("rotation-1.sig"))
	e.rejects(e.loader("bundle/current.cbnd"), true, ErrStateFault)
}

// T-S-20: a record counts when its transition bundle is expired or needs a
// newer engine. After a restart, the new key loads and the old key does not.
func TestTS20RotationRecordHasNoBundleRules(t *testing.T) {
	for name, repl := range map[string][]string{"expired": expiredRepl, "min_engine": engineRepl} {
		t.Run(name, func(t *testing.T) {
			e := running(t)
			k1, k3 := e.keys()[0], newKey(3, "k3")
			arch := transition(k1, k3, ver(3), repl...)
			e.record(1, arch, lineOf(k1, arch), lineOf(k3, arch))
			e.putBy(k3, ver(4))
			l2 := e.loader("bundle/current.cbnd")
			if _, err := l2.Load(true); err != nil || !l2.Healthy() {
				t.Fatalf("new key: %v", err)
			}
			e.putBy(k1, ver(5))
			e.rejects(l2, false, ErrBadSig)
		})
	}
}

// T-S-20: the loader refuses a new key or key ID that is in the set.
// It also refuses one that an earlier record removed. A new transition bundle
// gives bad_sig. A record gives a state fault. A fresh row has no earlier
// record: k1 is the old key and is in the set.
func TestTS20RotationRetiredKeys(t *testing.T) {
	k1, k2 := newKey(1, "k1"), newKey(2, "k2")
	for _, c := range []struct {
		name  string
		to    rkey
		fresh bool
	}{
		{"old ID, old key", k1, false},
		{"old ID, other key", newKey(9, "k1"), false},
		{"new ID, removed key", rkey{"k5", k1.priv, k1.pub}, false},
		{"new ID, the old key", rkey{"k5", k1.priv, k1.pub}, true},
		{"new ID, a key of the set", rkey{"k5", k2.priv, k2.pub}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			from, to, n := newKey(3, "k3"), c.to, 2
			if c.fresh {
				from, n = k1, 1
			} else {
				e.rotates(k1, from, ver(3))
			}
			arch := e.putBoth(from, to, ver(4))
			e.rejects(e.l, false, ErrBadSig)
			e.record(n, arch, lineOf(from, arch), lineOf(to, arch))
			e.rejects(e.loader("bundle/current.cbnd"), true, ErrStateFault)
		})
	}
}

// T-S-20: a file or another entry at the name of record 9 gives a state
// fault. This holds when no bundle file exists.
func TestTS20RotationNinthEntry(t *testing.T) {
	for _, name := range []string{"rotation-9.cbnd", "rotation-9.sig"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.write("bundle/"+name, []byte("x"))
			e.fault(e.loader("bundle/current.cbnd"), true)
		})
	}
}

// T-S-20: a load that is not at start uses the trust set in memory and reads no
// record. A record that changes after a check gives a fault at the next start.
func TestTS20RotationChainInMemory(t *testing.T) {
	e := running(t)
	k3 := newKey(3, "k3")
	e.rotates(e.keys()[0], k3, ver(3))
	e.write("bundle/rotation-1.cbnd", []byte("changed"))
	e.putBy(k3, ver(4))
	if _, err := e.l.Load(false); err != nil || !e.l.Healthy() {
		t.Fatalf("load or healthy after the change: %v", err)
	}
	l2 := e.loader("bundle/current.cbnd")
	e.rejects(l2, true, ErrStateFault)
	e.rejects(l2, false, ErrStateFault)
}

// T-S-20: a bundle directory that does not exist is healthy, as at a first
// start. Another error at the open of the directory is not healthy.
func TestTS20HealthyWithoutBundleDirectory(t *testing.T) {
	e := newEnv(t)
	must(t, os.Symlink("keys", filepath.Join(e.state, "b1")))
	for path, want := range map[string]bool{"none/current.cbnd": true, "b1/current.cbnd": false} {
		if got := e.loader(path).Healthy(); got != want {
			t.Errorf("%s: healthy %v; want %v", path, got, want)
		}
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
	link := func(p string) error { return os.Link(p, p+".link") }
	rename := func(p string) error { return os.Rename(p, strings.Replace(p, "rotation-1", "rotation-2", 1)) }
	// swap sets byte i to A or B, so the byte changes and stays valid base64.
	swap := func(b []byte, i int) []byte { b[i] = "AB"[b[i]&1]; return b }
	cases := []struct {
		name string
		do   func(e *env)
	}{
		{"archive byte", edit("rotation-1.cbnd", func(b []byte) []byte { return swap(b, len(b)/2) })},
		{"old key line byte", edit("rotation-1.sig", func(b []byte) []byte { return swap(b, 3+5) })},
		{"signed by another trusted key", func(e *env) {
			arch := e.read("rotation-1.cbnd")
			e.record(1, arch, lineOf(e.keys()[1], arch), lineOf(newKey(3, "k3"), arch))
		}},
		{"no rotation member", func(e *env) {
			arch := build(ent{name: "manifest.json", data: []byte(mf(ver(3)))})
			e.record(1, arch, lineOf(e.keys()[0], arch))
		}},
		{"no .sig", file(os.Remove, "rotation-1.sig")},
		{"no .cbnd", file(os.Remove, "rotation-1.cbnd")},
		{"gap", file(rename, "rotation-1.cbnd", "rotation-1.sig")},
		{"cbnd mode 0644", file(chmod, "rotation-1.cbnd")},
		{"sig mode 0644", file(chmod, "rotation-1.sig")},
		{"cbnd hard link", file(link, "rotation-1.cbnd")},
		{"sig hard link", file(link, "rotation-1.sig")},
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
			e.fault(e.loader("bundle/current.cbnd"), true)
		})
	}
}
