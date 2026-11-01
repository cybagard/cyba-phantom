package bundle

import (
	"bytes"
	"crypto/hpke"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// pattern gives n bytes from a fixed pattern, so no key or seed value comes
// from outside this file.
func pattern(n int, mul, add byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)*mul + add
	}
	return b
}

var (
	seedA = pattern(seedSize, 7, 3)
	seedB = pattern(seedSize, 11, 5)
)

func testInstall(t *testing.T, add byte) hpke.PrivateKey {
	t.Helper()
	k, err := installKEM().NewPrivateKey(pattern(32, 5, add))
	must(t, err)
	return k
}

// sealTo seals plain to the key with the info of this version and key ID.
func sealTo(t *testing.T, k hpke.PrivateKey, version, id string, plain []byte) []byte {
	t.Helper()
	ct, err := hpke.Seal(k.PublicKey(), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), seedInfo(version, id), plain)
	must(t, err)
	return ct
}

func sealedEnt(ct []byte) ent { return ent{name: seedSealedName, data: ct} }
func plainEnt(b []byte) ent   { return ent{name: seedPlainName, data: b} }

// seedLoader gives a loader from NewLoader, so it runs the real seed step.
func (e *env) seedLoader(install hpke.PrivateKey) *Loader {
	l := NewLoader(e.root, "bundle/current.cbnd", e.trust, install)
	l.now = func() time.Time { return testNow }
	return l
}

// putSeeded writes a bundle of key k and this version with these seed files.
func (e *env) putSeeded(k rkey, version string, files ...ent) {
	e.t.Helper()
	arch := build(append([]ent{{name: "manifest.json", data: []byte(mf(version, `"k1"`, q(k.id)))}}, files...)...)
	e.put(arch, lineOf(k, arch))
}

// good gives the valid seed file of the key: sealed for k1, plain for k2.
func (e *env) good(install hpke.PrivateKey, k rkey, version string, seed []byte) ent {
	if k.id == "k2" {
		return plainEnt(seed)
	}
	return sealedEnt(sealTo(e.t, install, version, k.id, seed))
}

// seeded gives an env whose loader runs a valid bundle of version 2 and key k.
func seeded(t *testing.T, k func(*env) rkey) (*env, *Loader, hpke.PrivateKey, rkey) {
	t.Helper()
	e, install := newEnv(t), testInstall(t, 1)
	key, l := k(e), e.seedLoader(install)
	e.putSeeded(key, ver(2), e.good(install, key, ver(2), seedA))
	_, err := l.Load(false)
	must(t, err)
	return e, l, install, key
}

func keyOne(e *env) rkey { return e.keys()[0] }
func keyTwo(e *env) rkey { return e.keys()[1] }

// T-S-20, T-U-08: each wrong seed gives seed_invalid. The running bundle and
// the files stay.
func TestTU08SeedInvalid(t *testing.T) {
	other := testInstall(t, 2)
	flip := func(ct []byte) []byte { ct = bytes.Clone(ct); ct[len(ct)/2] ^= 1; return ct }
	for _, c := range []struct {
		name  string
		two   bool // the reference key signs
		files func(in hpke.PrivateKey) []ent
	}{
		{"other install key", false, func(hpke.PrivateKey) []ent { return []ent{sealedEnt(sealTo(t, other, ver(3), "k1", seedA))} }},
		{"changed ciphertext", false, func(in hpke.PrivateKey) []ent {
			return []ent{sealedEnt(flip(sealTo(t, in, ver(3), "k1", seedA)))}
		}},
		{"other version in info", false, func(in hpke.PrivateKey) []ent { return []ent{sealedEnt(sealTo(t, in, ver(4), "k1", seedA))} }},
		{"other key ID in info", false, func(in hpke.PrivateKey) []ent { return []ent{sealedEnt(sealTo(t, in, ver(3), "k2", seedA))} }},
		{"plain seed in proprietary", false, func(hpke.PrivateKey) []ent { return []ent{plainEnt(seedA)} }},
		{"sealed seed in reference", true, func(in hpke.PrivateKey) []ent { return []ent{sealedEnt(sealTo(t, in, ver(3), "k2", seedA))} }},
		{"no seed, proprietary", false, func(hpke.PrivateKey) []ent { return nil }},
		{"no seed, reference", true, func(hpke.PrivateKey) []ent { return nil }},
		{"both files, proprietary", false, func(in hpke.PrivateKey) []ent {
			return []ent{plainEnt(seedA), sealedEnt(sealTo(t, in, ver(3), "k1", seedA))}
		}},
		{"both files, reference", true, func(in hpke.PrivateKey) []ent {
			return []ent{plainEnt(seedA), sealedEnt(sealTo(t, in, ver(3), "k2", seedA))}
		}},
		{"plain 31", true, func(hpke.PrivateKey) []ent { return []ent{plainEnt(seedA[:31])} }},
		{"plain 33", true, func(hpke.PrivateKey) []ent { return []ent{plainEnt(append(bytes.Clone(seedA), 1))} }},
		{"sealed 31", false, func(in hpke.PrivateKey) []ent {
			return []ent{sealedEnt(sealTo(t, in, ver(3), "k1", seedA[:31]))}
		}},
		{"sealed 33", false, func(in hpke.PrivateKey) []ent {
			return []ent{sealedEnt(sealTo(t, in, ver(3), "k1", append(bytes.Clone(seedA), 1)))}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := keyOne
			if c.two {
				k = keyTwo
			}
			e, l, in, key := seeded(t, k)
			e.putSeeded(key, ver(3), c.files(in)...)
			e.rejects(l, false, ErrSeedInvalid)
		})
	}
	code, ok := CodeOf(ErrSeedInvalid)
	if !ok || code != CodeSeedInvalid || code.String() != "seed_invalid" || ErrSeedInvalid.Error() != "bundle: seed_invalid" {
		t.Errorf("code %v %v, error %q", code, ok, ErrSeedInvalid)
	}
	t.Run("nil install key", func(t *testing.T) {
		e := newEnv(t)
		e.putSeeded(keyOne(e), ver(2), e.good(testInstall(t, 1), keyOne(e), ver(2), seedA))
		e.rejects(e.seedLoader(nil), false, ErrSeedInvalid)
	})
}

// T-S-20: a valid bundle of each class opens its seed, a copy. File gives no
// seed file. The plain archive entry is zero, and the sealed entry stays.
func TestTS20SeedOpened(t *testing.T) {
	for _, k := range []func(*env) rkey{keyOne, keyTwo} {
		e, l, in, key := seeded(t, k)
		b := l.Current()
		name := seedSealedName
		if key.id == "k2" {
			name = seedPlainName
		}
		raw, _ := b.archive.File(name)
		if _, ok := b.File(name); ok || b.seed == nil || !bytes.Equal(*b.seed, seedA) ||
			bytes.Equal(raw, zeros(len(raw))) != (key.id == "k2") {
			t.Fatalf("%s: seed or entry wrong", key.id)
		}
		if &(*b.seed)[0] == &raw[0] {
			t.Errorf("%s: the seed is a part of the archive bytes", key.id)
		}
		// A swap zeroes the old seed and keeps the new one.
		old := *b.seed
		e.putSeeded(key, ver(3), e.good(in, key, ver(3), seedB))
		nb, err := l.Load(false)
		must(t, err)
		if !bytes.Equal(old, zeros(seedSize)) || !bytes.Equal(*nb.seed, seedB) {
			t.Errorf("%s: after the swap the old seed %v or the new seed is wrong", key.id, old)
		}
	}
}

// T-S-20: the info of a sealed seed is the label, the version and the key ID.
// A zero byte comes before each part. The test gives the bytes in full.
func TestTS20SeedInfo(t *testing.T) {
	e, in := newEnv(t), testInstall(t, 1)
	info := []byte("phantom-bundle-seed-v1\x00" + ver(2) + "\x00k1")
	ct, err := hpke.Seal(in.PublicKey(), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info, seedA)
	must(t, err)
	e.putSeeded(keyOne(e), ver(2), sealedEnt(ct))
	b, err := e.seedLoader(in).Load(false)
	must(t, err)
	if !bytes.Equal(*b.seed, seedA) {
		t.Error("the seed differs")
	}
}

// T-S-20: a seed prints a fixed text and gives no byte to fmt, json, slog and
// gob.
func TestTS20SeedPrint(t *testing.T) {
	s := seedBytes(bytes.Clone(seedA))
	var out []string
	for _, v := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		for _, o := range []string{fmt.Sprintf(v, s), fmt.Sprintf(v, &s)} {
			if o != seedText {
				t.Errorf("%s: %q", v, o)
			}
		}
		out = append(out, fmt.Sprintf(v, struct{ S seedBytes }{s}))
	}
	js, err := json.Marshal(map[string]any{"s": s, "p": &s})
	must(t, err)
	var text, jsn bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("m", "seed", s)
	slog.New(slog.NewJSONHandler(&jsn, nil)).Info("m", "seed", &s)
	out = append(out, string(js), text.String(), jsn.String())
	for _, o := range out {
		if ikHas(o, seedMarkers(seedA)) || !strings.Contains(o, seedText) {
			t.Errorf("print: %q", o)
		}
	}
	if !strings.HasSuffix(text.String(), " msg=m seed=[seed]\n") {
		t.Errorf("text handler: %q", text.String())
	}
	if o := fmt.Sprintf("%+v", &Bundle{seed: &s}); ikHas(o, seedMarkers(seedA)) {
		t.Errorf("print of a Bundle: %q", o)
	}
	if seedText != "[seed]" {
		t.Errorf("seedText %q", seedText)
	}
	for _, v := range []any{s, &s} {
		var buf bytes.Buffer
		err := gob.NewEncoder(&buf).Encode(v) // gob refuses a seed
		if err == nil || ikHas(err.Error()+buf.String(), seedMarkers(seedA)) {
			t.Errorf("%T: gob error %v, output %q", v, err, buf.String())
		}
		if str, ok := v.(fmt.Stringer); !ok || str.String() != seedText {
			t.Errorf("%T is not a Stringer with seedText", v)
		}
	}
}

// seedMarkers gives the raw, base64, lower hex, upper hex and quoted form of b.
func seedMarkers(b []byte) []string {
	return append(ikMarkers(b), strings.ToUpper(hex.EncodeToString(b)), strconv.Quote(string(b)), fmt.Sprintf("%q", b))
}

// T-S-20: a reference bundle with a plain seed loads with a nil install key.
// File gives no entry below secrets/, also not one that is no seed file.
func TestTS20SeedReference(t *testing.T) {
	e := newEnv(t)
	e.putSeeded(keyTwo(e), ver(2), plainEnt(seedA), ent{name: "secrets/a", data: []byte("a")})
	b, err := e.seedLoader(nil).Load(false)
	must(t, err)
	if b.seed == nil || !bytes.Equal(*b.seed, seedA) {
		t.Error("the seed differs")
	}
	for _, name := range []string{"secrets/a", seedPlainName, seedSealedName} {
		if data, ok := b.File(name); ok || data != nil {
			t.Errorf("File(%q) gives %q, %v", name, data, ok)
		}
	}
}

// T-S-20: a candidate that passes the seed step and fails a later write keeps
// no seed. The blocker is a directory in place of the temporary file, as in
// TestTS20RotationWriteFails. The row of the record is another return in Load.
func TestTS20SeedRejectedCleared(t *testing.T) {
	for blocker, transition := range map[string]bool{StateName: false, "rotation-1.cbnd": true} {
		t.Run(blocker, func(t *testing.T) {
			e, install := newEnv(t), testInstall(t, 1)
			k1, l := e.keys()[0], e.seedLoader(install)
			var opened *seedBytes
			step := l.seed
			l.seed = func(a *Archive, class Class, m *Manifest) (*seedBytes, error) {
				s, err := step(a, class, m)
				opened = s
				return s, err
			}
			e.putSeeded(k1, ver(2), e.good(install, k1, ver(2), seedA))
			_, err := l.Load(false)
			must(t, err)
			if transition {
				k3 := newKey(3, "k3")
				arch := build(transitionEnt(k1, k3, ver(3)), sealedEnt(sealTo(t, install, ver(3), "k3", seedB)))
				e.put(arch, lineOf(k1, arch), lineOf(k3, arch))
			} else {
				e.putSeeded(k1, ver(3), e.good(install, k1, ver(3), seedB))
			}
			must(t, os.MkdirAll(filepath.Join(e.state, "bundle", blocker+".tmp", "x"), 0o700))
			if _, err := l.Load(false); err != ErrStateFault {
				t.Fatalf("got %v", err)
			}
			if !bytes.Equal(*opened, zeros(seedSize)) {
				t.Errorf("the seed of the rejected candidate is %v", opened)
			}
			if !bytes.Equal(*l.Current().seed, seedA) {
				t.Error("the running seed changed")
			}
		})
	}
}

// T-S-20: run a load, a swap and a rejection. No seed or key marker is in an
// error or in the default log. None is in a file below the state directory,
// except keys/install.key. This change adds no event.
func TestTS20SeedMarkers(t *testing.T) {
	ikLogs(t)
	e := newEnv(t)
	in, err := LoadOrCreateInstallKey(e.root)
	must(t, err)
	priv, err := in.Bytes()
	must(t, err)
	markers := append(seedMarkers(seedA), append(seedMarkers(seedB), seedMarkers(priv)...)...)
	l, k := e.seedLoader(in), keyOne(e)
	var errs []error
	for i, f := range [][]ent{
		{sealedEnt(sealTo(t, in, ver(2), "k1", seedA))},
		{sealedEnt(sealTo(t, in, ver(3), "k1", seedB))},
		{plainEnt(pattern(32, 13, 9))}, // rejected; no marker
	} {
		e.putSeeded(k, ver(2+i), f...)
		_, err := l.Load(false)
		errs = append(errs, err)
	}
	if errs[0] != nil || errs[1] != nil || errs[2] != ErrSeedInvalid {
		t.Fatalf("errors %v", errs)
	}
	for _, err := range errs {
		if err != nil && ikHas(err.Error(), markers) {
			t.Errorf("marker in error %q", err)
		}
	}
	ikWalk(t, e.state, markers)
}
