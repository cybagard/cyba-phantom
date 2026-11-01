package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"slices"
	"strings"
	"testing"
)

// testKey makes a test key. A test key is test text and is in no release set.
func testKey(seed byte, id string) (ed25519.PrivateKey, TrustKey) {
	priv := ed25519.NewKeyFromSeed(slices.Repeat([]byte{seed}, ed25519.SeedSize))
	return priv, TrustKey{KeyID: id, PublicKey: [32]byte(priv.Public().(ed25519.PublicKey)), Class: ClassProprietary}
}

var sigArchive = []byte("archive bytes of a signature test")

// sigRow makes one line of a signature file, with the newline.
func sigRow(id string, sig []byte) string {
	return id + " " + base64.StdEncoding.EncodeToString(sig) + "\n"
}

// signed makes a line with the right message.
func signed(id string, priv ed25519.PrivateKey) string {
	return sigRow(id, ed25519.Sign(priv, SigMessage(sigArchive)))
}

// T-S-20, T-U-08: the message is the prefix and the SHA-256 of the archive. A
// valid line verifies, and the result names the key IDs of the valid lines.
func TestTS20ValidLinesVerify(t *testing.T) {
	sum := sha256.Sum256(sigArchive)
	if m := SigMessage(sigArchive); string(m) != "phantom-bundle-sig-v1\n"+string(sum[:]) {
		t.Errorf("message %q", m)
	}
	privA, a := testKey(1, "a1")
	privB, b := testKey(2, "b2")
	for _, c := range []struct {
		sig  string
		want []string
	}{
		{signed("a1", privA), []string{"a1"}},
		{signed("b2", privB) + signed("a1", privA), []string{"b2", "a1"}},
		{signed("zz", privB) + signed("a1", privA), []string{"a1"}}} {
		got, err := VerifySig(sigArchive, []byte(c.sig), TrustSet{a, b})
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, %v; want %q", c.sig, got, err, c.want)
		}
	}
}

// T-S-20, T-U-08: each failure gives the one error, and CodeOf maps it to
// bad_sig. The text holds no input.
func TestTS20BadSig(t *testing.T) {
	priv, a := testKey(1, "a1")
	privB, b := testKey(2, "b2")
	privC, c3 := testKey(5, "c3")
	privOut, _ := testKey(3, "")
	privWrong, _ := testKey(4, "")
	good := signed("a1", priv)
	raw := ed25519.Sign(priv, SigMessage(sigArchive))
	sum := sha256.Sum256(sigArchive)
	// The group order L is 2^252 + 27742317777372353535851937790883648493.
	order, _ := new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	rev := func(b []byte) []byte { b = slices.Clone(b); slices.Reverse(b); return b }
	s := new(big.Int).Add(new(big.Int).SetBytes(rev(raw[32:])), order)
	over := slices.Concat(raw[:32], rev(s.FillBytes(make([]byte, 32))))
	// The last base64 character of 64 bytes has four padding bits. Flip one.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	pad := good[:len(good)-4] + string(alphabet[strings.IndexByte(alphabet, good[len(good)-4])^1]) + "==\n"
	changed := slices.Clone(sigArchive)
	changed[0] ^= 1
	for name, c := range map[string]struct {
		archive []byte
		sig     string
	}{
		"wrong key":                    {sigArchive, signed("a1", privWrong)},
		"changed archive byte":         {changed, good},
		"signature over the bare hash": {sigArchive, sigRow("a1", ed25519.Sign(priv, sum[:]))},
		"key outside the set":          {sigArchive, signed("zz", privOut)},
		"S plus the group order":       {sigArchive, sigRow("a1", over)},
		"non-canonical base64":         {sigArchive, pad},
		"duplicate key ID":             {sigArchive, good + good},
		"three lines":                  {sigArchive, good + signed("b2", privB) + signed("c3", privC)},
		"CR":                           {sigArchive, good[:len(good)-1] + "\r\n"},
		"trailing space":               {sigArchive, good[:len(good)-1] + " \n"},
		"empty line":                   {sigArchive, good + "\n"},
		"no final newline":             {sigArchive, good[:len(good)-1]},
		"bad trusted line, then valid": {sigArchive, signed("a1", privWrong) + signed("b2", privB)},
		"valid line, then bad trusted": {sigArchive, signed("a1", priv) + signed("b2", privWrong)},
	} {
		ids, err := VerifySig(c.archive, []byte(c.sig), TrustSet{a, b, c3})
		if code, ok := CodeOf(err); ids != nil || err != ErrBadSig || !ok || code != CodeBadSig || err.Error() != "bundle: bad_sig" {
			t.Errorf("%s: %q, %v", name, ids, err)
		}
	}
}

// T-S-20: parseSig accepts only the lines that make the same file again.
func FuzzTS20ParseSig(f *testing.F) {
	priv, _ := testKey(1, "")
	good := signed("a1", priv)
	three := good + signed("b2", priv) + signed("c3", priv)
	for _, s := range []string{good, good + signed("b2", priv), three, good + good, good + "\n", "", "a1 \n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		lines, ok := parseSig(b)
		var again strings.Builder
		for _, l := range lines {
			again.WriteString(sigRow(l.keyID, l.sig[:]))
		}
		if ok && (len(lines) < 1 || len(lines) > 2 || again.String() != string(b)) {
			t.Fatalf("%d lines do not make the input again", len(lines))
		}
	})
}

// T-S-20: Check refuses a duplicate key ID, a test key, and a key ID or class
// that is not valid. ParseKeyLine reads a valid public key line only.
func TestTS20TrustSet(t *testing.T) {
	_, a := testKey(1, "a1")
	_, b := testKey(2, "b2")
	dup := b
	dup.KeyID = "a1"
	for name, c := range map[string]struct {
		set  TrustSet
		test [][32]byte
		ok   bool
	}{
		"empty set":             {nil, nil, true},
		"two keys":              {TrustSet{a, b}, [][32]byte{{9}}, true},
		"one key ID twice":      {TrustSet{a, dup}, nil, false},
		"test key":              {TrustSet{a, b}, [][32]byte{{9}, b.PublicKey}, false},
		"key ID with a capital": {TrustSet{{KeyID: "A", Class: ClassReference}}, nil, false},
		"no class":              {TrustSet{{KeyID: "a"}}, nil, false},
	} {
		if err := c.set.Check(c.test); (err == nil) != c.ok || (err != nil && err != ErrTrustSet) {
			t.Errorf("%s: %v", name, err)
		}
	}
	line := "a1 " + base64.StdEncoding.EncodeToString(a.PublicKey[:])
	if id, k, ok := ParseKeyLine(line); !ok || id != "a1" || k != a.PublicKey {
		t.Errorf("valid line: %q, %v", id, ok)
	}
	if _, _, ok := ParseKeyLine(line + " "); ok {
		t.Error("line with a trailing space is accepted")
	}
}

// T-S-20: SigKeyIDs gives the key IDs in order, and false for a file that is
// not valid.
func TestTS20SigKeyIDs(t *testing.T) {
	privA, _ := testKey(1, "a1")
	privB, _ := testKey(2, "b2")
	a, b := signed("a1", privA), signed("b2", privB)
	for _, c := range []struct {
		sig  string
		want []string
		ok   bool
	}{
		{"", nil, false}, {a, []string{"a1"}, true}, {b + a, []string{"b2", "a1"}, true},
		{a + b + a, nil, false}, {a + a, nil, false}, {"junk\n", nil, false},
	} {
		if got, ok := SigKeyIDs([]byte(c.sig)); ok != c.ok || !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, %v", c.sig, got, ok)
		}
	}
}

// T-S-20: CheckSigned applies the rule of the loader. A normal bundle needs a
// line of its key ID. A transition bundle needs the old and the new line.
func TestTS20CheckSigned(t *testing.T) {
	privOld, old := testKey(1, "k1")
	privNew, newKey := testKey(2, "k2")
	privOther, _ := testKey(3, "k3")
	manifest := func(m string) []byte { return build(ent{name: "manifest.json", data: []byte(m)}) }
	normal := func(id string) []byte { return manifest(mf(ver(2), `"k1"`, q(id))) }
	pubText := base64.StdEncoding.EncodeToString(newKey.PublicKey[:])
	transition := manifest(strings.NewReplacer(`"k1"`, `"k2"`, `"zz"`, `"k1"`).Replace(with("rotation", rot("zz", pubText))))
	line := func(id string, priv ed25519.PrivateKey, arch []byte) string {
		return sigRow(id, ed25519.Sign(priv, SigMessage(arch)))
	}
	for _, c := range []struct {
		name  string
		arch  []byte
		sig   string
		trust TrustSet
		want  []string
		err   error
	}{
		{"normal", normal("k1"), line("k1", privOld, normal("k1")), TrustSet{old}, []string{"k1"}, nil},
		{"transition", transition, line("k1", privOld, transition) + line("k2", privNew, transition), TrustSet{old}, []string{"k1", "k2"}, nil},
		{"no new line", transition, line("k1", privOld, transition), TrustSet{old}, nil, ErrBadSig},
		{"no old line", transition, line("k2", privNew, transition), TrustSet{old}, nil, ErrBadSig},
		{"key ID not in the set", normal("k2"), line("k1", privOld, normal("k2")), TrustSet{old}, nil, ErrBadSig},
		{"key ID not the signer", normal("k2"), line("k1", privOld, normal("k2")), TrustSet{old, newKey}, nil, ErrBadSig},
		{"bad file", normal("k1"), "junk\n", TrustSet{old}, nil, ErrBadSig},
		{"bad archive", []byte("x"), line("k1", privOld, []byte("x")), TrustSet{old}, nil, ErrArchiveInvalid},
		{"bad manifest", manifest("{}"), line("k1", privOld, manifest("{}")), TrustSet{old}, nil, ErrManifestInvalid},
		{"other line", transition, line("k3", privOther, transition), TrustSet{old}, nil, ErrBadSig},
	} {
		got, err := CheckSigned(c.arch, []byte(c.sig), c.trust)
		if err != c.err || !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, %v; want %q, %v", c.name, got, err, c.want, c.err)
		}
	}
}
