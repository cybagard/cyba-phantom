package verify

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// hb returns the canonical base64 of a 32-byte hash whose bytes are all n.
func hb(n byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)) }

// hashList returns a JSON array of n hashes.
func hashList(n int) string {
	s := make([]string, n)
	for i := range s {
		s[i] = `"` + hb(byte(i)) + `"`
	}
	return "[" + strings.Join(s, ",") + "]"
}

// T-S-14, input cases: the inclusion proof file.
func TestTS14_Proof(t *testing.T) {
	h1, h2 := hb(1), hb(2)
	b64 := func(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
	obj := func(index, size, hashes, tail string) string {
		return fmt.Sprintf(`{"index":%s,"tree_size":%s,"hashes":%s%s}`, index, size, hashes, tail)
	}
	rc := fmt.Sprintf(`,"root":"%s","consistency":[%q]`, h1, h2)
	good := obj("5", "9", `["`+h1+`","`+h2+`"]`, "")
	p, err := ReadInclusionProof(strings.NewReader(good))
	if err != nil || p.Index != 5 || p.TreeSize != 9 || len(p.Hashes) != 2 || p.Hashes[0][0] != 1 || p.Root != nil || p.Consistency != nil {
		t.Fatalf("good proof: %+v, %v", p, err)
	}
	p, err = ParseInclusionProof([]byte(obj("0", "1", "[]", rc)))
	if err != nil || p.Root == nil || p.Root[0] != 1 || len(p.Consistency) != 1 || p.Hashes == nil {
		t.Fatalf("proof with root and consistency: %+v, %v", p, err)
	}
	if _, err := ParseInclusionProof([]byte(obj("0", "1", "[]", `,"root":"`+h1+`","consistency":[]`))); err != nil {
		t.Errorf("empty consistency list with a root: %v", err)
	}
	if _, err := ParseInclusionProof([]byte(obj("281474976710656", "281474976710656", hashList(48), `,"root":"`+h1+`","consistency":`+hashList(96)))); err != nil {
		t.Errorf("limits (2^48, 48 and 96 hashes): %v", err)
	}
	for name, tc := range map[string]struct {
		in   string
		want error
	}{
		"duplicate member":      {`{"index":1,"index":1,"tree_size":2,"hashes":[]}`, ErrProof},
		"unknown member":        {obj("1", "2", "[]", `,"SECRETMARKER":1`), ErrProof},
		"wrong-case member":     {`{"Index":1,"tree_size":2,"hashes":[]}`, ErrProof},
		"wrong-case hashes":     {`{"index":1,"tree_size":2,"Hashes":[]}`, ErrProof},
		"missing index":         {`{"tree_size":2,"hashes":[]}`, ErrProof},
		"missing tree_size":     {`{"index":1,"hashes":[]}`, ErrProof},
		"missing hashes":        {`{"index":1,"tree_size":2}`, ErrProof},
		"null hashes":           {obj("1", "2", "null", ""), ErrProof},
		"null index":            {obj("null", "2", "[]", ""), ErrProof},
		"null root":             {obj("1", "2", "[]", `,"root":null,"consistency":[]`), ErrProof},
		"null consistency":      {obj("1", "2", "[]", `,"root":"`+h1+`","consistency":null`), ErrProof},
		"null element":          {obj("1", "2", `[null]`, ""), ErrProof},
		"root alone":            {obj("1", "2", "[]", `,"root":"`+h1+`"`), ErrProof},
		"consistency alone":     {obj("1", "2", "[]", `,"consistency":[]`), ErrProof},
		"top-level null":        {`null`, ErrProof},
		"array":                 {`[]`, ErrProof},
		"string":                {`"x"`, ErrProof},
		"empty":                 {``, ErrProof},
		"second value":          {good + good, ErrProof},
		"trailing garbage":      {good + `x`, ErrProof},
		"hash without padding":  {obj("1", "2", `["`+strings.TrimRight(h1, "=")+`"]`, ""), ErrProof},
		"URL alphabet":          {obj("1", "2", `["`+strings.NewReplacer("+", "-", "/", "_").Replace(b64(bytes.Repeat([]byte{0xfb, 0xff}, 16)))+`"]`, ""), ErrProof},
		"newline in hash":       {obj("1", "2", `["`+h1[:20]+`\n`+h1[20:]+`"]`, ""), ErrProof},
		"hash with newline end": {obj("1", "2", `["`+h1+`\n"]`, ""), ErrProof},
		"31-byte hash":          {obj("1", "2", `["`+b64(make([]byte, 31))+`"]`, ""), ErrProof},
		"33-byte hash":          {obj("1", "2", `["`+b64(make([]byte, 33))+`"]`, ""), ErrProof},
		"non-zero pad bits":     {obj("1", "2", `["`+h1[:42]+`B="]`, ""), ErrProof},
		"49 hashes":             {obj("1", "2", hashList(49), ""), ErrProof},
		"97 consistency":        {obj("1", "2", "[]", `,"root":"`+h1+`","consistency":`+hashList(97)), ErrProof},
		"bad root":              {obj("1", "2", "[]", `,"root":"x","consistency":[]`), ErrProof},
		"negative index":        {obj("-1", "2", "[]", ""), ErrProof},
		"negative zero":         {obj("-0", "2", "[]", ""), ErrProof},
		"fraction":              {obj("1.5", "2", "[]", ""), ErrProof},
		"fraction zero":         {obj("1", "2.0", "[]", ""), ErrProof},
		"exponent":              {obj("1e2", "2", "[]", ""), ErrProof},
		"string size":           {obj(`"1"`, "2", "[]", ""), ErrProof},
		"index past 2^48":       {obj("281474976710657", "2", "[]", ""), ErrRange},
		"size past 2^48":        {obj("1", "281474976710657", "[]", ""), ErrRange},
		"size near 2^64":        {obj("1", "18446744073709551615", "[]", ""), ErrRange},
		"size past 2^64":        {obj("1", "18446744073709551616", "[]", ""), ErrRange},
		"size past 2^63":        {obj("1", "9223372036854775808", "[]", ""), ErrRange},
		"over 16 KiB":           {obj("1", "2", "[]", `,"x":"`+strings.Repeat("a", MaxProofBytes)+`"`), ErrTooLarge},
		"over 16 KiB reader":    {strings.Repeat(" ", 1<<20), ErrTooLarge},
	} {
		_, err := ReadInclusionProof(strings.NewReader(tc.in))
		wantErr(t, name, err, tc.want)
		if err != nil && strings.Contains(err.Error(), "SECRETMARKER") {
			t.Errorf("%s: error text holds input bytes", name)
		}
	}
}

// T-S-14: the proof parser never panics, and what it accepts holds the rules.
func FuzzTS14_Proof(f *testing.F) {
	h := hb(1)
	for _, s := range []string{
		`{"index":5,"tree_size":9,"hashes":["` + h + `"]}`,
		`{"index":0,"tree_size":1,"hashes":[],"root":"` + h + `","consistency":["` + h + `"]}`,
		`{"index":1,"index":1,"tree_size":2,"hashes":[]}`,
		`{"index":-1,"tree_size":1e2,"hashes":null}`,
		`{"index":1,"tree_size":18446744073709551615,"hashes":[]}`,
		`[]`, `null`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseInclusionProof(b)
		if err != nil {
			return
		}
		if p.Index < 0 || p.Index > maxSize || p.TreeSize < 0 || p.TreeSize > maxSize ||
			p.Hashes == nil || len(p.Hashes) > maxInclusionHashes ||
			(p.Root == nil) != (p.Consistency == nil) || len(p.Consistency) > maxConsistencyHashes {
			t.Errorf("accepted proof breaks a rule")
		}
	})
}
