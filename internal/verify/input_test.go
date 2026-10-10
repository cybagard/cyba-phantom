package verify

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"testing/iotest"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const origin = "phantom/test"

var testRoot = [32]byte{1, 2, 3}

// newKey makes a key pair. It returns the signer and the text of the key file.
func newKey(t testing.TB, name string) (note.Signer, string) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	return s, vkey + "\n"
}

func signed(t testing.TB, s note.Signer, size uint64) []byte {
	t.Helper()
	msg, err := tlog.SignCheckpoint(s, size, testRoot)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func wantErr(t *testing.T, name string, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Errorf("%s: error is %v, want %v", name, got, want)
	}
}

// T-S-14, input cases: the key file.
func TestTS14_Key(t *testing.T) {
	_, text := newKey(t, origin)
	v, err := ReadKey(strings.NewReader(text))
	if err != nil || v.Name() != origin {
		t.Fatalf("good key: %v, %v", v, err)
	}
	_, err = ReadKey(strings.NewReader(strings.TrimSuffix(text, "\n")))
	wantErr(t, "key without newline", err, nil)
	for name, in := range map[string]string{"empty": "", "text": "not a key", "two lines": text + text} {
		_, err := ReadKey(strings.NewReader(in))
		wantErr(t, name, err, ErrKey)
	}
	_, err = ReadKey(strings.NewReader(strings.Repeat("a", MaxKeyBytes+1)))
	wantErr(t, "oversize key", err, ErrTooLarge)
	_, err = ReadKey(iotest.ErrReader(errors.New("secret-marker")))
	wantErr(t, "read error", err, ErrRead)
	if err != nil && strings.Contains(err.Error(), "secret-marker") {
		t.Errorf("read error: error text holds the text of the reader error")
	}
}

// T-S-14, input cases: the checkpoint note.
func TestTS14_Checkpoint(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	other, otherText := newKey(t, origin) // same name, another key
	otherV, _ := ParseKey([]byte(otherText))
	good := signed(t, s, 7)
	c, err := ReadCheckpoint(bytes.NewReader(good), v)
	if err != nil || c.Size != 7 || c.Origin != origin || c.Root != testRoot {
		t.Fatalf("good note: %+v, %v", c, err)
	}
	sigLine := good[bytes.LastIndex(good, []byte("\n\n"))+2:]
	cosigned, err := note.Sign(&note.Note{Text: string(good[:bytes.LastIndex(good, []byte("\n\n"))+1])}, s, other)
	if err != nil {
		t.Fatal(err)
	}
	wrongOrigin, err := note.Sign(&note.Note{Text: "phantom/other\n7\n" + "AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"}, s)
	if err != nil {
		t.Fatal(err)
	}
	badBody, err := note.Sign(&note.Note{Text: origin + "\nseven\n" + "AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"}, s)
	if err != nil {
		t.Fatal(err)
	}
	// A changed signature or a changed body: the note does not verify (exit 1).
	changedSig := bytes.Clone(good)
	i := len(changedSig) - 20 // a base64 digit in the middle of the signature
	changedSig[i] = 'B'
	if good[i] == 'B' {
		changedSig[i] = 'C'
	}
	changedBody := bytes.Clone(good)
	changedBody[len(changedBody)-len(sigLine)-3] ^= 1
	// A key text with another name gives a verifier with another name. The
	// origin comes from the verifier, so a note for the first name is refused.
	_, nameText := newKey(t, "phantom/name")
	nameV, _ := ParseKey([]byte(nameText))
	for name, tc := range map[string]struct {
		msg  []byte
		v    note.Verifier
		want error
	}{
		"over 1 KiB":                       {append(bytes.Clone(good), make([]byte, 1024)...), v, ErrTooLarge},
		"two signature lines":              {append(bytes.Clone(good), sigLine...), v, ErrCheckpoint},
		"cosigned note":                    {cosigned, v, ErrCheckpoint},
		"another key":                      {signed(t, other, 7), v, ErrSignature},
		"other key as pinned":              {good, otherV, ErrSignature},
		"verifier of another name and key": {good, nameV, ErrSignature},
		"changed signature":                {changedSig, v, ErrSignature},
		"changed body":                     {changedBody, v, ErrSignature},
		"body origin not name":             {wrongOrigin, v, ErrCheckpoint},
		"signed bad body":                  {badBody, v, ErrCheckpoint},
		"size past 2^48":                   {signed(t, s, maxSize+1), v, ErrRange},
		"size near 2^64":                   {signed(t, s, 1<<64-1), v, ErrRange},
		"empty":                            {nil, v, ErrCheckpoint},
		"garbage text":                     {[]byte("not a note at all"), v, ErrCheckpoint},
		"no blank line":                    {bytes.ReplaceAll(good, []byte("\n\n"), []byte("\n")), v, ErrCheckpoint},
		"bad signature line form":          {append(bytes.Clone(good[:len(good)-len(sigLine)]), "- x\n"...), v, ErrCheckpoint},
	} {
		_, err := ParseCheckpoint(tc.msg, tc.v)
		wantErr(t, name, err, tc.want)
	}
	if c, err := ParseCheckpoint(signed(t, s, maxSize), v); err != nil || c.Size != maxSize {
		t.Errorf("size 2^48: %+v, %v", c, err)
	}
	if c, err := ParseCheckpoint(signed(t, s, 0), v); err != nil || c.Size != 0 {
		t.Errorf("size 0: %+v, %v", c, err)
	}
	_, err = ReadCheckpoint(bytes.NewReader(make([]byte, 1<<20)), v)
	wantErr(t, "large reader", err, ErrTooLarge)
}

// T-S-14, input cases: the event bytes.
func TestTS14_Event(t *testing.T) {
	good := []byte(`{"a":1,"b":"x"}`)
	e, err := ReadEvent(bytes.NewReader(good))
	if err != nil || !bytes.Equal(e.Raw, good) || e.Hash != tlog.EventHash(event.Hash(good)) {
		t.Fatalf("canonical event: %+v, %v", e, err)
	}
	// 04 §7 refuses only bytes that are not canonical. Two names that differ
	// only in case are two names, and {"A":1,"a":2} is in canonical order. The
	// parser accepts these bytes, and the hash covers the bytes.
	for _, in := range []string{`{"A":1}`, `{"A":1,"a":2}`} {
		e, err := ParseEvent([]byte(in))
		if err != nil || e.Hash != tlog.EventHash(event.Hash([]byte(in))) {
			t.Errorf("member names in another case %s: %+v, %v", in, e, err)
		}
	}
	tooBig := []byte(`{"a":"` + strings.Repeat("x", event.MaxRecordBytes) + `"}`)
	exact := []byte(`{"a":"` + strings.Repeat("x", event.MaxRecordBytes-8) + `"}`)
	if _, err := ParseEvent(exact); err != nil {
		t.Errorf("event of exactly 24 KiB: %v", err)
	}
	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"duplicate member":   {[]byte(`{"a":1,"a":2}`), ErrEvent},
		"member order":       {[]byte(`{"b":1,"a":2}`), ErrEvent},
		"space":              {[]byte(`{"a": 1}`), ErrEvent},
		"newline":            {[]byte("{\"a\":1}\n"), ErrEvent},
		"number form":        {[]byte(`{"a":1.0}`), ErrEvent},
		"exponent":           {[]byte(`{"a":1e2}`), ErrEvent},
		"escape":             {[]byte("{\"a\":\"\\u0041\"}"), ErrEvent},
		"invalid UTF-8":      {[]byte("{\"a\":\"\xff\"}"), ErrEvent},
		"not an object":      {[]byte(`[1]`), ErrEvent},
		"two values":         {[]byte(`{"a":1}{"a":1}`), ErrEvent},
		"empty":              {nil, ErrEvent},
		"over 24 KiB":        {tooBig, ErrTooLarge},
		"over 24 KiB reader": {bytes.Repeat([]byte("a"), 1<<20), ErrTooLarge},
	} {
		_, err := ReadEvent(bytes.NewReader(tc.in))
		wantErr(t, name, err, tc.want)
	}
}

// T-S-14: the parsers never panic, and what they accept holds the rules.
func FuzzTS14_Event(f *testing.F) {
	for _, s := range []string{`{"a":1,"b":"x"}`, `{"a":1,"a":2}`, `{"b":1,"a":2}`, `{"a":1e2}`, `[]`, "{\"a\":\"\xff\"}", ``} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := ParseEvent(b)
		if err != nil {
			return
		}
		if c, err := event.Canonical(b); err != nil || !bytes.Equal(c, b) || e.Hash != tlog.EventHash(event.Hash(b)) {
			t.Errorf("accepted event is not canonical or has another hash")
		}
	})
}

func FuzzTS14_Checkpoint(f *testing.F) {
	s, text := newKey(f, origin)
	v, _ := ParseKey([]byte(text))
	good := signed(f, s, 7)
	for _, b := range [][]byte{good, append(bytes.Clone(good), good...), good[:len(good)-3], nil} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := ParseCheckpoint(b, v); err == nil && (c.Size > maxSize || c.Origin != origin) {
			t.Errorf("accepted checkpoint out of range: %+v", c)
		}
	})
}
