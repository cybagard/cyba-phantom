package event

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/v2"
	"flag"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "write the sha256 of each expected canonical text into testdata")

const vectorsPath = "testdata/jcs_vectors.json"

type vector struct {
	Name      string `json:"name"`
	Input     string `json:"input"`
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

func loadVectors(t testing.TB) ([]byte, []vector) {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil || len(vs) == 0 {
		t.Fatalf("bad vector file: %v", err)
	}
	return raw, vs
}

// T-U-06: each vector has hand-written canonical text. The -update flag
// hashes that text with crypto/sha256, not the encoder output. After the
// write, the test checks every vector, so a wrong canonical text fails.
func TestTU06_Vectors(t *testing.T) {
	raw, vs := loadVectors(t)
	if *update {
		re := regexp.MustCompile(`"sha256": "[0-9a-f]*"`)
		if n := len(re.FindAll(raw, -1)); n != len(vs) {
			t.Fatalf("found %d sha256 fields for %d vectors", n, len(vs))
		}
		i := 0
		out := re.ReplaceAllFunc(raw, func([]byte) []byte {
			h := sha256.Sum256([]byte(vs[i].Canonical))
			i++
			return []byte(fmt.Sprintf(`"sha256": "%x"`, h))
		})
		if err := os.WriteFile(vectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		_, vs = loadVectors(t)
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			got, err := Canonical([]byte(v.Input))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != v.Canonical {
				t.Errorf("canonical:\n got %q\nwant %q", got, v.Canonical)
			}
			if v.SHA256 == "" {
				t.Fatal("empty sha256: run with -update")
			}
			if h := fmt.Sprintf("%x", Hash(got)); h != v.SHA256 {
				t.Errorf("sha256 %s, want %s", h, v.SHA256)
			}
			again, err := Canonical(got)
			if err != nil || !bytes.Equal(again, got) {
				t.Errorf("encoding the output again gave %q, %v", again, err)
			}
		})
	}
}

func TestTU06_Hash(t *testing.T) {
	// This is the FIPS 180-2 test vector for abc.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := fmt.Sprintf("%x", Hash([]byte("abc"))); got != want {
		t.Errorf("Hash(abc) = %s", got)
	}
}

func TestTU06_Encode(t *testing.T) {
	type rec struct {
		Z string `json:"z"`
		A int64  `json:"a"`
		M string `json:"m"`
	}
	got, err := Encode(rec{Z: "<&>", A: 7, M: " "})
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"a\":7,\"m\":\" \",\"z\":\"<&>\"}"; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
	for name, v := range map[string]any{
		"float":         map[string]any{"a": 1.5},
		"bad utf-8":     map[string]string{"a": "\xff"},
		"big integer":   map[string]int64{"a": 1 << 53},
		"not an object": []int{1},
	} {
		if out, err := Encode(v); err == nil || out != nil {
			t.Errorf("%s: got %q, %v", name, out, err)
		}
	}
}

// bs is one backslash. It starts a JSON escape in the inputs below.
const bs = `\`

type rejectCase struct{ name, in, rule string }

var rejects = []rejectCase{
	{"bad utf-8 in value", "{\"a\":\"\xff\"}", "invalid UTF-8"},
	{"bad utf-8 in name", "{\"\xff\":1}", "invalid UTF-8"},
	{"truncated utf-8", "{\"a\":\"\xc3\"}", "invalid UTF-8"},
	{"high surrogate", `{"a":"\ud800"}`, "malformed JSON"},
	{"low surrogate", `{"a":"\udc00"}`, "malformed JSON"},
	{"surrogate in name", `{"\ud800":1}`, "malformed JSON"},
	{"high surrogate, no low", `{"a":"\ud800A"}`, "malformed JSON"},
	{"duplicate name", `{"a":1,"a":2}`, "duplicate member name"},
	{"duplicate name, escaped", `{"a":1,"` + bs + `u0061":2}`, "duplicate member name"},
	{"duplicate name, nested", `{"o":{"b":1,"b":2}}`, "duplicate member name"},
	{"duplicate name, nested and escaped", `{"o":{"b":1,"` + bs + `u0062":2}}`, "duplicate member name"},
	{"duplicate name, raw and escaped non-BMP", "{\"\U0001F600\":1,\"\\ud83d\\ude00\":2}", "duplicate member name"},
	{"1.0", `{"a":1.0}`, "not an integer"},
	{"1e2", `{"a":1e2}`, "not an integer"},
	{"1E2", `{"a":1E2}`, "not an integer"},
	{"float in array", `{"a":[1,2.5]}`, "not an integer"},
	{"-0", `{"a":-0}`, "negative zero"},
	{"-0.0", `{"a":-0.0}`, "not an integer"},
	{"2^53", `{"a":9007199254740992}`, "integer outside"},
	{"-2^53", `{"a":-9007199254740992}`, "integer outside"},
	{"30 digits", `{"a":` + strings.Repeat("9", 30) + `}`, "integer outside"},
	{"array", `[]`, "top level is not an object"},
	{"string", `"s"`, "top level is not an object"},
	{"number", `1`, "top level is not an object"},
	{"null", `null`, "top level is not an object"},
	{"empty", ``, "top level is not an object"},
	{"two objects", `{"a":1} {"b":2}`, "data after the object"},
	{"text after object", `{"a":1}x`, "data after the object"},
	{"truncated", `{"a":`, "malformed JSON"},
}

// T-S-12: every input outside the domain gives an error and no bytes. The
// error text names the rule.
func TestTS12_Reject(t *testing.T) {
	for _, c := range rejects {
		t.Run(c.name, func(t *testing.T) {
			in := []byte(c.in)
			out, err := Canonical(in)
			if err == nil || out != nil {
				t.Fatalf("got %q, %v", out, err)
			}
			if !strings.Contains(err.Error(), c.rule) {
				t.Errorf("error %q does not name the rule %q", err, c.rule)
			}
			if string(in) != c.in {
				t.Error("input changed")
			}
		})
	}
}

// The error text names the rule and the offset. It holds no input text.
func TestTS12_ErrorText(t *testing.T) {
	for _, in := range []string{
		"{\"SECRET\":\"\xff\"}", `{"SECRET":1,"SECRET":2}`, `{"SECRET":1.5}`,
		`{"SECRET":"\ud800"}`, `["SECRET"]`, `{"SECRET":9007199254740992}`,
	} {
		_, err := Canonical([]byte(in))
		if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "offset") {
			t.Errorf("%q: bad error %v", in, err)
		}
	}
}

// A valid U+FFFD is data. Canonical keeps it as it is.
func TestTS12_ReplacementCharKept(t *testing.T) {
	got, err := Canonical([]byte(`{"a":"` + bs + `ufffd","b":"` + "\xef\xbf\xbd" + `"}`))
	if want := "{\"a\":\"\xef\xbf\xbd\",\"b\":\"\xef\xbf\xbd\"}"; err != nil || string(got) != want {
		t.Errorf("got %q, %v", got, err)
	}
}

// BenchmarkCanonical measures the allocation of Canonical.
func BenchmarkCanonical(b *testing.B) {
	for _, c := range []struct {
		name, member string
		size         int
	}{
		{"members", `"k%07[1]d":"value %[1]d"`, 64 << 10},
		{"members", `"k%07[1]d":"value %[1]d"`, 1 << 20},
		// This case uses the shortest members. Each input byte costs most here.
		{"short", `"%[1]x":1`, 1 << 20},
	} {
		// The input is one object of members. Its text is about size bytes.
		var sb strings.Builder
		sb.WriteByte('{')
		for i := 0; sb.Len() < c.size; i++ {
			if i > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, c.member, i)
		}
		sb.WriteByte('}')
		in := []byte(sb.String())
		b.Run(fmt.Sprintf("%s/%dKiB", c.name, len(in)>>10), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(in)))
			for range b.N {
				if _, err := Canonical(in); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// T-S-12: each input gives an error and no bytes, or an output that is stable and decodes to the same value.
func FuzzCanonical(f *testing.F) {
	for _, c := range rejects {
		f.Add([]byte(c.in))
	}
	_, vs := loadVectors(f)
	for _, v := range vs {
		f.Add([]byte(v.Input))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		orig := bytes.Clone(in)
		out, err := Canonical(in)
		if !bytes.Equal(in, orig) {
			t.Fatal("input changed")
		}
		if err != nil {
			if out != nil {
				t.Fatalf("error with output %q", out)
			}
			return
		}
		again, err := Canonical(out)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("not stable: %q -> %q, %v", out, again, err)
		}
		var a, b any
		if err := json.Unmarshal(in, &a); err != nil {
			t.Fatalf("input does not decode: %v", err)
		}
		if err := json.Unmarshal(out, &b); err != nil || !reflect.DeepEqual(a, b) {
			t.Fatalf("value changed: %q -> %q, %v", in, out, err)
		}
	})
}
