package event

import (
	"bytes"
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
// hashes that text, not the encoder output.
func TestTU06_Vectors(t *testing.T) {
	raw, vs := loadVectors(t)
	if *update {
		i := 0
		out := regexp.MustCompile(`"sha256": "[0-9a-f]*"`).ReplaceAllFunc(raw, func([]byte) []byte {
			h := Hash([]byte(vs[i].Canonical))
			i++
			return []byte(fmt.Sprintf(`"sha256": "%x"`, h))
		})
		if i != len(vs) {
			t.Fatalf("found %d sha256 fields for %d vectors", i, len(vs))
		}
		if err := os.WriteFile(vectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
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
	// FIPS 180-2 test vector for "abc".
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

type rejectCase struct{ name, in string }

var rejects = []rejectCase{
	{"bad utf-8 in value", "{\"a\":\"\xff\"}"},
	{"bad utf-8 in name", "{\"\xff\":1}"},
	{"truncated utf-8", "{\"a\":\"\xc3\"}"},
	{"high surrogate", `{"a":"\ud800"}`},
	{"low surrogate", `{"a":"\udc00"}`},
	{"surrogate in name", `{"\ud800":1}`},
	{"high surrogate, no low", `{"a":"\ud800A"}`},
	{"duplicate name", `{"a":1,"a":2}`},
	{"duplicate name, escaped", `{"a":1,"` + bs + `u0061":2}`},
	{"duplicate name, nested", `{"o":{"b":1,"b":2}}`},
	{"duplicate name, nested and escaped", `{"o":{"b":1,"` + bs + `u0062":2}}`},
	{"duplicate name, raw and escaped non-BMP", "{\"\U0001F600\":1,\"\\ud83d\\ude00\":2}"},
	{"1.0", `{"a":1.0}`},
	{"1e2", `{"a":1e2}`},
	{"1E2", `{"a":1E2}`},
	{"float in array", `{"a":[1,2.5]}`},
	{"-0", `{"a":-0}`},
	{"-0.0", `{"a":-0.0}`},
	{"2^53", `{"a":9007199254740992}`},
	{"-2^53", `{"a":-9007199254740992}`},
	{"30 digits", `{"a":` + strings.Repeat("9", 30) + `}`},
	{"array", `[]`},
	{"string", `"s"`},
	{"number", `1`},
	{"null", `null`},
	{"empty", ``},
	{"two objects", `{"a":1} {"b":2}`},
	{"text after object", `{"a":1}x`},
	{"truncated", `{"a":`},
}

// T-S-12: every input outside the domain gives an error and no bytes.
func TestTS12_Reject(t *testing.T) {
	for _, c := range rejects {
		t.Run(c.name, func(t *testing.T) {
			in := []byte(c.in)
			out, err := Canonical(in)
			if err == nil || out != nil {
				t.Fatalf("got %q, %v", out, err)
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

func BenchmarkCanonical(b *testing.B) {
	for _, size := range []int{64 << 10, 1 << 20} {
		// One object of short members. Its text is about size bytes.
		var sb strings.Builder
		sb.WriteByte('{')
		for i := 0; sb.Len() < size; i++ {
			if i > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, `"k%07d":"value %d"`, i, i)
		}
		sb.WriteByte('}')
		in := []byte(sb.String())
		b.Run(fmt.Sprintf("%dKiB", len(in)>>10), func(b *testing.B) {
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
