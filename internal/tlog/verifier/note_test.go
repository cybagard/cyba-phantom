package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

var update = flag.Bool("update", false, "write the signed note into the golden section of testdata/notes.txt")

const testOrigin = "phantom/test"

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// noteKeys makes a signer and a verifier from a fixed seed. The keys are made
// only for the tests.
func noteKeys(t *testing.T, name string, seedByte byte) (note.Signer, note.Verifier) {
	t.Helper()
	seed := bytes.NewReader(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
	skey, vkey, err := note.GenerateKey(seed, name)
	must(t, err)
	signer, err := note.NewSigner(skey)
	must(t, err)
	verifier, err := note.NewVerifier(vkey)
	must(t, err)
	return signer, verifier
}

// signRaw signs text with signer and builds the note bytes by hand, for texts
// that note.Sign refuses.
func signRaw(t *testing.T, signer note.Signer, text string) []byte {
	t.Helper()
	sig, err := signer.Sign([]byte(text))
	must(t, err)
	raw := binary.BigEndian.AppendUint32(nil, signer.KeyHash())
	line := "— " + signer.Name() + " " + base64.StdEncoding.EncodeToString(append(raw, sig...)) + "\n"
	return []byte(text + "\n" + line)
}

// noteSections reads testdata/notes.txt: a line "-- name --" starts a section.
func noteSections(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("testdata/notes.txt")
	must(t, err)
	out := map[string]string{}
	name := ""
	for _, line := range strings.SplitAfter(string(b), "\n") {
		switch tl := strings.TrimSuffix(line, "\n"); {
		case strings.HasPrefix(tl, "-- ") && strings.HasSuffix(tl, " --"):
			name = tl[3 : len(tl)-3]
		case name != "" && !strings.HasPrefix(tl, "#"):
			out[name] += line
		}
	}
	return out
}

func testRoot() (r [32]byte) {
	for i := range r {
		r[i] = byte(i)
	}
	return r
}

func testRootB64() string {
	r := testRoot()
	return base64.StdEncoding.EncodeToString(r[:])
}

func TestTU12_BodyFormat(t *testing.T) {
	got := CheckpointBody(Checkpoint{testOrigin, 42, testRoot()})
	if want := noteSections(t)["ok"]; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if n := strings.Count(got, "\n"); n != 3 || !strings.HasSuffix(got, "\n") {
		t.Fatalf("body must be three lines with a newline each: %q", got)
	}
}

func TestTU12_RoundTrip(t *testing.T) {
	signer, verifier := noteKeys(t, testOrigin, 1)
	msg, err := SignCheckpoint(signer, 42, testRoot())
	must(t, err)

	n, err := note.Open(msg, note.VerifierList(verifier))
	must(t, err)
	if n.Text != CheckpointBody(Checkpoint{testOrigin, 42, testRoot()}) || len(n.Sigs) != 1 {
		t.Fatalf("opened note = %+v", n)
	}
	c, err := ParseCheckpoint(msg, testOrigin, verifier)
	must(t, err)
	if c != (Checkpoint{testOrigin, 42, testRoot()}) {
		t.Fatalf("parsed = %+v", c)
	}

	_, other := noteKeys(t, testOrigin, 2) // same name, other key
	if _, err := note.Open(msg, note.VerifierList(other)); err == nil {
		t.Fatal("note.Open accepted a verifier of another key")
	}
	if _, err := ParseCheckpoint(msg, testOrigin, other); err == nil {
		t.Fatal("ParseCheckpoint accepted a verifier of another key")
	}
}

// writeGolden replaces the body of the golden section of testdata/notes.txt with msg.
// It keeps the comment lines and all other sections.
func writeGolden(t *testing.T, msg []byte) {
	t.Helper()
	const path = "testdata/notes.txt"
	b, err := os.ReadFile(path)
	must(t, err)
	var out strings.Builder
	inGolden, found := false, false
	for _, line := range strings.SplitAfter(string(b), "\n") {
		tl := strings.TrimSuffix(line, "\n")
		if strings.HasPrefix(tl, "-- ") && strings.HasSuffix(tl, " --") {
			inGolden = tl == "-- golden --"
			if inGolden {
				found = true
				out.WriteString(line)
				out.Write(msg)
				continue
			}
		}
		if !inGolden {
			out.WriteString(line)
		}
	}
	if !found {
		t.Fatal("testdata/notes.txt has no golden section")
	}
	must(t, os.WriteFile(path, []byte(out.String()), 0o644))
}

// T-U-12: the -update flag writes the signed note that the test makes into the golden
// section. After the write, the test compares the file with the note.
func TestTU12_Golden(t *testing.T) {
	signer, _ := noteKeys(t, testOrigin, 1)
	msg, err := SignCheckpoint(signer, 42, testRoot())
	must(t, err)
	if *update {
		writeGolden(t, msg)
	}
	if want := noteSections(t)["golden"]; string(msg) != want {
		t.Fatalf("signed note changed:\n%s", msg)
	}
}

func TestTU12_SizeLimits(t *testing.T) {
	signer, verifier := noteKeys(t, testOrigin, 1)
	for _, size := range []uint64{0, 1<<64 - 1} {
		msg, err := SignCheckpoint(signer, size, testRoot())
		must(t, err)
		c, err := ParseCheckpoint(msg, testOrigin, verifier)
		if err != nil || c.Size != size {
			t.Fatalf("size %d: got %+v, %v", size, c, err)
		}
	}
}

func TestTU12_Rejects(t *testing.T) {
	signer, verifier := noteKeys(t, testOrigin, 1)
	sections := noteSections(t)
	sign := func(s note.Signer, text string) []byte {
		msg, err := note.Sign(&note.Note{Text: text}, s)
		must(t, err)
		return msg
	}
	const wantOpen = "checkpoint note is malformed or its signature does not verify"
	root := testRootB64()
	urlRoot := base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)) // "-" and "_"
	if strings.ContainsAny(urlRoot, "+/") || !strings.ContainsAny(urlRoot, "-_") {
		t.Fatalf("test root is not URL-safe base64: %s", urlRoot)
	}
	for _, tc := range []struct{ section, want string }{
		{"fourth-line", "exactly three lines"},
		{"extension-line", "exactly three lines"},
		{"two-lines", "exactly three lines"},
		{"size-leading-zero", "canonical decimal"},
		{"size-sign", "canonical decimal"},
		{"size-space", "canonical decimal"},
		{"size-empty", "canonical decimal"},
		{"size-overflow", "too large"},
		{"root-padding-bits", "canonical base64"},
		{"root-no-padding", "canonical base64"},
		{"root-31-bytes", "not 32 bytes"},
		{"root-33-bytes", "not 32 bytes"},
		{"root-empty", "not 32 bytes"},
	} {
		t.Run(tc.section, func(t *testing.T) {
			text, ok := sections[tc.section]
			if !ok {
				t.Fatal("missing section")
			}
			_, err := ParseCheckpoint(sign(signer, text), testOrigin, verifier)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}

	good, err := SignCheckpoint(signer, 42, testRoot())
	must(t, err)
	// The edge of the size limit. The key name and the origin are the same
	// string of 438 bytes. The name is in the body and in the signature line,
	// so 2 × 438 bytes, plus 2 bytes for the size 10, plus 146 other bytes
	// make 1024.
	t.Run("1024-bytes-accepted", func(t *testing.T) {
		name := "phantom/" + strings.Repeat("a", 438-len("phantom/"))
		s, v := noteKeys(t, name, 1)
		msg, err := SignCheckpoint(s, 10, testRoot())
		must(t, err)
		if len(msg) != MaxNoteSize {
			t.Fatalf("len(msg) = %d, want %d", len(msg), MaxNoteSize)
		}
		if c, err := ParseCheckpoint(msg, name, v); err != nil || c.Size != 10 {
			t.Fatalf("got %+v, %v", c, err)
		}
		_, err = ParseCheckpoint(append(msg, '\n'), name, v) // 1025 bytes
		if err == nil || err.Error() != "checkpoint note is larger than 1 KiB" {
			t.Fatalf("1025 bytes: error = %v", err)
		}
	})
	t.Run("larger-than-1-KiB", func(t *testing.T) {
		big := append(append([]byte{}, good...), bytes.Repeat([]byte("x"), MaxNoteSize)...)
		_, err := ParseCheckpoint(big, testOrigin, verifier)
		if err == nil || !strings.Contains(err.Error(), "larger than 1 KiB") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("nil-verifier", func(t *testing.T) {
		_, err := ParseCheckpoint(good, testOrigin, nil)
		if err == nil || err.Error() != "checkpoint note verifier is nil" {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("key-name-is-not-origin", func(t *testing.T) {
		// The body origin is the configured origin. The key has another name.
		otherSigner, otherVerifier := noteKeys(t, "phantom/other", 1)
		msg := sign(otherSigner, CheckpointBody(Checkpoint{testOrigin, 42, testRoot()}))
		_, err := ParseCheckpoint(msg, testOrigin, otherVerifier) // the signature is valid
		if err == nil || err.Error() != "checkpoint note key name is not the configured origin" {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("body-origin-is-not-origin", func(t *testing.T) {
		// The key name is the configured origin. The first line of the body is not.
		msg := sign(signer, CheckpointBody(Checkpoint{"phantom/other", 42, testRoot()}))
		_, err := ParseCheckpoint(msg, testOrigin, verifier)
		if err == nil || err.Error() != "checkpoint note origin is not the configured origin" {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("changed-body", func(t *testing.T) {
		bad := bytes.Replace(good, []byte("\n42\n"), []byte("\n43\n"), 1)
		_, err := ParseCheckpoint(bad, testOrigin, verifier)
		if err == nil || err.Error() != wantOpen {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("no-signature", func(t *testing.T) {
		_, err := ParseCheckpoint([]byte(sections["ok"]), testOrigin, verifier)
		if err == nil || err.Error() != wantOpen {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("not-a-note", func(t *testing.T) {
		_, err := ParseCheckpoint([]byte("not a note"), testOrigin, verifier)
		if err == nil || err.Error() != wantOpen {
			t.Fatalf("error = %v", err)
		}
	})

	// Bytes that the strict parser refuses. In the first four cases note.Open
	// refuses the note (a control character other than LF, or invalid UTF-8),
	// so note.Sign cannot make it and the note is built by hand.
	body := func(origin, size, root string) string { return origin + "\n" + size + "\n" + root + "\n" }
	for _, tc := range []struct {
		name, want string
		raw        bool
		text       string
	}{
		{"cr-in-origin-line", wantOpen, true, body(testOrigin+"\r", "42", root)},
		{"tab-in-size-line", wantOpen, true, body(testOrigin, "4\t2", root)},
		{"nul-in-root-line", wantOpen, true, body(testOrigin, "42", root[:10]+"\x00"+root[10:])},
		{"invalid-utf8-in-origin-line", wantOpen, true, body(testOrigin+"\xff", "42", root)},
		// A LF in the origin line makes four lines.
		{"lf-in-origin-line", "exactly three lines", false, body("phantom/\ntest", "42", root)},
		// A space at the end of the root line.
		{"space-in-root-line", "canonical base64", false, body(testOrigin, "42", root+" ")},
		// "-" and "_" in the root line instead of "+" and "/".
		{"url-base64-in-root-line", "canonical base64", false, body(testOrigin, "42", urlRoot)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var msg []byte
			if tc.raw {
				msg = signRaw(t, signer, tc.text)
			} else {
				msg = sign(signer, tc.text)
			}
			_, err := ParseCheckpoint(msg, testOrigin, verifier)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// T-U-12: the sensor's own notes carry one signature. A second signature (from
// another key of the same name, or from an unknown name) is an error, even
// if the first signature is good. A repeated line with the key name and key hash
// of the good line is an error too, although note.Open drops it before it
// verifies it. A cosigned note needs another parser.
func TestTU12_RejectsExtraSignatures(t *testing.T) {
	signer, verifier := noteKeys(t, testOrigin, 1)
	body := CheckpointBody(Checkpoint{testOrigin, 42, testRoot()})
	second, _ := noteKeys(t, testOrigin, 2)
	unknown, _ := noteKeys(t, "phantom/witness", 3)
	for name, extra := range map[string]note.Signer{"second-key-same-name": second, "unknown-key": unknown} {
		t.Run(name, func(t *testing.T) {
			msg, err := note.Sign(&note.Note{Text: body}, signer, extra)
			must(t, err)
			if _, err := note.Open(msg, note.VerifierList(verifier)); err != nil {
				t.Fatalf("note.Open: %v (the first signature must be good)", err)
			}
			_, err = ParseCheckpoint(msg, testOrigin, verifier)
			if err == nil || !strings.Contains(err.Error(), "exactly one signature") {
				t.Fatalf("error = %v", err)
			}
		})
	}

	good, err := SignCheckpoint(signer, 42, testRoot())
	must(t, err)
	line := good[bytes.LastIndex(good, []byte("\n\n"))+2:] // the one signature line
	fields := strings.Fields(string(line))                 // the dash, the key name, the base64 text
	raw, err := base64.StdEncoding.DecodeString(fields[2])
	must(t, err)
	other := fmt.Sprintf("%s %s %s\n", fields[0], fields[1], base64.StdEncoding.EncodeToString(append(raw[:4:4], make([]byte, 64)...)))
	for name, extra := range map[string]string{"identical-copy": string(line), "own-name-and-hash-other-bytes": other} {
		t.Run(name, func(t *testing.T) {
			msg := append(slices.Clone(good), extra...)
			if _, err := note.Open(msg, note.VerifierList(verifier)); err != nil {
				t.Fatalf("note.Open: %v (it must drop the repeated line)", err)
			}
			_, err := ParseCheckpoint(msg, testOrigin, verifier)
			if err == nil || !strings.Contains(err.Error(), "exactly one signature") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
