package tlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
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

// noteKeys makes a signer and a verifier from a fixed seed. The keys are made
// only for the tests.
func noteKeys(t *testing.T, name string, seedByte byte) (note.Signer, note.Verifier) {
	t.Helper()
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	sum := sha256.Sum256(append(append([]byte(name+"\n"), 1), pub...))
	hash := binary.BigEndian.Uint32(sum[:4])
	enc := base64.StdEncoding.EncodeToString
	signer, err := note.NewSigner(fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, hash, enc(append([]byte{1}, seed...))))
	must(t, err)
	verifier, err := note.NewVerifier(fmt.Sprintf("%s+%08x+%s", name, hash, enc(append([]byte{1}, pub...))))
	must(t, err)
	return signer, verifier
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

func TestTU12_BodyFormat(t *testing.T) {
	got := checkpointBody(Checkpoint{testOrigin, 42, testRoot()})
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
	if n.Text != checkpointBody(Checkpoint{testOrigin, 42, testRoot()}) || len(n.Sigs) != 1 {
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
	sign := func(s *note.Signer, text string) []byte {
		msg, err := note.Sign(&note.Note{Text: text}, *s)
		must(t, err)
		return msg
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
			_, err := ParseCheckpoint(sign(&signer, text), testOrigin, verifier)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}

	good, err := SignCheckpoint(signer, 42, testRoot())
	must(t, err)
	t.Run("larger-than-1-KiB", func(t *testing.T) {
		big := append(append([]byte{}, good...), bytes.Repeat([]byte("x"), maxNoteSize)...)
		_, err := ParseCheckpoint(big, testOrigin, verifier)
		if err == nil || !strings.Contains(err.Error(), "larger than 1 KiB") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("other-origin", func(t *testing.T) {
		otherSigner, otherVerifier := noteKeys(t, "phantom/other", 1)
		msg, err := SignCheckpoint(otherSigner, 42, testRoot())
		must(t, err)
		_, err = ParseCheckpoint(msg, testOrigin, otherVerifier) // the signature is valid
		if err == nil || !strings.Contains(err.Error(), "origin") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("changed-body", func(t *testing.T) {
		bad := bytes.Replace(good, []byte("\n42\n"), []byte("\n43\n"), 1)
		_, err := ParseCheckpoint(bad, testOrigin, verifier)
		if err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("no-signature", func(t *testing.T) {
		_, err := ParseCheckpoint([]byte(sections["ok"]), testOrigin, verifier)
		if err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("error = %v", err)
		}
	})
}

// T-U-12: the sensor's own notes carry one signature. A second signature (from
// another key of the same name, or from an unknown name) is an error, even
// if the first signature is good. A repeated line with the key name and key hash
// of the good line is an error too, although note.Open drops it before it
// verifies it. A cosigned note needs another parser.
func TestTU12_RejectsExtraSignatures(t *testing.T) {
	signer, verifier := noteKeys(t, testOrigin, 1)
	body := checkpointBody(Checkpoint{testOrigin, 42, testRoot()})
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
