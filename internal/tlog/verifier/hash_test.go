package verifier

import (
	"encoding/base64"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// T-S-14: one rule for a 32-byte hash. A root with CR, LF, non-zero padding
// bits or another length is refused by ParseHash and by ParseCheckpoint.
func TestTS14_ParseHash(t *testing.T) {
	good := testRootB64()
	if h, err := ParseHash(good); err != nil || h != testRoot() {
		t.Fatalf("good hash: %x, %v", h, err)
	}
	signer, verifier := noteKeys(t, testOrigin, 1)
	// A CR in the root line is a control character: note.Open refuses the note
	// before the root rule. A LF in the root line makes four lines.
	for _, tc := range []struct{ name, s, want, wantNote string }{
		{"cr", good[:20] + "\r" + good[20:], "canonical base64", "malformed"},
		{"cr-at-end", good + "\r", "canonical base64", "malformed"},
		{"lf", good[:20] + "\n" + good[20:], "canonical base64", "exactly three lines"},
		{"lf-at-end", good + "\n", "canonical base64", "exactly three lines"},
		{"padding-bits", good[:42] + "B=", "canonical base64", "root is not canonical base64"},
		{"31-bytes", base64.StdEncoding.EncodeToString(make([]byte, 31)), "not 32 bytes", "root is not 32 bytes"},
		{"33-bytes", base64.StdEncoding.EncodeToString(make([]byte, 33)), "not 32 bytes", "root is not 32 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ParseHash(tc.s)
			if err == nil || !strings.Contains(err.Error(), tc.want) || h != ([32]byte{}) {
				t.Fatalf("ParseHash: %x, %v, want %q", h, err, tc.want)
			}
			msg := signRaw(t, signer, testOrigin+"\n42\n"+tc.s+"\n")
			if _, err := ParseCheckpoint(msg, testOrigin, verifier); err == nil || !strings.Contains(err.Error(), tc.wantNote) {
				t.Fatalf("ParseCheckpoint: %v, want %q", err, tc.wantNote)
			}
		})
	}
}

// importAllowed lists the packages that the non-test files import directly.
// A new import needs a new line here, so that a review sees it.
var importAllowed = map[string]bool{
	"bytes":                       true,
	"crypto/sha256":               true,
	"encoding/base64":             true,
	"errors":                      true,
	"golang.org/x/mod/sumdb/note": true,
	"golang.org/x/mod/sumdb/tlog": true,
	"strconv":                     true,
	"strings":                     true,
}

// T-S-14: the package opens no file. The non-test files import only the
// packages in importAllowed, and none of them is for files or system calls.
// This is not the whole proof. The packages os, io/fs, and syscall are in the
// dependency graph through the imports of golang.org/x/mod/sumdb/note, for
// example fmt. So "opens no file" also rests on a review of the package code.
func TestTS14_NoFileImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	must(t, err)
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		checked++
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		must(t, err)
		for _, imp := range af.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			must(t, err)
			if !importAllowed[path] {
				t.Errorf("%s imports %q, which is not in the allow list", f, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no non-test .go file found")
	}
}
