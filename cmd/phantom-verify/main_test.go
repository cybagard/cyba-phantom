package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/mod/sumdb/note"
	modtlog "golang.org/x/mod/sumdb/tlog"

	"github.com/cybagard/cyba-phantom/internal/tlog"
	"github.com/cybagard/cyba-phantom/internal/verify"
)

const origin = "phantom/test"

// The marker strings go into paths, flag names and file contents. No error
// text may hold them.
const (
	pathMarker    = "pathmarker"
	flagMarker    = "flagmarker"
	contentMarker = "contentmarker"
)

// testKey makes a key pair. It returns the signer and the text of the key file.
func testKey(t *testing.T, name string) (note.Signer, string) {
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

// testLog opens a real log and appends n events. Event i is form with the index.
func testLog(t *testing.T, n int, form string) (*tlog.Log, []verify.Event) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Close() })
	l, err := tlog.OpenLog(state, "tlog")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var events []verify.Event
	for i := 0; i < n; i++ {
		e, err := verify.ParseEvent([]byte(fmt.Sprintf(form, i)))
		if err != nil {
			t.Fatal(err)
		}
		if idx, err := l.Append(e.Hash); err != nil || idx != int64(i) {
			t.Fatalf("append %d: index %d, %v", i, idx, err)
		}
		events = append(events, e)
	}
	return l, events
}

// checkpointAt signs the checkpoint of the first size leaves of the log.
func checkpointAt(t *testing.T, l *tlog.Log, s note.Signer, size int64) []byte {
	t.Helper()
	root, err := l.RootAt(size)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tlog.SignCheckpoint(s, uint64(size), root)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func b64(h [32]byte) string { return base64.StdEncoding.EncodeToString(h[:]) }

func hashList(hs []modtlog.Hash) string {
	items := make([]string, 0, len(hs))
	for _, h := range hs {
		items = append(items, `"`+b64(h)+`"`)
	}
	return "[" + strings.Join(items, ",") + "]"
}

// inclusionJSON is the proof file for leaf index in the tree of size.
func inclusionJSON(t *testing.T, l *tlog.Log, index, size int64) string {
	t.Helper()
	hs, err := l.ProveInclusion(index, size)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"index":%d,"tree_size":%d,"hashes":%s}`, index, size, hashList(hs))
}

// bridgedJSON is the proof file for leaf index in the tree of size m, with the
// root at m and the consistency proof from m to n. It also returns the hashes.
func bridgedJSON(t *testing.T, l *tlog.Log, index, m, n int64) (string, []modtlog.Hash, []modtlog.Hash) {
	t.Helper()
	hs, err := l.ProveInclusion(index, m)
	if err != nil {
		t.Fatal(err)
	}
	root, err := l.RootAt(m)
	if err != nil {
		t.Fatal(err)
	}
	cons, err := l.ProveConsistency(m, n)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"index":%d,"tree_size":%d,"hashes":%s,"root":"%s","consistency":%s}`,
		index, m, hashList(hs), b64(root), hashList(cons)), hs, cons
}

func consistencyJSON(t *testing.T, l *tlog.Log, oldSize, newSize int64) string {
	t.Helper()
	hs, err := l.ProveConsistency(oldSize, newSize)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"old_size":%d,"new_size":%d,"hashes":%s}`, oldSize, newSize, hashList(hs))
}

// files writes input files into a directory with a marker in its name.
type files struct {
	t   *testing.T
	dir string
}

func newFiles(t *testing.T) files {
	t.Helper()
	dir := filepath.Join(t.TempDir(), pathMarker)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return files{t, dir}
}

func (f files) write(name string, data []byte) string {
	f.t.Helper()
	p := filepath.Join(f.dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		f.t.Fatal(err)
	}
	return p
}

// invoke runs the command and returns the exit code, stdout and stderr.
func invoke(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// noLeak fails if the text holds a path, a flag name, or the content of an input.
func noLeak(t *testing.T, name, text string, extra ...string) {
	t.Helper()
	for _, m := range append([]string{pathMarker, flagMarker, contentMarker, os.TempDir()}, extra...) {
		if strings.Contains(text, m) {
			t.Errorf("%s: output holds %q: %q", name, m, text)
		}
	}
}

func wantLines(t *testing.T, name, stdout string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains("\n"+stdout, "\n"+l+"\n") {
			t.Errorf("%s: stdout has no line %q:\n%s", name, l, stdout)
		}
	}
}

// T-S-14: the verified cases give exit 0 and the required output.
func TestTS14_Verified(t *testing.T) {
	s, keyText := testKey(t, origin)
	l, events := testLog(t, 300, `{"n":%d}`)
	f := newFiles(t)
	key := f.write("key", []byte(keyText))
	cp := func(size int64) string { return f.write(fmt.Sprintf("cp%d", size), checkpointAt(t, l, s, size)) }
	root300, _ := l.RootAt(300)
	head := []string{"origin: " + origin, "size: 300", "root: " + b64(root300)}

	code, stdout, stderr := invoke("--key", key, "--checkpoint", cp(300))
	if code != 0 || stderr != "" {
		t.Fatalf("checkpoint only: exit %d, stderr %q", code, stderr)
	}
	wantLines(t, "checkpoint only", stdout, head...)

	// An event with a proof at the checkpoint size.
	ev := f.write("event", events[7].Raw)
	proof := f.write("proof", []byte(inclusionJSON(t, l, 7, 300)))
	hs, _ := l.ProveInclusion(7, 300)
	code, stdout, stderr = invoke("--key", key, "--checkpoint", cp(300), "--event", ev, "--proof", proof)
	if code != 0 || stderr != "" {
		t.Fatalf("event and proof: exit %d, stderr %q", code, stderr)
	}
	want := append(head, "event hash: "+b64(events[7].Hash), "leaf index: 7")
	for _, h := range hs {
		want = append(want, "proof hash: "+b64(h))
	}
	wantLines(t, "event and proof", stdout, want...)
	if strings.Contains(stdout, "consistency") || strings.Contains(stdout, `"n"`) {
		t.Errorf("event and proof: unexpected output:\n%s", stdout)
	}

	// A bridged proof: the file holds the consistency hashes.
	pj, incl, cons := bridgedJSON(t, l, 3, 5, 300)
	ev = f.write("event3", events[3].Raw)
	proof = f.write("bridged", []byte(pj))
	code, stdout, stderr = invoke("--key", key, "--checkpoint", cp(300), "--event", ev, "--proof", proof)
	if code != 0 || stderr != "" {
		t.Fatalf("bridged proof: exit %d, stderr %q", code, stderr)
	}
	want = append(head, "event hash: "+b64(events[3].Hash), "leaf index: 3")
	for _, h := range incl {
		want = append(want, "proof hash: "+b64(h))
	}
	for _, h := range cons {
		want = append(want, "consistency hash: "+b64(h))
	}
	wantLines(t, "bridged proof", stdout, want...)

	// A prior checkpoint with one consistency file, and with an extra file.
	c1 := f.write("c1", []byte(consistencyJSON(t, l, 5, 300)))
	c2 := f.write("c2", []byte(consistencyJSON(t, l, 6, 300)))
	code, stdout, stderr = invoke("--key", key, "--checkpoint", cp(300), "--prior", cp(5), "--consistency", c1, "--consistency", c2)
	if code != 0 || stderr != "" {
		t.Fatalf("prior: exit %d, stderr %q", code, stderr)
	}
	wantLines(t, "prior", stdout, append(head, "prior consistency: verified")...)
	// The same size needs no file.
	code, stdout, _ = invoke("--key", key, "--checkpoint", cp(300), "--prior", cp(300))
	if code != 0 {
		t.Errorf("prior of the same size: exit %d", code)
	}
	wantLines(t, "prior, same size", stdout, "prior consistency: verified")
}

// T-S-14: the refused cases give exit 1, a fixed message and no stdout.
func TestTS14_Refused(t *testing.T) {
	s, keyText := testKey(t, origin)
	other, _ := testKey(t, origin) // same name, another key
	l, events := testLog(t, 20, `{"n":%d}`)
	fork, _ := testLog(t, 20, `{"m":%d}`)
	f := newFiles(t)
	key := f.write("key", []byte(keyText))
	cp10 := f.write("cp10", checkpointAt(t, l, s, 10))
	proof := f.write("proof", []byte(inclusionJSON(t, l, 3, 10)))
	good := checkpointAt(t, l, s, 10)
	badSig := bytes.Clone(good)
	i := len(badSig) - 20 // a base64 digit in the middle of the signature
	badSig[i] = 'B'
	if good[i] == 'B' {
		badSig[i] = 'C'
	}
	bigProof := inclusionJSON(t, l, 3, 10)
	bigProof = strings.Replace(bigProof, `"tree_size":10`, `"tree_size":11`, 1)
	for name, tc := range map[string]struct {
		args []string
		msg  string
	}{
		"changed event": {[]string{"--checkpoint", cp10, "--event", f.write("e4", events[4].Raw), "--proof", proof},
			"not verified: the event is not in the tree"},
		"another key": {[]string{"--checkpoint", f.write("other", checkpointAt(t, l, other, 10))},
			"checkpoint signature does not verify"},
		"changed signature": {[]string{"--checkpoint", f.write("badsig", badSig)},
			"checkpoint signature does not verify"},
		"forked prior": {[]string{"--checkpoint", f.write("fcp", checkpointAt(t, fork, s, 20)), "--prior", f.write("pcp", checkpointAt(t, l, s, 5)),
			"--consistency", f.write("fc", []byte(consistencyJSON(t, fork, 5, 20)))},
			"the log has a fork"},
		"proof size larger": {[]string{"--checkpoint", cp10, "--event", f.write("e3", events[3].Raw), "--proof", f.write("big", []byte(bigProof))},
			"larger than the checkpoint size"},
	} {
		code, stdout, stderr := invoke(append([]string{"--key", key}, tc.args...)...)
		if code != 1 || stdout != "" || !strings.Contains(stderr, tc.msg) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
		if strings.Contains(strings.ToLower(stderr), "fork") != (name == "forked prior") {
			t.Errorf("%s: fork in the wrong place: %q", name, stderr)
		}
		noLeak(t, name, stderr)
	}
	if code, _, _ := invoke("--key", key, "--checkpoint", cp10, "--event", f.write("e3", events[3].Raw), "--proof", proof); code != 0 {
		t.Errorf("unchanged inputs: exit %d", code)
	}
}

// T-S-14: usage errors and input errors give exit 2 and a fixed message. The
// message holds no path, no flag value and no input byte.
func TestTS14_InputFaults(t *testing.T) {
	s, keyText := testKey(t, origin)
	l, events := testLog(t, 10, `{"n":%d}`)
	f := newFiles(t)
	key := f.write("key", []byte(keyText))
	good := checkpointAt(t, l, s, 10)
	cp := f.write("cp", good)
	sigLine := good[bytes.LastIndex(good, []byte("\n\n"))+2:]
	twoSigs := f.write("twosigs", append(bytes.Clone(good), sigLine...))
	ev := f.write("event", events[3].Raw)
	proof := f.write("proof", []byte(inclusionJSON(t, l, 3, 10)))
	c5 := f.write("c5", []byte(consistencyJSON(t, l, 5, 10)))
	c5b := f.write("c5b", []byte(consistencyJSON(t, l, 5, 10)))
	prior := f.write("prior", checkpointAt(t, l, s, 5))
	missing := filepath.Join(f.dir, "missing")
	for name, args := range map[string][]string{
		"no arguments":                 nil,
		"no key":                       {"--checkpoint", cp},
		"no checkpoint":                {"--key", key},
		"unknown flag":                 {"--key", key, "--checkpoint", cp, "--" + flagMarker, contentMarker},
		"extra argument":               {"--key", key, "--checkpoint", cp, flagMarker},
		"event without proof":          {"--key", key, "--checkpoint", cp, "--event", ev},
		"proof without event":          {"--key", key, "--checkpoint", cp, "--proof", proof},
		"consistency without prior":    {"--key", key, "--checkpoint", cp, "--consistency", c5},
		"missing key":                  {"--key", missing, "--checkpoint", cp},
		"missing checkpoint":           {"--key", key, "--checkpoint", missing},
		"directory as file":            {"--key", f.dir, "--checkpoint", cp},
		"key is not a key":             {"--key", f.write("badkey", []byte(contentMarker)), "--checkpoint", cp},
		"key past its size cap":        {"--key", f.write("bigkey", bytes.Repeat([]byte("a"), 2048)), "--checkpoint", cp},
		"garbage checkpoint":           {"--key", key, "--checkpoint", f.write("garbage", []byte(contentMarker))},
		"note with two signatures":     {"--key", key, "--checkpoint", twoSigs},
		"bad event":                    {"--key", key, "--checkpoint", cp, "--event", f.write("badev", []byte(`{"b":1,"a":"`+contentMarker+`"}`)), "--proof", proof},
		"bad proof":                    {"--key", key, "--checkpoint", cp, "--event", ev, "--proof", f.write("badproof", []byte(`{"`+contentMarker+`":1}`))},
		"prior with two signatures":    {"--key", key, "--checkpoint", cp, "--prior", twoSigs},
		"bad consistency file":         {"--key", key, "--checkpoint", cp, "--prior", prior, "--consistency", f.write("badc", []byte(contentMarker))},
		"no file with the sizes":       {"--key", key, "--checkpoint", cp, "--prior", prior},
		"file with other sizes":        {"--key", key, "--checkpoint", cp, "--prior", prior, "--consistency", f.write("c1", []byte(consistencyJSON(t, l, 1, 10)))},
		"two files with the same size": {"--key", key, "--checkpoint", cp, "--prior", prior, "--consistency", c5, "--consistency", c5b},
	} {
		code, stdout, stderr := invoke(args...)
		if code != 2 || stdout != "" || stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
		noLeak(t, name, stdout+stderr)
		if strings.Contains(strings.ToLower(stdout+stderr), "fork") {
			t.Errorf("%s: output says fork: %q", name, stderr)
		}
	}
	// A usage error prints the fixed usage text.
	if _, _, stderr := invoke("--" + flagMarker); !strings.HasPrefix(stderr, "usage: phantom-verify ") {
		t.Errorf("usage text: %q", stderr)
	}
}

// T-S-14: the origin is the key name. It can hold characters that a terminal
// acts on. The output holds the escaped form only.
func TestTS14_OriginEscaped(t *testing.T) {
	// U+0085 is a space for note, so the name uses another C1 character.
	name := "ph\x7fa\u009bn\u202et\u2066o\u061cm/test"
	s, keyText := testKey(t, name)
	l, _ := testLog(t, 3, `{"n":%d}`)
	f := newFiles(t)
	code, stdout, stderr := invoke("--key", f.write("key", []byte(keyText)), "--checkpoint", f.write("cp", checkpointAt(t, l, s, 3)))
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if strings.ContainsAny(stdout, "\x7f\u009b\u202e\u2066\u061c") {
		t.Errorf("stdout holds a raw character: %q", stdout)
	}
	wantLines(t, "origin", stdout, `origin: ph\x7fa\u009bn\u202et\u2066o\u061cm/test`)
}

// T-S-14: the escape function.
func TestTS14_Escape(t *testing.T) {
	for in, want := range map[string]string{
		"\x01": `\x01`, "\x1b[31m": `\x1b[31m`, "\xff": `\xff`, "a\x00b": `a\x00b`, "plain/text": "plain/text", "\n": `\n`,
	} {
		if got := escape(in); got != want {
			t.Errorf("escape(%q) = %q, want %q", in, got, want)
		}
	}
	// Each C0 and C1 control character, U+007F, and each bidirectional format
	// character changes. The result has only printable ASCII.
	var runes []rune
	for r := rune(0); r < 0x20; r++ {
		runes = append(runes, r)
	}
	for r := rune(0x7f); r < 0xa0; r++ {
		runes = append(runes, r)
	}
	for _, r := range "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" {
		runes = append(runes, r)
	}
	for _, r := range runes {
		got := escape(string(r))
		if got == string(r) || strings.ContainsFunc(got, func(c rune) bool { return c > unicode.MaxASCII || !unicode.IsPrint(c) }) {
			t.Errorf("escape(%U) = %q", r, got)
		}
	}
}

// T-S-14: the fields of an event are never printed. Member names that differ
// only in case are two members. The command shows the hash of the bytes.
func TestTS14_EventFieldsNotPrinted(t *testing.T) {
	s, keyText := testKey(t, origin)
	l, events := testLog(t, 4, `{"A":2,"a":%d}`)
	f := newFiles(t)
	code, stdout, stderr := invoke("--key", f.write("key", []byte(keyText)), "--checkpoint", f.write("cp", checkpointAt(t, l, s, 4)),
		"--event", f.write("event", events[2].Raw), "--proof", f.write("proof", []byte(inclusionJSON(t, l, 2, 4))))
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	wantLines(t, "event", stdout, "event hash: "+b64(events[2].Hash), "leaf index: 2")
	if strings.ContainsAny(stdout, `{}"`) {
		t.Errorf("stdout holds event text: %q", stdout)
	}
}

// T-I-14: the command accepts an event with the checkpoint of a real log, and
// refuses a modified event.
func TestTI14_EndToEnd(t *testing.T) {
	s, keyText := testKey(t, origin)
	l, events := testLog(t, 50, `{"n":%d}`)
	f := newFiles(t)
	key := f.write("key", []byte(keyText))
	cp := f.write("cp", checkpointAt(t, l, s, 50))
	proof := f.write("proof", []byte(inclusionJSON(t, l, 11, 50)))
	code, stdout, stderr := invoke("--key", key, "--checkpoint", cp, "--event", f.write("event", events[11].Raw), "--proof", proof)
	if code != 0 || stderr != "" {
		t.Fatalf("event and checkpoint: exit %d, stderr %q", code, stderr)
	}
	wantLines(t, "event and checkpoint", stdout, "origin: "+origin, "size: 50", "event hash: "+b64(events[11].Hash), "leaf index: 11")
	modified := bytes.Replace(events[11].Raw, []byte("11"), []byte("12"), 1)
	if code, _, _ := invoke("--key", key, "--checkpoint", cp, "--event", f.write("modified", modified), "--proof", proof); code != 1 {
		t.Errorf("modified event: exit %d, want 1", code)
	}

	t.Run("alert event", func(t *testing.T) {
		// This is the place for the alert event of a later milestone. The sensor
		// will append the event of an alert to the log before it sends the alert.
		// Then this test will read the event and the checkpoint of that log, and
		// run the command on them.
		t.Skip("the alert event does not exist yet")
	})
}
