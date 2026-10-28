package bundle

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

// sumOf gives a SHA-256 value that is the byte b repeated.
func sumOf(b byte) [32]byte { return [32]byte(bytes.Repeat([]byte{b}, 32)) }

// stateJSON gives the bytes of a valid state file.
func stateJSON(version string, sum [32]byte, class string) string {
	return fmt.Sprintf(`{"version":%q,"sha256":"%x","class":%q}`, version, sum, class)
}

// newDir makes a bundle directory with an open root.
func newDir(t *testing.T) (string, *Rollback) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return dir, NewRollback(root)
}

func putState(t *testing.T, dir, text string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, StateName)
	if err := os.WriteFile(p, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// snapshot gives the mode, the bytes and the link target of the state name.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, StateName)
	fi, err := os.Lstat(p)
	if err != nil {
		return "none"
	}
	b, _ := os.ReadFile(p)
	link, _ := os.Readlink(p)
	return fmt.Sprintf("%v %q %q", fi.Mode(), b, link)
}

var (
	farNow  = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	farExp  = farNow.Add(24 * time.Hour)
	goodRec = stateJSON("2026.01.01-5", sumOf(1), "proprietary")
)

func manifestOf(version string, expires time.Time) *Manifest {
	return &Manifest{Version: version, Expires: expires}
}

// T-S-20: a state file that the rule refuses or that does not parse is a fault.
// Check refuses, Healthy is false, and Record writes nothing. The file keeps
// its bytes and its mode.
func TestTS20StateFault(t *testing.T) {
	pad := strings.Repeat(" ", 4096-len(goodRec))
	cases := []struct {
		name, text string
		mode       os.FileMode
	}{
		{"changed", "{\"version\":\"x\"}", 0o600},
		{"truncated prefix", goodRec[:len(goodRec)-1], 0o600},
		{"empty", "", 0o600},
		{"unknown member", strings.Replace(goodRec, "}", `,"extra":1}`, 1), 0o600},
		{"duplicate member", strings.Replace(goodRec, "}", `,"class":"reference"}`, 1), 0o600},
		{"case variant", strings.Replace(goodRec, `"class"`, `"Class"`, 1), 0o600},
		{"missing member", strings.Replace(goodRec, `,"class":"proprietary"`, "", 1), 0o600},
		{"null member", strings.Replace(goodRec, `"proprietary"`, "null", 1), 0o600},
		{"bad class", strings.Replace(goodRec, "proprietary", "other", 1), 0o600},
		{"bad version", strings.Replace(goodRec, "2026.01.01-5", "2026.01.01-05", 1), 0o600},
		{"upper case hash", strings.Replace(stateJSON("2026.01.01-5", sumOf(0xab), "reference"), "abab", "ABAB", 1), 0o600},
		{"short hash", strings.Replace(goodRec, "0101", "01", 1), 0o600},
		{"trailing bytes", goodRec + "x", 0o600},
		{"over the cap", goodRec + pad + " ", 0o600},
		{"group read", goodRec, 0o640},
		{"other read", goodRec, 0o604},
		{"mode 0644", goodRec, 0o644},
		{"group write", goodRec, 0o620},
		{"group execute", goodRec, 0o610},
		{"other write", goodRec, 0o602},
		{"other execute", goodRec, 0o601},
		{"setuid", goodRec, 0o600 | os.ModeSetuid},
		{"setgid", goodRec, 0o600 | os.ModeSetgid},
		{"sticky", goodRec, 0o600 | os.ModeSticky},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, r := newDir(t)
			putState(t, dir, c.text, c.mode)
			before := snapshot(t, dir)
			wantFault(t, r, dir, before)
		})
	}
	t.Run("at the cap", func(t *testing.T) {
		dir, r := newDir(t)
		putState(t, dir, goodRec+pad, 0o600)
		if !r.Healthy() {
			t.Error("a state file of 4096 bytes is a fault")
		}
	})
	t.Run("other owner", func(t *testing.T) {
		dir, r := newDir(t)
		putState(t, dir, goodRec, 0o600)
		fi, err := os.Stat(filepath.Join(dir, StateName))
		if err != nil {
			t.Fatal(err)
		}
		id, ok := safefile.Identity(fi)
		if !ok {
			t.Skip("this platform gives no file identity")
		}
		safefiletest.Set(t, safefiletest.Hooks{OtherOwner: func(o safefile.FileID) bool { return o == id }})
		wantFault(t, r, dir, snapshot(t, dir))
	})
	t.Run("symlink", func(t *testing.T) {
		dir, r := newDir(t)
		if err := os.WriteFile(filepath.Join(dir, "real"), []byte(goodRec), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(dir, StateName)); err != nil {
			t.Fatal(err)
		}
		wantFault(t, r, dir, snapshot(t, dir))
		if b, _ := os.ReadFile(filepath.Join(dir, "real")); string(b) != goodRec {
			t.Error("the target of the link changed")
		}
	})
	t.Run("hard link", func(t *testing.T) {
		dir, r := newDir(t)
		putState(t, dir, goodRec, 0o600)
		if err := os.Link(filepath.Join(dir, StateName), filepath.Join(dir, "other")); err != nil {
			t.Fatal(err)
		}
		wantFault(t, r, dir, snapshot(t, dir))
	})
	t.Run("directory", func(t *testing.T) {
		dir, r := newDir(t)
		if err := os.Mkdir(filepath.Join(dir, StateName), 0o700); err != nil {
			t.Fatal(err)
		}
		wantFault(t, r, dir, snapshot(t, dir))
	})
}

// wantFault checks each fault rule for the state file in dir.
func wantFault(t *testing.T, r *Rollback, dir, before string) {
	t.Helper()
	m := manifestOf("2030.01.01-1", farExp)
	for i := 0; i < 2; i++ { // the fault stays
		_, err := r.Check(m, sumOf(1), ClassProprietary, farNow, true)
		if code, ok := CodeOf(err); !errors.Is(err, ErrStateFault) || ok || code != 0 {
			t.Fatalf("Check: %v, code %v %v", err, code, ok)
		}
	}
	if r.Healthy() {
		t.Error("Healthy is true")
	}
	if err := r.Record(m, sumOf(2), ClassProprietary); !errors.Is(err, ErrStateFault) {
		t.Errorf("Record: %v", err)
	}
	if after := snapshot(t, dir); after != before {
		t.Errorf("file changed: %s -> %s", before, after)
	}
	if _, err := os.Lstat(filepath.Join(dir, stateTempName)); err == nil {
		t.Error("a temporary file is left")
	}
}

// T-S-20: the fault and its text hold no byte of the state file.
func TestTS20StateFaultHoldsNoBytes(t *testing.T) {
	dir, r := newDir(t)
	putState(t, dir, strings.Replace(goodRec, "}", `,"MARKER-9f3":1}`, 1), 0o600)
	_, err := r.Check(manifestOf("2030.01.01-1", farExp), sumOf(1), ClassProprietary, farNow, false)
	if err != ErrStateFault || strings.Contains(err.Error(), "MARKER") || err.Error() != "bundle: state fault" {
		t.Errorf("error %q", err)
	}
	putState(t, dir, goodRec, 0o644)
	_, err = r.Check(manifestOf("2030.01.01-1", farExp), sumOf(1), ClassProprietary, farNow, false)
	if !errors.Is(err, ErrStateFault) || strings.Contains(err.Error(), dir) {
		t.Errorf("error %q", err)
	}
}

// T-S-20: no state file is a first start. It is not a fault.
func TestTS20FirstStart(t *testing.T) {
	_, r := newDir(t)
	if !r.Healthy() {
		t.Error("not healthy at first start")
	}
	for _, class := range []Class{ClassProprietary, ClassReference} {
		if _, err := r.Check(manifestOf("2026.01.01-1", farExp), sumOf(1), class, farNow, false); err != nil {
			t.Errorf("class %d: %v", class, err)
		}
	}
}

// faultyTemp makes one step of the temporary file fail. Close always closes
// the real file, so the test leaks no descriptor.
type faultyTemp struct {
	f    *os.File
	step string
}

var errInjected = errors.New("injected write fault")

func (w faultyTemp) Write(b []byte) (int, error) {
	if w.step == "write" {
		return 0, errInjected
	}
	return w.f.Write(b)
}

func (w faultyTemp) Sync() error {
	if w.step == "sync" {
		return errInjected
	}
	return w.f.Sync()
}

func (w faultyTemp) Close() error {
	err := w.f.Close()
	if w.step == "close" {
		return errInjected
	}
	return err
}

// T-S-20: a write can fail after writeFile creates the temporary file. Then
// Record gives an error, leaves no temporary file, and keeps the old state.
func TestTS20WriteFileFailsAfterCreate(t *testing.T) {
	for _, step := range []string{"write", "sync", "close"} {
		t.Run(step, func(t *testing.T) {
			dir, r := newDir(t)
			putState(t, dir, goodRec, 0o600)
			before := snapshot(t, dir)
			wrapTemp = func(f *os.File) tempFile { return faultyTemp{f, step} }
			t.Cleanup(func() { wrapTemp = nil })
			if err := r.Record(manifestOf("2030.01.01-1", farExp), sumOf(2), ClassProprietary); !errors.Is(err, errInjected) {
				t.Errorf("Record: %v", err)
			}
			if snapshot(t, dir) != before {
				t.Error("a failed write changed the state")
			}
			if _, err := os.Lstat(filepath.Join(dir, stateTempName)); err == nil {
				t.Error("a temporary file is left")
			}
		})
	}
	t.Run("no fault", func(t *testing.T) {
		_, r := newDir(t)
		wrapTemp = func(f *os.File) tempFile { return faultyTemp{f, "none"} }
		t.Cleanup(func() { wrapTemp = nil })
		if err := r.Record(manifestOf("2030.01.01-1", farExp), sumOf(2), ClassProprietary); err != nil {
			t.Errorf("Record: %v", err)
		}
		if !r.Healthy() {
			t.Error("not healthy after the write")
		}
	})
}

// T-S-20: a failed Rename gives an error and leaves no temporary file. The
// old content stays at the target name. The test puts a directory with a file
// in it at that name.
func TestTS20WriteFileRenameFails(t *testing.T) {
	dir, r := newDir(t)
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(filepath.Join(target, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(r.root, "target", []byte("new")); err == nil {
		t.Fatal("the write worked")
	}
	if _, err := os.Lstat(filepath.Join(target, "x")); err != nil {
		t.Errorf("the old content at the target is gone: %v", err)
	}
	if _, err := os.Lstat(target + ".tmp"); err == nil {
		t.Error("a temporary file is left")
	}
}
