package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// T-S-20: a lower version, the same version with another SHA-256, and a
// reference bundle after a proprietary one give ErrRollback. The same SHA-256
// is accepted. N of the version is a number: "-9" is lower than "-10".
func TestTS20Rollback(t *testing.T) {
	cases := []struct {
		name, state, stateClass, version string
		sum                              byte
		class                            Class
		want                             error
	}{
		{"lower N", "2026.01.01-10", "proprietary", "2026.01.01-9", 2, ClassProprietary, ErrRollback},
		{"higher N with two digits", "2026.01.01-9", "proprietary", "2026.01.01-10", 2, ClassProprietary, nil},
		{"lower date", "2026.01.02-1", "proprietary", "2026.01.01-999", 2, ClassProprietary, ErrRollback},
		{"higher date", "2026.01.01-999", "proprietary", "2026.01.02-1", 2, ClassProprietary, nil},
		{"same version other hash", "2026.01.01-3", "proprietary", "2026.01.01-3", 2, ClassProprietary, ErrRollback},
		{"same bundle", "2026.01.01-3", "proprietary", "2026.01.01-3", 1, ClassProprietary, nil},
		{"reference after proprietary", "2026.01.01-3", "proprietary", "2026.02.01-1", 2, ClassReference, ErrRollback},
		{"proprietary after reference", "2026.01.01-3", "reference", "2026.02.01-1", 2, ClassProprietary, nil},
		{"reference after reference", "2026.01.01-3", "reference", "2026.02.01-1", 2, ClassReference, nil},
	}
	for _, c := range cases {
		dir, r := newDir(t)
		putState(t, dir, stateJSON(c.state, sumOf(1), c.stateClass), 0o600)
		before := snapshot(t, dir)
		_, err := r.Check(manifestOf(c.version, farExp), sumOf(c.sum), c.class, farNow, false)
		if err != c.want {
			t.Errorf("%s: %v", c.name, err)
		}
		if code, ok := CodeOf(err); err != nil && (!ok || code != CodeRollback || err.Error() != "bundle: rollback") {
			t.Errorf("%s: code %v", c.name, code)
		}
		if snapshot(t, dir) != before {
			t.Errorf("%s: Check changed the file", c.name)
		}
	}
}

// T-S-20: Record writes after an accept. The file has mode 0600 and the new
// state. The same SHA-256 again does not write. A rollback does not write.
func TestTS20Record(t *testing.T) {
	dir, r := newDir(t)
	p := filepath.Join(dir, StateName)
	if err := r.Record(manifestOf("2026.01.01-2", farExp), sumOf(1), ClassProprietary); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil || fi.Mode() != 0o600 {
		t.Fatalf("%v, %v", fi, err)
	}
	if !r.Healthy() {
		t.Error("not healthy after a write")
	}
	if err := r.Record(manifestOf("2026.01.01-2", farExp), sumOf(1), ClassProprietary); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.Lstat(p); !os.SameFile(fi, again) {
		t.Error("the same SHA-256 wrote the file again")
	}
	before := snapshot(t, dir)
	if err := r.Record(manifestOf("2026.01.01-1", farExp), sumOf(2), ClassProprietary); err != ErrRollback {
		t.Errorf("Record of a lower version: %v", err)
	}
	if err := r.Record(manifestOf("2026.01.01-3", farExp), sumOf(2), ClassReference); err != ErrRollback {
		t.Errorf("Record of a reference bundle: %v", err)
	}
	if snapshot(t, dir) != before {
		t.Error("a refused Record changed the file")
	}
	if err := r.Record(manifestOf("2026.01.01-3", farExp), sumOf(2), ClassProprietary); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Check(manifestOf("2026.01.01-2", farExp), sumOf(1), ClassProprietary, farNow, false); err != ErrRollback {
		t.Errorf("old bundle after Record: %v", err)
	}
}

// T-S-20: Record refuses a version or a class that readState refuses. At a
// first start it writes nothing, and Healthy stays true.
func TestTS20RecordRefusesInput(t *testing.T) {
	cases := []struct {
		name    string
		version string
		class   Class
	}{
		{"empty version", "", ClassProprietary},
		{"bad version", "bad", ClassProprietary},
		{"class 0", "2026.01.01-1", Class(0)},
		{"unknown class", "2026.01.01-1", Class(99)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, r := newDir(t)
			if err := r.Record(manifestOf(c.version, farExp), sumOf(1), c.class); !errors.Is(err, errStateInput) {
				t.Errorf("Record: %v", err)
			}
			if snapshot(t, dir) != "none" {
				t.Error("Record wrote a state file")
			}
			if _, err := os.Lstat(filepath.Join(dir, stateTempName)); err == nil {
				t.Error("a temporary file is left")
			}
			if !r.Healthy() {
				t.Error("not healthy")
			}
		})
	}
}

// T-S-20: Record refuses a version or a class that readState refuses, also
// when the SHA-256 is that of the state. The state file does not change.
func TestTS20RecordRefusesInputSameSum(t *testing.T) {
	cases := []struct {
		name    string
		version string
		class   Class
	}{
		{"bad version", "bad", ClassProprietary},
		{"class 0", "2026.01.01-5", Class(0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, r := newDir(t)
			putState(t, dir, goodRec, 0o600)
			before := snapshot(t, dir)
			if err := r.Record(manifestOf(c.version, farExp), sumOf(1), c.class); !errors.Is(err, errStateInput) {
				t.Errorf("Record: %v", err)
			}
			if snapshot(t, dir) != before {
				t.Error("the state file changed")
			}
			if !r.Healthy() {
				t.Error("not healthy")
			}
		})
	}
}

// T-S-20: a hand-built Manifest can have a short version. When a state with
// another SHA-256 exists, Check and Record give an error and do not panic.
// The state file does not change.
func TestTS20ShortVersion(t *testing.T) {
	for _, v := range []string{"", "2026", "2026.01.01", "2026.01.01-", "2026.01.01-0", "2030.01.01-0", "2030.02.30-1"} {
		t.Run(v, func(t *testing.T) {
			dir, r := newDir(t)
			putState(t, dir, goodRec, 0o600)
			before := snapshot(t, dir)
			m := manifestOf(v, farExp)
			if _, err := r.Check(m, sumOf(2), ClassProprietary, farNow, false); !errors.Is(err, errStateInput) {
				t.Errorf("Check: %v", err)
			}
			if err := r.Record(m, sumOf(2), ClassProprietary); !errors.Is(err, errStateInput) {
				t.Errorf("Record: %v", err)
			}
			if snapshot(t, dir) != before {
				t.Error("the state file changed")
			}
		})
	}
}

// T-S-20: a crash between the swap and the state write leaves the old state.
// The next check accepts the running bundle again, because its version is
// higher. The test puts a directory with a file in it at the temporary name.
// Record cannot remove it, so the write fails before it makes a new file.
func TestTS20FailedWriteKeepsOldState(t *testing.T) {
	dir, r := newDir(t)
	putState(t, dir, stateJSON("2026.01.01-1", sumOf(1), "proprietary"), 0o600)
	before := snapshot(t, dir)
	tmp := filepath.Join(dir, stateTempName)
	if err := os.MkdirAll(filepath.Join(tmp, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	m := manifestOf("2026.01.01-2", farExp)
	if _, err := r.Check(m, sumOf(2), ClassProprietary, farNow, false); err != nil {
		t.Fatal(err)
	}
	if err := r.Record(m, sumOf(2), ClassProprietary); err == nil {
		t.Fatal("the write worked")
	}
	if snapshot(t, dir) != before {
		t.Error("a failed write changed the state")
	}
	if _, err := r.Check(m, sumOf(2), ClassProprietary, farNow, true); err != nil {
		t.Errorf("the running bundle after the failed write: %v", err)
	}
}

// T-S-20: a temporary file that a crash left does not block the next write.
func TestTS20LeftoverTempFile(t *testing.T) {
	dir, r := newDir(t)
	tmp := filepath.Join(dir, stateTempName)
	if err := os.WriteFile(tmp, []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Record(manifestOf("2026.01.01-1", farExp), sumOf(1), ClassProprietary); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(tmp); err == nil {
		t.Error("the temporary file is left")
	}
	if fi, _ := os.Lstat(filepath.Join(dir, StateName)); fi == nil || fi.Mode() != 0o600 || !r.Healthy() {
		t.Error("the state is not valid")
	}
}

// T-S-20: the write does not follow a symlink at the temporary name.
func TestTS20TempSymlinkNotFollowed(t *testing.T) {
	dir, r := newDir(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, stateTempName)); err != nil {
		t.Fatal(err)
	}
	if err := r.Record(manifestOf("2026.01.01-1", farExp), sumOf(1), ClassProprietary); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Errorf("the victim file holds %q", b)
	}
	if !r.Healthy() {
		t.Error("not healthy")
	}
}

// T-S-20: at start, the bundle whose SHA-256 equals the state loads after
// expires with the expired flag. Another expired bundle, a check that is not
// at start, and a first start give ErrExpired. The expiry check comes before
// the rollback check.
func TestTS20ExpiredAtStart(t *testing.T) {
	dir, r := newDir(t)
	putState(t, dir, stateJSON("2026.01.01-5", sumOf(1), "proprietary"), 0o600)
	cases := []struct {
		name     string
		version  string
		sum      byte
		expires  time.Duration // from now
		start    bool
		wantErr  error
		wantFlag bool
	}{
		{"running bundle at start", "2026.01.01-5", 1, -time.Second, true, nil, true},
		{"expires equals now", "2026.01.01-5", 1, 0, true, nil, true},
		{"running bundle, not expired", "2026.01.01-5", 1, time.Second, true, nil, false},
		{"running bundle, not at start", "2026.01.01-5", 1, -time.Second, false, ErrExpired, false},
		{"other bundle at start", "2026.01.01-6", 2, -time.Second, true, ErrExpired, false},
		{"expired and lower", "2026.01.01-4", 2, -time.Second, true, ErrExpired, false},
	}
	for _, c := range cases {
		flag, err := r.Check(manifestOf(c.version, farNow.Add(c.expires)), sumOf(c.sum), ClassProprietary, farNow, c.start)
		if err != c.wantErr || flag != c.wantFlag {
			t.Errorf("%s: %v, %v", c.name, flag, err)
		}
	}
	_, fresh := newDir(t)
	if _, err := fresh.Check(manifestOf("2026.01.01-5", farNow.Add(-time.Second)), sumOf(1), ClassProprietary, farNow, true); err != ErrExpired {
		t.Errorf("first start: %v", err)
	}
}
