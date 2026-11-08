package bundle

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

// fetched is a running env (version 2). It holds the old pair and a new signed
// pair of version 3 in memory.
type fetched struct {
	*env
	p                          *probe
	oldArch, oldSig, arch, sig []byte
}

// noSeams fails the test when a seam of an earlier test is still set.
func noSeams(t *testing.T) {
	t.Helper()
	if wrapTemp != nil || beforeRename != nil || afterTempRemove != nil {
		t.Fatal("a test seam is set on entry")
	}
}

func newFetched(t *testing.T) *fetched {
	t.Helper()
	noSeams(t)
	e := running(t)
	f := &fetched{env: e, p: e.observe(e.l)}
	f.oldArch, f.oldSig = f.bytesOf("bundle/current.cbnd"), f.bytesOf("bundle/current.sig")
	f.arch = build(ent{name: "manifest.json", data: []byte(mf(ver(3)))})
	f.sig = e.sign(f.arch)
	return f
}

func (e *env) bytesOf(rel string) []byte {
	b, _ := os.ReadFile(filepath.Join(e.state, rel))
	return b
}

// files gives the name and the content of each entry of the bundle directory.
// A directory mtime changes when a temporary file comes and goes.
func (e *env) files() string {
	ents, err := os.ReadDir(filepath.Join(e.state, "bundle"))
	must(e.t, err)
	var sb strings.Builder
	for _, d := range ents {
		fmt.Fprintf(&sb, "%s %x\n", d.Name(), e.bytesOf("bundle/"+d.Name()))
	}
	return sb.String()
}

func (e *env) stateVersion() string {
	d, err := e.root.OpenRoot("bundle")
	must(e.t, err)
	defer d.Close()
	st, err := readState(d)
	must(e.t, err)
	return st.Version
}

// snap tells which bytes each install file holds, and the version state.
func (f *fetched) snap() string {
	label := func(rel string) string {
		b := f.bytesOf(rel)
		for name, v := range map[string][]byte{"new-arch": f.arch, "new-sig": f.sig, "old-arch": f.oldArch, "old-sig": f.oldSig} {
			if b != nil && bytes.Equal(b, v) {
				return name
			}
		}
		if b == nil {
			return "none"
		}
		return "other"
	}
	return fmt.Sprintf("cbnd=%s sig=%s ctmp=%s stmp=%s state=%s", label("bundle/current.cbnd"), label("bundle/current.sig"),
		label("bundle/current.cbnd.tmp"), label("bundle/current.sig.tmp"), f.stateVersion())
}

// events takes the events and checks the kind and the source of each.
func (f *fetched) events(kinds string) {
	f.t.Helper()
	evs, _ := f.p.take(f.t)
	var got []string
	for _, e := range evs {
		got = append(got, e.Record().Kind.String()+"/"+detail(f.t, e)["source"])
	}
	if strings.Join(got, ",") != kinds {
		f.t.Errorf("events %v, want %q", got, kinds)
	}
}

// T-U-08, T-S-20: each check of Load runs on fetched bytes. A rejection gives
// one bundle_rejected event with source fetch, and changes no file and not the
// running bundle. The bundle files hold junk, so a read of them would give
// archive_invalid.
func TestTU08FetchedRejects(t *testing.T) {
	signed := func(f *fetched, m string) ([]byte, []byte) {
		a := build(ent{name: "manifest.json", data: []byte(m)})
		return a, f.sign(a)
	}
	cases := []struct {
		name string
		mk   func(f *fetched) ([]byte, []byte)
		want error
	}{
		{"bad_sig", func(f *fetched) ([]byte, []byte) { return append(bytes.Clone(f.arch), 0), f.sig }, ErrBadSig},
		{"archive_invalid", func(f *fetched) ([]byte, []byte) { return []byte("not gzip"), f.sign([]byte("not gzip")) }, ErrArchiveInvalid},
		{"manifest_invalid", func(f *fetched) ([]byte, []byte) { return signed(f, "{}") }, ErrManifestInvalid},
		{"min_engine", func(f *fetched) ([]byte, []byte) { return signed(f, mf(ver(3), engineRepl...)) }, ErrMinEngine},
		{"expired", func(f *fetched) ([]byte, []byte) { return signed(f, mf(ver(3), expiredRepl...)) }, ErrExpired},
		{"rollback", func(f *fetched) ([]byte, []byte) { return signed(f, mf(ver(1))) }, ErrRollback},
		{"archive over the cap", func(f *fetched) ([]byte, []byte) { return make([]byte, MaxBundleBytes+1), f.sig }, ErrArchiveInvalid},
		{"signature over the cap", func(f *fetched) ([]byte, []byte) { return f.arch, make([]byte, MaxSigBytes+1) }, ErrArchiveInvalid},
		// At the cap, the size is no reason to refuse. The signature check
		// refuses.
		{"archive at the cap", func(f *fetched) ([]byte, []byte) { return make([]byte, MaxBundleBytes), f.sig }, ErrBadSig},
		{"signature at the cap", func(f *fetched) ([]byte, []byte) { return f.arch, make([]byte, MaxSigBytes) }, ErrBadSig},
		// The version state holds the SHA-256 of this expired bundle. Only a
		// start load accepts it then, so a fetch must refuse it.
		{"expired, state holds its SHA-256", func(f *fetched) ([]byte, []byte) {
			a, s := signed(f, mf(ver(3), expiredRepl...))
			dir, err := f.root.OpenRoot("bundle")
			must(f.t, err)
			defer dir.Close()
			must(f.t, writeState(dir, state{Version: ver(2), SHA256: sha256.Sum256(a), Class: ClassProprietary}))
			return a, s
		}, ErrExpired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFetched(t)
			f.write("bundle/current.cbnd", []byte("junk"))
			f.write("bundle/current.sig", []byte("junk"))
			arch, sig := c.mk(f)
			before, run := dirListing(t, f.state), f.l.Current()
			if b, err := f.l.LoadFetched(arch, sig); b != nil || err != c.want {
				t.Fatalf("got %v, %v; want %v", b, err, c.want)
			}
			if f.l.Current() != run || dirListing(t, f.state) != before || f.stateVersion() != ver(2) {
				t.Error("a file, the version state or the running bundle changed")
			}
			f.events("bundle_rejected/fetch")
		})
	}
}

// T-S-20: LoadFetched checks the directory part and the state-file name of the
// path before the bytes. A symlink as directory part and a record name, also in
// upper case, give archive_invalid. LoadFetched writes nothing.
func TestTS20FetchedPathChecks(t *testing.T) {
	f := newFetched(t)
	must(t, os.Symlink(filepath.Join(f.state, "bundle"), filepath.Join(f.state, "link")))
	for _, path := range []string{"link/current.cbnd", "bundle/rotation-1.cbnd", "bundle/ROTATION-1.cbnd", "bundle/current.sig", "bundle/.cbnd"} {
		before := dirListing(t, f.state)
		l := f.loader(path)
		if b, err := l.LoadFetched(f.arch, f.sig); b != nil || err != ErrArchiveInvalid {
			t.Errorf("%s: got %v, %v", path, b, err)
		}
		if dirListing(t, f.state) != before || l.Current() != nil {
			t.Errorf("%s: a file changed", path)
		}
	}
}

// syncCount counts the Sync calls of a temporary file.
type syncCount struct {
	*os.File
	n *int
}

func (s syncCount) Sync() error { *s.n++; return s.File.Sync() }

// T-U-23: an accepted fetched bundle goes to disk in the order of SEC-25.
// First two synced temporary files. Then the archive rename and the signature
// file rename. Then the version state and the swap.
func TestTU23FetchedInstallOrder(t *testing.T) {
	f := newFetched(t)
	syncs := 0
	wrapTemp = func(w *os.File) tempFile { return syncCount{w, &syncs} }
	var seen []string
	beforeRename = func(from, to string) error {
		seen = append(seen, fmt.Sprintf("%s>%s %s syncs=%d", from, to, f.snap(), syncs))
		return nil
	}
	t.Cleanup(func() { wrapTemp, beforeRename = nil, nil })
	b, err := f.l.LoadFetched(f.arch, f.sig)
	must(t, err)
	want := []string{
		"current.cbnd.tmp>current.cbnd cbnd=old-arch sig=old-sig ctmp=new-arch stmp=new-sig state=" + ver(2) + " syncs=2",
		"current.sig.tmp>current.sig cbnd=new-arch sig=old-sig ctmp=none stmp=new-sig state=" + ver(2) + " syncs=2",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Errorf("order:\n%s", strings.Join(seen, "\n"))
	}
	if got := f.snap(); got != "cbnd=new-arch sig=new-sig ctmp=none stmp=none state="+ver(3) {
		t.Errorf("after: %s", got)
	}
	if f.l.Current() != b || b.Manifest().Version != ver(3) || !bytes.Equal(b.Signature(), f.sig) {
		t.Error("the new bundle does not run with its signature file")
	}
	b.Signature()[0] ^= 1
	if !bytes.Equal(b.Signature(), f.sig) {
		t.Error("Signature gives the kept bytes")
	}
	for _, n := range []string{"current.cbnd", "current.sig"} {
		if fi, err := os.Stat(filepath.Join(f.state, "bundle", n)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", n, fi, err)
		}
	}
	f.sig[0] ^= 1
	if bytes.Equal(b.Signature(), f.sig) {
		t.Error("the bundle keeps the slice of the caller")
	}
	f.events("bundle_load/fetch")
}

// transitionFetched makes the new pair of f a transition bundle from k1 to k3.
func transitionFetched(t *testing.T) *fetched {
	f := newFetched(t)
	k1, k3 := f.keys()[0], newKey(3, "k3")
	f.arch = transition(k1, k3, ver(3))
	f.sig = []byte(lineOf(k1, f.arch) + lineOf(k3, f.arch))
	return f
}

func (f *fetched) hasRecord() bool {
	_, err := os.Lstat(filepath.Join(f.state, "bundle", recordName(1, "cbnd")))
	return err == nil
}

// T-U-23: a fetched transition bundle writes its record after the two files.
// A crash between the renames, or after them and before the record, leaves a
// pair that the next start loads. The start load writes the record. Then a
// bundle that only the old key signs gives bad_sig.
func TestTU23FetchedTransitionCrash(t *testing.T) {
	stop := func(f *fetched) {
		f.crashAfterFirstRename()
		if f.hasRecord() {
			f.t.Fatal("a record between the renames")
		}
	}
	afterRenames := func(f *fetched) {
		tmp := filepath.Join(f.state, "bundle", recordName(1, "cbnd")+".tmp", "x")
		must(f.t, os.MkdirAll(tmp, 0o700))
		if _, err := f.l.LoadFetched(f.arch, f.sig); err != ErrStateFault || f.hasRecord() || f.snap() !=
			"cbnd=new-arch sig=new-sig ctmp=none stmp=none state="+ver(2) {
			f.t.Fatalf("after the renames: %v, record %v, %s", err, f.hasRecord(), f.snap())
		}
		must(f.t, os.RemoveAll(filepath.Join(f.state, "bundle", recordName(1, "cbnd")+".tmp")))
	}
	for name, crash := range map[string]func(*fetched){"between the renames": stop, "after the renames": afterRenames} {
		t.Run(name, func(t *testing.T) {
			f := transitionFetched(t)
			crash(f)
			l := f.loader("bundle/current.cbnd")
			b, err := l.Load(true)
			must(t, err)
			if b.Manifest().Version != ver(3) || !f.hasRecord() || f.stateVersion() != ver(3) {
				t.Error("the start load did not install the transition bundle")
			}
			f.putBy(f.keys()[0], ver(4))
			if _, err := l.Load(false); err != ErrBadSig {
				t.Errorf("a bundle of the old key: %v", err)
			}
		})
	}
}

// T-U-23: a roll-forward whose rename of the signature temporary file fails
// gives ErrInstallFault, one log line and no event. The start load keeps the
// pair and the signature temporary file. The next start with no fault loads the
// new bundle.
func TestTU23RollForwardRenameFails(t *testing.T) {
	f := newFetched(t)
	f.crashAfterFirstRename()
	cbnd, sig := f.bytesOf("bundle/current.cbnd"), f.bytesOf("bundle/current.sig")
	failRenameTo(t, "current.sig")
	l := f.loader("bundle/current.cbnd")
	p := f.observe(l)
	if b, err := l.Load(true); b != nil || err != ErrInstallFault || l.Current() != nil {
		t.Fatalf("got %v, %v", b, err)
	}
	if evs, _ := p.take(t); len(evs) != 0 {
		t.Errorf("events %v", evs)
	}
	if lines := logLines(t, p.buf.String()); len(lines) != 1 || lines[0]["msg"] != "bundle install fault" {
		t.Errorf("log: %q", p.buf.String())
	}
	if got := f.snap(); got != "cbnd=new-arch sig=old-sig ctmp=none stmp=new-sig state="+ver(2) {
		t.Errorf("after: %s", got)
	}
	if !bytes.Equal(f.bytesOf("bundle/current.cbnd"), cbnd) || !bytes.Equal(f.bytesOf("bundle/current.sig"), sig) {
		t.Error("the pair changed")
	}
	f.startLoads(ver(3))
}

// startLoads runs a start load with a new loader and no fault. It expects the
// bundle with this version, and the new pair on disk.
func (f *fetched) startLoads(version string) {
	f.t.Helper()
	beforeRename = nil
	b, err := f.loader("bundle/current.cbnd").Load(true)
	if err != nil || b.Manifest().Version != version {
		f.t.Fatalf("next start: %v, %v", b, err)
	}
	if got := f.snap(); got != "cbnd=new-arch sig=new-sig ctmp=none stmp=none state="+version {
		f.t.Errorf("after the next start: %s", got)
	}
}

// T-U-23: a roll-forward whose later step fails leaves a pair that the next
// start loads. An expired bundle stops before the rename, so the temporary
// signature file stays. The record write, the chain check and the version-state
// write come after the rename. The file is then the signature file. The next
// start with no fault loads the new bundle.
func TestTU23RollForwardLaterStepFails(t *testing.T) {
	const renamed = "cbnd=new-arch sig=new-sig ctmp=none stmp=none state="
	const kept = "cbnd=new-arch sig=old-sig ctmp=none stmp=new-sig state="
	blocked := func(name string) func(f *fetched, l *Loader) func() {
		return func(f *fetched, l *Loader) func() {
			dir := filepath.Join(f.state, "bundle", name+".tmp")
			must(f.t, os.MkdirAll(filepath.Join(dir, "x"), 0o700))
			return func() { must(f.t, os.RemoveAll(dir)) }
		}
	}
	cases := []struct {
		name       string
		transition bool
		fault      func(f *fetched, l *Loader) func()
		want       error
		after      string
	}{
		{"record write", true, blocked(recordName(1, "cbnd")), ErrStateFault, renamed},
		{"chain check", true, func(_ *fetched, l *Loader) func() {
			calls := 0
			l.decompress = func(b []byte) (*Archive, error) {
				if calls++; calls > 1 {
					return nil, ErrArchiveInvalid
				}
				return ReadArchive(b)
			}
			return func() {}
		}, ErrStateFault, renamed},
		{"version-state write", false, blocked(StateName), ErrStateFault, renamed},
		{"expired bundle", false, func(_ *fetched, l *Loader) func() {
			l.now = func() time.Time { return testNow.AddDate(2, 0, 0) }
			return func() {}
		}, ErrBadSig, kept},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mk := newFetched
			if c.transition {
				mk = transitionFetched
			}
			f := mk(t)
			f.crashAfterFirstRename()
			l := f.loader("bundle/current.cbnd")
			undo := c.fault(f, l)
			if b, err := l.Load(true); b != nil || err != c.want {
				t.Fatalf("got %v, %v; want %v", b, err, c.want)
			}
			if got := f.snap(); got != c.after+ver(2) {
				t.Errorf("after: %s", got)
			}
			undo()
			f.startLoads(ver(3))
		})
	}
}

// T-U-23: after a failed rename of the signature file, the next fetched bundle
// first renames the kept file. Then it writes its own two files. When that
// first rename fails, the install writes nothing and the file stays. When the
// install fails before its archive rename, the next start loads the first
// bundle.
func TestTU23SecondInstallRenamesKeptFile(t *testing.T) {
	second := func(t *testing.T) *fetched {
		f := newFetched(t)
		f.crashAfterFirstRename()
		// The first pair is now "old" for snap, and the second pair is "new".
		f.oldArch, f.oldSig = f.arch, f.sig
		f.arch = build(ent{name: "manifest.json", data: []byte(mf(ver(4)))})
		f.sig = f.sign(f.arch)
		return f
	}
	t.Run("renames first", func(t *testing.T) {
		f := second(t)
		var seen []string
		beforeRename = func(from, to string) error {
			seen = append(seen, from+">"+to+" "+f.snap())
			return nil
		}
		t.Cleanup(func() { beforeRename = nil })
		_, err := f.l.LoadFetched(f.arch, f.sig)
		must(t, err)
		want := []string{
			"current.sig.tmp>current.sig cbnd=old-arch sig=other ctmp=none stmp=old-sig state=" + ver(2),
			"current.cbnd.tmp>current.cbnd cbnd=old-arch sig=old-sig ctmp=new-arch stmp=new-sig state=" + ver(2),
			"current.sig.tmp>current.sig cbnd=new-arch sig=old-sig ctmp=none stmp=new-sig state=" + ver(2),
		}
		if strings.Join(seen, "\n") != strings.Join(want, "\n") {
			t.Errorf("order:\n%s", strings.Join(seen, "\n"))
		}
		if got := f.snap(); got != "cbnd=new-arch sig=new-sig ctmp=none stmp=none state="+ver(4) {
			t.Errorf("after: %s", got)
		}
		// The rename cleared the mark. The next install renames no kept file.
		seen = nil
		arch := build(ent{name: "manifest.json", data: []byte(mf(ver(5)))})
		if _, err := f.l.LoadFetched(arch, f.sign(arch)); err != nil || len(seen) != 2 {
			t.Errorf("third install: %v, renames %v", err, seen)
		}
	})
	for _, dst := range []string{"current.sig", "current.cbnd"} {
		t.Run("fails at "+dst, func(t *testing.T) {
			f := second(t)
			failRenameTo(t, dst)
			before := f.files()
			if b, err := f.l.LoadFetched(f.arch, f.sig); b != nil || err != ErrInstallFault {
				t.Fatalf("got %v, %v", b, err)
			}
			if dst == "current.sig" {
				if f.files() != before {
					t.Error("the install wrote a file")
				}
				beforeRename = nil
				if _, err := f.l.LoadFetched(f.arch, f.sig); err != nil {
					t.Errorf("install after the fault: %v", err)
				}
				return
			}
			if got := f.snap(); got != "cbnd=old-arch sig=old-sig ctmp=new-arch stmp=new-sig state="+ver(2) {
				t.Errorf("after: %s", got)
			}
			// The pair of the first install is the "new" pair again.
			f.arch, f.sig, f.oldArch, f.oldSig = f.oldArch, f.oldSig, nil, nil
			f.startLoads(ver(3))
		})
	}
}

// T-U-23: a start with <name>.cbnd and no <name>.sig rolls forward with
// <name>.sig.tmp. Another archive_invalid gives no roll-forward, and the start
// removes the temporary file.
func TestTU23StartWithoutSignatureFile(t *testing.T) {
	cases := map[string]func(f *fetched){
		"no signature file": func(f *fetched) { must(f.t, os.Remove(filepath.Join(f.state, "bundle/current.sig"))) },
		"signature file refused": func(f *fetched) {
			must(f.t, os.Chmod(filepath.Join(f.state, "bundle/current.sig"), 0o644))
		},
		"no archive": func(f *fetched) { must(f.t, os.Remove(filepath.Join(f.state, "bundle/current.cbnd"))) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFetched(t)
			f.write("bundle/current.cbnd", f.arch)
			f.write("bundle/current.sig.tmp", f.sig)
			setup(f)
			b, err := f.loader("bundle/current.cbnd").Load(true)
			if name == "no signature file" {
				if err != nil || b.Manifest().Version != ver(3) {
					t.Fatalf("got %v, %v", b, err)
				}
				return
			}
			if b != nil || err != ErrArchiveInvalid || strings.Contains(f.snap(), "stmp=new-sig") {
				t.Errorf("got %v, %v, %s", b, err, f.snap())
			}
		})
	}
}

// T-U-23: some start loads stop at the directory part, the state-file name or
// the chain check. They remove no temporary file.
func TestTU23StartStopsKeepTemps(t *testing.T) {
	f := newFetched(t)
	must(t, os.Symlink(filepath.Join(f.state, "bundle"), filepath.Join(f.state, "link")))
	arch := f.bytesOf("bundle/current.cbnd")
	f.record(1, arch, string(f.bytesOf("bundle/current.sig"))+lineOf(newKey(9, "kx"), arch))
	for _, c := range []struct {
		path string
		want error
	}{{"link/current.cbnd", ErrArchiveInvalid}, {"bundle/rotation-2.cbnd", ErrArchiveInvalid}, {"bundle/current.cbnd", ErrStateFault}} {
		for _, n := range []string{"current", "rotation-2"} {
			f.write("bundle/"+n+".cbnd.tmp", []byte("x"))
			f.write("bundle/"+n+".sig.tmp", []byte("y"))
		}
		before := dirListing(t, f.state)
		if b, err := f.loader(c.path).Load(true); b != nil || err != c.want {
			t.Errorf("%s: got %v, %v", c.path, b, err)
		}
		if dirListing(t, f.state) != before {
			t.Errorf("%s: a file changed", c.path)
		}
	}
}

// T-U-23: a roll-forward whose version-state write fails gives ErrStateFault,
// one log line and no event. The test puts a directory with a file in it at
// the temporary name of the version state.
func TestTU23RollForwardStateFault(t *testing.T) {
	f := newFetched(t)
	f.crashAfterFirstRename()
	must(t, os.MkdirAll(filepath.Join(f.state, "bundle", StateName+".tmp", "x"), 0o700))
	l := f.loader("bundle/current.cbnd")
	p := f.observe(l)
	if b, err := l.Load(true); b != nil || err != ErrStateFault || l.Current() != nil {
		t.Fatalf("got %v, %v", b, err)
	}
	if evs, _ := p.take(t); len(evs) != 0 {
		t.Errorf("events %v", evs)
	}
	if lines := logLines(t, p.buf.String()); len(lines) != 1 || lines[0]["msg"] != "bundle state fault" {
		t.Errorf("log: %q", p.buf.String())
	}
}

// T-U-23: only a start load rolls forward. A reload of the same files gives
// bad_sig and keeps the temporary file.
func TestTU23ReloadNoRollForward(t *testing.T) {
	f := newFetched(t)
	f.write("bundle/current.cbnd", f.arch)
	f.write("bundle/current.sig.tmp", f.sig)
	before := f.files()
	if b, err := f.loader("bundle/current.cbnd").Load(false); b != nil || err != ErrBadSig {
		t.Fatalf("got %v, %v", b, err)
	}
	if f.files() != before {
		t.Error("a file changed")
	}
}

// failRenameTo makes each rename to dst fail until the test ends.
func failRenameTo(t *testing.T, dst string) {
	t.Helper()
	beforeRename = func(_, to string) error {
		if to == dst {
			return errInjected
		}
		return nil
	}
	t.Cleanup(func() { beforeRename = nil })
}

// crashAfterFirstRename makes the second rename of the install fail. The files
// then look like the files after a crash between the two renames.
func (f *fetched) crashAfterFirstRename() {
	f.t.Helper()
	failRenameTo(f.t, "current.sig")
	if b, err := f.l.LoadFetched(f.arch, f.sig); b != nil || err != ErrInstallFault {
		f.t.Fatalf("got %v, %v", b, err)
	}
	beforeRename = nil
}

// T-U-23: a failed write gives ErrInstallFault, no event and one fixed log
// line. The running bundle and the version state stay. A failure before the
// first rename leaves the files as they were. A failure at or after it keeps
// the files.
func TestTU23FetchedWriteFails(t *testing.T) {
	temp := func(call int, step string) func(f *fetched) {
		return func(*fetched) {
			n := 0
			wrapTemp = func(w *os.File) tempFile {
				n++
				if n == call {
					return faultyTemp{w, step}
				}
				return faultyTemp{w, "none"}
			}
		}
	}
	rename := func(dst string) func(f *fetched) {
		return func(f *fetched) { failRenameTo(f.t, dst) }
	}
	kept := " state=" + ver(2)
	cases := []struct {
		name  string
		setup func(f *fetched)
		after string // empty: the listing of the directory does not change
	}{
		{"create", func(f *fetched) { must(f.t, os.MkdirAll(filepath.Join(f.state, "bundle/current.cbnd.tmp/x"), 0o700)) }, ""},
		{"archive write", temp(1, "write"), ""}, {"archive sync", temp(1, "sync"), ""}, {"archive close", temp(1, "close"), ""},
		{"sig write", temp(2, "write"), ""}, {"sig sync", temp(2, "sync"), ""}, {"sig close", temp(2, "close"), ""},
		{"first rename", rename("current.cbnd"), "cbnd=old-arch sig=old-sig ctmp=new-arch stmp=new-sig" + kept},
		{"second rename", rename("current.sig"), "cbnd=new-arch sig=old-sig ctmp=none stmp=new-sig" + kept},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFetched(t)
			c.setup(f)
			t.Cleanup(func() { wrapTemp, beforeRename = nil, nil })
			before, run := f.files(), f.l.Current()
			b, err := f.l.LoadFetched(f.arch, f.sig)
			if code, ok := CodeOf(err); b != nil || err != ErrInstallFault || ok || code != 0 || err.Error() != "bundle: install fault" {
				t.Fatalf("got %v, %v", b, err)
			}
			if f.l.Current() != run || f.stateVersion() != ver(2) {
				t.Error("the running bundle or the version state changed")
			}
			if c.after == "" && f.files() != before {
				t.Error("the files changed")
			}
			if c.after != "" && f.snap() != c.after {
				t.Errorf("files: %s", f.snap())
			}
			lines := logLines(t, f.p.buf.String())
			if len(lines) != 1 || lines[0]["msg"] != "bundle install fault" || strings.Contains(f.p.buf.String(), f.state) {
				t.Errorf("log: %q", f.p.buf.String())
			}
			f.events("")
		})
	}
}

// T-U-23: after a crash between the two renames, the next start loads the
// archive with the kept signature temporary file. Then it renames that file.
// It gives one event.
func TestTU23StartRollsForward(t *testing.T) {
	f := newFetched(t)
	f.crashAfterFirstRename()
	l := f.loader("bundle/current.cbnd")
	p := f.observe(l)
	b, err := l.Load(true)
	must(t, err)
	if b.Manifest().Version != ver(3) || !bytes.Equal(b.Signature(), f.sig) || l.Current() != b {
		t.Error("the new bundle does not run")
	}
	if got := f.snap(); got != "cbnd=new-arch sig=new-sig ctmp=none stmp=none state="+ver(3) {
		t.Errorf("after: %s", got)
	}
	if evs, _ := p.take(t); len(evs) != 1 || detail(t, evs[0])["source"] != "start" || evs[0].Record().Kind.String() != "bundle_load" {
		t.Errorf("events %v", evs)
	}
}

// T-U-23, T-S-20: a signature temporary file that fails the file rule or the
// signature does not load. The start load gives the first bad_sig, one event,
// and no roll-forward. It removes each install temporary file.
func TestTS20RollForwardRefusesTemp(t *testing.T) {
	plant := func(mut func(f *fetched, p string)) func(f *fetched) {
		return func(f *fetched) {
			f.write("bundle/current.sig.tmp", f.sig)
			mut(f, filepath.Join(f.state, "bundle/current.sig.tmp"))
		}
	}
	cases := map[string]func(f *fetched){
		"bad signature": func(f *fetched) { f.write("bundle/current.sig.tmp", f.oldSig) },
		"mode 0644":     plant(func(f *fetched, p string) { must(f.t, os.Chmod(p, 0o644)) }),
		"mode 0620":     plant(func(f *fetched, p string) { must(f.t, os.Chmod(p, 0o620)) }),
		"second link":   plant(func(f *fetched, p string) { must(f.t, os.Link(p, p+".l")) }),
		"over the cap":  func(f *fetched) { f.write("bundle/current.sig.tmp", make([]byte, MaxSigBytes+1)) },
		"symlink": func(f *fetched) {
			f.write("bundle/real", f.sig)
			must(f.t, os.Symlink("real", filepath.Join(f.state, "bundle/current.sig.tmp")))
		},
		"other owner": plant(func(f *fetched, p string) {
			fi, err := os.Stat(p)
			must(f.t, err)
			id, ok := safefile.Identity(fi)
			if !ok {
				f.t.Skip("this platform gives no file identity")
			}
			safefiletest.Set(f.t, safefiletest.Hooks{OtherOwner: func(o safefile.FileID) bool { return o == id }})
		}),
		"no temporary file": func(*fetched) {},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFetched(t)
			f.write("bundle/current.cbnd", f.arch)
			f.write("bundle/current.cbnd.tmp", f.arch)
			setup(f)
			l := f.loader("bundle/current.cbnd")
			p := f.observe(l)
			if b, err := l.Load(true); b != nil || err != ErrBadSig {
				t.Fatalf("got %v, %v", b, err)
			}
			if got := f.snap(); got != "cbnd=new-arch sig=old-sig ctmp=none stmp=none state="+ver(2) {
				t.Errorf("after: %s", got)
			}
			if evs, _ := p.take(t); len(evs) != 1 || detail(t, evs[0])["reason"] != "bad_sig" {
				t.Errorf("events %v", evs)
			}
		})
	}
}

// T-U-23: a start load removes the install temporary files that it finds.
func TestTU23StartRemovesTemps(t *testing.T) {
	f := newFetched(t)
	f.write("bundle/current.cbnd.tmp", []byte("x"))
	f.write("bundle/current.sig.tmp", []byte("y"))
	b, err := f.loader("bundle/current.cbnd").Load(true)
	must(t, err)
	if !bytes.Equal(b.Signature(), f.oldSig) {
		t.Error("a start load keeps no signature file")
	}
	if got := f.snap(); got != "cbnd=old-arch sig=old-sig ctmp=none stmp=none state="+ver(2) {
		t.Errorf("after: %s", got)
	}
}

// T-U-23: a fetched archive with the SHA-256 of the running bundle loads
// nothing. There is no wait for the swap gap, no write and no event.
func TestTU23FetchedUnchanged(t *testing.T) {
	f := newFetched(t)
	waits := 0
	f.l.sleep = func(d time.Duration) {
		waits++
		f.l.swapMu.Lock()
		f.l.swapAt = testNow.Add(-swapGap)
		f.l.swapMu.Unlock()
	}
	f.l.swapMu.Lock()
	f.l.swapAt = testNow
	f.l.swapMu.Unlock()
	before := dirListing(t, f.state)
	for _, sig := range [][]byte{f.oldSig, []byte("other")} {
		if b, err := f.l.LoadFetched(f.oldArch, sig); b != nil || err != nil {
			t.Fatalf("got %v, %v", b, err)
		}
	}
	if waits != 0 || dirListing(t, f.state) != before {
		t.Errorf("waits %d, or a file changed", waits)
	}
	f.events("")
	if _, err := f.l.LoadFetched(f.arch, f.sig); err != nil || waits != 1 {
		t.Errorf("a changed bundle: %v, waits %d", err, waits)
	}
}
