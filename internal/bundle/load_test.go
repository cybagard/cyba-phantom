package bundle

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

// env is a state directory with a bundle directory and a loader for the test
// key. n counts the calls of the decompress step.
type env struct {
	t     *testing.T
	state string
	root  *os.Root
	priv  ed25519.PrivateKey // key k1, proprietary
	priv2 ed25519.PrivateKey // key k2, reference
	trust TrustSet
	l     *Loader
	n     atomic.Int32
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, state: t.TempDir()}
	for _, d := range []string{"bundle", "keys", "tlog"} {
		if err := os.Mkdir(filepath.Join(e.state, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	if e.root, err = os.OpenRoot(e.state); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.root.Close() })
	var tk, ref TrustKey
	e.priv, tk = testKey(1, "k1")
	e.priv2, ref = testKey(2, "k2")
	ref.Class = ClassReference
	e.trust = TrustSet{tk, ref}
	e.l = e.loader("bundle/current.cbnd")
	return e
}

func (e *env) loader(path string) *Loader {
	l := NewLoader(e.root, path, e.trust)
	l.now = func() time.Time { return testNow }
	l.decompress = func(b []byte) (*Archive, error) { e.n.Add(1); return ReadArchive(b) }
	return l
}

// mf gives a manifest of the given version. repl is pairs of old and new text.
func mf(version string, repl ...string) string {
	return strings.NewReplacer(repl...).Replace(with("version", q(version)))
}

func ver(n int) string { return fmt.Sprintf("2026.09.19-%d", n) }

var (
	expiredRepl = []string{"2027-09-19T00:00:00Z", "2026-09-20T00:00:00Z"}
	engineRepl  = []string{`"1.0.0"`, `"9.0.0"`}
)

func (e *env) sign(arch []byte) []byte {
	return []byte(sigRow("k1", ed25519.Sign(e.priv, SigMessage(arch))))
}

func (e *env) write(rel string, b []byte) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.state, rel), b, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// install writes a signed bundle with this manifest as rel.cbnd and rel.sig.
func (e *env) install(rel, manifest string) [32]byte {
	e.t.Helper()
	arch := build(ent{name: "manifest.json", data: []byte(manifest)})
	e.write(rel+".cbnd", arch)
	e.write(rel+".sig", e.sign(arch))
	return sha256.Sum256(arch)
}

// running gives an env whose loader runs the bundle of version 2.
func running(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.install("bundle/current", mf(ver(2)))
	if _, err := e.l.Load(false); err != nil {
		t.Fatal(err)
	}
	return e
}

// dirListing gives the name, size, mode, mtime and content hash of each entry.
func dirListing(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(&sb, "%s %d %v %d", p, fi.Size(), fi.Mode(), fi.ModTime().UnixNano())
		if fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			fmt.Fprintf(&sb, " %x", sha256.Sum256(b))
		}
		sb.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

// rejects loads and expects the error want. The running bundle and the files
// do not change. It returns the number of decompress calls of the load.
func (e *env) rejects(l *Loader, start bool, want error) int32 {
	e.t.Helper()
	before, run, n := dirListing(e.t, e.state), l.Current(), e.n.Load()
	b, err := l.Load(start)
	if err != want || b != nil {
		e.t.Fatalf("got %v, %v; want %v", b, err, want)
	}
	if l.Current() != run || dirListing(e.t, e.state) != before {
		e.t.Error("the running bundle or the files changed")
	}
	return e.n.Load() - n
}

// T-U-08: each code that the load path gives. The error is a fixed value, and
// the running bundle, the directory and the version state do not change.
func TestTU08RejectionCodes(t *testing.T) {
	bad := func(e *env, arch, sig []byte) {
		e.write("bundle/current.cbnd", arch)
		e.write("bundle/current.sig", sig)
	}
	cases := []struct {
		name  string
		setup func(e *env)
		want  error
		code  Code
	}{
		{"archive_invalid", func(e *env) { bad(e, []byte("not gzip"), e.sign([]byte("not gzip"))) }, ErrArchiveInvalid, CodeArchiveInvalid},
		{"bad_sig", func(e *env) {
			e.install("bundle/current", mf(ver(3)))
			e.write("bundle/current.sig", []byte(sigRow("k1", make([]byte, 64))))
		}, ErrBadSig, CodeBadSig},
		{"manifest_invalid", func(e *env) { e.install("bundle/current", "{}") }, ErrManifestInvalid, CodeManifestInvalid},
		{"min_engine", func(e *env) { e.install("bundle/current", mf(ver(3), engineRepl...)) }, ErrMinEngine, CodeMinEngine},
		{"expired", func(e *env) { e.install("bundle/current", mf(ver(3), expiredRepl...)) }, ErrExpired, CodeExpired},
		{"rollback", func(e *env) { e.install("bundle/current", mf(ver(1))) }, ErrRollback, CodeRollback},
		{"rollback, reference key", func(e *env) {
			arch := build(ent{name: "manifest.json", data: []byte(mf(ver(3), `"k1"`, `"k2"`))})
			bad(e, arch, []byte(sigRow("k2", ed25519.Sign(e.priv2, SigMessage(arch)))))
		}, ErrRollback, CodeRollback},
		{"template_parse", func(e *env) {
			e.install("bundle/current", mf(ver(3)))
			e.l.template = func(*Archive) error { return errors.New("stub") }
		}, ErrTemplateParse, CodeTemplateParse},
		{"state fault", func(e *env) {
			e.install("bundle/current", mf(ver(3)))
			if err := os.Chmod(filepath.Join(e.state, "bundle", StateName), 0o644); err != nil {
				t.Fatal(err)
			}
		}, ErrStateFault, 0},
		{"state write fails", func(e *env) {
			e.install("bundle/current", mf(ver(3)))
			tmp := filepath.Join(e.state, "bundle", stateTempName)
			if err := os.MkdirAll(filepath.Join(tmp, "x"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, ErrStateFault, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			c.setup(e)
			e.rejects(e.l, false, c.want)
			if code, ok := CodeOf(c.want); code != c.code || ok != (c.code != 0) {
				t.Errorf("code %v, %v", code, ok)
			}
		})
	}
}

// T-U-08: when two checks fail, the first check of the order gives the code.
func TestTU08FirstFailureGivesTheCode(t *testing.T) {
	cases := []struct {
		name string
		m    string
		want error
	}{
		{"key_id and min_engine", mf(ver(3), append([]string{`"k1"`, `"k2"`}, engineRepl...)...), ErrBadSig},
		{"min_engine and expired", mf(ver(3), append(engineRepl, expiredRepl...)...), ErrMinEngine},
		{"expired and rollback", mf(ver(1), expiredRepl...), ErrExpired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			e.install("bundle/current", c.m)
			e.rejects(e.l, false, c.want)
		})
	}
}

// T-S-20: a bundle file or signature file that the file rule refuses gives
// archive_invalid. The decompress step does not run.
func TestTS20FileRules(t *testing.T) {
	type variant struct {
		name string
		fn   func(p string, max int) error
	}
	variants := []variant{
		{"symlink", func(p string, _ int) error { return errors.Join(os.Rename(p, p+".real"), os.Symlink(p+".real", p)) }},
		{"second link", func(p string, _ int) error { return os.Link(p, p+".l") }},
		{"over the cap", func(p string, max int) error { return os.WriteFile(p, make([]byte, max+1), 0o600) }},
		{"missing", func(p string, _ int) error { return os.Remove(p) }},
	}
	for _, m := range []os.FileMode{0o644, 0o664, 0o660, 0o602} {
		variants = append(variants, variant{fmt.Sprintf("mode %o", m), func(p string, _ int) error { return os.Chmod(p, m) }})
	}
	for _, f := range []struct {
		name string
		max  int
	}{{"current.cbnd", MaxBundleBytes}, {"current.sig", MaxSigBytes}} {
		for _, v := range variants {
			t.Run(f.name+" "+v.name, func(t *testing.T) {
				e := running(t)
				if err := v.fn(filepath.Join(e.state, "bundle", f.name), f.max); err != nil {
					t.Fatal(err)
				}
				if n := e.rejects(e.l, false, ErrArchiveInvalid); n != 0 {
					t.Errorf("%d decompress calls", n)
				}
			})
		}
	}
}

// T-S-20: a file of another owner is refused. The hook marks one inode as
// owned by another user, so the test runs as any user.
func TestTS20OtherOwnerIsRefusedByHook(t *testing.T) {
	for _, name := range []string{"current.cbnd", "current.sig"} {
		t.Run(name, func(t *testing.T) {
			e := running(t)
			fi, err := os.Stat(filepath.Join(e.state, "bundle", name))
			if err != nil {
				t.Fatal(err)
			}
			id, _ := safefile.Identity(fi)
			safefiletest.Set(t, safefiletest.Hooks{OtherOwner: func(o safefile.FileID) bool { return o == id }})
			e.rejects(e.l, false, ErrArchiveInvalid)
		})
	}
}

// T-S-20: a file that another user owns is refused. The test needs root.
func TestTS20OtherOwnerIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the test must run as root to change the owner of a file")
	}
	for _, name := range []string{"current.cbnd", "current.sig"} {
		e := running(t)
		if err := os.Chown(filepath.Join(e.state, "bundle", name), 12345, -1); err != nil {
			t.Fatal(err)
		}
		e.rejects(e.l, false, ErrArchiveInvalid)
	}
}

// T-S-20: a symlink at a directory part of the bundle path is refused. A valid
// bundle is behind each link, and no file below keys/ or tlog/ changes.
func TestTS20DirectoryPartsAreRefused(t *testing.T) {
	e := newEnv(t)
	for _, rel := range []string{"keys/checkpoint", "keys/x", "tlog/x"} {
		e.install(rel, mf(ver(1)))
	}
	for _, c := range [][3]string{
		{"b1", "keys", "b1/checkpoint.cbnd"},
		{"b2", "tlog", "b2/x.cbnd"},
		{"b3", "../" + filepath.Base(e.state) + "/keys", "b3/x.cbnd"},
		{"bundle/sub", "../keys", "bundle/sub/x.cbnd"},
	} {
		if err := os.Symlink(c[1], filepath.Join(e.state, c[0])); err != nil {
			t.Fatal(err)
		}
		if n := e.rejects(e.loader(c[2]), false, ErrArchiveInvalid); n != 0 {
			t.Errorf("%s: %d decompress calls", c[2], n)
		}
	}
}

// T-S-20: a bad signature is checked before the decompress step. A gzip bomb
// and a gzip stream that is not a tar give bad_sig, and nothing decompresses.
func TestTS20BadSigBeforeDecompress(t *testing.T) {
	for name, arch := range map[string][]byte{"bomb": gz(zeros(16 << 20)), "not a tar": gz([]byte("not a tar"))} {
		t.Run(name, func(t *testing.T) {
			e := running(t)
			e.write("bundle/current.cbnd", arch)
			e.write("bundle/current.sig", []byte(sigRow("k1", make([]byte, 64))))
			if n := e.rejects(e.l, false, ErrBadSig); n != 0 {
				t.Errorf("%d decompress calls", n)
			}
		})
	}
}

// T-S-20: a file that changes after the read does not change the bundle. The
// accepted bundle is the one that the loader read.
func TestTS20FileChangedAfterRead(t *testing.T) {
	e := newEnv(t)
	sum := e.install("bundle/current", mf(ver(1)))
	e.l.afterRead = func() { e.install("bundle/current", mf(ver(2))) }
	b, err := e.l.Load(false)
	if err != nil {
		t.Fatal(err)
	}
	if b.SHA256() != sum || b.Manifest().Version != ver(1) || e.l.Current() != b {
		t.Errorf("accepted %x version %s", b.SHA256(), b.Manifest().Version)
	}
}

// T-S-20: a signed bundle file at the cap that holds many empty gzip members
// loads with one result. The test logs its wall time.
func TestTS20ManyGzipMembers(t *testing.T) {
	e := newEnv(t)
	first := build(ent{name: "manifest.json", data: []byte(mf(ver(1)))})
	var empty bytes.Buffer
	if err := gzip.NewWriter(&empty).Close(); err != nil {
		t.Fatal(err)
	}
	arch := append(first, bytes.Repeat(empty.Bytes(), (MaxBundleBytes-len(first))/empty.Len())...)
	e.write("bundle/current.cbnd", arch)
	e.write("bundle/current.sig", e.sign(arch))
	begin := time.Now()
	_, err := e.l.Load(false)
	t.Logf("wall time %v for %d bytes", time.Since(begin), len(arch))
	if err != nil {
		t.Errorf("got %v", err)
	}
}

// T-S-20: at start, the accepted bundle loads after its expiry time and the
// result says so. Another expired bundle, and a load that is not at start,
// give expired.
func TestTS20ExpiredBundleAtStart(t *testing.T) {
	e := running(t)
	e.l.now = func() time.Time { return testNow.AddDate(2, 0, 0) }
	if b, err := e.l.Load(true); err != nil || !b.Expired() {
		t.Fatalf("start: %v, %v", b, err)
	}
	e.rejects(e.l, false, ErrExpired)
	e.install("bundle/current", mf(ver(3)))
	e.rejects(e.l, true, ErrExpired)
}

// T-U-08: readers in other goroutines see a whole bundle while loads swap the
// running bundle. The SHA-256, manifest and archive belong together.
func TestTU08ReadersSeeWholeBundles(t *testing.T) {
	e := newEnv(t)
	const gens = 8
	type want struct {
		sum      [32]byte
		manifest string
	}
	wants := map[string]want{}
	for i := 1; i <= gens; i++ {
		m := mf(ver(i))
		wants[ver(i)] = want{e.install(fmt.Sprintf("bundle/g%d", i), m), m}
	}
	e.l = e.loader("bundle/g1.cbnd")
	if _, err := e.l.Load(false); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var ready, done sync.WaitGroup
	for range 4 {
		ready.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			for first := true; first || !stop.Load(); first = false {
				b := e.l.Current()
				w := wants[b.Manifest().Version]
				raw, _ := b.File("manifest.json")
				if b.SHA256() != w.sum || string(raw) != w.manifest {
					t.Errorf("mixed bundle: version %s", b.Manifest().Version)
				}
				if first {
					ready.Done()
				}
			}
		}()
	}
	ready.Wait()
	for i := 2; i <= gens; i++ {
		e.l.path = fmt.Sprintf("bundle/g%d.cbnd", i)
		if _, err := e.l.Load(false); err != nil {
			t.Error(err)
		}
	}
	stop.Store(true)
	done.Wait()
}

// T-U-08: two loads never run together. Loaders for bundles of rising versions
// load at the same time. The version state holds the highest version.
func TestTU08LoadsAreSerialized(t *testing.T) {
	e := newEnv(t)
	const k = 6
	errs := make([]error, k)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range k {
		e.install(fmt.Sprintf("bundle/b%d", i), mf(ver(i+1)))
		l := e.loader(fmt.Sprintf("bundle/b%d.cbnd", i))
		l.afterRead = runtime.Gosched
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = l.Load(false)
		}()
	}
	close(start)
	wg.Wait()
	dir, err := e.root.OpenRoot("bundle")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	st, err := readState(dir)
	if err != nil || st.Version != ver(k) || errs[k-1] != nil {
		t.Errorf("state %v, %v; last load %v", st, err, errs[k-1])
	}
	for _, err := range errs {
		if err != nil && err != ErrRollback {
			t.Errorf("load: %v", err)
		}
	}
}
