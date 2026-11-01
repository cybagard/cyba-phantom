package bundle

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"html/template"
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

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, state: t.TempDir()}
	for _, d := range []string{"bundle", "keys", "tlog"} {
		must(t, os.Mkdir(filepath.Join(e.state, d), 0o700))
	}
	var err error
	e.root, err = os.OpenRoot(e.state)
	must(t, err)
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
	l := NewLoader(e.root, path, e.trust, nil)
	// These archives hold no seed file. seedLoader runs the seed step.
	l.seed = nil
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
	must(e.t, os.WriteFile(filepath.Join(e.state, rel), b, 0o600))
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
	_, err := e.l.Load(false)
	must(t, err)
	return e
}

// dirListing gives the name, size, mode, mtime and content hash of each entry.
func dirListing(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	must(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, _ := d.Info()
		b, _ := os.ReadFile(p)
		fmt.Fprintf(&sb, "%s %d %v %d %x\n", p, fi.Size(), fi.Mode(), fi.ModTime().UnixNano(), sha256.Sum256(b))
		return nil
	}))
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

// stubParse is a template step that fails.
func stubParse(*Archive) (map[string]*template.Template, error) {
	return nil, errors.New("stub")
}

// T-U-08: each code is a fixed error, and nothing on disk or in memory changes.
// When two checks fail, the first check of the order gives the code.
func TestTU08RejectionCodes(t *testing.T) {
	put := func(m string) func(e *env) { return func(e *env) { e.install("bundle/current", m) } }
	badSig := func(arch []byte) func(e *env) {
		return func(e *env) {
			e.write("bundle/current.cbnd", arch)
			e.write("bundle/current.sig", []byte(sigRow("k1", make([]byte, 64))))
		}
	}
	fault := func(f func(dir string) error) func(e *env) {
		return func(e *env) {
			put(mf(ver(3)))(e)
			must(e.t, f(filepath.Join(e.state, "bundle")))
		}
	}
	// viaRotation makes a bundle of key k3 with a rotation member from k1. The
	// signature file has the line of k3, and with both set, the line of k1. The
	// line of k3 comes from the key that signs.
	viaRotation := func(both bool, signs func(e *env) ed25519.PrivateKey) func(e *env) {
		return func(e *env) {
			k1, k3 := e.keys()[0], newKey(3, "k3")
			arch := transition(k1, k3, ver(3))
			lines := []string{sigRow("k3", ed25519.Sign(signs(e), SigMessage(arch)))}
			if both {
				lines = append([]string{lineOf(k1, arch)}, lines...)
			}
			e.put(arch, lines...)
		}
	}
	k3Signs := func(*env) ed25519.PrivateKey { return newKey(3, "k3").priv }
	k2Signs := func(e *env) ed25519.PrivateKey { return e.priv2 }
	cases := []struct {
		name  string
		setup func(e *env)
		want  error
		code  Code
	}{
		{"archive_invalid", func(e *env) {
			e.write("bundle/current.cbnd", []byte("not gzip"))
			e.write("bundle/current.sig", e.sign([]byte("not gzip")))
		}, ErrArchiveInvalid, CodeArchiveInvalid},
		{"bad_sig", badSig(build(ent{name: "manifest.json", data: []byte(mf(ver(3)))})), ErrBadSig, CodeBadSig},
		{"bad_sig, bomb", badSig(gz(zeros(16 << 20))), ErrBadSig, CodeBadSig},
		{"bad_sig, not a tar", badSig(gz([]byte("not a tar"))), ErrBadSig, CodeBadSig},
		{"manifest_invalid", put("{}"), ErrManifestInvalid, CodeManifestInvalid},
		{"min_engine", put(mf(ver(3), engineRepl...)), ErrMinEngine, CodeMinEngine},
		{"expired", put(mf(ver(3), expiredRepl...)), ErrExpired, CodeExpired},
		{"rollback", put(mf(ver(1))), ErrRollback, CodeRollback},
		{"rollback, reference key", func(e *env) {
			arch := build(ent{name: "manifest.json", data: []byte(mf(ver(3), `"k1"`, `"k2"`))})
			e.write("bundle/current.cbnd", arch)
			e.write("bundle/current.sig", []byte(sigRow("k2", ed25519.Sign(e.priv2, SigMessage(arch)))))
		}, ErrRollback, CodeRollback},
		{"template_parse", func(e *env) {
			put(mf(ver(3)))(e)
			e.l.template = stubParse
		}, ErrTemplateParse, CodeTemplateParse},
		{"state fault", fault(func(d string) error { return os.Chmod(filepath.Join(d, StateName), 0o644) }), ErrStateFault, 0},
		{"state write fails", fault(func(d string) error { return os.MkdirAll(filepath.Join(d, stateTempName, "x"), 0o700) }), ErrStateFault, 0},
		{"key_id and min_engine", put(mf(ver(3), append([]string{`"k1"`, `"k2"`}, engineRepl...)...)), ErrBadSig, CodeBadSig},
		{"min_engine and expired", put(mf(ver(3), append(engineRepl, expiredRepl...)...)), ErrMinEngine, CodeMinEngine},
		{"expired and rollback", put(mf(ver(1), expiredRepl...)), ErrExpired, CodeExpired},
		{"rollback and template_parse", func(e *env) {
			put(mf(ver(1)))(e)
			e.l.template = stubParse
		}, ErrRollback, CodeRollback},
		{"rollback and a bad template, real parse", func(e *env) {
			arch := build(ent{name: "manifest.json", data: []byte(mf(ver(1)))}, ent{name: vhostFile, data: []byte("{{if}}")})
			e.write("bundle/current.cbnd", arch)
			e.write("bundle/current.sig", e.sign(arch))
		}, ErrRollback, CodeRollback},
		{"rotation, new key line only", viaRotation(false, k3Signs), ErrBadSig, CodeBadSig},
		{"rotation, new key line of another key", viaRotation(true, k2Signs), ErrBadSig, CodeBadSig},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			c.setup(e)
			if n := e.rejects(e.l, false, c.want); n != 0 && strings.HasPrefix(c.name, "bad_sig") {
				t.Errorf("%d decompress calls", n)
			}
			if code, ok := CodeOf(c.want); code != c.code || ok != (c.code != 0) {
				t.Errorf("code %v, %v", code, ok)
			}
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
	}{{"current.cbnd", 8 << 20}, {"current.sig", 1 << 10}} {
		for _, v := range variants {
			t.Run(f.name+" "+v.name, func(t *testing.T) {
				e := running(t)
				must(t, v.fn(filepath.Join(e.state, "bundle", f.name), f.max))
				if n := e.rejects(e.l, false, ErrArchiveInvalid); n != 0 {
					t.Errorf("%d decompress calls", n)
				}
			})
		}
	}
}

// T-S-20: a file of another owner is refused. The hook marks one inode as
// owned by another user, so it runs as any user. The chown case needs root.
func TestTS20OtherOwnerIsRefused(t *testing.T) {
	for _, name := range []string{"current.cbnd", "current.sig"} {
		t.Run("hook "+name, func(t *testing.T) {
			e := running(t)
			fi, err := os.Stat(filepath.Join(e.state, "bundle", name))
			must(t, err)
			id, _ := safefile.Identity(fi)
			safefiletest.Set(t, safefiletest.Hooks{OtherOwner: func(o safefile.FileID) bool { return o == id }})
			if n := e.rejects(e.l, false, ErrArchiveInvalid); n != 0 {
				t.Errorf("%d decompress calls", n)
			}
		})
		t.Run("chown "+name, func(t *testing.T) {
			if os.Geteuid() != 0 {
				t.Skip("the test must run as root to change the owner of a file")
			}
			e := running(t)
			must(t, os.Chown(filepath.Join(e.state, "bundle", name), 12345, -1))
			if n := e.rejects(e.l, false, ErrArchiveInvalid); n != 0 {
				t.Errorf("%d decompress calls", n)
			}
		})
	}
}

// T-S-20: a file at the cap passes the read step. The bundle file then fails
// in the archive step. The signature file fails in the signature step.
func TestTS20FilesAtTheCap(t *testing.T) {
	for _, c := range []struct {
		name  string
		size  int
		want  error
		calls int32
	}{{"current.cbnd", 8 << 20, ErrArchiveInvalid, 1}, {"current.sig", 1 << 10, ErrBadSig, 0}} {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			b := zeros(c.size)
			e.write("bundle/"+c.name, b)
			if c.name == "current.cbnd" {
				e.write("bundle/current.sig", e.sign(b))
			}
			if n := e.rejects(e.l, false, c.want); n != c.calls {
				t.Errorf("%d decompress calls; want %d", n, c.calls)
			}
		})
	}
}

// T-S-20: a file with a mode that the rule permits loads.
func TestTS20PermittedModesLoad(t *testing.T) {
	for _, name := range []string{"current.cbnd", "current.sig"} {
		for _, m := range []os.FileMode{0o640, 0o400, 0o601} {
			t.Run(fmt.Sprintf("%s mode %o", name, m), func(t *testing.T) {
				e := newEnv(t)
				e.install("bundle/current", mf(ver(1)))
				must(t, os.Chmod(filepath.Join(e.state, "bundle", name), m))
				_, err := e.l.Load(false)
				must(t, err)
			})
		}
	}
}

// T-S-20: a path that is not a relative path to a named .cbnd file is
// refused. A signed bundle and signature file are behind it.
func TestTS20PathFormsAreRefused(t *testing.T) {
	e := running(t)
	arch := build(ent{name: "manifest.json", data: []byte(mf(ver(3)))})
	for _, c := range [][2]string{
		{"bundle/x.bin", "bundle/x.bin.sig"},
		{"bundle/.cbnd", "bundle/.sig"},
		{"/bundle/current.cbnd", "/bundle/current.sig"},
	} {
		e.write(c[0], arch)
		e.write(c[1], e.sign(arch))
		if n := e.rejects(e.loader(c[0]), false, ErrArchiveInvalid); n != 0 {
			t.Errorf("%s: %d decompress calls", c[0], n)
		}
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
		must(t, os.Symlink(c[1], filepath.Join(e.state, c[0])))
		if n := e.rejects(e.loader(c[2]), false, ErrArchiveInvalid); n != 0 {
			t.Errorf("%s: %d decompress calls", c[2], n)
		}
	}
}

// T-S-20: a file that changes after the read does not change the bundle.
func TestTS20FileChangedAfterRead(t *testing.T) {
	e := newEnv(t)
	sum := e.install("bundle/current", mf(ver(1)))
	e.l.afterRead = func() { e.install("bundle/current", mf(ver(2))) }
	b, err := e.l.Load(false)
	must(t, err)
	if b.SHA256() != sum || b.Manifest().Version != ver(1) || e.l.Current() != b {
		t.Errorf("accepted %x version %s", b.SHA256(), b.Manifest().Version)
	}
}

// T-S-20: a signed bundle at the cap with many empty gzip members loads. The
// test logs its wall time.
func TestTS20ManyGzipMembers(t *testing.T) {
	e := newEnv(t)
	first, empty := build(ent{name: "manifest.json", data: []byte(mf(ver(1)))}), gz(nil)
	arch := append(first, bytes.Repeat(empty, (8<<20-len(first))/len(empty)-1)...)
	// The last member has a header comment that pads the file to the cap.
	var last bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&last, gzip.BestSpeed)
	zw.Comment = strings.Repeat("a", 8<<20-len(arch)-len(empty)-1)
	must(t, zw.Close())
	arch = append(arch, last.Bytes()...)
	if len(arch) != 8<<20 {
		t.Fatalf("file of %d bytes", len(arch))
	}
	e.write("bundle/current.cbnd", arch)
	e.write("bundle/current.sig", e.sign(arch))
	begin := time.Now()
	_, err := e.l.Load(false)
	t.Logf("wall time %v for %d bytes", time.Since(begin), len(arch))
	must(t, err)
}

// T-S-20: at start, the accepted bundle loads after its expiry and says so.
// A new expired bundle, and a load not at start, give expired.
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
	sums := map[string][32]byte{}
	for i := 1; i <= gens; i++ {
		sums[ver(i)] = e.install(fmt.Sprintf("bundle/g%d", i), mf(ver(i)))
	}
	e.l = e.loader("bundle/g1.cbnd")
	_, err := e.l.Load(false)
	must(t, err)
	var stop atomic.Bool
	var ready, done sync.WaitGroup
	for range 4 {
		ready.Add(1)
		done.Go(func() {
			for first := true; first || !stop.Load(); first = false {
				b := e.l.Current()
				v := b.Manifest().Version
				raw, _ := b.File("manifest.json")
				if b.SHA256() != sums[v] || string(raw) != mf(v) {
					t.Errorf("mixed bundle: version %s", b.Manifest().Version)
				}
				if first {
					ready.Done()
				}
			}
		})
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

// T-U-08: two loads never run together. Loaders for rising versions load at
// once, and the version state holds the highest version.
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
		wg.Go(func() {
			<-start
			_, errs[i] = l.Load(false)
		})
	}
	close(start)
	wg.Wait()
	dir, err := e.root.OpenRoot("bundle")
	must(t, err)
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
