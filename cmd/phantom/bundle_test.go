package main

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/store"
)

const bundleVersion = "2026.11.01-1"

// seedKey makes a test key in the form of the bundle package tests.
// The seed is 32 copies of one byte. No release set holds a test key.
func seedKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func pubOf(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }

// The fixed test keys of the tests of this package.
const (
	goodSeed  = 0xA5 // the key of the trust set of the tests
	wrongSeed = 0xA6 // a key that the trust set does not hold
)

var fixedTestKeys = [][32]byte{pubOf(seedKey(goodSeed)), pubOf(seedKey(wrongSeed))}

func testTrust() bundle.TrustSet {
	return bundle.TrustSet{{KeyID: "t1", PublicKey: pubOf(seedKey(goodSeed)), Class: bundle.ClassReference}}
}

type tarFile struct {
	name string
	data []byte
}

// mustOK stops the test or the benchmark on an error.
func mustOK(tb testing.TB, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatal(err)
	}
}

// archiveOf makes a bundle archive: a gzip stream of a ustar tar.
func archiveOf(tb testing.TB, files ...tarFile) []byte {
	tb.Helper()
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	tw := tar.NewWriter(zw)
	for _, f := range files {
		mustOK(tb, tw.WriteHeader(&tar.Header{Name: f.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f.data)), Format: tar.FormatUSTAR}))
		_, err := tw.Write(f.data)
		mustOK(tb, err)
	}
	mustOK(tb, tw.Close())
	mustOK(tb, zw.Close())
	return buf.Bytes()
}

// referenceFiles are the files of a valid reference bundle with a plain seed.
func referenceFiles(extra ...tarFile) []tarFile {
	stamp := func(d time.Duration) string { return time.Now().Add(d).UTC().Format("2006-01-02T15:04:05Z") }
	m := fmt.Sprintf(`{"version":%q,"min_engine":"1.0.0","created":%q,"expires":%q,"key_id":"t1"}`,
		bundleVersion, stamp(-time.Hour), stamp(24*time.Hour))
	return append([]tarFile{{"manifest.json", []byte(m)}, {"secrets/token.seed", bytes.Repeat([]byte{9}, 32)}}, extra...)
}

// bundleFile is the default bundle path below the state directory.
const bundleFile = "bundle/current.cbnd"

// putBundle writes the archive at rel below root and its signature file.
func putBundle(tb testing.TB, root, rel string, arch []byte, key ed25519.PrivateKey) {
	tb.Helper()
	sig := "t1 " + base64.StdEncoding.EncodeToString(ed25519.Sign(key, bundle.SigMessage(arch))) + "\n"
	mustOK(tb, os.MkdirAll(filepath.Join(root, filepath.Dir(rel)), 0o700))
	mustOK(tb, os.WriteFile(filepath.Join(root, rel), arch, 0o600))
	mustOK(tb, os.WriteFile(filepath.Join(root, strings.TrimSuffix(rel, ".cbnd")+".sig"), []byte(sig), 0o600))
}

// answered tells if the server at addr answers a request within a short time.
func answered(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, netWait)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(150 * time.Millisecond))
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: "+decoyName+"\r\n\r\n")
	_, err = c.Read(make([]byte, 1))
	return err == nil
}

// bundleRun is a start with the test trust set. loads counts the calls of the
// loader seam. early is true when the plain listener answered at that call.
type bundleRun struct {
	p          startParams
	loads      atomic.Int32
	early      atomic.Bool
	line, errs string // the start line, stderr
}

// startBundleRun starts serveWith with realDeps and the loader seam, waits for
// the start line, and checks that the decoys serve. path is the bundle.path
// below the state directory. prep makes the state. Then it stops serveWith,
// which needs exit 0.
func startBundleRun(t *testing.T, trust bundle.TrustSet, path string, prep func(*testing.T, startParams)) *bundleRun {
	t.Helper()
	httpsLn, plainLn, ca := openListeners(t)
	cfg := serveCfg(t, httpsLn.Addr().String(), plainLn.Addr().String(), ca, "PHANTOM_BUNDLE_PATH="+filepath.Join(stateDir, path))
	br := &bundleRun{p: tempState(t, cfg)}
	if prep != nil {
		prep(t, br.p)
	}
	oldTrust, oldNew := bundleTrust, newLoader
	t.Cleanup(func() { bundleTrust, newLoader = oldTrust, oldNew })
	bundleTrust = func() bundle.TrustSet { return trust }
	newLoader = func(s *os.Root, got string, ts bundle.TrustSet, k hpke.PrivateKey) *bundle.Loader {
		br.loads.Add(1)
		if k == nil || got != path || !reflect.DeepEqual(ts, trust) {
			t.Errorf("loader got nil install key %v, path %q, trust set %v", k == nil, got, ts)
		}
		br.early.Store(answered(plainLn.Addr().String()))
		return oldNew(s, got, ts, k)
	}
	r := launchServe(t, cfg, br.p, realDeps)
	r.waitStarted(t)
	br.line = r.out.String()
	select {
	case <-r.done:
		t.Fatalf("serve ended before the stop: exit %d, stderr %q", r.code, r.err.String())
	default:
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+plainLn.Addr().String()+"/", nil)
	req.Host = decoyName
	hc := &http.Client{Timeout: netWait, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if resp, err := hc.Do(req); err != nil || resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("redirect: %v, %v; want 308", resp, err)
	}
	r.cancel()
	<-r.done
	if br.errs = r.err.String(); r.code != 0 {
		t.Errorf("exit %d, want 0; stderr %q", r.code, br.errs)
	}
	return br
}

type bundleRow struct{ kind, detail string }

// rows returns the bundle events in the store after the stop.
func (br *bundleRun) rows(tb testing.TB) []bundleRow {
	tb.Helper()
	root, err := os.OpenRoot(br.p.Root)
	mustOK(tb, err)
	defer root.Close()
	db, err := store.Open(root, br.p.StorePath, store.Options{Reserved: br.p.Reserved})
	mustOK(tb, err)
	defer db.Close()
	q, err := db.Query("SELECT kind, detail FROM event WHERE kind IN ('bundle_load', 'bundle_rejected')")
	mustOK(tb, err)
	defer q.Close()
	var out []bundleRow
	for q.Next() {
		var r bundleRow
		mustOK(tb, q.Scan(&r.kind, &r.detail))
		out = append(out, r)
	}
	return out
}

// TestTU08_StartLoadsBundle starts serveWith in each state of the bundle
// (T-U-08, C3). A valid bundle gives one bundle_load row with the source
// start and a healthy bundle part. The load runs before the serve calls. Each
// other row serves the decoys and ends only at the stop. Its start line has
// " — bundle not healthy". A refused store, a trust set that fails Check,
// and an install key fault make no load. kind is the kind of the one bundle
// row: "" for no row, "-" for a refused store. path is the bundle.path ("" is
// the default). errLine is the one bundle line of stderr ("" is not checked).
func TestTU08_StartLoadsBundle(t *testing.T) {
	// put writes a valid bundle and, with file, one more file as [path, text].
	put := func(seed byte, file ...string) func(*testing.T, startParams) {
		return func(t *testing.T, p startParams) {
			putBundle(t, p.Root, p.BundlePath, archiveOf(t, referenceFiles()...), seedKey(seed))
			if file != nil {
				f := filepath.Join(p.Root, file[0])
				mustOK(t, os.MkdirAll(filepath.Dir(f), 0o700))
				mustOK(t, os.WriteFile(f, []byte(file[1]), 0o600))
			}
		}
	}
	k := testTrust()[0]
	for _, c := range []struct {
		name          string
		trust         bundle.TrustSet
		prep          func(*testing.T, startParams)
		loads         int32
		kind          string
		path, errLine string
	}{
		{"valid", testTrust(), put(goodSeed), 1, "bundle_load", "b2/x.cbnd", ""},
		{"no bundle", testTrust(), nil, 1, "bundle_rejected", "", ""},
		{"bad signature", testTrust(), put(wrongSeed), 1, "bundle_rejected", "", ""},
		{"state file does not parse", testTrust(), put(goodSeed, "bundle/"+bundle.StateName, "x\n"), 1, "", "", ""},
		{"state directory others can write", testTrust(), func(t *testing.T, p startParams) {
			put(goodSeed)(t, p)
			mustOK(t, os.Chmod(p.Root, 0o777))
		}, 0, "-", "", ""},
		{"trust set fails Check", bundle.TrustSet{k, k}, put(goodSeed), 0, "", "",
			`level=ERROR msg="bundle does not load: trust set is not valid"`},
		{"install key fault", testTrust(), put(goodSeed, "keys/install.pub", "x\n"), 0, "", "",
			`level=ERROR msg="bundle does not load: install key is not valid"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			br := startBundleRun(t, c.trust, cmp.Or(c.path, bundleFile), c.prep)
			// The line is exact after the time attribute (a space before it).
			if c.errLine != "" && (strings.Count(br.errs, `msg="bundle`) != 1 || !strings.Contains(br.errs, " "+c.errLine+"\n")) {
				t.Errorf("stderr %q; want the one bundle line %q", br.errs, c.errLine)
			}
			if healthy := !strings.Contains(br.line, " — bundle not healthy"); healthy != (c.kind == "bundle_load") ||
				br.loads.Load() != c.loads || br.early.Load() {
				t.Errorf("start line %q, loads %d, served before the load %v", br.line, br.loads.Load(), br.early.Load())
			}
			if _, err := os.Stat(filepath.Join(br.p.Root, "keys", "install.key")); (c.loads == 0) != os.IsNotExist(err) {
				t.Errorf("keys/install.key: %v; loads %d", err, c.loads)
			}
			if c.kind == "-" {
				return
			}
			rows := br.rows(t)
			if (c.kind == "") != (len(rows) == 0) || len(rows) > 1 || (len(rows) == 1 &&
				(rows[0].kind != c.kind || !strings.Contains(rows[0].detail, `"source":"start"`))) {
				t.Errorf("rows %v; want one %q row with source start", rows, c.kind)
			}
		})
	}
}

// TestTU08_BadBundlePathNeverLoads gives a bundle.path that the config loader
// refuses. The process ends with exit 1 and the loader seam is not called.
func TestTU08_BadBundlePathNeverLoads(t *testing.T) {
	var loads atomic.Int32
	old := newLoader
	t.Cleanup(func() { newLoader = old })
	newLoader = func(s *os.Root, path string, ts bundle.TrustSet, k hpke.PrivateKey) *bundle.Loader {
		loads.Add(1)
		return old(s, path, ts, k)
	}
	env := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32), "PHANTOM_BUNDLE_PATH=/var/lib/phantom/keys/x.cbnd"}
	var so, se strings.Builder
	if code := run([]string{writeFile(t, validBody(t))}, env, &so, &se); code != 1 || loads.Load() != 0 {
		t.Errorf("exit %d, loader calls %d, stderr %q; want 1 and 0", code, loads.Load(), se.String())
	}
}

// TestTS20_ReleaseTrustSetHasNoTestKey checks the release set against the
// test keys. The list holds the fixed test keys of this package. It also
// holds the 256 keys of the form of the bundle package tests. A set with a
// test key must fail. A set with a repeated key ID must fail. So the test
// can fail.
func TestTS20_ReleaseTrustSetHasNoTestKey(t *testing.T) {
	keys := append([][32]byte(nil), fixedTestKeys...)
	for b := range 256 {
		keys = append(keys, pubOf(seedKey(byte(b))))
	}
	if err := releaseTrust().Check(keys); err != nil {
		t.Fatalf("release trust set: %v", err)
	}
	add := func(k ...bundle.TrustKey) bundle.TrustSet { return append(releaseTrust(), k...) }
	other := bundle.TrustKey{KeyID: "dup", PublicKey: pubOf(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1, 2}, 16))), Class: bundle.ClassReference}
	again := other
	again.PublicKey = pubOf(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3, 4}, 16)))
	for name, set := range map[string]bundle.TrustSet{
		"fixed test key": add(testTrust()[0]),
		"form test key":  add(bundle.TrustKey{KeyID: "form", PublicKey: pubOf(seedKey(7)), Class: bundle.ClassReference}),
		"repeated ID":    add(other, again),
	} {
		if set.Check(keys) == nil {
			t.Errorf("%s: Check accepted the set", name)
		}
	}
}

// TestTS20_DefaultTrustIsReleaseSet checks that, without a test seam, the
// start gives the loader the release set.
func TestTS20_DefaultTrustIsReleaseSet(t *testing.T) {
	if got := bundleTrust(); !reflect.DeepEqual(got, releaseTrust()) || reflect.DeepEqual(got, testTrust()) {
		t.Errorf("default trust set %v; want the release set", got)
	}
}

// heapInUse runs a GC and gives the bytes of the heap in use.
func heapInUse() int64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return int64(ms.HeapInuse)
}

// startBoth starts the store part and the bundle part with the test trust set.
// The new state directory holds the bundle arch. stop stops the store.
func startBoth(tb testing.TB, arch []byte) (dir string, bp *bundlePart, stop func()) {
	tb.Helper()
	old := bundleTrust
	tb.Cleanup(func() { bundleTrust = old })
	bundleTrust = testTrust
	dir = tb.TempDir()
	mustOK(tb, os.Chmod(dir, 0o700))
	putBundle(tb, dir, bundleFile, arch, seedKey(goodSeed))
	p := startParams{Root: dir, StorePath: "events.db", TlogDir: "tlog", Origin: "bench/origin", CacheDir: "certs",
		BundlePath: bundleFile, Reserved: []string{"tlog", "certs", "bundle"}, Interval: time.Hour}
	c := event.NewCounters()
	q, err := event.NewQueue(16, c)
	mustOK(tb, err)
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := start(p, q, c, realDeps, lg)
	return dir, startBundle(p, s, q, lg), s.Stop
}

// TestTU08_HealthFollowsLoaderState checks that the bundle part is healthy
// after an accepted start. A state file that does not parse makes it not
// healthy.
func TestTU08_HealthFollowsLoaderState(t *testing.T) {
	dir, bp, stop := startBoth(t, archiveOf(t, referenceFiles()...))
	defer stop()
	before := bp.Healthy()
	mustOK(t, os.WriteFile(filepath.Join(dir, "bundle", bundle.StateName), []byte("x\n"), 0o600))
	if after := bp.Healthy(); !before || after {
		t.Errorf("healthy %v before and %v after a state fault; want true and false", before, after)
	}
}

// tmplBytes is the size of a template of the benchmark. The trap file adds 64
// bytes of instruction templates to the sum of the bundle cap of 512 KiB.
const tmplBytes = 64<<10 - 16

// benchRoutes is a route map with one route to the first template.
const benchRoutes = `{"routes":[{"path":"/","template":"vhosts/h.example/0000.tmpl",` +
	`"type":"text/html; charset=utf-8"}]}`

// BenchmarkStartLargeBundle starts the store part and the bundle part with a
// bundle near the caps. The case files has two random files of 4 MiB less
// 4 KiB. The case templates has 8 templates of 65 520 bytes. Each one has 64
// actions that the load check permits. It also has a trap file. Its first
// random file is 600 KiB smaller than in the case files. The bundle file has at
// most
// 8 MiB. It reports the growth of the heap in use after a GC, from before the
// start to after the load. The bundle bytes of the test are not in the value.
// The case templates also has a route map for its vhost.
func BenchmarkStartLargeBundle(b *testing.B) {
	big := func(name string, size int) tarFile {
		d := make([]byte, size)
		rand.Read(d)
		return tarFile{name, d}
	}
	for _, c := range []struct {
		name         string
		first, tmpls int
	}{{"files", 4<<20 - 4<<10, 0}, {"templates", 4<<20 - 4<<10 - 600<<10, 8}} {
		b.Run(c.name, func(b *testing.B) {
			files := []tarFile{big("traps/a.bin", c.first), big("traps/b.bin", 4<<20-4<<10)}
			// Each template has the most actions that the load check permits:
			// 64 of {{index .Trap "<id>"}}. The rest is text.
			var ids, actions []string
			for i := range 64 {
				id := fmt.Sprintf("t%02d", i)
				ids = append(ids, fmt.Sprintf(`{"id":%q,"slot":"hidden-p","surface":"path",`+
					`"visibility":"human-visible","instruction_template":"x"}`, id))
				actions = append(actions, fmt.Sprintf(`{{index .Trap %q}}`, id))
			}
			acts := strings.Join(actions, "")
			for i := range c.tmpls {
				text := acts + strings.Repeat("a", tmplBytes-len(acts))
				files = append(files, tarFile{fmt.Sprintf("vhosts/h.example/%04d.tmpl", i), []byte(text)})
			}
			if c.tmpls > 0 {
				files = append(files, tarFile{"vhosts/h.example/routes.json", []byte(benchRoutes)},
					tarFile{"traps/traps.json", []byte("[" + strings.Join(ids, ",") + "]")})
			}
			arch := archiveOf(b, referenceFiles(files...)...)
			if len(arch) > bundle.MaxBundleBytes {
				b.Fatalf("bundle has %d bytes, cap %d", len(arch), bundle.MaxBundleBytes)
			}
			b.ResetTimer()
			var heap int64
			for range b.N {
				before := heapInUse()
				_, bp, stop := startBoth(b, arch)
				if !bp.Healthy() {
					b.Fatal("bundle part is not healthy")
				}
				heap = heapInUse() - before
				runtime.KeepAlive(bp)
				stop()
			}
			b.ReportMetric(float64(heap), "heap-bytes")
		})
	}
}
