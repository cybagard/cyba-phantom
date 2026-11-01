package main

import (
	"archive/tar"
	"bytes"
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

// mustOK panics on an error. A fixture does not need a testing.TB.
func mustOK(err error) {
	if err != nil {
		panic(err)
	}
}

// archiveOf makes a bundle archive: a gzip stream of a ustar tar.
func archiveOf(files ...tarFile) []byte {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	tw := tar.NewWriter(zw)
	for _, f := range files {
		mustOK(tw.WriteHeader(&tar.Header{Name: f.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f.data)), Format: tar.FormatUSTAR}))
		_, err := tw.Write(f.data)
		mustOK(err)
	}
	mustOK(tw.Close())
	mustOK(zw.Close())
	return buf.Bytes()
}

// referenceFiles are the files of a valid reference bundle with a plain seed.
func referenceFiles(extra ...tarFile) []tarFile {
	stamp := func(d time.Duration) string { return time.Now().Add(d).UTC().Format("2006-01-02T15:04:05Z") }
	m := fmt.Sprintf(`{"version":%q,"min_engine":"1.0.0","created":%q,"expires":%q,"key_id":"t1"}`,
		bundleVersion, stamp(-time.Hour), stamp(24*time.Hour))
	return append([]tarFile{{"manifest.json", []byte(m)}, {"secrets/token.seed", bytes.Repeat([]byte{9}, 32)}}, extra...)
}

// putBundle writes the archive and its signature file below root.
func putBundle(root string, arch []byte, key ed25519.PrivateKey) {
	dir := filepath.Join(root, "bundle")
	sig := "t1 " + base64.StdEncoding.EncodeToString(ed25519.Sign(key, bundle.SigMessage(arch))) + "\n"
	mustOK(os.MkdirAll(dir, 0o700))
	mustOK(os.WriteFile(filepath.Join(dir, "current.cbnd"), arch, 0o600))
	mustOK(os.WriteFile(filepath.Join(dir, "current.sig"), []byte(sig), 0o600))
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
	p     startParams
	loads atomic.Int32
	early atomic.Bool
	line  string
}

// startBundleRun starts serveWith with realDeps and the loader seam, waits for
// the start line, and checks that the decoys serve. prep makes the state.
// Then it stops serveWith, which needs exit 0.
func startBundleRun(t *testing.T, trust bundle.TrustSet, prep func(*testing.T, startParams)) *bundleRun {
	t.Helper()
	httpsLn, plainLn, ca := openListeners(t)
	cfg := serveCfg(t, httpsLn.Addr().String(), plainLn.Addr().String(), ca)
	br := &bundleRun{p: tempState(t, cfg)}
	if prep != nil {
		prep(t, br.p)
	}
	oldTrust, oldNew := bundleTrust, newLoader
	t.Cleanup(func() { bundleTrust, newLoader = oldTrust, oldNew })
	bundleTrust = func() bundle.TrustSet { return trust }
	newLoader = func(s *os.Root, path string, ts bundle.TrustSet, k hpke.PrivateKey) *bundle.Loader {
		br.loads.Add(1)
		if k == nil || path != "bundle/current.cbnd" || !reflect.DeepEqual(ts, trust) {
			t.Errorf("loader got nil install key %v, path %q, trust set %v", k == nil, path, ts)
		}
		br.early.Store(answered(plainLn.Addr().String()))
		return oldNew(s, path, ts, k)
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
	if r.code != 0 {
		t.Errorf("exit %d, want 0; stderr %q", r.code, r.err.String())
	}
	return br
}

type bundleRow struct{ kind, detail string }

// rows returns the bundle events in the store after the stop.
func (br *bundleRun) rows() []bundleRow {
	root, err := os.OpenRoot(br.p.Root)
	mustOK(err)
	defer root.Close()
	db, err := store.Open(root, br.p.StorePath, store.Options{Reserved: br.p.Reserved})
	mustOK(err)
	defer db.Close()
	q, err := db.Query("SELECT kind, detail FROM event WHERE kind IN ('bundle_load', 'bundle_rejected')")
	mustOK(err)
	defer q.Close()
	var out []bundleRow
	for q.Next() {
		var r bundleRow
		mustOK(q.Scan(&r.kind, &r.detail))
		out = append(out, r)
	}
	return out
}

// TestTU08_StartLoadsBundle starts serveWith in each state of the bundle
// (T-U-08, C3). A valid signed bundle gives one bundle_load row with the
// source start. The bundle part is healthy. The load runs before the serve
// calls. Each other row serves the decoys and ends only at the stop. Its
// start line says that the bundle part is not healthy. A refused store makes
// no install key and no load. A trust set that fails Check does the same.
// kind is the kind of the one bundle row. It is "" for no row. It is "-"
// when the store is refused.
func TestTU08_StartLoadsBundle(t *testing.T) {
	put := func(seed byte) func(*testing.T, startParams) {
		return func(_ *testing.T, p startParams) { putBundle(p.Root, archiveOf(referenceFiles()...), seedKey(seed)) }
	}
	k := testTrust()[0]
	for _, c := range []struct {
		name  string
		trust bundle.TrustSet
		prep  func(*testing.T, startParams)
		loads int32
		kind  string
	}{
		{"valid", testTrust(), put(goodSeed), 1, "bundle_load"},
		{"no bundle", testTrust(), nil, 1, "bundle_rejected"},
		{"bad signature", testTrust(), put(wrongSeed), 1, "bundle_rejected"},
		{"state file does not parse", testTrust(), func(t *testing.T, p startParams) {
			put(goodSeed)(t, p)
			must(t, os.WriteFile(filepath.Join(p.Root, "bundle", bundle.StateName), []byte("x\n"), 0o600))
		}, 1, ""},
		{"state directory others can write", testTrust(), func(t *testing.T, p startParams) {
			put(goodSeed)(t, p)
			must(t, os.Chmod(p.Root, 0o777))
		}, 0, "-"},
		{"trust set fails Check", bundle.TrustSet{k, k}, put(goodSeed), 0, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			br := startBundleRun(t, c.trust, c.prep)
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
			rows := br.rows()
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
	if err := releaseTrust.Check(keys); err != nil {
		t.Fatalf("release trust set: %v", err)
	}
	add := func(k ...bundle.TrustKey) bundle.TrustSet {
		return append(append(bundle.TrustSet{}, releaseTrust...), k...)
	}
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
	if got := bundleTrust(); !reflect.DeepEqual(got, releaseTrust) || reflect.DeepEqual(got, testTrust()) {
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

// BenchmarkStartLargeBundle starts the store part and the bundle part with a
// bundle near the caps. It has two random files of 4 MiB less 4 KiB. The
// bundle file has at most 8 MiB. It reports the growth of the heap in use
// after a GC. It measures from before the start to after the load. The
// bundle bytes of the test are not in the value.
func BenchmarkStartLargeBundle(b *testing.B) {
	big := func(name string) tarFile {
		d := make([]byte, 4<<20-4<<10)
		rand.Read(d)
		return tarFile{name, d}
	}
	arch := archiveOf(referenceFiles(big("traps/a.bin"), big("traps/b.bin"))...)
	if len(arch) > bundle.MaxBundleBytes {
		b.Fatalf("bundle has %d bytes, cap %d", len(arch), bundle.MaxBundleBytes)
	}
	old := bundleTrust
	b.Cleanup(func() { bundleTrust = old })
	bundleTrust = testTrust
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	var heap int64
	for range b.N {
		dir := b.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			b.Fatal(err)
		}
		putBundle(dir, arch, seedKey(goodSeed))
		p := startParams{Root: dir, StorePath: "events.db", TlogDir: "tlog", Origin: "bench/origin", CacheDir: "certs",
			BundlePath: "bundle/current.cbnd", Reserved: []string{"tlog", "certs", "bundle"}, Interval: time.Hour}
		c := event.NewCounters()
		q, err := event.NewQueue(16, c)
		if err != nil {
			b.Fatal(err)
		}
		before := heapInUse()
		s := start(p, q, c, realDeps, lg)
		bp := startBundle(p, s, q, lg)
		if !bp.Healthy() {
			b.Fatal("bundle part is not healthy")
		}
		heap = heapInUse() - before
		runtime.KeepAlive(bp)
		s.Stop()
	}
	b.ReportMetric(float64(heap), "heap-bytes")
}
