package fetch

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
)

var testKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xA5}, ed25519.SeedSize))

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// pair is the archive and the signature file of one signed test bundle.
type pair struct{ archive, sig []byte }

// signedPair makes a small bundle with the manifest version and signs it.
func signedPair(t *testing.T, version string) pair {
	t.Helper()
	now := time.Now().UTC()
	files := map[string]string{
		"manifest.json": fmt.Sprintf(`{"version":%q,"min_engine":"1.0.0","created":%q,"expires":%q,"key_id":"t1"}`,
			version, now.Add(-time.Hour).Format("2006-01-02T15:04:05Z"), now.Add(24*time.Hour).Format("2006-01-02T15:04:05Z")),
		"secrets/token.seed":             strings.Repeat("\x09", 32),
		"score/a":                        "score\n",
		"fp/a":                           "fp\n",
		"traps/traps.json":               `[{"id":"a","slot":"hidden-p","surface":"path","visibility":"human-visible","instruction_template":"x"}]`,
		"vhosts/example.com/routes.json": `{"routes":[{"path":"/","asset":"vhosts/example.com/index.html","type":"text/html; charset=utf-8"}]}`,
		"vhosts/example.com/index.html":  "<p>" + version + "</p>\n",
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range files {
			if !yield(k) {
				return
			}
		}
	}) {
		data := files[name]
		noErr(t, tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data)), Format: tar.FormatUSTAR}))
		_, err := tw.Write([]byte(data))
		noErr(t, err)
	}
	noErr(t, tw.Close())
	noErr(t, zw.Close())
	sig := "t1 " + base64.StdEncoding.EncodeToString(ed25519.Sign(testKey, bundle.SigMessage(buf.Bytes()))) + "\n"
	return pair{buf.Bytes(), []byte(sig)}
}

// runningLoader starts a loader on the pair a, as the start load does. Its
// events go to the queue that it returns.
func runningLoader(t *testing.T, a pair) (*bundle.Loader, *event.Queue) {
	t.Helper()
	return loaderAt(t, t.TempDir(), &a)
}

// loaderAt makes a loader on dir. With a start pair, it does the start load.
// With nil, it has no running bundle.
func loaderAt(t *testing.T, dir string, a *pair) (*bundle.Loader, *event.Queue) {
	t.Helper()
	noErr(t, os.MkdirAll(filepath.Join(dir, "bundle"), 0o700))
	if a != nil {
		noErr(t, os.WriteFile(filepath.Join(dir, "bundle/current.cbnd"), a.archive, 0o600))
		noErr(t, os.WriteFile(filepath.Join(dir, "bundle/current.sig"), a.sig, 0o600))
	}
	root, err := os.OpenRoot(dir)
	noErr(t, err)
	t.Cleanup(func() { root.Close() })
	trust := bundle.TrustSet{{KeyID: "t1", PublicKey: [32]byte(testKey.Public().(ed25519.PublicKey)), Class: bundle.ClassReference}}
	l := bundle.NewLoader(root, "bundle/current.cbnd", trust, nil)
	// A sleep moves the clock, so the swap gap ends at once.
	var shift atomic.Int64
	l.SetClock(func() time.Time { return time.Now().Add(time.Duration(shift.Load())) },
		func(d time.Duration) { shift.Add(int64(d)) })
	if a != nil {
		if _, err := l.Load(true); err != nil {
			t.Fatal(err)
		}
	}
	q, err := event.NewQueue(8, event.NewCounters())
	noErr(t, err)
	l.SetEvents(q, slog.New(slog.DiscardHandler))
	return l, q
}

// origin is the bundle server. sigs gives the body of the n-th request of the
// signature file, counted from 0.
type origin struct {
	mu      sync.Mutex
	paths   []string
	sigs    func(n int) []byte
	archive []byte
	nsig    int
}

func (o *origin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.paths = append(o.paths, r.URL.Path)
	if !strings.HasSuffix(r.URL.Path, ".sig") {
		_, _ = w.Write(o.archive)
		return
	}
	o.nsig++
	_, _ = w.Write(o.sigs(o.nsig - 1))
}

func (o *origin) requests() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.paths)
}

// events closes the queue and gives the kind and the detail of each event.
func events(t *testing.T, q *event.Queue) (kinds []event.Kind, details []map[string]string) {
	t.Helper()
	q.Close()
	for _, e := range q.Drain() {
		b, err := json.Marshal(e.Record().Detail)
		noErr(t, err)
		m := map[string]string{}
		noErr(t, json.Unmarshal(b, &m))
		kinds, details = append(kinds, e.Kind()), append(details, m)
	}
	return kinds, details
}

// fetchRig is a fetcher on the real client and a loopback TLS server, with a
// running bundle a.
type fetchRig struct {
	f   *Fetcher
	l   *bundle.Loader
	q   *event.Queue
	old *bundle.Bundle
	o   *origin
	sim *sim
}

func newFetchRig(t *testing.T, a pair, o *origin) *fetchRig {
	t.Helper()
	l, q := runningLoader(t, a)
	return rigOn(t, l, q, o)
}

// rigOn is a fetchRig on the loader l and its queue q.
func rigOn(t *testing.T, l *bundle.Loader, q *event.Queue, o *origin) *fetchRig {
	t.Helper()
	s := newSim(t, 0.5)
	r := newClientFor(t, start(t, o, nil), settings{archiveCap: 1 << 16, sigCap: smallSig, now: s.clk.now}, mode{})
	f := NewFetcher(r.c, l, time.Hour)
	s.attach(f)
	return &fetchRig{f, l, q, l.Current(), o, s}
}

// checkOrder checks that the paths are signature, archive, signature.
func checkOrder(t *testing.T, paths []string) {
	t.Helper()
	want := []string{".sig", ".cbnd", ".sig"}
	if len(paths) != len(want) {
		t.Fatalf("requests %v, want signature, archive, signature", paths)
	}
	for i, p := range paths {
		if !strings.HasSuffix(p, want[i]) {
			t.Errorf("requests %v, want signature, archive, signature", paths)
			return
		}
	}
}

// T-S-01: a changed archive from the fetch URL gives bad_sig. The old bundle
// serves, and the one event has source fetch. The signature file of the server
// differs from the running one, so the change check does not end the fetch.
func TestTS01ChangedArchiveFromFetch(t *testing.T) {
	b := signedPair(t, "2026.11.01-2")
	bad := slices.Clone(b.archive)
	bad[len(bad)/2] ^= 1
	r := newFetchRig(t, signedPair(t, "2026.11.01-1"), &origin{archive: bad, sigs: func(int) []byte { return b.sig }})
	if r.f.fetch(context.Background()) {
		t.Error("a changed archive gave a good fetch")
	}
	if got := r.l.Current(); got != r.old || got == nil {
		t.Errorf("the running bundle is %v, want the old bundle", got)
	}
	kinds, details := events(t, r.q)
	if len(kinds) != 1 || kinds[0] != event.KindBundleRejected ||
		details[0]["reason"] != "bad_sig" || details[0]["source"] != "fetch" {
		t.Errorf("events %v, details %v", kinds, details)
	}
	checkOrder(t, r.o.requests())
	if r.f.c.Count(ClassRejected) != 1 || !r.f.c.LastGood().IsZero() {
		t.Errorf("rejected %d, last good %v", r.f.c.Count(ClassRejected), r.f.c.LastGood())
	}
	if r.f.LoadFaults() != 0 {
		t.Errorf("load faults %d, want 0", r.f.LoadFaults())
	}
}

// T-S-30: each rejection code counts the class rejected, not a load fault. A
// pair with a lower version gives rollback. Bytes that are no archive, with a
// valid signature, give archive_invalid. The old bundle serves, and the one
// event has the reason and source fetch.
func TestTS30OtherRejections(t *testing.T) {
	junk := []byte("not an archive")
	junkSig := []byte("t1 " + base64.StdEncoding.EncodeToString(ed25519.Sign(testKey, bundle.SigMessage(junk))) + "\n")
	older := signedPair(t, "2026.10.01-1")
	for _, tc := range []struct {
		reason string
		p      pair
	}{
		{"rollback", older},
		{"archive_invalid", pair{junk, junkSig}},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			r := newFetchRig(t, signedPair(t, "2026.11.01-1"), &origin{archive: tc.p.archive, sigs: func(int) []byte { return tc.p.sig }})
			if r.f.fetch(context.Background()) {
				t.Error("a rejected pair gave a good fetch")
			}
			if r.f.c.Count(ClassRejected) != 1 || r.f.LoadFaults() != 0 {
				t.Errorf("rejected %d, load faults %d, want 1 and 0", r.f.c.Count(ClassRejected), r.f.LoadFaults())
			}
			if got := r.l.Current(); got != r.old || got == nil {
				t.Errorf("the running bundle is %v, want the old bundle", got)
			}
			kinds, details := events(t, r.q)
			if len(kinds) != 1 || kinds[0] != event.KindBundleRejected ||
				details[0]["reason"] != tc.reason || details[0]["source"] != "fetch" {
				t.Errorf("events %v, details %v", kinds, details)
			}
		})
	}
}

// T-S-30: a signature file equal to the running one ends the fetch after one
// request. There is no archive request, no load and no event.
func TestTS30UnchangedSignature(t *testing.T) {
	a := signedPair(t, "2026.11.01-1")
	r := newFetchRig(t, a, &origin{archive: a.archive, sigs: func(int) []byte { return a.sig }})
	if !r.f.fetch(context.Background()) {
		t.Error("an unchanged fetch was not good")
	}
	if got := r.o.requests(); len(got) != 1 || !strings.HasSuffix(got[0], ".sig") {
		t.Errorf("requests %v, want one signature request", got)
	}
	if kinds, _ := events(t, r.q); len(kinds) != 0 {
		t.Errorf("events %v", kinds)
	}
	if r.l.Current() != r.old || !r.f.c.LastGood().Equal(r.sim.clk.t) {
		t.Errorf("running bundle changed, or last good = %v", r.f.c.LastGood())
	}
}

// T-S-30: a signature file that changes between the two reads loads nothing.
// The fetch counts the class changed, and the next wait is a backoff step. Then
// the server gives a stable pair, and the second fetch loads it.
func TestTS30PairChangesBetweenReads(t *testing.T) {
	b := signedPair(t, "2026.11.01-2")
	c := signedPair(t, "2026.11.01-3")
	r := newFetchRig(t, signedPair(t, "2026.11.01-1"), &origin{archive: b.archive, sigs: func(n int) []byte {
		if n == 1 {
			return c.sig
		}
		return b.sig
	}})
	r.sim.maxWaits = 3
	var tries int
	var loaded bool
	var changed, faults uint64
	r.f.try = func(ctx context.Context) bool {
		good := r.f.fetch(ctx)
		if tries++; tries == 1 { // the state after the changed pair
			loaded, changed, faults = r.l.Current() != r.old, r.f.c.Count(ClassChanged), r.f.LoadFaults()
		}
		return good
	}
	r.sim.run()
	if loaded || changed != 1 || r.f.c.Count(ClassRejected) != 0 || faults != 0 {
		t.Errorf("after the first fetch: loaded %v, changed %d, rejected %d, load faults %d", loaded, changed, r.f.c.Count(ClassRejected), faults)
	}
	// The wait after the changed pair is the 60 s step. A good fetch gives 1 h.
	checkWaits(t, r.sim.waits, secs(60, 3600))
	if tries != 2 {
		t.Errorf("%d fetches, want 2", tries)
	}
	if r.f.LoadFaults() != 0 {
		t.Errorf("load faults %d, want 0", r.f.LoadFaults())
	}
	kinds, details := events(t, r.q)
	if len(kinds) != 1 || kinds[0] != event.KindBundleLoad || details[0]["source"] != "fetch" {
		t.Errorf("events %v, details %v", kinds, details)
	}
	if got := r.l.Current(); got == nil || !bytes.Equal(got.Signature(), b.sig) {
		t.Errorf("the running bundle is %v", got)
	}
}

// T-S-30: no running bundle. The fetch reads the pair and loads it.
func TestTS30NoRunningBundle(t *testing.T) {
	b := signedPair(t, "2026.11.01-2")
	l, q := loaderAt(t, t.TempDir(), nil)
	if l.Current() != nil {
		t.Fatal("the loader has a running bundle")
	}
	r := rigOn(t, l, q, &origin{archive: b.archive, sigs: func(int) []byte { return b.sig }})
	if !r.f.fetch(context.Background()) {
		t.Fatal("the fetch was not good")
	}
	checkOrder(t, r.o.requests())
	kinds, details := events(t, q)
	if len(kinds) != 1 || kinds[0] != event.KindBundleLoad || details[0]["source"] != "fetch" {
		t.Errorf("events %v, details %v", kinds, details)
	}
	if got := l.Current(); got == nil || !bytes.Equal(got.Signature(), b.sig) {
		t.Errorf("the running bundle is %v", got)
	}
}

// checkFaultOnly checks that the one fetch ended as a load fault. The fault
// counter is 1 and no class has a count. The old bundle serves, and there is
// no event and no last good time.
func checkFaultOnly(t *testing.T, r *fetchRig) {
	t.Helper()
	if r.f.LoadFaults() != 1 {
		t.Errorf("load faults %d, want 1", r.f.LoadFaults())
	}
	for _, c := range classes {
		if n := r.f.c.Count(c); n != 0 {
			t.Errorf("class %s has count %d, want 0", c, n)
		}
	}
	if r.l.Current() != r.old || !r.f.c.LastGood().IsZero() {
		t.Errorf("the running bundle changed, or last good = %v", r.f.c.LastGood())
	}
	if kinds, _ := events(t, r.q); len(kinds) != 0 {
		t.Errorf("events %v", kinds)
	}
}

// T-U-23: a load that cannot write its files is no rejection. The fetcher
// counts it as a load fault. The old bundle serves, and there is no event.
func TestTU23InstallFault(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to a directory with mode 0500")
	}
	b := signedPair(t, "2026.11.01-2")
	dir := t.TempDir()
	a := signedPair(t, "2026.11.01-1")
	l, q := loaderAt(t, dir, &a)
	r := rigOn(t, l, q, &origin{archive: b.archive, sigs: func(int) []byte { return b.sig }})
	bundleDir := filepath.Join(dir, "bundle")
	noErr(t, os.Chmod(bundleDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(bundleDir, 0o700) })
	if r.f.fetch(context.Background()) {
		t.Error("a fetch that could not write gave a good fetch")
	}
	checkFaultOnly(t, r)
}

// T-U-23: a load that cannot write the version state is no rejection. The
// files of the bundle can be written. A blocked name for the temporary state
// file makes the state write fail after each check. The fetcher counts a load
// fault. The old bundle serves, and there is no event.
func TestTU23StateFault(t *testing.T) {
	b := signedPair(t, "2026.11.01-2")
	dir := t.TempDir()
	a := signedPair(t, "2026.11.01-1")
	l, q := loaderAt(t, dir, &a)
	r := rigOn(t, l, q, &origin{archive: b.archive, sigs: func(int) []byte { return b.sig }})
	block := filepath.Join(dir, "bundle", bundle.StateName+".tmp")
	noErr(t, os.MkdirAll(filepath.Join(block, "x"), 0o700))
	if r.f.fetch(context.Background()) {
		t.Error("a fetch that could not write the state gave a good fetch")
	}
	checkFaultOnly(t, r)
	// The install passed. Only the state write failed.
	if disk, err := os.ReadFile(filepath.Join(dir, "bundle/current.cbnd")); err != nil || !bytes.Equal(disk, b.archive) {
		t.Errorf("current.cbnd does not hold the fetched archive (read error %v)", err)
	}
}

// T-U-23: the context ends after the second signature read. The fetch starts
// no load, so there is no event and the running bundle stays.
func TestTU23StopBeforeLoad(t *testing.T) {
	b := signedPair(t, "2026.11.01-2")
	r := newFetchRig(t, signedPair(t, "2026.11.01-1"), &origin{archive: b.archive, sigs: func(int) []byte { return b.sig }})
	if r.f.pairRead == nil {
		t.Fatal("NewFetcher left no pair hook")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.f.pairRead = cancel
	if r.f.fetch(ctx) {
		t.Error("a fetch that the stop ended was good")
	}
	if r.l.Current() != r.old {
		t.Error("a load started after the stop")
	}
	if kinds, _ := events(t, r.q); len(kinds) != 0 {
		t.Errorf("events %v", kinds)
	}
}

// T-S-30: a new pair gives one bundle_load with source fetch, and a good fetch.
func TestTS30NewPair(t *testing.T) {
	b := signedPair(t, "2026.11.01-2")
	r := newFetchRig(t, signedPair(t, "2026.11.01-1"), &origin{archive: b.archive, sigs: func(int) []byte { return b.sig }})
	if !r.f.fetch(context.Background()) {
		t.Fatal("a new pair was not a good fetch")
	}
	kinds, details := events(t, r.q)
	if len(kinds) != 1 || kinds[0] != event.KindBundleLoad || details[0]["source"] != "fetch" {
		t.Errorf("events %v, details %v", kinds, details)
	}
	if got := r.l.Current(); got == nil || got == r.old || !bytes.Equal(got.Signature(), b.sig) {
		t.Errorf("the running bundle is %v", got)
	}
	if r.f.c.LastGood().IsZero() {
		t.Error("no last good time")
	}
	// The next fetch finds the new signature file and ends after one request.
	n := len(r.o.requests())
	if !r.f.fetch(context.Background()) || len(r.o.requests()) != n+1 {
		t.Errorf("the second fetch made %d requests", len(r.o.requests())-n)
	}
}
