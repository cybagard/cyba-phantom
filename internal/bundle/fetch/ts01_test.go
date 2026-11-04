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
	dir := t.TempDir()
	noErr(t, os.MkdirAll(filepath.Join(dir, "bundle"), 0o700))
	noErr(t, os.WriteFile(filepath.Join(dir, "bundle/current.cbnd"), a.archive, 0o600))
	noErr(t, os.WriteFile(filepath.Join(dir, "bundle/current.sig"), a.sig, 0o600))
	root, err := os.OpenRoot(dir)
	noErr(t, err)
	t.Cleanup(func() { root.Close() })
	trust := bundle.TrustSet{{KeyID: "t1", PublicKey: [32]byte(testKey.Public().(ed25519.PublicKey)), Class: bundle.ClassReference}}
	l := bundle.NewLoader(root, "bundle/current.cbnd", trust, nil)
	// A sleep moves the clock, so the swap gap ends at once.
	var shift atomic.Int64
	l.SetClock(func() time.Time { return time.Now().Add(time.Duration(shift.Load())) },
		func(d time.Duration) { shift.Add(int64(d)) })
	if _, err := l.Load(true); err != nil {
		t.Fatal(err)
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
	s := newSim(t, 0.5)
	r := newClientFor(t, start(t, o, nil), settings{archiveCap: 1 << 16, sigCap: smallSig, now: s.clk.now}, mode{})
	f := NewFetcher(r.c, l, time.Hour)
	s.attach(f)
	return &fetchRig{f, l, q, l.Current(), o, s}
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
	if n := len(r.o.requests()); n != 3 {
		t.Errorf("%d requests, want signature, archive, signature", n)
	}
	if r.f.c.Count(ClassRejected) != 1 || !r.f.c.LastGood().IsZero() {
		t.Errorf("rejected %d, last good %v", r.f.c.Count(ClassRejected), r.f.c.LastGood())
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
// The fetch counts the class changed, and the next wait is a backoff step.
func TestTS30PairChangesBetweenReads(t *testing.T) {
	b := signedPair(t, "2026.11.01-2")
	c := signedPair(t, "2026.11.01-3")
	r := newFetchRig(t, signedPair(t, "2026.11.01-1"), &origin{archive: b.archive, sigs: func(n int) []byte {
		return [][]byte{b.sig, c.sig}[n%2]
	}})
	r.sim.maxWaits = 2
	r.sim.run()
	if r.l.Current() != r.old {
		t.Error("the running bundle changed")
	}
	if kinds, _ := events(t, r.q); len(kinds) != 0 {
		t.Errorf("events %v", kinds)
	}
	if r.f.c.Count(ClassChanged) != 1 || r.f.c.Count(ClassRejected) != 0 {
		t.Errorf("changed %d, rejected %d", r.f.c.Count(ClassChanged), r.f.c.Count(ClassRejected))
	}
	checkWaits(t, r.sim.waits, secs(60))
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
