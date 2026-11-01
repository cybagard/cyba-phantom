package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// probe holds the queue and the log buffer that a loader reports to.
type probe struct {
	q   *event.Queue
	buf *bytes.Buffer
}

func (e *env) observe(l *Loader) *probe {
	e.t.Helper()
	q, err := event.NewQueue(8, event.NewCounters())
	must(e.t, err)
	p := &probe{q, new(bytes.Buffer)}
	l.SetEvents(q, slog.New(slog.NewTextHandler(p.buf, nil)))
	return p
}

// take returns the events on the queue and the evidence bytes of each one.
func (p *probe) take(t *testing.T) (evs []*event.Event, ev []string) {
	t.Helper()
	p.q.Close()
	for _, e := range p.q.Drain() {
		b, err := event.EvidenceBytes(e.Record())
		must(t, err)
		evs, ev = append(evs, e), append(ev, string(b))
	}
	return evs, ev
}

// detail returns the detail members of an event as text.
func detail(t *testing.T, e *event.Event) map[string]string {
	t.Helper()
	r := e.Record()
	b, err := json.Marshal(r.Detail)
	must(t, err)
	var m map[string]string
	must(t, json.Unmarshal(b, &m))
	if r.Session != nil || r.Vhost != nil || r.Path != nil {
		t.Errorf("record has more than kind, ts and detail: %+v", r)
	}
	return m
}

func fileSum(t *testing.T, e *env) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.state, "bundle/current.cbnd"))
	must(t, err)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// T-U-08: each accept gives one bundle_load event and each rejection one
// bundle_rejected event with the fixed detail members only. A state fault gives
// no event.
func TestTU08EventsAndLogLines(t *testing.T) {
	put := func(m string) func(e *env) { return func(e *env) { e.install("bundle/current", m) } }
	zeroSig := func(e *env) {
		e.write("bundle/current.cbnd", build(ent{name: "manifest.json", data: []byte(mf(ver(3)))}))
		e.write("bundle/current.sig", []byte(sigRow("k1", make([]byte, 64))))
	}
	cases := []struct {
		name   string
		setup  func(e *env)
		kind   event.Kind
		reason string // empty for an accept
		noSum  bool
		fault  bool
	}{
		{"accept", put(mf(ver(3))), event.KindBundleLoad, "", false, false},
		{"archive_invalid", func(e *env) {
			e.write("bundle/current.cbnd", []byte("not gzip"))
			e.write("bundle/current.sig", e.sign([]byte("not gzip")))
		}, event.KindBundleRejected, "archive_invalid", false, false},
		{"archive_invalid, no signature file", func(e *env) {
			put(mf(ver(3)))(e)
			must(e.t, os.Remove(filepath.Join(e.state, "bundle/current.sig")))
		}, event.KindBundleRejected, "archive_invalid", true, false},
		{"bad_sig", zeroSig, event.KindBundleRejected, "bad_sig", false, false},
		{"manifest_invalid", put("{}"), event.KindBundleRejected, "manifest_invalid", false, false},
		{"min_engine", put(mf(ver(3), engineRepl...)), event.KindBundleRejected, "min_engine", false, false},
		{"expired", put(mf(ver(3), expiredRepl...)), event.KindBundleRejected, "expired", false, false},
		{"rollback", put(mf(ver(1))), event.KindBundleRejected, "rollback", false, false},
		{"template_parse", func(e *env) { put(mf(ver(3)))(e); e.l.template = stubParse }, event.KindBundleRejected, "template_parse", false, false},
		{"seed_invalid", func(e *env) { put(mf(ver(3)))(e); e.l = e.seedLoader(nil) }, event.KindBundleRejected, "seed_invalid", false, false},
		{"state fault", func(e *env) {
			put(mf(ver(3)))(e)
			must(e.t, os.Chmod(filepath.Join(e.state, "bundle", StateName), 0o644))
		}, 0, "", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			c.setup(e)
			p := e.observe(e.l)
			_, err := e.l.LoadFrom(SourceSignal)
			evs, _ := p.take(t)
			log := p.buf.String()
			if c.fault {
				if len(evs) != 0 || !strings.Contains(log, `msg="bundle state fault" source=signal`) || err != ErrStateFault {
					t.Errorf("fault: %d events, log %q, err %v", len(evs), log, err)
				}
				return
			}
			if len(evs) != 1 || evs[0].Kind() != c.kind {
				t.Fatalf("%d events, err %v; want one of kind %v", len(evs), err, c.kind)
			}
			want := map[string]string{"source": "signal"}
			if !c.noSum {
				want["sha256"] = fileSum(t, e)
			}
			msg := "bundle rejected"
			if c.reason == "" {
				want["version"], want["key_id"], msg = ver(3), "k1", "bundle loaded"
			} else {
				want["reason"] = c.reason
			}
			got := detail(t, evs[0])
			if len(got) != len(want) {
				t.Errorf("detail %v, want %v", got, want)
			}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("detail %s = %q, want %q", k, got[k], v)
				}
				if !strings.Contains(log, k+"="+v) {
					t.Errorf("log %q has no %s=%s", log, k, v)
				}
			}
			if strings.Count(log, "\n") != 1 || !strings.Contains(log, `msg="`+msg+`"`) || strings.Contains(log, "bundle:") {
				t.Errorf("log %q; want one line %q", log, msg)
			}
		})
	}
}

// T-U-08, T-S-20: the text of a manifest member of a rejected bundle is not in
// the record. It is not in the log or the error.
func TestTU08ManifestMarkersStayOut(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(pattern(32, 3, 9))
	cases := []struct {
		name, manifest, marker string
		want                   error
	}{
		{"version", mf("2031.07.13-777", engineRepl...), "2031.07.13", ErrMinEngine},
		{"min_engine", mf(ver(3), `"1.0.0"`, `"7777.7777.7777"`), "7777.7777.7777", ErrMinEngine},
		{"created", mf(ver(3), "2026-09-19T00:00:00Z", "2025-03-04T05:06:07Z", "2027-09-19T00:00:00Z", "2026-03-04T05:06:08Z"), "2025-03-04T05:06", ErrExpired},
		{"expires", mf(ver(3), "2026-09-19T00:00:00Z", "2025-03-04T05:06:07Z", "2027-09-19T00:00:00Z", "2026-03-04T05:06:08Z"), "2026-03-04T05:06", ErrExpired},
		{"key_id", mf(ver(3), `"k1"`, `"kmark77"`), "kmark77", ErrBadSig},
		{"rotation", mf(ver(3), `"k1"`, `"k1","rotation":`+rot("fmark88", b64)), "fmark88", ErrBadSig},
		{"rotation key", mf(ver(3), `"k1"`, `"k1","rotation":`+rot("fmark88", b64)), b64, ErrBadSig},
		{"invalid members", mf("vmark-0", `"k1"`, `"KMARK-9"`, `"1.0.0"`, `"emark.1.1"`), "mark", ErrManifestInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			p := e.observe(e.l)
			e.install("bundle/current", c.manifest)
			_, err := e.l.Load(false)
			_, evs := p.take(t)
			if err != c.want || len(evs) != 1 {
				t.Fatalf("err %v, %d events; want %v and one event", err, len(evs), c.want)
			}
			for _, s := range []string{evs[0], p.buf.String(), err.Error()} {
				if strings.Contains(s, c.marker) {
					t.Errorf("marker %q in %q", c.marker, s)
				}
			}
		})
	}
}

// T-S-20: seed and install key bytes never go to an event or a log line. This
// holds for an accept of a proprietary bundle and for a seed_invalid rejection.
func TestTS20SeedMarkersStayOut(t *testing.T) {
	for _, reject := range []bool{false, true} {
		e, install, other := newEnv(t), testInstall(t, 1), testInstall(t, 2)
		l := e.seedLoader(install)
		p := e.observe(l)
		k := e.keys()[0]
		sealer := install
		if reject {
			sealer = other
		}
		ct := sealTo(t, sealer, ver(2), k.id, seedA)
		e.putSeeded(k, ver(2), sealedEnt(ct))
		_, err := l.Load(false)
		if (err != nil) != reject {
			t.Fatalf("reject %v: err %v", reject, err)
		}
		_, evs := p.take(t)
		if len(evs) != 1 {
			t.Fatalf("%d events", len(evs))
		}
		var markers []string
		for _, b := range [][]byte{seedA, ct} {
			markers = append(markers, ikMarkers(b)...)
		}
		for _, key := range []hpke.PrivateKey{install, other} {
			priv, err := key.Bytes()
			must(t, err)
			markers = append(markers, ikMarkers(priv)...)
		}
		if ikHas(evs[0], markers) || ikHas(p.buf.String(), markers) {
			t.Errorf("reject %v: marker in %q or %q", reject, evs[0], p.buf.String())
		}
	}
}

// T-S-01: a changed bundle from a fetch source gives bad_sig. The old bundle
// serves, and the event and the log line have source fetch.
func TestTS01ChangedBundleFromFetch(t *testing.T) {
	e := running(t)
	old := e.l.Current()
	p := e.observe(e.l)
	arch := e.read("current.cbnd")
	arch[len(arch)/2] ^= 1
	e.write("bundle/current.cbnd", arch)
	b, err := e.l.LoadFrom(SourceFetch)
	evs, _ := p.take(t)
	if b != nil || err != ErrBadSig || e.l.Current() != old || len(evs) != 1 {
		t.Fatalf("bundle %v, err %v, %d events", b, err, len(evs))
	}
	d := detail(t, evs[0])
	if evs[0].Kind() != event.KindBundleRejected || d["reason"] != "bad_sig" || d["source"] != "fetch" || d["sha256"] != fileSum(t, e) {
		t.Errorf("kind %v, detail %v", evs[0].Kind(), d)
	}
	if !strings.Contains(p.buf.String(), "source=fetch") {
		t.Errorf("log %q", p.buf.String())
	}
}

// T-U-08: Load gives the sources start and reload. A value that is not a Source
// reads nothing. It gives no event and no line. A nil queue and a nil log are
// allowed.
func TestTU08Sources(t *testing.T) {
	e := running(t)
	p := e.observe(e.l)
	reads := 0
	e.l.afterRead = func() { reads++ }
	_, err1 := e.l.Load(true)
	_, err2 := e.l.Load(false)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	for _, s := range []Source{0, 5, 255} {
		if _, err := e.l.LoadFrom(s); err != ErrSource {
			t.Errorf("source %d: %v", s, err)
		}
	}
	evs, _ := p.take(t)
	if reads != 2 || len(evs) != 2 || strings.Count(p.buf.String(), "\n") != 2 {
		t.Fatalf("%d reads, %d events, log %q", reads, len(evs), p.buf.String())
	}
	if a, b := detail(t, evs[0])["source"], detail(t, evs[1])["source"]; a != "start" || b != "reload" {
		t.Errorf("sources %q, %q", a, b)
	}
	for i, s := range []string{"start", "signal", "reload", "fetch", "unknown"} {
		if got := Source(i + 1).String(); got != s {
			t.Errorf("Source(%d) = %q, want %q", i+1, got, s)
		}
	}
	e.l.SetEvents(nil, nil)
	if _, err := e.l.LoadFrom(SourceFetch); err != nil {
		t.Error(err)
	}
	e.l.SetEvents(nil, slog.New(slog.DiscardHandler))
	e.write("bundle/current.sig", []byte(sigRow("k1", ed25519.Sign(e.priv2, nil))))
	if _, err := e.l.LoadFrom(SourceFetch); err != ErrBadSig {
		t.Error(err)
	}
}
