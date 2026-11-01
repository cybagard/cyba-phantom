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
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

// logLines parses the lines of a slog text handler into maps of attribute
// names and values. Each line must have a time, which the map does not keep.
func logLines(t *testing.T, s string) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		if line == "" {
			continue
		}
		m := map[string]string{}
		for line != "" {
			k, rest, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("log line %q has no value", line)
			}
			v := rest
			if q, err := strconv.QuotedPrefix(rest); err == nil {
				v, _ = strconv.Unquote(q)
				line = strings.TrimPrefix(rest[len(q):], " ")
			} else {
				v, line, _ = strings.Cut(rest, " ")
			}
			m[k] = v
		}
		if m["time"] == "" {
			t.Fatalf("log line %v has no time", m)
		}
		delete(m, "time")
		out = append(out, m)
	}
	return out
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
			want := map[string]string{"source": "signal"}
			if !c.noSum {
				want["sha256"] = fileSum(t, e)
			}
			logWant := map[string]string{"level": "WARN", "msg": "bundle rejected"}
			switch {
			case c.fault:
				logWant["level"], logWant["msg"] = "ERROR", "bundle state fault"
			case c.reason == "":
				want["version"], want["key_id"] = ver(3), "k1"
				logWant["level"], logWant["msg"] = "INFO", "bundle loaded"
			default:
				want["reason"] = c.reason
			}
			maps.Copy(logWant, want)
			if lines := logLines(t, p.buf.String()); len(lines) != 1 || !maps.Equal(lines[0], logWant) {
				t.Errorf("log %v, want one line %v", lines, logWant)
			}
			if c.fault {
				if len(evs) != 0 || err != ErrStateFault {
					t.Errorf("fault: %d events, err %v", len(evs), err)
				}
				return
			}
			if len(evs) != 1 || evs[0].Kind() != c.kind {
				t.Fatalf("%d events, err %v; want one of kind %v", len(evs), err, c.kind)
			}
			if got := detail(t, evs[0]); !maps.Equal(got, want) {
				t.Errorf("detail %v, want %v", got, want)
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

// T-U-08, T-S-19: real archive, template and manifest errors have marker text
// in the input. Each gives a fixed error, one event and one log line. The
// marker text and the ESC byte are not in the record, the log or the error.
func TestTU08ErrorTextMarkersStayOut(t *testing.T) {
	man := ent{name: "manifest.json", data: []byte(mf(ver(3)))}
	badMan := func(data string) []byte { return build(ent{name: man.name, data: []byte(data)}) }
	tmpl := func(text string) []byte {
		return build(man, ent{name: "vhosts/" + markerName + ".tmpl", data: []byte(text)})
	}
	cases := []struct {
		name string
		arch []byte
		want error
	}{
		{"template parse", tmpl("{{" + markerData + " \x1b\n}}"), ErrTemplateParse},
		{"template unclosed", tmpl(`{{template "` + markerData + `"}}{{`), ErrTemplateParse},
		{"entry name", build(man, ent{name: "../" + markerName, data: []byte(markerData)}), ErrArchiveInvalid},
		{"tar garbage", gz([]byte(markerData + strings.Repeat("\x1b", 1024))), ErrArchiveInvalid},
		{"json syntax", badMan("{\x1b" + markerData), ErrManifestInvalid},
		{"unknown member", badMan(mf(ver(3), `"k1"`, `"k1","`+markerName+`\n":"`+markerData+`"`)), ErrManifestInvalid},
		{"wrong type", badMan(mf(ver(3), `"k1"`, `{"`+markerData+`":1}`)), ErrManifestInvalid},
		{"version text", badMan(mf(ver(3) + "\\nlevel=ERROR msg=FORGED")), ErrManifestInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			p := e.observe(e.l)
			e.write("bundle/current.cbnd", c.arch)
			e.write("bundle/current.sig", e.sign(c.arch))
			_, err := e.l.LoadFrom(SourceFetch)
			evs, raw := p.take(t)
			lines := logLines(t, p.buf.String())
			if err != c.want || len(evs) != 1 || len(lines) != 1 {
				t.Fatalf("err %v, %d events, %d log lines; want %v, 1, 1", err, len(evs), len(lines), c.want)
			}
			code, _ := CodeOf(c.want)
			if r := detail(t, evs[0])["reason"]; r != code.String() || lines[0]["reason"] != r {
				t.Errorf("event reason %q, log %v; want %q", r, lines[0], code)
			}
			for _, s := range []string{raw[0], p.buf.String(), err.Error()} {
				for _, m := range []string{markerName, markerData, "FORGED", "\x1b", `\u001b`, `\x1b`} {
					if strings.Contains(s, m) {
						t.Errorf("marker %q in %q", m, s)
					}
				}
			}
		})
	}
}

// T-S-20: the sources signal and fetch are not start loads. An expired bundle
// that runs gives expired for them. Only a start load accepts it.
func TestTS20SignalAndFetchAreNotStartLoads(t *testing.T) {
	e := running(t)
	e.l.now = func() time.Time { return testNow.AddDate(2, 0, 0) }
	for _, src := range []Source{SourceSignal, SourceFetch} {
		p := e.observe(e.l)
		b, err := e.l.LoadFrom(src)
		evs, _ := p.take(t)
		if b != nil || err != ErrExpired || len(evs) != 1 {
			t.Fatalf("%v: bundle %v, err %v, %d events", src, b, err, len(evs))
		}
		if d := detail(t, evs[0]); d["reason"] != "expired" || d["source"] != src.String() {
			t.Errorf("%v: detail %v", src, d)
		}
	}
	if b, err := e.l.LoadFrom(SourceStart); err != nil || !b.Expired() {
		t.Fatalf("start: %v, %v", b, err)
	}
}

// T-U-08: SetEvents and LoadFrom run in parallel goroutines. The race detector
// finds a load that reads the queue and the log without the lock.
func TestTU08SetEventsWithLoadFrom(t *testing.T) {
	e := running(t)
	q, err := event.NewQueue(8, event.NewCounters())
	must(t, err)
	log := slog.New(slog.DiscardHandler)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 20 {
				e.l.SetEvents(q, log)
				if _, err := e.l.LoadFrom(SourceReload); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
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
		if reject != (err == ErrSeedInvalid) || (!reject && err != nil) {
			t.Fatalf("reject %v: err %v", reject, err)
		}
		got, evs := p.take(t)
		if len(evs) != 1 {
			t.Fatalf("%d events", len(evs))
		}
		wantKind, wantReason := event.KindBundleLoad, ""
		if reject {
			wantKind, wantReason = event.KindBundleRejected, "seed_invalid"
		}
		if got[0].Kind() != wantKind || detail(t, got[0])["reason"] != wantReason {
			t.Fatalf("reject %v: kind %v, detail %v", reject, got[0].Kind(), detail(t, got[0]))
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
	for i, s := range []string{"unknown", "start", "signal", "reload", "fetch", "unknown"} {
		if got := Source(i).String(); got != s {
			t.Errorf("Source(%d) = %q, want %q", i, got, s)
		}
	}
	e.l.SetEvents(nil, nil)
	if _, err := e.l.LoadFrom(SourceFetch); err != nil {
		t.Error(err)
	}
	e.l.SetEvents(nil, slog.New(slog.NewTextHandler(p.buf, nil)))
	e.write("bundle/current.sig", []byte(sigRow("k1", ed25519.Sign(e.priv2, nil))))
	if _, err := e.l.LoadFrom(SourceFetch); err != ErrBadSig || strings.Count(p.buf.String(), "reason=bad_sig") != 1 || strings.Count(p.buf.String(), "source=fetch") != 1 {
		t.Error(err, p.buf.String())
	}
}
