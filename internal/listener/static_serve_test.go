package listener

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"log/slog"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	warnMsg    = `level=WARN msg="static certificate expires in less than 14 days or has expired" name=`
	staticName = "static.test"
	day        = 24 * time.Hour
)

// staticEntry returns the entry of name, parsed at staticNow.
// The leaf ends notAfter after staticNow (zero is one hour).
func staticEntry(t *testing.T, name string, notAfter time.Duration) StaticEntry {
	t.Helper()
	der, keyPEM := leafSpec{dns: []string{name}, notAfter: notAfter}.build(t)
	c, err := ParseStatic(name, blockPEM("CERTIFICATE", der), keyPEM, staticNow)
	mustNil(t, err)
	return StaticEntry{Name: name, Cert: c}
}

// handshakeGet is a handshake over a pipe with the server ALPN list of the
// decoy listener and the given GetCertificate. It returns the client state.
func handshakeGet(get func(*tls.ClientHelloInfo) (*tls.Certificate, error), sni string, protos ...string) (tls.ConnectionState, error) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	dl := time.Now().Add(10 * time.Second)
	c.SetDeadline(dl)
	s.SetDeadline(dl)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tls.Server(s, &tls.Config{GetCertificate: get, NextProtos: []string{"http/1.1", challengeProto}}).Handshake()
	}()
	cl := tls.Client(c, &tls.Config{ServerName: sni, NextProtos: protos, InsecureSkipVerify: true})
	err := cl.Handshake()
	c.Close()
	<-done
	return cl.ConnectionState(), err
}

// sourceWithACME returns a source with the static entries and an ACME client
// for decoy.test. The storage counts reads and OnEgress counts requests.
// The client logs to logger when it is not nil.
func sourceWithACME(t *testing.T, logger *slog.Logger, entries ...StaticEntry) (*CertSource, *countingStorage, *atomic.Int64) {
	t.Helper()
	var cs *countingStorage
	var egress atomic.Int64
	a := newTestACME(t, func(p *ACMEParams) {
		cs = &countingStorage{Storage: p.Storage}
		p.Storage = cs
		p.OnEgress = func(string) { egress.Add(1) }
		if logger != nil {
			p.Logger = logger
		}
	})
	src, err := NewCertSource(entries, a)
	mustNil(t, err)
	return src, cs, &egress
}

// T-S-27, T-S-16: a static name serves its leaf from the first handshake.
// It makes no ACME request and no cache read.
// This holds with and without an ACME client. The cache of the client holds
// another certificate for the static name. A route through it would serve that.
func TestTS27StaticServesLeaf(t *testing.T) {
	for _, withACME := range []bool{true, false} {
		t.Run(map[bool]string{true: "acme", false: "nil acme"}[withACME], func(t *testing.T) {
			e := staticEntry(t, staticName, 0)
			var src *CertSource
			var cs *countingStorage
			var egress *atomic.Int64
			if withACME {
				src, cs, egress = sourceWithACME(t, nil, e)
				other := seedCert(t, src.acme, staticName)
				_, err := src.acme.cfg.CacheManagedCertificate(context.Background(), staticName)
				mustNil(t, err)
				// Control: the client serves its cached certificate here.
				c, err := src.acme.cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: staticName})
				if err != nil || !bytes.Equal(c.Certificate[0], other) || bytes.Equal(other, e.Cert.Certificate[0]) {
					t.Fatalf("control: the client does not serve its cached certificate: %v", err)
				}
				cs.reads.Store(0)
				cs.calls.Store(0)
				egress.Store(0)
			} else {
				var err error
				src, err = NewCertSource([]StaticEntry{e}, nil)
				mustNil(t, err)
			}
			for _, tc := range []struct {
				protos []string
				fails  bool
			}{
				{nil, false},
				{[]string{"http/1.1"}, false},
				{[]string{"acme-tls/1", "http/1.1"}, false},
				{[]string{"acme-tls/1"}, true},
				{[]string{"h2", "acme-tls/1"}, true},
			} {
				st, err := handshakeGet(src.GetCertificate, staticName, tc.protos...)
				if tc.fails {
					if err == nil {
						t.Errorf("ALPN %v: handshake worked", tc.protos)
					}
					continue
				}
				if err != nil || len(st.PeerCertificates) == 0 || !st.PeerCertificates[0].Equal(e.Cert.Leaf) {
					t.Errorf("ALPN %v: err %v, the peer certificate is not the leaf", tc.protos, err)
				}
			}
			if withACME && (cs.reads.Load() != 0 || cs.calls.Load() != 0 || egress.Load() != 0) {
				t.Errorf("storage reads %d, calls %d, ACME requests %d; want 0", cs.reads.Load(), cs.calls.Load(), egress.Load())
			}
		})
	}
}

// T-S-27: the name is normalized as the ACME gate does.
func TestTS27StaticNameVariants(t *testing.T) {
	e := staticEntry(t, staticName, 0)
	src, err := NewCertSource([]StaticEntry{e}, nil)
	mustNil(t, err)
	for _, n := range []string{"STATIC.Test", "static.test.", "Static.TEST."} {
		if c, err := src.GetCertificate(&tls.ClientHelloInfo{ServerName: n}); err != nil || c.Leaf != e.Cert.Leaf {
			t.Errorf("%q: err %v, or not the leaf", n, err)
		}
	}
	for _, n := range []string{"stätic.test", "static.test\xff", "static.test..", "Katic.test"} {
		if _, err := src.GetCertificate(&tls.ClientHelloInfo{ServerName: n}); !errors.Is(err, errName) {
			t.Errorf("%q: err %v; want the name error", n, err)
		}
	}
}

// T-S-16: the refusals of the gate give the reason through a real server, also
// with no ACME client. A static name with acme-tls/1 gives no event.
// An ACME name goes to the ACME client.
// Another name makes no storage call, no request and no log line.
// This holds also with acme-tls/1.
func TestTS16SourceGateReasons(t *testing.T) {
	for _, withACME := range []bool{true, false} {
		t.Run(map[bool]string{true: "acme", false: "nil acme"}[withACME], func(t *testing.T) {
			var logs, std syncBuf
			old := log.Writer()
			log.SetOutput(&std)
			t.Cleanup(func() { log.SetOutput(old) })
			e := staticEntry(t, staticName, 0)
			var src *CertSource
			var cs *countingStorage
			var egress *atomic.Int64
			if withACME {
				logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
				src, cs, egress = sourceWithACME(t, logger, e)
			} else {
				var err error
				src, err = NewCertSource([]StaticEntry{e}, nil)
				mustNil(t, err)
			}
			for _, tc := range []struct {
				sni, reason string
				alpn        []string
			}{
				{"", "no_server_name", nil},
				{otherName, "unknown_name", nil},
				{"café.test", "unknown_name", nil},
				{otherName, "unknown_name", []string{challengeProto}},
				{"café.test", "unknown_name", []string{challengeProto}},
				{staticName, "", []string{challengeProto}},
				{staticName, "", []string{"h2", challengeProto}},
			} {
				q, c := testSinks(t, 16)
				s, err := newServer(Config{TLS: &tls.Config{GetCertificate: src.GetCertificate}, MaxConns: 8, HeaderBytes: testHeaderBytes, Queue: q, Counters: c}, okHandler, defaultTimeouts)
				mustNil(t, err)
				g := &gateRig{rig: &rig{s: s}, closed: watchClosed(s.srv)}
				g.serve(t)
				before := src.Refused()
				g.handshake(t, clientCfg(tc.sni, tc.alpn...))
				waitClosed(t, g.closed)
				g.events(t, tc.reason)
				if got := src.Refused() - before; got != 1 {
					t.Errorf("%q %v: Refused went up by %d, want 1", tc.sni, tc.alpn, got)
				}
			}
			if withACME && (cs.reads.Load() != 0 || cs.calls.Load() != 0 || egress.Load() != 0) {
				t.Errorf("storage reads %d, calls %d, ACME requests %d; want 0", cs.reads.Load(), cs.calls.Load(), egress.Load())
			}
			if logs.String() != "" || std.String() != "" {
				t.Errorf("log output: %q %q", logs.String(), std.String())
			}
		})
	}
	src, _, _ := sourceWithACME(t, nil, staticEntry(t, staticName, 0))
	before := src.Refused()
	hello := &tls.ClientHelloInfo{ServerName: "decoy.test", SupportedProtos: []string{challengeProto}}
	if _, err := src.GetCertificate(hello); !errors.Is(err, errNoChallenge) || src.acme.Refused() != 1 || src.Refused() != before+1 {
		t.Errorf("an ACME name did not go to the ACME client: %v", err)
	}
}

// T-S-27: the constructor refuses these entries with a fixed error.
func TestTS27SourceConstructorRefusals(t *testing.T) {
	e := staticEntry(t, staticName, 0)
	acme := newTestACME(t, func(p *ACMEParams) { p.Names = []string{"decoy.test", staticName} })
	noLeaf := e
	noLeaf.Cert.Leaf = nil
	for _, tc := range []struct {
		name    string
		entries []StaticEntry
		acme    *ACME
		want    error
	}{
		{"overlap", []StaticEntry{e}, acme, ErrSourceOverlap},
		{"duplicate", []StaticEntry{e, e}, nil, ErrSourceDup},
		{"duplicate by case", []StaticEntry{e, {Name: "STATIC.test.", Cert: e.Cert}}, nil, ErrSourceDup},
		{"no leaf", []StaticEntry{noLeaf}, nil, ErrSourceEntry},
		{"no name", []StaticEntry{{Cert: e.Cert}}, nil, ErrSourceEntry},
		{"byte 0x80 in the name", []StaticEntry{{Name: "a\x80.test", Cert: e.Cert}}, nil, ErrSourceEntry},
	} {
		if _, err := NewCertSource(tc.entries, tc.acme); err != tc.want {
			t.Errorf("%s: err %v, want %v", tc.name, err, tc.want)
		}
	}
	// The source keeps its own copy of the DER bytes: a change of the caller
	// does not reach it.
	want := bytes.Clone(e.Cert.Certificate[0])
	entries := []StaticEntry{e}
	src, err := NewCertSource(entries, nil)
	mustNil(t, err)
	entries[0].Name = "changed.test"
	entries[0].Cert.Certificate[0][0] ^= 0xff
	entries[0].Cert.Certificate[0] = nil
	if c, err := src.GetCertificate(&tls.ClientHelloInfo{ServerName: staticName}); err != nil || !bytes.Equal(c.Certificate[0], want) {
		t.Errorf("the source shares the entries of the caller: %v", err)
	}
}

// warnRun runs the warning loop with a frozen clock at now.
// It sends ticks ticks, ends the context, and waits for the goroutine.
// It returns the log text after the call and after the end.
// It also returns the interval of the ticker and whether the ticker stopped.
func warnRun(t *testing.T, src *CertSource, now time.Time, ticks int) (start, end string, every time.Duration, stopped bool) {
	t.Helper()
	var buf syncBuf
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
	tick := make(chan time.Time)
	var stop atomic.Bool
	src.now = func() time.Time { return now }
	src.newTicker = func(d time.Duration) (<-chan time.Time, func()) {
		every = d
		return tick, func() { stop.Store(true) }
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := src.warnExpiry(ctx, logger)
	if every == 0 {
		t.Fatal("the code did not use the ticker hook")
	}
	start = buf.String()
	for range ticks {
		// The loop takes this only after it wrote the lines of the last tick.
		tick <- now
	}
	cancel()
	<-done
	return start, buf.String(), every, stop.Load()
}

// T-S-27: the warning at start and each 24 h, also after the expiry. The leaf
// is still served.
func TestTS27ExpiryWarning(t *testing.T) {
	line := func(n int) string { return strings.Repeat(warnMsg+staticName+"\n", n) }
	for _, tc := range []struct {
		name         string
		notAfter     time.Duration // from staticNow
		clock        time.Duration // from staticNow
		start, ticks int           // lines at start, lines after two ticks
	}{
		{"15 days left", 15 * day, 0, 0, 0},
		{"exactly 14 days left", 14 * day, 0, 0, 0},
		{"13 days left", 13 * day, 0, 1, 3},
		{"expired", time.Hour, 2 * time.Hour, 1, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := staticEntry(t, staticName, tc.notAfter)
			src, err := NewCertSource([]StaticEntry{e}, nil)
			mustNil(t, err)
			start, end, every, stopped := warnRun(t, src, staticNow.Add(tc.clock), 2)
			if start != line(tc.start) || end != line(tc.ticks) {
				t.Errorf("at start %q, at end %q; want %d and %d lines", start, end, tc.start, tc.ticks)
			}
			if every != day || !stopped {
				t.Errorf("ticker interval %v, stopped %v; want 24h, true", every, stopped)
			}
			if st, err := handshakeGet(src.GetCertificate, staticName); err != nil || !st.PeerCertificates[0].Equal(e.Cert.Leaf) {
				t.Errorf("the leaf is not served: %v", err)
			}
		})
	}
}

// T-S-27: a leaf whose NotAfter is before the real clock is served. The leaf
// is parsed at a time inside its period.
func TestTS27ServesLeafAfterNotAfterOnTheRealClock(t *testing.T) {
	der, keyPEM := leafSpec{
		dns: []string{staticName}, notBefore: -10 * 365 * day, notAfter: -9 * 365 * day,
	}.build(t)
	c, err := ParseStatic(staticName, blockPEM("CERTIFICATE", der), keyPEM, staticNow.Add(-9*365*day-time.Hour))
	mustNil(t, err)
	if !c.Leaf.NotAfter.Before(time.Now()) {
		t.Fatal("the leaf does not end before the real clock")
	}
	src, err := NewCertSource([]StaticEntry{{Name: staticName, Cert: c}}, nil)
	mustNil(t, err)
	st, err := handshakeGet(src.GetCertificate, staticName)
	if err != nil || len(st.PeerCertificates) == 0 || !st.PeerCertificates[0].Equal(c.Leaf) {
		t.Errorf("err %v, or the peer certificate is not the expired leaf", err)
	}
}

// T-S-27: only the name that is near expiry gets the line.
func TestTS27ExpiryWarningNamesOnlyTheLeafNearExpiry(t *testing.T) {
	src, err := NewCertSource([]StaticEntry{staticEntry(t, "far.test", 60*day), staticEntry(t, "near.test", 5*day)}, nil)
	mustNil(t, err)
	start, end, _, _ := warnRun(t, src, staticNow, 1)
	want := warnMsg + "near.test\n"
	if start != want || end != want+want {
		t.Errorf("at start %q, at end %q", start, end)
	}
}

// T-S-27: with the real clock hooks unset, the goroutine ends with the context.
func TestTS27ExpiryWarningEndsWithContext(t *testing.T) {
	src, err := NewCertSource([]StaticEntry{staticEntry(t, staticName, 0)}, nil)
	mustNil(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := src.warnExpiry(ctx, nil)
	select {
	case <-done:
		t.Fatal("the goroutine ended before the context")
	default:
	}
	cancel()
	<-done
}

// T-S-27: a nil logger discards the lines of a leaf that is due.
func TestTS27ExpiryWarningNilLogger(t *testing.T) {
	src, err := NewCertSource([]StaticEntry{staticEntry(t, staticName, time.Hour)}, nil)
	mustNil(t, err)
	src.now = func() time.Time { return staticNow.Add(2 * time.Hour) }
	ctx, cancel := context.WithCancel(context.Background())
	done := src.warnExpiry(ctx, nil)
	cancel()
	<-done
}

// T-S-27: no log line and no error holds key bytes, PEM text or a PEM type
// line.
func TestTS27NoKeyMarkers(t *testing.T) {
	var std bytes.Buffer
	old := log.Writer()
	log.SetOutput(&std)
	t.Cleanup(func() { log.SetOutput(old) })

	e := staticEntry(t, staticName, time.Hour)
	var texts []string
	add := func(err error) {
		if err != nil {
			texts = append(texts, err.Error())
		}
	}
	for _, entries := range [][]StaticEntry{{e, e}, {{Name: staticName}}} {
		_, err := NewCertSource(entries, nil)
		add(err)
	}
	acme := newTestACME(t, func(p *ACMEParams) { p.Names = []string{staticName} })
	_, err := NewCertSource([]StaticEntry{e}, acme)
	add(err)
	src, err := NewCertSource([]StaticEntry{e}, nil)
	mustNil(t, err)
	for _, h := range []*tls.ClientHelloInfo{
		{ServerName: otherName}, {}, {ServerName: "é"},
		{ServerName: staticName, SupportedProtos: []string{challengeProto}},
	} {
		_, err := src.GetCertificate(h)
		add(err)
	}
	for _, p := range [][]string{{challengeProto}, {"h2", challengeProto}} {
		_, err := handshakeGet(src.GetCertificate, staticName, p...)
		add(err)
	}
	_, end, _, _ := warnRun(t, src, staticNow.Add(2*time.Hour), 1)
	texts = append(texts, end, std.String())

	key := staticKeySet().p256
	der, err := x509.MarshalPKCS8PrivateKey(key)
	mustNil(t, err)
	markers := []string{"PRIVATE KEY", "BEGIN", key.D.String(), string(der)}
	for _, text := range []string{base64.StdEncoding.EncodeToString(der), hex.EncodeToString(der)} {
		for i := 0; i+16 <= len(text); i++ {
			markers = append(markers, text[i:i+16])
		}
	}
	if !slices.ContainsFunc(texts, func(s string) bool { return strings.Contains(s, staticName) }) {
		t.Fatal("the test saw no output")
	}
	for _, s := range texts {
		for _, m := range markers {
			if strings.Contains(s, m) {
				t.Errorf("output %q holds %q", s, m)
			}
		}
	}
}

// BenchmarkGetCertificateStatic measures one GetCertificate call for a static
// name.
func BenchmarkGetCertificateStatic(b *testing.B) {
	key := staticKeySet().p256
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: []string{staticName}, NotAfter: staticNow}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	mustNil(b, err)
	leaf, err := x509.ParseCertificate(der)
	mustNil(b, err)
	src, err := NewCertSource([]StaticEntry{{Name: staticName, Cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}, nil)
	mustNil(b, err)
	hello := &tls.ClientHelloInfo{ServerName: staticName}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := src.GetCertificate(hello); err != nil {
			b.Fatal(err)
		}
	}
}
