package listener

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/letsencrypt/challtestsrv"
	pebbleCA "github.com/letsencrypt/pebble/v2/ca"
	pebbleDB "github.com/letsencrypt/pebble/v2/db"
	pebbleVA "github.com/letsencrypt/pebble/v2/va"
	pebbleWFE "github.com/letsencrypt/pebble/v2/wfe"
)

// newOrderPath is the path of the new-order URL of Pebble.
const newOrderPath = "/order-plz"

// pebbleRig is a Pebble CA in the test process. Pebble listens on loopback. The
// DNS server listens on loopback too, and it answers 127.0.0.1 for each name.
type pebbleRig struct {
	dir   string         // the directory URL, with an IP authority
	host  string         // host:port of the directory
	trust *x509.CertPool // a pool that holds the certificate of the directory server (ACMEParams.trustedRoots)
	root  *x509.CertPool // the root that issues the certificates
}

// newPebbleRig starts Pebble. Its validation connects to port tlsPort of the
// name. front may wrap the handler of the CA. t.Setenv panics in a parallel
// test, so a caller of newPebbleRig must not use t.Parallel.
func newPebbleRig(t *testing.T, tlsPort int, front func(http.Handler) http.Handler) *pebbleRig {
	t.Helper()
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")      // no random sleep before a validation
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0") // Pebble rejects no good nonce
	t.Setenv("PEBBLE_AUTHZREUSE", "0")      // each order gets a new challenge
	logger := log.New(io.Discard, "", 0)
	dnsAddr := closedAddr(t)
	dns, err := challtestsrv.New(challtestsrv.Config{Log: logger, DNSAddrs: []string{dnsAddr}})
	mustNil(t, err)
	dns.SetDefaultDNSIPv4("127.0.0.1")
	dns.SetDefaultDNSIPv6("")
	dns.Run()
	t.Cleanup(dns.Shutdown)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if c, err := net.Dial("tcp", dnsAddr); err == nil {
			c.Close()
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("DNS server is not up: %v", err)
		}
	}
	db := pebbleDB.NewMemoryStore()
	ca := pebbleCA.New(logger, db, "", "rsa", 0, 1, map[string]pebbleCA.Profile{"default": {ValidityPeriod: 90 * 24 * 3600}})
	va := pebbleVA.New(logger, 0, tlsPort, true, dnsAddr, db)
	wfe := pebbleWFE.New(logger, db, va, ca, nil, true, false, 0, 0)
	api := wfe.Handler()
	if front != nil {
		api = front(api)
	}
	// With HTTP/1.1, each request of the ACME client calls the proxy function, so
	// the set of authorities that the guard saw covers every request.
	var notHTTP11 atomic.Int64
	t.Cleanup(func() {
		if n := notHTTP11.Load(); n != 0 {
			t.Errorf("Pebble got %d requests that were not HTTP/1.1", n)
		}
	})
	inner := api
	api = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
			notHTTP11.Add(1)
		}
		inner.ServeHTTP(w, r)
	})
	mux := http.NewServeMux() // Pebble serves its roots on a management handler
	mux.Handle("/", api)
	mux.Handle(pebbleWFE.RootCertPath, wfe.ManagementHandler())
	srv := httptest.NewUnstartedServer(mux)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	r := &pebbleRig{dir: srv.URL + pebbleWFE.DirectoryPath, host: strings.TrimPrefix(srv.URL, "https://"), trust: x509.NewCertPool(), root: x509.NewCertPool()}
	r.trust.AddCert(srv.Certificate())
	resp, err := srv.Client().Get(srv.URL + pebbleWFE.RootCertPath + "0")
	mustNil(t, err)
	defer resp.Body.Close()
	pemBytes, err := io.ReadAll(resp.Body)
	mustNil(t, err)
	if !r.root.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("Pebble gave no root certificate: %s %q", resp.Status, pemBytes)
	}
	return r
}

// egressSet records the distinct authorities that the egress guard sees.
type egressSet struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func (e *egressSet) record(host string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.seen == nil {
		e.seen = map[string]struct{}{}
	}
	e.seen[host] = struct{}{}
}

func (e *egressSet) hosts() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := make([]string, 0, len(e.seen))
	for k := range e.seen {
		h = append(h, k)
	}
	slices.Sort(h)
	return h
}

// issueFixture is an ACME with a decoy socket and a Pebble that it uses.
type issueFixture struct {
	a      *ACME
	rig    *pebbleRig
	egress *egressSet
	name   string
	addr   string       // host:port of the decoy socket
	alpn   atomic.Int64 // the handshakes of the decoy socket that negotiated acme-tls/1
}

// newIssueFixture binds the decoy socket, then builds the ACME for name with
// Pebble as the CA. Then it serves the socket with a Server from New and
// GetCertificate of the ACME. It does not call Start.
func newIssueFixture(t *testing.T, name string, front func(http.Handler) http.Handler, mod func(*ACMEParams)) *issueFixture {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	mustNil(t, err)
	t.Cleanup(func() { l.Close() })
	port := l.Addr().(*net.TCPAddr).Port
	f := &issueFixture{name: name, addr: l.Addr().String(), egress: &egressSet{}, rig: newPebbleRig(t, port, front)}
	f.a = newTestACME(t, func(p *ACMEParams) {
		p.Names, p.CA, p.Host, p.Port = []string{name}, f.rig.dir, "127.0.0.1", port
		p.OnEgress, p.trustedRoots = f.egress.record, f.rig.trust
		if mod != nil {
			mod(p)
		}
	})
	s, err := New(Config{TLS: &tls.Config{GetCertificate: f.a.GetCertificate}, MaxConns: 64, HeaderBytes: testHeaderBytes}, okHandler)
	mustNil(t, err)
	// Count the connections that negotiated acme-tls/1, then run the real function.
	next := s.srv.TLSNextProto[challengeProto]
	s.srv.TLSNextProto[challengeProto] = func(sv *http.Server, c *tls.Conn, h http.Handler) {
		f.alpn.Add(1)
		next(sv, c, h)
	}
	go func() { _ = s.Serve(l) }()
	t.Cleanup(func() { _ = s.Close() })
	return f
}

// chain makes a handshake with the decoy socket and returns the chain that it
// serves. The client does not check the chain.
func (f *issueFixture) chain() ([]*x509.Certificate, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", f.addr, &tls.Config{ServerName: f.name, InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates, nil
}

// waitChain polls the decoy socket until it serves a chain that pred accepts, or
// until limit has passed.
func (f *issueFixture) waitChain(t *testing.T, limit time.Duration, pred func(leaf *x509.Certificate) bool) []*x509.Certificate {
	t.Helper()
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if ch, err := f.chain(); err == nil && pred(ch[0]) {
			return ch
		}
	}
	t.Fatalf("no accepted certificate within %v", limit)
	return nil
}

// verifyToPebble checks that chain is a chain for the name that ends at the root
// of Pebble.
func (f *issueFixture) verifyToPebble(t *testing.T, chain []*x509.Certificate) {
	t.Helper()
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: f.rig.root, Intermediates: inter, DNSName: f.name}); err != nil {
		t.Fatalf("the chain does not end at the root of Pebble: %v", err)
	}
}

// onlyPebble fails the test unless the guard has seen the authority of Pebble
// and no other authority.
func (f *issueFixture) onlyPebble(t *testing.T, when string) {
	t.Helper()
	if got := f.egress.hosts(); !slices.Equal(got, []string{f.rig.host}) {
		t.Errorf("%s: guard saw %v, want only %s", when, got, f.rig.host)
	}
}

// requireALPN fails the test unless the decoy socket completed a handshake with
// acme-tls/1, so the TLS-ALPN-01 validation came to the decoy socket.
func (f *issueFixture) requireALPN(t *testing.T) {
	t.Helper()
	if n := f.alpn.Load(); n < 1 {
		t.Errorf("the decoy socket completed %d acme-tls/1 handshakes", n)
	}
}

// listeningInodes returns the inodes of the TCP sockets in the LISTEN state that
// this process holds, with their local address. It reads /proc.
func listeningInodes(t *testing.T) map[string]string {
	t.Helper()
	out, err := listeningSockets()
	mustNil(t, err)
	return out
}

// listeningSockets is listeningInodes with an error result, for a goroutine. An
// IPv4 address is host:port; an IPv6 address stays as /proc writes it.
func listeningSockets() (map[string]string, error) {
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, err
	}
	held := map[string]bool{}
	for _, fd := range fds {
		if l, err := os.Readlink("/proc/self/fd/" + fd.Name()); err == nil && strings.HasPrefix(l, "socket:[") {
			held[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	out := map[string]string{}
	for _, file := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // the header row
		for sc.Scan() {
			if row := strings.Fields(sc.Text()); len(row) > 9 && row[3] == "0A" && held[row[9]] {
				out[row[9]] = procAddr(row[1])
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// procAddr turns a local address of /proc/net/tcp ("0100007F:1F90") into
// "127.0.0.1:8080". It returns any other form as it is.
func procAddr(s string) string {
	ip, port, _ := strings.Cut(s, ":")
	b, err := hex.DecodeString(ip)
	n, perr := strconv.ParseUint(port, 16, 16)
	if err != nil || perr != nil || len(b) != 4 {
		return s
	}
	return net.JoinHostPort(net.IPv4(b[3], b[2], b[1], b[0]).String(), strconv.FormatUint(n, 10))
}
