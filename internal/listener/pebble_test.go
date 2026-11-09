package listener

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	trust *ACMERoots     // roots with the directory server certificate
	root  *x509.CertPool // the root that issues the certificates
	db    *pebbleDB.MemoryStore
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
	r := &pebbleRig{dir: srv.URL + pebbleWFE.DirectoryPath, host: strings.TrimPrefix(srv.URL, "https://"), trust: mustRoots(t, certPEM(srv.Certificate())), root: x509.NewCertPool(), db: db}
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

// egressRecorder records the authorities that the egress guard sees, in the
// order of the calls. It is the one egress recorder of the package tests.
type egressRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (e *egressRecorder) record(host string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seen = append(e.seen, host)
}

// calls returns each recorded authority, one for each call of the guard.
func (e *egressRecorder) calls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.seen)
}

// hosts returns the distinct authorities, sorted.
func (e *egressRecorder) hosts() []string {
	h := e.calls()
	slices.Sort(h)
	return slices.Compact(h)
}

// issueFixture is an ACME with a decoy socket and a Pebble that it uses.
type issueFixture struct {
	a      *ACME
	rig    *pebbleRig
	egress *egressRecorder
	name   string
	addr   string       // host:port that a client dials to reach the decoy socket
	listen string       // the local address of the decoy socket
	alpn   atomic.Int64 // the handshakes of the decoy socket that negotiated acme-tls/1
}

// newIssueFixture binds the decoy socket, then builds the ACME for name with
// Pebble as the CA. Then it serves the socket with a Server from New and
// GetCertificate of the ACME. It does not call Start.
func newIssueFixture(t *testing.T, name string, front func(http.Handler) http.Handler, mod func(*ACMEParams)) *issueFixture {
	t.Helper()
	return newIssueFixtureOn(t, "127.0.0.1:0", "127.0.0.1", name, front, mod)
}

// newIssueFixtureOn is newIssueFixture with the listen address of the decoy
// socket and the Host of the ACMEParams as parameters. When the listen address
// is a wildcard, f.addr is the loopback address of the same port, because a
// client cannot dial a wildcard address, and f.listen is the listen address.
func newIssueFixtureOn(t *testing.T, listen, host, name string, front func(http.Handler) http.Handler, mod func(*ACMEParams)) *issueFixture {
	t.Helper()
	l, err := net.Listen("tcp", listen)
	mustNil(t, err)
	t.Cleanup(func() { l.Close() })
	port := l.Addr().(*net.TCPAddr).Port
	addr := l.Addr().String()
	if l.Addr().(*net.TCPAddr).IP.IsUnspecified() {
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	f := &issueFixture{name: name, addr: addr, listen: l.Addr().String(), egress: &egressRecorder{}, rig: newPebbleRig(t, port, front)}
	f.a = newTestACME(t, func(p *ACMEParams) {
		p.Names, p.CA, p.Host, p.Port = []string{name}, f.rig.dir, host, port
		p.OnEgress, p.CARoots = f.egress.record, f.rig.trust
		if mod != nil {
			mod(p)
		}
	})
	q, c := testSinks(t, 16)
	s, err := New(Config{TLS: &tls.Config{GetCertificate: f.a.GetCertificate}, MaxConns: 64, HeaderBytes: testHeaderBytes, Queue: q, Counters: c}, okHandler)
	mustNil(t, err)
	// Count the connections that negotiated acme-tls/1. Then run the real
	// function. The Config of the Server has no hook for this count, and a
	// hook there would be a product change. The count must be of handshakes
	// that ended well. A hook in the TLS config sees each hello that offers
	// acme-tls/1, also when the handshake fails. TLSNextProto runs only after
	// a good handshake, so the test wraps it.
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

// requireServes fails the test unless the decoy socket serves the certificate
// want. The message tells a failed handshake from another leaf.
func (f *issueFixture) requireServes(t *testing.T, want *x509.Certificate, what string) {
	t.Helper()
	ch, err := f.chain()
	if err != nil {
		t.Fatalf("%s: handshake failed: %v", what, err)
	}
	if !ch[0].Equal(want) {
		t.Fatalf("%s: served serial %v, subject %q; want serial %v", what, ch[0].SerialNumber, ch[0].Subject, want.SerialNumber)
	}
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

// requireBindRefused fails the test unless a new bind of addr fails with
// "address already in use". The decoy socket holds addr.
func requireBindRefused(t *testing.T, addr, when string) {
	t.Helper()
	if l, err := net.Listen("tcp", addr); err == nil {
		l.Close()
		t.Fatalf("%s: a second listener bound the solver address %s", when, addr)
	} else if !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("%s: second bind: %v", when, err)
	}
}

// watchListeners samples the listening TCP sockets of the process every
// millisecond. The sockets in before may listen. The function that it returns
// stops the sampler, and it fails the test if no sample was read or if a socket
// that is not in before listened in any sample. It is safe to call it twice, and
// the test calls it again at cleanup.
func watchListeners(t *testing.T, before map[string]string) (finish func()) {
	t.Helper()
	// The goroutine writes these. finish reads them after done.
	var samples, failed int
	var lastErr error
	var extra []string
	quit, done := make(chan struct{}), make(chan struct{})
	go func() { // no t.Fatal here
		defer close(done)
		for stop := false; !stop; {
			select {
			case <-quit:
				stop = true
			case <-time.After(time.Millisecond):
			}
			now, err := listeningSockets()
			if err != nil {
				failed, lastErr = failed+1, err
				continue
			}
			samples++
			for inode, addr := range now {
				if _, ok := before[inode]; !ok && !slices.Contains(extra, addr) {
					extra = append(extra, addr)
				}
			}
		}
	}()
	var once sync.Once
	finish = func() {
		once.Do(func() {
			close(quit)
			<-done
			t.Logf("%d samples of the listening sockets, %d failed reads of /proc (last error: %v)", samples, failed, lastErr)
			if samples == 0 {
				t.Error("no sample of the listening sockets was read, so the check saw nothing")
			}
			if len(extra) != 0 {
				t.Errorf("new listening sockets since before Start: %v", extra)
			}
		})
	}
	t.Cleanup(finish)
	return finish
}

// mustListeningSockets is listeningSockets that fails the test on an error.
func mustListeningSockets(t *testing.T) map[string]string {
	t.Helper()
	out, err := listeningSockets()
	mustNil(t, err)
	return out
}

// listeningSockets returns the inodes of the TCP sockets in the LISTEN state
// that this process holds. The value of each inode is the local address as
// host:port. It reads /proc. It returns an error, so a goroutine can use it.
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

// procAddr turns a local address of /proc/net/tcp ("0100007F:1F90") or of
// /proc/net/tcp6 into "127.0.0.1:8080". An IPv4-mapped address becomes an
// IPv4 address. Any other form stays as it is. The kernel prints each 32-bit
// word of the address with %08X (get_tcp4_sock, get_tcp6_sock). That is a
// number in the byte order of the host, so the decode uses
// binary.NativeEndian. No test runs on a big-endian host.
func procAddr(s string) string {
	ip, port, _ := strings.Cut(s, ":")
	b, err := hex.DecodeString(ip)
	n, perr := strconv.ParseUint(port, 16, 16)
	if err != nil || perr != nil || (len(b) != 4 && len(b) != 16) {
		return s
	}
	for i := 0; i < len(b); i += 4 {
		binary.NativeEndian.PutUint32(b[i:], binary.BigEndian.Uint32(b[i:]))
	}
	addr, _ := netip.AddrFromSlice(b)
	return net.JoinHostPort(addr.Unmap().String(), strconv.FormatUint(n, 10))
}

// TestTS16ProcAddrDecodesIPv4AndIPv6 builds the /proc form of an address. It
// writes the form as the kernel does. Then it checks that procAddr gives the
// address back.
func TestTS16ProcAddrDecodesIPv4AndIPv6(t *testing.T) {
	for _, c := range []struct{ ip, want string }{
		{"127.0.0.1", "127.0.0.1:8080"},
		{"::", "[::]:8080"},
		{"::1", "[::1]:8080"},
		{"2001:db8::1", "[2001:db8::1]:8080"},
		{"::ffff:10.0.0.1", "10.0.0.1:8080"},
	} {
		b := netip.MustParseAddr(c.ip).AsSlice()
		var in strings.Builder
		for i := 0; i < len(b); i += 4 {
			fmt.Fprintf(&in, "%08X", binary.NativeEndian.Uint32(b[i:]))
		}
		if got := procAddr(in.String() + ":1F90"); got != c.want {
			t.Errorf("procAddr(%s:1F90) = %q, want %q", in.String(), got, c.want)
		}
	}
}
