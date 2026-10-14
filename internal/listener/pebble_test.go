package listener

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
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

// pebbleRig is a Pebble CA in the test process. It listens on loopback, and so
// does the DNS server that gives 127.0.0.1 for each name.
type pebbleRig struct {
	dir   string         // the directory URL, with an IP authority
	host  string         // host:port of the directory
	trust *x509.CertPool // the TLS certificate of the directory server (ACMEParams.TrustedRoots)
	root  *x509.CertPool // the root that issues the certificates
}

// newPebbleRig starts Pebble. Its validation connects to port tlsPort of the
// name. front may wrap the handler of the CA. Pebble reads the environment when
// it starts, so a caller of newPebbleRig must not use t.Parallel.
func newPebbleRig(t *testing.T, tlsPort int, front func(http.Handler) http.Handler) *pebbleRig {
	t.Helper()
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")      // no random sleep before a validation
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0") // no good nonce is rejected
	t.Setenv("PEBBLE_AUTHZREUSE", "0")      // each order gets a new challenge
	logger := log.New(io.Discard, "", 0)
	dnsAddr := closedAddr(t)
	dns, err := challtestsrv.New(challtestsrv.Config{Log: logger, DNSAddrs: []string{dnsAddr}})
	mustNil(t, err)
	dns.SetDefaultDNSIPv4("127.0.0.1")
	dns.SetDefaultDNSIPv6("")
	go dns.Run()
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
	addr   string // host:port of the decoy socket
}

// newIssueFixture binds the decoy socket first. It answers on that socket only,
// with GetCertificate of the ACME, and with acme-tls/1 in its ALPN list. Then it
// builds the ACME for name, with Pebble as the CA. It does not call Start.
func newIssueFixture(t *testing.T, name string, front func(http.Handler) http.Handler, mod func(*ACMEParams)) *issueFixture {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	mustNil(t, err)
	t.Cleanup(func() { l.Close() })
	port := l.Addr().(*net.TCPAddr).Port
	f := &issueFixture{name: name, addr: l.Addr().String(), egress: &egressSet{}, rig: newPebbleRig(t, port, front)}
	f.a = newTestACME(t, func(p *ACMEParams) {
		p.Names, p.CA, p.Host, p.Port = []string{name}, f.rig.dir, "127.0.0.1", port
		p.OnEgress, p.TrustedRoots = f.egress.record, f.rig.trust
		if mod != nil {
			mod(p)
		}
	})
	tl := tls.NewListener(l, &tls.Config{GetCertificate: f.a.GetCertificate, NextProtos: []string{"acme-tls/1"}})
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				c.(*tls.Conn).Handshake()
			}()
		}
	}()
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

// listeningInodes returns the inodes of the TCP sockets in the LISTEN state that
// this process holds, with their local address. It reads /proc.
func listeningInodes(t *testing.T) map[string]string {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	mustNil(t, err)
	held := map[string]bool{}
	for _, fd := range fds {
		if l, err := os.Readlink("/proc/self/fd/" + fd.Name()); err == nil && strings.HasPrefix(l, "socket:[") {
			held[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	out := map[string]string{}
	for _, file := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		f, err := os.Open(file)
		mustNil(t, err)
		sc := bufio.NewScanner(f)
		sc.Scan() // the header row
		for sc.Scan() {
			if row := strings.Fields(sc.Text()); len(row) > 9 && row[3] == "0A" && held[row[9]] {
				out[row[9]] = row[1]
			}
		}
		f.Close()
	}
	return out
}
