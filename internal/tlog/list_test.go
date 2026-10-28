package tlog

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress"
	"github.com/cybagard/cyba-phantom/internal/egress/egresstest"
)

const privateAddr = "10.1.2.3"

var errStopDial = errors.New("test: stop before the connect")

// namedTarget is a test target whose URL has the host, with a port if host has
// one. The test never contacts the server of the target.
func namedTarget(t *testing.T, host string) *fakeTarget {
	t.Helper()
	f := newTarget(t)
	f.alias = "https://" + host + "/put"
	return f
}

// guardCall is one call of the guard of a dialer, with the result.
type guardCall struct {
	network, address string
	err              error
}

// guardLog records the guard calls of each target.
type guardLog struct {
	mu    sync.Mutex
	calls map[int][]guardCall
}

// find returns the guard call of target i for "network address".
func (l *guardLog) find(i int, want string) (guardCall, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.calls[i] {
		if c.network+" "+c.address == want {
			return c, true
		}
	}
	return guardCall{}, false
}

func (l *guardLog) all(i int) []guardCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]guardCall(nil), l.calls[i]...)
}

// resolveTo keeps the item dialer that NewPublisher makes for each target. It
// gives the dialer a resolver with no network, where each name in names has the
// address addr. It wraps the guard of the dialer. The wrapper records the call.
// When the guard permits the address, it stops the dial before the connect.
func resolveTo(t *testing.T, addr string, names ...string) (publishOption, *guardLog) {
	t.Helper()
	n := egresstest.NewNames(t)
	for _, name := range names {
		n.Set(name, netip.MustParseAddr(addr))
	}
	log := &guardLog{calls: map[int][]guardCall{}}
	opt := func(c *publishConfig) {
		c.dialer = nil
		c.dialerFor = func(i int, d *net.Dialer) *net.Dialer {
			d.Resolver = n.Resolver()
			guard := d.ControlContext
			d.ControlContext = func(ctx context.Context, network, address string, rc syscall.RawConn) error {
				err := guard(ctx, network, address, rc)
				log.mu.Lock()
				log.calls[i] = append(log.calls[i], guardCall{network, address, err})
				log.mu.Unlock()
				if err != nil {
					return err
				}
				return errStopDial
			}
			return d
		}
	}
	return opt, log
}

// T-S-26: a target dials with the item dialer of its own list. A name that
// resolves to a listed private address passes the guard, on the port of the
// URL. The same name for a target with no list, or with another list, fails the
// guard. A refused dial has no address in the error or in the log.
func TestTS26_PublisherDialsWithListOfItsTarget(t *testing.T) {
	ten := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	other := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	for name, second := range map[string][]netip.Prefix{"no list": nil, "another list": other} {
		t.Run(name, func(t *testing.T) {
			a, b := namedTarget(t, "a.tlog.test:8443"), namedTarget(t, "b.tlog.test:443")
			opt, calls := resolveTo(t, privateAddr, "a.tlog.test.", "b.tlog.test.")
			e := newPubLists(t, time.Minute, []*fakeTarget{a, b}, [][]netip.Prefix{ten, second}, opt)
			e.add(t, 1)
			_ = e.spool.Publish(0, e.pub)
			c, ok := calls.find(0, "tcp4 "+privateAddr+":8443")
			if !ok || c.err != nil {
				t.Errorf("listed target: guard calls %v, want tcp4 on the URL port with no error", calls.all(0))
			}
			err := e.spool.Publish(1, e.pub)
			if !errors.Is(err, errPublishAddress) {
				t.Fatalf("target of another list: err = %v, want a refused address", err)
			}
			if c, ok := calls.find(1, "tcp4 "+privateAddr+":443"); !ok || !errors.Is(c.err, egress.ErrRefused) {
				t.Errorf("target of another list: guard calls %v, want a guard error", calls.all(1))
			}
			e.assertClean(t, "error", err.Error())
			e.assertClean(t, "log", e.logs.String())
			for _, s := range []string{err.Error(), e.logs.String()} {
				if strings.Contains(s, privateAddr) {
					t.Errorf("output has the address: %s", s)
				}
			}
		})
	}
}

// T-S-26: a listed target gets the default port 443 when its URL has no port.
// An IPv6 literal in the URL passes the guard with its port.
func TestTS26_ListedTargetAddressText(t *testing.T) {
	for _, tc := range []struct {
		host, list, want string
	}{
		{"c.tlog.test", "10.0.0.0/8", "tcp4 10.1.2.3:443"},
		{"[fd12::1]:8443", "fd00::/8", "tcp6 [fd12::1]:8443"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			a := namedTarget(t, tc.host)
			opt, calls := resolveTo(t, privateAddr, "c.tlog.test.")
			list := []netip.Prefix{netip.MustParsePrefix(tc.list)}
			e := newPubLists(t, time.Minute, []*fakeTarget{a}, [][]netip.Prefix{list}, opt)
			e.add(t, 1)
			_ = e.spool.Publish(0, e.pub)
			if c, ok := calls.find(0, tc.want); !ok || c.err != nil {
				t.Errorf("guard calls %v, want %q with no error", calls.all(0), tc.want)
			}
			e.assertClean(t, "log", e.logs.String())
		})
	}
}

// T-S-26: two targets have the same host and port, with two paths. Only the
// first can dial the address. After a publish to the first, the connection is
// idle. The second target fails the guard. It gets no idle connection of the
// first, and the server sees no new connection and no request.
func TestTS26_TargetsDoNotShareConnections(t *testing.T) {
	a := newTarget(t)
	a.alias = a.URL + "/one"
	b := &fakeTarget{Server: a.Server, alias: a.URL + "/two"}
	allow := egresstest.Dialer(t, dialTimeout, netip.MustParseAddr("127.0.0.1"))
	e := newPub(t, time.Minute, []*fakeTarget{a, b}, func(c *publishConfig) {
		c.dialerFor = func(i int, _ *net.Dialer) *net.Dialer {
			if i == 0 {
				return allow
			}
			return egress.Dialer(dialTimeout)
		}
	})
	e.add(t, 1)
	must(t, e.spool.Publish(0, e.pub))
	if n := a.connCount(); n != 1 {
		t.Fatalf("connections = %d after the first target, want 1", n)
	}
	err := e.spool.Publish(1, e.pub)
	if !errors.Is(err, errPublishAddress) {
		t.Fatalf("second target: err = %v, want a refused address", err)
	}
	if n := a.connCount(); n != 1 {
		t.Errorf("connections = %d after the second target, want 1", n)
	}
	if attempts, _, _ := a.got(); len(attempts) != 1 {
		t.Errorf("the server got %d requests, want 1", len(attempts))
	}
}

// T-S-26: NewPublisher refuses a target whose list has a bad entry. The error
// names the index of the target. It has no address.
func TestTS26_NewPublisherRefusesBadListEntry(t *testing.T) {
	a, b := newTarget(t), newTarget(t)
	e := newPub(t, time.Minute, []*fakeTarget{a, b})
	hostBits := netip.PrefixFrom(netip.MustParseAddr("10.0.0.7"), 8)
	targets := []PublishTarget{
		{URL: a.url(), TokenEnv: tokenVar},
		{URL: b.url(), TokenEnv: tokenVar, Private: []netip.Prefix{hostBits}},
	}
	p, err := NewPublisher(e.spool, targets, time.Minute, nil)
	if err == nil || p != nil {
		t.Fatalf("publisher is nil: %v, error %v, want an error and no publisher", p == nil, err)
	}
	if !strings.Contains(err.Error(), "target 1") {
		t.Errorf("error does not name the target index: %v", err)
	}
	e.assertClean(t, "error", err.Error())
	if strings.Contains(err.Error(), "10.0.0") {
		t.Errorf("error has the address: %v", err)
	}
}

// T-S-26: NewPublisher refuses a target whose URL has port 0 or a port above
// 65535. The error names the index of the target. It has no URL, host or port.
func TestTS26_NewPublisherRefusesBadPort(t *testing.T) {
	for _, port := range []string{"0", "70000"} {
		t.Run(port, func(t *testing.T) {
			root, _ := newState(t)
			t.Setenv(tokenVar, tokenMarker)
			_, verifier := noteKeys(t, testOrigin, 1)
			lg, _ := testLogger()
			urls := []string{"https://a.tlog.test/put", "https://b.tlog.test:" + port + "/put"}
			spool, err := OpenSpool(root, lg, testOrigin, verifier, urls)
			must(t, err)
			targets := []PublishTarget{{URL: urls[0], TokenEnv: tokenVar}, {URL: urls[1], TokenEnv: tokenVar}}
			p, err := NewPublisher(spool, targets, time.Minute, nil)
			if err == nil || p != nil {
				t.Fatalf("publisher is nil: %v, error %v, want an error and no publisher", p == nil, err)
			}
			if !strings.Contains(err.Error(), "target 1") {
				t.Errorf("error does not name the target index: %v", err)
			}
			(&pubEnv{urls: urls}).assertClean(t, "error", err.Error())
			if strings.Contains(err.Error(), port) {
				t.Errorf("error has the port: %v", err)
			}
		})
	}
}
