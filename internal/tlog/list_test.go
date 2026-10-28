package tlog

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress"
	"github.com/cybagard/cyba-phantom/internal/egress/egresstest"
)

const privateAddr = "10.1.2.3"

// namedTarget is a test target whose URL has a host name and a port. The
// server of the target is not used: the name resolves to a private address.
func namedTarget(t *testing.T, name, port string) *fakeTarget {
	f := newTarget(t)
	f.alias = "https://" + name + ":" + port + "/put"
	return f
}

// resolveTo gives the publisher the dialers that NewPublisher makes, with a
// resolver that has no network. Each name in names resolves to addr.
func resolveTo(t *testing.T, addr string, names ...string) publishOption {
	n := egresstest.NewNames(t)
	for _, name := range names {
		n.Set(name, netip.MustParseAddr(addr))
	}
	return func(c *publishConfig) {
		c.dialer = nil
		c.dialerFor = func(_ int, d *net.Dialer) *net.Dialer {
			d.Resolver = n.Resolver()
			return d
		}
	}
}

// T-S-26: a target dials with the item dialer of its own list. A name that
// resolves to a listed private address passes the control step, on the port of
// the URL. The same name for a target with no list, or with another list, is
// refused. A refused dial has no address in the error or in the log. In a test
// with no network, a permitted dial fails with another error than the guard
// error.
func TestTS26_PublisherDialsWithListOfItsTarget(t *testing.T) {
	ten := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	other := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	for name, second := range map[string][]netip.Prefix{"no list": nil, "another list": other} {
		t.Run(name, func(t *testing.T) {
			a, b := namedTarget(t, "a.tlog.test", "8443"), namedTarget(t, "b.tlog.test", "443")
			opt := resolveTo(t, privateAddr, "a.tlog.test.", "b.tlog.test.")
			e := newPubLists(t, time.Minute, []*fakeTarget{a, b}, [][]netip.Prefix{ten, second}, opt)
			e.add(t, 1)
			err := e.spool.Publish(0, e.pub)
			if err == nil || errors.Is(err, errPublishAddress) {
				t.Fatalf("listed target: err = %v, want a failed dial that the guard did not refuse", err)
			}
			err = e.spool.Publish(1, e.pub)
			if !errors.Is(err, errPublishAddress) {
				t.Fatalf("target of another list: err = %v, want a refused address", err)
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

// T-S-26: two targets have the same host and port, with two paths. Only the
// first may dial the address. After a publish to the first, the connection is
// idle. The second target is refused. It gets no idle connection of the
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
