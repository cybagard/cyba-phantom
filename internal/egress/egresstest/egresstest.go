// Package egresstest gives a test a dialer and a resolver. The dialer also
// permits the loopback addresses that the test names. The resolver answers
// from memory. Production code never imports this package. The dialer calls
// the production hook for each other address, so the rule stays the same.
package egresstest

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress"
)

// Dialer gives a dialer like egress.Dialer. It also permits each address in
// permit, for each port. Each address must be a loopback address with no zone
// and not in IPv4-mapped form. It fails t when the binary is not a test
// binary or when an address is not valid.
func Dialer(t testing.TB, timeout time.Duration, permit ...netip.Addr) *net.Dialer {
	t.Helper()
	if !testing.Testing() {
		t.Fatalf("egresstest: dialers are for test binaries only")
		return nil
	}
	for _, a := range permit {
		if !a.IsLoopback() || a.Zone() != "" || a.Is4In6() {
			t.Fatalf("egresstest: %v is not a plain loopback address", a)
			return nil
		}
	}
	permit = slices.Clone(permit)
	d := egress.Dialer(timeout)
	production := d.ControlContext
	d.ControlContext = func(
		ctx context.Context, network, address string, c syscall.RawConn,
	) error {
		switch network {
		case "tcp4", "tcp6", "udp4", "udp6":
			if ap, err := netip.ParseAddrPort(address); err == nil &&
				slices.Contains(permit, ap.Addr()) {
				return nil
			}
		}
		return production(ctx, network, address, c)
	}
	return d
}

// Names is a set of host names with the addresses that a Resolver gives.
type Names struct {
	mu    sync.Mutex
	m     map[string][]netip.Addr
	conns []net.Conn
}

// NewNames gives an empty set. It fails t when the binary is not a test
// binary. It closes the connections of its resolvers in t.Cleanup.
func NewNames(t testing.TB) *Names {
	t.Helper()
	if !testing.Testing() {
		t.Fatalf("egresstest: names are for test binaries only")
		return nil
	}
	n := &Names{m: map[string][]netip.Addr{}}
	t.Cleanup(func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		for _, c := range n.conns {
			c.Close()
		}
	})
	return n
}

// Set makes addrs the answers for name. Write name as a full name with a dot
// at the end, in lower case. A later Set replaces the answers.
func (n *Names) Set(name string, addrs ...netip.Addr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.m[name] = slices.Clone(addrs)
}

// Resolver gives a resolver that answers from n with no network.
func (n *Names) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			n.mu.Lock()
			n.conns = append(n.conns, client, server)
			n.mu.Unlock()
			go n.serve(server)
			return client, nil
		},
	}
}

// serve answers the queries on c, which has a 2-byte length before each
// message, until c is closed.
func (n *Names) serve(c net.Conn) {
	defer c.Close()
	for {
		var size [2]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp := n.answer(q)
		if resp == nil {
			return
		}
		msg := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
		if _, err := c.Write(append(msg, resp...)); err != nil {
			return
		}
	}
}

// answer builds the reply to the query q, or nil if q is not a query with one
// question.
func (n *Names) answer(q []byte) []byte {
	var name strings.Builder
	i := 12
	for ; i < len(q) && q[i] != 0; i += int(q[i]) + 1 {
		if q[i] >= 64 || i+int(q[i]) >= len(q) {
			return nil
		}
		name.Write(q[i+1 : i+1+int(q[i])])
		name.WriteByte('.')
	}
	end := i + 5 // the zero byte, the type and the class
	if len(q) < 12 || end > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[end-4:])
	n.mu.Lock()
	addrs, known := n.m[strings.ToLower(name.String())]
	n.mu.Unlock()

	var rdata [][]byte
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() && qtype == 1 {
			rdata = append(rdata, a.AsSlice())
		} else if a.Is6() && qtype == 28 {
			rdata = append(rdata, a.AsSlice())
		}
	}
	flags := uint16(0x8180) // response, recursion desired and available
	if !known {
		flags |= 3 // no such name
	}
	resp := binary.BigEndian.AppendUint16(slices.Clone(q[:2]), flags)
	resp = binary.BigEndian.AppendUint16(resp, 1)
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(rdata)))
	resp = append(resp, 0, 0, 0, 0)
	resp = append(resp, q[12:end]...)
	for _, r := range rdata {
		resp = append(resp, 0xc0, 12) // the name of the question
		resp = binary.BigEndian.AppendUint16(resp, qtype)
		resp = binary.BigEndian.AppendUint16(resp, 1) // class IN
		resp = append(resp, 0, 0, 0, 0)               // time to live
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(r)))
		resp = append(resp, r...)
	}
	return resp
}
