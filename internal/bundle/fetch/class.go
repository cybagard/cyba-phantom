package fetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress"
)

// Class is the fixed class of a fetch failure. It is also the error that the
// client returns, so the error text holds no URL, address or system error.
type Class string

// The classes. The client produces the first seven. A caller records changed
// (the two signature reads differ) and rejected (the loader refused the bundle)
// with Record.
const (
	ClassAddress   Class = "address"
	ClassTLS       Class = "tls"
	ClassTimeout   Class = "timeout"
	ClassRedirect  Class = "redirect"
	ClassStatus    Class = "status"
	ClassSize      Class = "size"
	ClassTransport Class = "transport"
	ClassChanged   Class = "changed"
	ClassRejected  Class = "rejected"
)

var classes = [...]Class{
	ClassAddress, ClassTLS, ClassTimeout, ClassRedirect, ClassStatus,
	ClassSize, ClassTransport, ClassChanged, ClassRejected,
}

func (c Class) Error() string { return "bundle fetch failed: " + string(c) }

// errRedirect is what CheckRedirect gives. The client maps it to ClassRedirect.
var errRedirect = errors.New("bundle fetch: redirect refused")

// Record counts one failure of class. It writes one log line with the class
// and the HTTP status, which is 0 when there is no response. It gives class
// back as the error. A class outside the set above is not counted and not
// logged. The client uses Record for its own failures, so a later caller gets
// the same counter and the same line.
func (c *Client) Record(class Class, status int) error {
	if i := slices.Index(classes[:], class); i >= 0 {
		c.counts[i].Add(1)
		c.log.Warn("bundle fetch failed", "class", string(class), "status", status)
	}
	return class
}

// Count gives the number of failures of class. It is 0 for an unknown class.
func (c *Client) Count(class Class) uint64 {
	if i := slices.Index(classes[:], class); i >= 0 {
		return c.counts[i].Load()
	}
	return 0
}

// Good records the time of a good fetch: a status 200 with a load, or an
// unchanged signature file. The caller decides when a fetch is good.
func (c *Client) Good() { c.lastGood.Store(c.now().UnixNano()) }

// LastGood gives the time that Good recorded last. It is the zero time before
// the first good fetch.
func (c *Client) LastGood() time.Time {
	n := c.lastGood.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// classify maps an error of the HTTP client to a class. It drops the error,
// which holds the URL and the tried address.
func classify(err error) Class {
	var (
		ne   net.Error
		cert *tls.CertificateVerificationError
		hdr  tls.RecordHeaderError
		alrt tls.AlertError
		unk  x509.UnknownAuthorityError
	)
	switch {
	case errors.Is(err, errRedirect):
		return ClassRedirect
	case errors.Is(err, egress.ErrRefused):
		return ClassAddress
	case errors.As(err, &cert), errors.As(err, &hdr), errors.As(err, &alrt), errors.As(err, &unk):
		return ClassTLS
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return ClassTimeout
	}
	return ClassTransport
}
