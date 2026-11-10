package listener

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// recorder makes one request event for each request and puts it on the queue.
type recorder struct {
	q    *event.Queue
	errs atomic.Uint64 // requests for which NewEvent returned an error
}

// record makes the event from r and from code (the status that the handler
// writes). vhost is the configured name that the Host matched, or "" when it
// matched none. The event has no vhost for "". It never holds the Host
// (SEC-41).
// record never reads the body, a forwarded header, or the protocol fields
// of r. The fingerprint values stay empty. The path is the value of
// event.RequestPath: it keeps each escape, with upper-case hex digits, and
// holds no control byte. A NewEvent error adds one to errs. A full queue
// counts its own drop. The call never waits.
func (rc *recorder) record(r *http.Request, vhost string, code int) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr // NewEvent refuses a value that is not an address
	}
	// NewEvent refuses a zone. Remove it with WithZone(""), as the refused
	// emitter does. The address is not unmapped.
	if strings.IndexByte(ip, '%') >= 0 {
		if a, err := netip.ParseAddr(ip); err == nil {
			ip = a.WithZone("").String()
		}
	}
	st := int64(code)
	e, err := event.NewEvent(nil, event.Input{
		Kind:     event.KindRequest,
		Vhost:    vhost,
		Method:   r.Method,
		Path:     event.RequestPath(r.URL.RawPath, r.URL.Path),
		Status:   &st,
		ClientIP: ip,
	})
	if err != nil {
		rc.errs.Add(1)
		return
	}
	rc.q.Enqueue(e)
}
