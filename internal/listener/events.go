package listener

import (
	"net"
	"net/http"
	"sync/atomic"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// recorder makes one request event for each request and puts it on the queue.
type recorder struct {
	q    *event.Queue
	errs atomic.Uint64 // requests for which NewEvent returned an error
}

// record makes the event from r and from code (the status that the handler
// writes). It never reads the body, a forwarded header, or the protocol fields of r. The
// fingerprint values stay empty. A NewEvent error adds one to errs. A full
// queue counts its own drop. The call never waits.
func (rc *recorder) record(r *http.Request, code int) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr // NewEvent refuses a value that is not an address
	}
	st := int64(code)
	e, err := event.NewEvent(nil, event.Input{
		Kind:     event.KindRequest,
		Vhost:    r.Host,
		Method:   r.Method,
		Path:     r.URL.EscapedPath(),
		Status:   &st,
		ClientIP: ip,
	})
	if err != nil {
		rc.errs.Add(1)
		return
	}
	rc.q.Enqueue(e)
}
