// Package bait serves the pages of the running bundle: the vhost and path
// routes, the assets and the 404 decoy.
package bait

import (
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// entry is one route of a vhost, ready to serve. Only an asset route sets
// asset, isAsset and clen.
type entry struct {
	route   bundle.Route
	asset   bundle.Asset
	isAsset bool
	// slots are the header slots with a valid value. left counts the others.
	slots []slotHeader
	left  int
	// cb is set for a callback route (SEC-37). It has no header slots.
	cb *callbackPos
	// ctype and clen are Content-Type and Content-Length values. A response
	// uses them as they are, so a request allocates no header value. A
	// template route has no clen.
	ctype, clen []string
}

// site is the lookup table of one bundle. It does not change after the build.
type site struct {
	// hosts maps a vhost name to a map from an escaped route path to a route.
	hosts map[string]map[string]*entry
	// notFound maps a vhost name to its 404 template, if the route map has one.
	notFound map[string]*entry
	// texts maps a trap id to its text. The build makes it from one Traps call
	// and one token. A request only reads it.
	texts map[string]string
}

// buildSite makes the table of b. The text of each trap is the instruction of
// the trap with token. It takes the asset names only from the
// route map of each vhost. The loader refuses a route whose asset is missing.
// If Asset still gives false, the build makes no entry for that route.
func buildSite(b *bundle.Bundle, token string) *site {
	traps := b.Traps()
	s := &site{hosts: map[string]map[string]*entry{}, notFound: map[string]*entry{},
		texts: make(map[string]string, len(traps))}
	for _, t := range traps {
		s.texts[t.ID] = t.Render(token)
	}
	for _, host := range b.Vhosts() {
		rm, ok := b.Routes(host)
		if !ok {
			continue
		}
		paths := make(map[string]*entry, len(rm.Routes))
		for _, r := range rm.Routes {
			e := &entry{route: r}
			if r.Asset != "" {
				a, ok := b.Asset(r.Asset)
				if !ok {
					continue
				}
				e.asset, e.isAsset = a, true
				e.clen = []string{strconv.Itoa(a.Len())}
			}
			if r.Callback != nil {
				// A callback route has no header slots. Its 204 has no type.
				e.cb = newCallbackPos(r.Callback)
				if e.isAsset {
					e.ctype = []string{r.Type}
				}
				paths[r.Path] = e
				continue
			}
			e.ctype = []string{r.Type}
			e.slots, e.left = slotHeaders(r.Headers, s.texts)
			paths[r.Path] = e
		}
		if rm.NotFound != "" {
			s.notFound[host] = &entry{route: bundle.Route{Template: rm.NotFound}, ctype: htmlType}
		}
		s.hosts[host] = paths
	}
	return s
}

// slot holds the site of one bundle. once makes the build run one time. count
// is the build counter of the handler. token is the token seam of the handler.
type slot struct {
	b     *bundle.Bundle
	once  sync.Once
	s     *site
	count *atomic.Int64
	token func() string
}

// site returns the table of b and builds it at the first call.
func (sl *slot) site() *site {
	sl.once.Do(func() {
		sl.count.Add(1)
		sl.s = buildSite(sl.b, sl.token())
	})
	return sl.s
}

// maxHost is the size in bytes of the longest host name.
const maxHost = 253

// foldHost removes a port from host and changes A-Z to a-z. It also removes a
// ":" with no digits at the end. It returns false for a host with a byte of
// 0x80 or more, or over maxHost bytes. The result is in buf, so a lookup does
// not allocate.
func foldHost(host string, buf *[maxHost]byte) ([]byte, bool) {
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return nil, false
		}
	}
	i := len(host)
	for i > 0 && host[i-1] >= '0' && host[i-1] <= '9' {
		i--
	}
	if i > 0 && host[i-1] == ':' {
		host = host[:i-1]
	}
	if len(host) > len(buf) {
		return nil, false
	}
	n := copy(buf[:], host)
	for i := 0; i < n; i++ {
		if buf[i] >= 'A' && buf[i] <= 'Z' {
			buf[i] += 'a' - 'A'
		}
	}
	return buf[:n], true
}
