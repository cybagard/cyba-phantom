// Package bait serves the pages of the running bundle: the vhost and path
// routes, the assets and the 404 decoy.
package bait

import (
	"net/http"
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
	// mint holds the key-set indexes of one mint. The first acts are the
	// trap actions of the template. The header slots named in names follow.
	// The site build makes it from the bundle of the site.
	mint  []int
	acts  int
	names []string
	// left counts the header slots with no trap in the bundle.
	left int
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
	// traps are the traps of the bundle in file order, so a key-set index is a
	// position in this list. The build makes it from one Traps call.
	traps []bundle.Trap
}

// mintOf gives the entry the key-set indexes of one mint. They are the trap
// actions of its template, then the header slots whose trap is in the bundle.
// A slot with no trap adds to left. pos maps a trap id to its index.
func (e *entry) mintOf(b *bundle.Bundle, pos map[string]int) {
	if e.route.Template != "" {
		e.mint, _ = b.TrapIndexes(e.route.Template)
	}
	e.acts = len(e.mint)
	for _, hs := range e.route.Headers {
		i, ok := pos[hs.Trap]
		if !ok {
			e.left++
			continue
		}
		e.mint = append(e.mint, i)
		e.names = append(e.names, http.CanonicalHeaderKey(hs.Name))
	}
}

// buildSite makes the table of b. It takes the asset names only from the
// route map of each vhost. The loader refuses a route whose asset is missing.
// If Asset still gives false, the build makes no entry for that route. The
// key-set indexes of each route come from b, so only b.Tokens() can use them.
func buildSite(b *bundle.Bundle) *site {
	s := &site{hosts: map[string]map[string]*entry{}, notFound: map[string]*entry{}, traps: b.Traps()}
	pos := make(map[string]int, len(s.traps))
	for i, t := range s.traps {
		pos[t.ID] = i
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
			e.ctype = []string{r.Type}
			e.mintOf(b, pos)
			paths[r.Path] = e
		}
		if rm.NotFound != "" {
			nf := &entry{route: bundle.Route{Template: rm.NotFound}, ctype: htmlType}
			nf.mintOf(b, pos)
			s.notFound[host] = nf
		}
		s.hosts[host] = paths
	}
	return s
}

// slot holds the site of one bundle. once makes the build run one time. count
// is the build counter of the handler.
type slot struct {
	b     *bundle.Bundle
	once  sync.Once
	s     *site
	count *atomic.Int64
}

// site returns the table of b and builds it at the first call.
func (sl *slot) site() *site {
	sl.once.Do(func() {
		sl.count.Add(1)
		sl.s = buildSite(sl.b)
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
