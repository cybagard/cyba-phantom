// Package bait serves the pages of the running bundle: the vhost and path
// routes, the assets and the 404 decoy.
package bait

import (
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// entry is one route of a vhost, ready to serve. Only an asset route sets
// asset, isAsset and clen.
type entry struct {
	// route is the route of the entry. After the build, route.Headers is nil:
	// the build copies the slots into slots and names.
	route   bundle.Route
	asset   bundle.Asset
	isAsset bool
	// acts are the key-set indexes of the trap actions of the template. All
	// entries of one template share this slice, so no code may change it.
	acts []int
	// plan is the render plan of the template, or nil. All entries of one
	// template share it. Only a site that the handler keeps has plans.
	plan *plan
	// slots are the key-set indexes of the header slots whose trap is in the
	// bundle. The entry owns this slice. It has the exact length. names has the
	// header name of each slot, in the same order.
	slots []int
	names []string
	// left counts the header slots with no trap in the bundle.
	left int
	// cb is set for a callback route (SEC-37). A callback route has no header
	// slots.
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
	// beacons maps a vhost name to its beacon paths, if the route map has them.
	beacons map[string]*beacon
	// traps are the traps of the bundle in file order, so a key-set index is a
	// position in this list. The build makes it from one Traps call.
	traps []bundle.Trap
	// acts maps a template name to its trap action indexes. The build calls
	// TrapIndexes one time for each name. Each entry of the template shares
	// the slice. The slice has no spare capacity and must not change.
	acts map[string][]int
}

// mintOf gives the entry the key-set indexes of one mint. They are the trap
// actions of its template, then the header slots whose trap is in the bundle.
// The entries of the template share the action part. The entry owns the slot
// part. A slot with no trap adds to left. pos maps a trap id to its index.
func (s *site) mintOf(e *entry, b *bundle.Bundle, pos map[string]int) {
	if name := e.route.Template; name != "" {
		a, ok := s.acts[name]
		if !ok {
			a, _ = b.TrapIndexes(name)
			// Clip leaves no spare capacity, so an append copies the slice.
			a = slices.Clip(a)
			s.acts[name] = a
		}
		e.acts = a
	}
	n := 0
	for _, hs := range e.route.Headers {
		if _, ok := pos[hs.Trap]; ok {
			n++
		}
	}
	e.left = len(e.route.Headers) - n
	if n == 0 {
		return
	}
	e.slots, e.names = make([]int, 0, n), make([]string, 0, n)
	for _, hs := range e.route.Headers {
		if i, ok := pos[hs.Trap]; ok {
			e.slots = append(e.slots, i)
			e.names = append(e.names, http.CanonicalHeaderKey(hs.Name))
		}
	}
}

// buildSite makes the table of b. It takes the asset names only from the
// route map of each vhost. The loader refuses a route whose asset is missing.
// If Asset still gives false, the build makes no entry for that route. The
// key-set indexes of each route come from b. Use them only with b.Tokens().
func buildSite(b *bundle.Bundle) *site { return makeSite(b, nil) }

// buildPlannedSite is buildSite with a render plan for each template that fits
// in the budget. The handler calls it for the site that it keeps only. The
// order of the plans is fixed. It is the sorted vhosts. For each vhost, it is
// the routes in route-map order, then the not_found member. Each template gets
// one try.
func buildPlannedSite(b *bundle.Bundle) *site {
	return makeSite(b, newPlanner(b, b.Traps(), planBudget-planSlack))
}

// makeSite is buildSite with the planner pl. With a nil pl, no template gets a
// plan.
func makeSite(b *bundle.Bundle, pl *planner) *site {
	s := &site{hosts: map[string]map[string]*entry{}, notFound: map[string]*entry{}, beacons: map[string]*beacon{}, traps: b.Traps(), acts: map[string][]int{}}
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
			if r.Callback != nil {
				// A callback route with no asset has no type.
				e.cb = newCallbackPos(r.Callback, host)
				if e.isAsset {
					e.ctype = []string{r.Type}
				}
				paths[r.Path] = e
				continue
			}
			e.ctype = []string{r.Type}
			s.mintOf(e, b, pos)
			e.plan = pl.of(r.Template, e.acts)
			// The build has copied the slots into slots and names. No request
			// reads the headers, so the entry does not keep them.
			e.route.Headers = nil
			paths[r.Path] = e
		}
		if rm.NotFound != "" {
			nf := &entry{route: bundle.Route{Template: rm.NotFound}, ctype: htmlType}
			s.mintOf(nf, b, pos)
			nf.plan = pl.of(rm.NotFound, nf.acts)
			s.notFound[host] = nf
		}
		if rm.Beacon != nil {
			s.beacons[host] = &beacon{rm.Beacon.Script, rm.Beacon.Post, host}
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
		sl.s = buildPlannedSite(sl.b)
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
