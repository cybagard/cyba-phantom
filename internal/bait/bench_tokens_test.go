package bait

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// mintCases are the token counts of one mint and the reference values of
// allocations and bytes for the mint. 68 is the 64 trap actions of a template
// and the 4 header slots of a route.
var mintCases = []struct{ n, allocs, bytes int }{
	{1, 4, 480}, {16, 36, 3544}, {64, 132, 14169}, {68, 140, 14745},
}

// mintFixture is a handler and a route whose mint has n tokens. The first 64
// are trap actions. The rest are header slots.
type mintFixture struct {
	h *Handler
	b *bundle.Bundle
	s *site
	e *entry
}

func newMintFixture(tb testing.TB, n int) mintFixture {
	tb.Helper()
	acts := min(n, 64)
	var ids []string
	var page strings.Builder
	for i := range acts {
		ids = append(ids, fmt.Sprint("t", i))
		fmt.Fprintf(&page, `<p>{{index .Trap "t%d"}}</p>`, i)
	}
	heads := []string{"h0", "h1", "h2", "h3"}[:n-acts]
	b := slotBundle(tb, append(ids, heads...), page.String(), heads)
	s := buildSite(b)
	return mintFixture{New(fixedSource{b}, &fallbackFn{}, testQueue(tb)), b, s, s.hosts["example.com"]["/t"]}
}

// mintSink keeps the result of a mint, so the compiler cannot remove the call.
var mintSink minted

// run is one mint with the time of testDay.
func (f mintFixture) run() {
	mintSink = f.h.mint(f.b, f.s, f.e, &reqSession{at: testDay})
}

// BenchmarkTS31Mint measures the mint step of a render for each token count of
// mintCases.
func BenchmarkTS31Mint(b *testing.B) {
	for _, c := range mintCases {
		b.Run(fmt.Sprint("N=", c.n), func(b *testing.B) { benchMint(b, newMintFixture(b, c.n)) })
	}
}

func benchMint(b *testing.B, f mintFixture) {
	b.ReportAllocs()
	for b.Loop() {
		f.run()
	}
}

// TestTS31MintBounds checks the mint step for 1, 16, 64 and 68 tokens. It
// allocates at most the reference value plus 10 %. testing.AllocsPerRun gives
// the allocations of one mint. The bytes are the growth of TotalAlloc in
// runtime.ReadMemStats over 100 mints, after one warm-up mint, divided by 100.
// With -race, N=68 allocated 147 times on the commit of this test. The limit
// is 154.
func TestTS31MintBounds(t *testing.T) {
	const runs = 100
	var before, after runtime.MemStats
	for _, c := range mintCases {
		f := newMintFixture(t, c.n)
		got := f.h.mint(f.b, f.s, f.e, &reqSession{at: testDay})
		if len(got.slots)+len(got.page.Trap) != c.n || f.h.noKeys.Load() != 0 {
			t.Fatalf("N=%d: mint gives %d texts, noKeys %d", c.n, len(got.slots)+len(got.page.Trap), f.h.noKeys.Load())
		}
		for id, v := range got.page.Trap {
			if !tokenRE.MatchString(v) {
				t.Fatalf("N=%d: trap text of %s has no token", c.n, id)
			}
		}
		for _, sh := range got.slots {
			if len(sh.val) != 1 || !tokenRE.MatchString(sh.val[0]) {
				t.Fatalf("N=%d: header slot %s has no token", c.n, sh.name)
			}
		}
		allocs := testing.AllocsPerRun(100, f.run)
		f.run()
		runtime.ReadMemStats(&before)
		for range runs {
			f.run()
		}
		runtime.ReadMemStats(&after)
		bytes := (after.TotalAlloc - before.TotalAlloc) / runs
		t.Logf("N=%d: %v allocations, %d bytes", c.n, allocs, bytes)
		if limit := c.allocs + c.allocs/10; allocs > float64(limit) {
			t.Errorf("N=%d: %v allocations, limit %d", c.n, allocs, limit)
		}
		if limit := uint64(c.bytes + c.bytes/10); bytes > limit {
			t.Errorf("N=%d: %d bytes, limit %d", c.n, bytes, limit)
		}
	}
}
