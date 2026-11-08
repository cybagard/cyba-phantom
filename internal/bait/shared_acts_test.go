package bait

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

// TestTS31SharedActsReadOnly serves the routes of one template from many
// goroutines. The entries share the action indexes of the template. A write to
// them, or an append that fits in spare capacity, is a data race or changes the
// content. So the test checks the race detector, the content and the capacity
// of each shared slice.
func TestTS31SharedActsReadOnly(t *testing.T) {
	const (
		dir     = "vhosts/example.com/"
		actions = 5
		routes  = 4
	)
	specs := make([]trapSpec, 0, actions+1)
	for i := range actions {
		specs = append(specs, trapSpec{fmt.Sprint("t", i), "hidden-p", "x {{.Token}}"})
	}
	specs = append(specs, trapSpec{"h0", "hidden-p", "{{.Token}}"})
	var parts []string
	for i := range routes {
		parts = append(parts, fmt.Sprintf(`{"path":"/r%d","template":"%sp.tmpl","type":"text/html; charset=utf-8",`+
			`"headers":[{"name":"X-Slot-%d","trap":"h0"}]}`, i, dir, i))
	}
	b := bundleFiles(t, "", map[string]string{
		"traps/traps.json":  trapsJSON(specs),
		dir + "routes.json": `{"routes":[` + strings.Join(parts, ",") + `],"not_found":"` + dir + `p.tmpl"}`,
		dir + "p.tmpl":      actionsPage(actions),
	})
	h := New(fixedSource{b}, &fallbackFn{}, testQueue(t))
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			for i := range 50 {
				target := fmt.Sprintf("/r%d", (g+i)%routes)
				if i%routes == 0 {
					target = "/missing"
				}
				serve(t, h, get(target, "example.com"))
			}
		})
	}
	wg.Wait()
	// The count of requests is odd, so a swap in each mint shows in the list.
	serve(t, h, get("/r0", "example.com"))

	s := h.siteOf(b)
	want, ok := b.TrapIndexes(dir + "p.tmpl")
	if !ok || len(want) != actions {
		t.Fatalf("TrapIndexes gives %v, %v, want %d indexes", want, ok, actions)
	}
	if len(s.acts) != 1 {
		t.Fatalf("site has %d action slices, want 1", len(s.acts))
	}
	for name, got := range s.acts {
		if !slices.Equal(got, want) {
			t.Errorf("acts of %s are %v, want %v", name, got, want)
		}
		if cap(got) != len(got) {
			t.Errorf("acts of %s have len %d and cap %d, want no spare capacity", name, len(got), cap(got))
		}
	}
}
