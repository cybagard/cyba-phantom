package bait

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// tmplName is the archive name of the template of the route /t of example.com.
const tmplName = "vhosts/example.com/t.tmpl"

const (
	hexSet    = "abcdef234567"
	letterSet = "ghijklmnopqrstuvwxyz"
)

// tokClasses are the classes of the first and last character of a test token.
// They are any, hex digits, other letters, and the two mixes.
var tokClasses = [][2]string{{alphabet, alphabet}, {hexSet, hexSet}, {letterSet, letterSet}, {hexSet, letterSet}, {letterSet, hexSet}}

// tokOf makes a token text of 26 characters. The first and last character are
// from class.
func tokOf(rng *rand.Rand, class [2]string) string {
	b := make([]byte, 26)
	for i := range b {
		b[i] = alphabet[rng.IntN(len(alphabet))]
	}
	b[0], b[25] = class[0][rng.IntN(len(class[0]))], class[1][rng.IntN(len(class[1]))]
	return string(b)
}

// setTokens makes h give toks as the token texts of the actions of the next
// renders, in order.
func setTokens(h *Handler, toks []string) {
	calls := 0
	h.text = func([token.Size]byte) string {
		calls++
		return toks[(calls-1)%len(toks)]
	}
}

// planContexts are the escaper contexts of the tests. %s is the place of the
// actions.
var planContexts = []struct{ name, text string }{
	{"html text", `<p>%s</p>`},
	{"attr dq", `<p title="%s">`},
	{"attr sq", `<p title='%s'>`},
	{"attr unquoted", `<p title=%s>`},
	{"rcdata textarea", `<textarea>%s</textarea>`},
	{"rcdata title", `<title>%s</title>`},
	{"script dq string", `<script>var a="%s";</script>`},
	{"script sq string", `<script>var a='%s';</script>`},
	{"script template literal", "<script>var a=`%s`;</script>"},
	{"script value", `<script>var a=%s;</script>`},
	{"script regexp", `<script>var a=/%s/;</script>`},
	{"ld+json string", `<script type="application/ld+json">{"a":"%s"}</script>`},
	{"onclick dq js sq", `<p onclick="f('%s')">`},
	{"onclick sq js dq", `<p onclick='f("%s")'>`},
	{"onclick unq js value", `<p onclick=%s>`},
	{"onclick dq js value", `<p onclick="f(%s)">`},
	{"onclick dq template literal", "<p onclick=\"f(`%s`)\">"},
	{"style css dq", `<style>p{content:"%s"}</style>`},
	{"style attr css sq", `<p style="content:'%s'">`},
	{"style attr unq css dq", `<p style='content:"%s"'>`},
	{"css url sq", `<p style="background:url('/x?%s')">`},
	{"href query dq", `<a href="/x?q=%s">`},
	{"href path dq", `<a href="/x/%s">`},
	{"href start", `<a href="%s">`},
	{"srcset", `<img srcset="%s">`},
	{"srcdoc", `<iframe srcdoc="%s"></iframe>`},
	{"meta content", `<meta name="description" content="%s">`},
	{"attr name value", `<p %s=1>`},
	{"attr name only", `<p %s>`},
	{"attr name quoted value", `<p %s="v">`},
	{"css value", `<style>p{color:%s}</style>`},
	{"css value attr", `<p style="color: %s">`},
}

// noPlanContexts are the contexts that get no plan. In a CSS string, the escape
// of the byte before a token depends on the token. So the two runs differ. In
// an attribute name and in a CSS value, a filter refuses the marker.
var noPlanContexts = map[string]bool{
	"style css dq": true, "style attr css sq": true, "style attr unq css dq": true,
	"attr name value": true, "attr name only": true, "attr name quoted value": true,
	"css value": true, "css value attr": true,
}

// execOf runs the template name of b as a render with no plan does. toks has
// one token text for each action.
func execOf(b *bundle.Bundle, name string, toks []string) (string, error) {
	traps, page := b.Traps(), bundle.Page{Trap: map[string]string{}}
	idx, _ := b.TrapIndexes(name)
	for i, ix := range idx {
		page.Trap[traps[ix].ID] = traps[ix].Render(toks[i])
	}
	var sb strings.Builder
	err := b.Execute(&sb, name, page)
	return sb.String(), err
}

// planHandler returns a handler for b.
func planHandler(tb testing.TB, b *bundle.Bundle) *Handler {
	return New(&swap{list: []*bundle.Bundle{b}}, &fallbackFn{}, testQueue(tb))
}

// installSite makes s the kept site of h for b.
func installSite(h *Handler, b *bundle.Bundle, s *site) {
	sl := &slot{b: b, count: &h.builds}
	sl.once.Do(func() { sl.s = s })
	h.sites.Store(&state{cur: sl})
}

// plansOf gives the plan of each template of s, or nil, by template name.
func plansOf(s *site) map[string]*plan {
	out := map[string]*plan{}
	for _, paths := range s.hosts {
		for _, e := range paths {
			if e.route.Template != "" {
				out[e.route.Template] = e.plan
			}
		}
	}
	for _, e := range s.notFound {
		out[e.route.Template] = e.plan
	}
	return out
}

// planCount is the size of p against the budget. It is the capacity of each
// array in bytes, at least 16 for an array that is not empty. It adds the 80
// bytes of the plan struct.
func planCount(p *plan) int {
	n := 80
	for _, c := range []int{cap(p.fixed), 4 * cap(p.offs), cap(p.acts)} {
		if c > 0 {
			n += max(c, 16)
		}
	}
	return n
}

var sink any

// TestTS28PlanHeapCount checks that the count is the heap. The heap of one
// slice made with append equals its capacity in bytes, for some lengths. For
// a slice under 16 bytes it is 16. The heap of a plan struct equals planHeader.
func TestTS28PlanHeapCount(t *testing.T) {
	// heapOf is the least TotalAlloc difference of one call in 50 tries. Other
	// goroutines can only add to a try.
	heapOf := func(mk func() any) uint64 {
		best := ^uint64(0)
		for range 50 {
			var a, b runtime.MemStats
			runtime.ReadMemStats(&a)
			sink = mk()
			runtime.ReadMemStats(&b)
			best = min(best, b.TotalAlloc-a.TotalAlloc)
		}
		return best
	}
	for _, n := range []int{1, 33, 1000, 40000, 464773} {
		x := make([]byte, n)
		var c int
		got := heapOf(func() any { s := append([]byte(nil), x...); c = cap(s); return &s[0] })
		if got != uint64(max(c, 16)) || c < n {
			t.Errorf("%d bytes: heap %d, capacity %d", n, got, c)
		}
		y := make([]uint32, n)
		got = heapOf(func() any { s := append([]uint32(nil), y...); c = 4 * cap(s); return &s[0] })
		if got != uint64(max(c, 16)) || c < 4*n {
			t.Errorf("%d words: heap %d, capacity in bytes %d", n, got, c)
		}
	}
	if got := heapOf(func() any { return &plan{} }); got != planHeader || unsafe.Sizeof(plan{}) > planHeader {
		t.Errorf("plan struct: heap %d, size %d, planHeader %d", got, unsafe.Sizeof(plan{}), planHeader)
	}
}

// TestTS28PlanEquality checks that a page with a plan has the bytes of Execute,
// for both action forms in each context. The trap texts have escaped bytes
// before and after the token. The tokens start and end with a hex digit or
// another letter. A context with no plan must give the Execute bytes and count
// one for each page.
func TestTS28PlanEquality(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	rounds := 2 * len(tokClasses)
	for _, form := range []string{"index", "comment"} {
		affixes := []string{"", "<", `"`, "&", "\x00", " "}
		act := func(id string) string { return `{{index .Trap "` + id + `"}}` }
		if form == "comment" {
			affixes = []string{"", `"`, "&", " "}
			act = func(id string) string { return `{{comment (index .Trap "` + id + `")}}` }
		}
		for _, c := range planContexts {
			t.Run(form+"/"+c.name, func(t *testing.T) {
				var specs []trapSpec
				var acts strings.Builder
				add := func(text string) {
					id := fmt.Sprint("t", len(specs))
					specs = append(specs, trapSpec{id, "hidden-p", text})
					acts.WriteString(act(id))
				}
				for _, pre := range affixes {
					for _, suf := range affixes {
						add(pre + "{{.Token}}" + suf)
					}
				}
				// A trap with no token and a trap with two tokens.
				add("plain")
				add("{{.Token}} {{.Token}}")
				b := tmplBundle(t, specs, map[string][]route{"example.com": {{"/t", "t.tmpl", html, fmt.Sprintf(c.text, acts.String())}}})
				h := planHandler(t, b)
				hasPlan := h.siteOf(b).hosts["example.com"]["/t"].plan != nil
				if form == "index" && hasPlan == noPlanContexts[c.name] || form == "comment" && c.name == "html text" && !hasPlan {
					t.Errorf("plan = %v", hasPlan)
				}
				for round := range rounds {
					toks := make([]string, len(specs))
					for i := range toks {
						toks[i] = tokOf(rng, tokClasses[(round+i)%len(tokClasses)])
					}
					want, err := execOf(b, tmplName, toks)
					if err != nil {
						t.Fatal(err)
					}
					setTokens(h, toks)
					if got := serve(t, h, get("/t", "example.com")).Body.String(); got != want {
						t.Fatalf("round %d: page differs from Execute\n got %q\nwant %q", round, got, want)
					}
				}
				if got, want := h.noPlan.Load(), int64(rounds); hasPlan && got != 0 || !hasPlan && got != want {
					t.Errorf("noPlan = %d with plan %v, want %d without a plan", got, hasPlan, want)
				}
			})
		}
	}
}

// TestTS28PlanFallback checks the templates that get no plan. Each renders with
// Execute, gives the same bytes and counts one for each page.
func TestTS28PlanFallback(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for _, c := range []struct {
		name, tmpl, trap string
		execErr          bool
	}{
		{"url filter", `<a href="{{index .Trap "t0"}}">`, "js:{{.Token}}", false},
		{"comment refusal", `<p>{{comment (index .Trap "t0")}}</p>`, "a<{{.Token}}", false},
		{"escape error", `<p onclick=f('{{index .Trap "t0"}}')>`, "x {{.Token}}", true},
		{"marker in the template", `<p>` + markerOf(0, 0) + `{{index .Trap "t0"}}</p>`, "x {{.Token}}", false},
		{"marker of run 2 in the template", `<p>` + markerOf(0, 1) + `{{index .Trap "t0"}}</p>`, "x {{.Token}}", false},
		{"marker in a trap text", `<p>{{index .Trap "t0"}}</p>`, markerOf(0, 1) + "{{.Token}}", false},
		{"marker of run 1 in a trap text", `<p>{{index .Trap "t0"}}</p>`, markerOf(0, 0) + "{{.Token}}", false},
		{"marker of another action in a trap text", `<p>{{index .Trap "t0"}}</p>`, markerOf(5, 0) + "{{.Token}}", false},
		{"alphabet at the start, no action", alphabet + "!", "x {{.Token}}", false},
		{"two runs differ", `<style>p{content:"{{index .Trap "t0"}}"}</style>`, "<{{.Token}}", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := tmplBundle(t, []trapSpec{{"t0", "hidden-p", c.trap}}, map[string][]route{"example.com": {{"/t", "t.tmpl", html, c.tmpl}}})
			h := planHandler(t, b)
			if h.siteOf(b).hosts["example.com"]["/t"].plan != nil {
				t.Fatal("the template has a plan")
			}
			for i, class := range tokClasses[1:3] {
				tok := []string{tokOf(rng, class)}
				want, err := execOf(b, tmplName, tok)
				if (err != nil) != c.execErr {
					t.Fatalf("Execute error = %v", err)
				}
				setTokens(h, tok)
				w := serve(t, h, get("/t", "example.com"))
				if c.execErr {
					want = string(notFoundBody)
				}
				if got := w.Body.String(); got != want || c.execErr == (w.Code == http.StatusOK) {
					t.Errorf("code %d body %q, want %q", w.Code, got, want)
				}
				if n := h.noPlan.Load(); n != int64(i+1) {
					t.Errorf("noPlan = %d, want %d", n, i+1)
				}
			}
		})
	}
}

// orderBundle has two vhosts with two routes and a not_found template each.
// The not_found template is larger than the others.
func orderBundle(tb testing.TB) *bundle.Bundle {
	page := func(n int) string { return "<p>" + strings.Repeat("f", n) + `{{index .Trap "t0"}}</p>` }
	files := map[string]string{"traps/traps.json": trapsJSON([]trapSpec{{"t0", "hidden-p", "x {{.Token}}"}})}
	for _, host := range []string{"m.example", "b.example"} {
		dir := "vhosts/" + host + "/"
		files[dir+"routes.json"] = fmt.Sprintf(`{"routes":[{"path":"/1","template":"%[1]sone.tmpl","type":"text/html; charset=utf-8"},`+
			`{"path":"/2","template":"%[1]stwo.tmpl","type":"text/html; charset=utf-8"}],"not_found":"%[1]snf.tmpl"}`, dir)
		files[dir+"one.tmpl"], files[dir+"two.tmpl"], files[dir+"nf.tmpl"] = page(500), page(500), page(1100)
	}
	return bundleFiles(tb, "", files)
}

// templateOrder is the order of the plans. It is the sorted vhosts. For each
// vhost, it is the routes in route-map order, then the not_found template.
func templateOrder(b *bundle.Bundle) (names []string) {
	add := func(n string) {
		if n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	for _, host := range b.Vhosts() {
		rm, _ := b.Routes(host)
		for _, r := range rm.Routes {
			add(r.Template)
		}
		add(rm.NotFound)
	}
	return names
}

// TestTS28PlanOrder checks that the budget goes to the templates in the fixed
// order. A template that does not fit gets no plan and a later one that fits
// gets one. When the budget is full, the build runs no more marker runs.
func TestTS28PlanOrder(t *testing.T) {
	b := orderBundle(t)
	names := templateOrder(b)
	cost := map[string]int{}
	for name, p := range plansOf(makeSite(b, newPlanner(b, b.Traps(), planBudget))) {
		if p == nil {
			t.Fatalf("%s has no plan with the full budget", name)
		}
		if p.size() != planCount(p) {
			t.Errorf("%s: size %d, count %d", name, p.size(), planCount(p))
		}
		cost[name] = planCount(p)
	}
	one, two, nf, mOne := "vhosts/b.example/one.tmpl", "vhosts/b.example/two.tmpl", "vhosts/b.example/nf.tmpl", "vhosts/m.example/one.tmpl"
	if names[0] != one || names[1] != two || names[2] != nf || !slices.Contains(names, mOne) {
		t.Fatalf("order = %v", names)
	}
	// The budget fits the first two plans. It does not fit the large
	// not_found template. It fits the plans of example.com and of the first
	// route of m.example. A run writes its markers too. The margin of 100
	// bytes lets the last run reach its end.
	budget := cost[one] + cost[two] + cost[tmplName] + cost[mOne] + 100
	pl := newPlanner(b, b.Traps(), budget)
	s := makeSite(b, pl)
	got, left := plansOf(s), budget
	for _, name := range names {
		want := cost[name] <= left
		if want {
			left -= cost[name]
		}
		if (got[name] != nil) != want {
			t.Errorf("%s: plan = %v, want %v", name, got[name] != nil, want)
		}
	}
	if got[nf] != nil || got[mOne] == nil {
		t.Errorf("not_found of b.example has a plan: %v, first route of m.example has one: %v", got[nf] != nil, got[mOne] != nil)
	}
	// A page of a template over the budget renders with Execute and counts one.
	h := planHandler(t, b)
	installSite(h, b, s)
	for _, c := range []struct {
		path, name string
		code       int
		counted    int64
	}{{"/1", one, 200, 0}, {"/nope", nf, 404, 1}} {
		tok := []string{tokOf(rand.New(rand.NewPCG(5, 6)), tokClasses[0])}
		want, err := execOf(b, c.name, tok)
		mustOK(t, err)
		setTokens(h, tok)
		w := serve(t, h, get(c.path, "b.example"))
		if w.Code != c.code || w.Body.String() != want || h.noPlan.Load() != c.counted {
			t.Errorf("%s: code %d, noPlan %d, page differs: %v", c.path, w.Code, h.noPlan.Load(), w.Body.String() != want)
		}
	}
	// Four templates with no action and 100 bytes each, and a budget of two
	// plans. The first two plans fill it. No marker run follows.
	files := map[string]string{}
	var routes []string
	for i := range 4 {
		files[fmt.Sprintf("vhosts/b.example/%d.tmpl", i)] = strings.Repeat("f", 100)
		routes = append(routes, fmt.Sprintf(`{"path":"/%d","template":"vhosts/b.example/%d.tmpl","type":"text/html; charset=utf-8"}`, i, i))
	}
	files["vhosts/b.example/routes.json"] = `{"routes":[` + strings.Join(routes, ",") + `]}`
	fb := bundleFiles(t, "", files)
	one100 := planCount(plansOf(makeSite(fb, newPlanner(fb, fb.Traps(), planBudget)))["vhosts/b.example/0.tmpl"])
	pl = newPlanner(fb, fb.Traps(), 2*one100)
	got = plansOf(makeSite(fb, pl))
	if pl.runs != 4 || pl.left != 0 || got["vhosts/b.example/1.tmpl"] == nil || got["vhosts/b.example/2.tmpl"] != nil {
		t.Errorf("runs = %d, left = %d, plans %v, want 4 runs, left 0, plans for the first two", pl.runs, pl.left, got)
	}
}

// TestTS28PlanRunWriter checks the cap of a marker run. A write to exactly the
// cap is kept. One more byte is refused.
func TestTS28PlanRunWriter(t *testing.T) {
	w := runWriter{max: 10}
	if n, err := w.Write(make([]byte, 10)); n != 10 || err != nil {
		t.Errorf("write of the cap: %d, %v", n, err)
	}
	if n, err := w.Write([]byte{1}); n != 0 || err != errPlanOver || w.buf.Len() != 10 {
		t.Errorf("write over the cap: %d, %v, %d bytes kept", n, err, w.buf.Len())
	}
	v := runWriter{max: 10}
	if _, err := v.Write(make([]byte, 11)); err != errPlanOver || v.buf.Len() != 0 {
		t.Errorf("write of cap + 1: %v, %d bytes kept", err, v.buf.Len())
	}
}

// TestTS28PlanCut checks cut with output that a template can make. Each
// marker check has a case where it alone refuses. The want lists with 224 and
// 255 hold the values that a bad index character gives. So only the check of
// the index character refuses these. 64 is the first action position over the
// cap. 256 is the first one that wraps in a byte.
func TestTS28PlanCut(t *testing.T) {
	head := markerHead(0)
	m := func(hi, lo byte) string { return head + alphabet + string(hi) + string(lo) + "7" }
	for _, c := range []struct {
		name, out string
		want      []uint8
		fixed     string // the fixed bytes if the output is accepted
	}{
		{"marker alone", markerOf(0, 0), []uint8{0}, ""},
		{"marker with text", "x" + markerOf(3, 0) + "y", []uint8{3}, "xy"},
		{"last position", m('b', '7'), []uint8{63}, ""},
		{"alphabet at the start", alphabet + "x", nil, "refused"},
		{"cut at the end", "x" + head + alphabet + "a", []uint8{0}, "refused"},
		{"first edge", "z" + markerWords + alphabet + "aa7", []uint8{0}, "refused"},
		{"words", "a" + markerWords[:len(markerWords)-1] + "x" + alphabet + "aa7", []uint8{0}, "refused"},
		{"head too short", "a" + alphabet + "aa7", []uint8{0}, "refused"},
		{"last edge", head + alphabet + "aaz", []uint8{0}, "refused"},
		{"high character", m('!', 'a'), []uint8{224}, "refused"},
		{"low character", m('a', '!'), []uint8{255}, "refused"},
		{"position 64", m('c', 'a'), []uint8{64}, "refused"},
		{"position 256", m('i', 'a'), []uint8{0}, "refused"},
		{"other action", markerOf(1, 0), []uint8{0}, "refused"},
		{"marker of run 2", markerOf(0, 1), []uint8{0}, "refused"},
	} {
		got := cut([]byte(c.out), 0, c.want)
		if c.fixed == "refused" {
			if got != nil {
				t.Errorf("%s: output accepted", c.name)
			}
			continue
		}
		if got == nil || string(got.fixed) != c.fixed || !slices.Equal(got.acts, c.want) {
			t.Errorf("%s: output refused or wrong plan %+v", c.name, got)
		}
	}
}

// writeSizes is a response writer that keeps the size and the bytes of each
// write.
type writeSizes struct {
	*discard
	sizes []int
	body  strings.Builder
}

func (w *writeSizes) Write(p []byte) (int, error) {
	w.sizes = append(w.sizes, len(p))
	w.body.Write(p)
	return len(p), nil
}

// serveSizes serves the route /t of b with the token texts toks. It gives the
// writer, which has the sizes and the bytes of the writes.
func serveSizes(h *Handler, b *bundle.Bundle, toks []string) *writeSizes {
	setTokens(h, toks)
	w, r := &writeSizes{discard: &discard{h: http.Header{}}}, get("/t", "example.com")
	s := h.sessionOf(r)
	h.serve(w, r, b, &s)
	return w
}

// TestTS28PlanTokenText checks the token texts at the limit of the scratch
// array. A text of 32 bytes renders from the plan: the first write is the
// fixed bytes before the token. A text of 33 bytes renders with Execute: the
// first write is the text before the action. The test compares the bytes with
// Execute. A second case has two actions and the long text on the second. The
// first action then needs its trap text for Execute.
func TestTS28PlanTokenText(t *testing.T) {
	b := tmplBundle(t, []trapSpec{{"t0", "hidden-p", "x {{.Token}}"}, {"t1", "hidden-p", "y {{.Token}}"}},
		map[string][]route{"example.com": {{"/t", "t.tmpl", html, `<p>{{index .Trap "t0"}}</p>`}}})
	for _, c := range []struct{ n, first int }{{31, 5}, {32, 5}, {33, 3}} {
		h := planHandler(t, b)
		toks := []string{strings.Repeat("a", c.n)}
		w := serveSizes(h, b, toks)
		want, err := execOf(b, tmplName, toks)
		mustOK(t, err)
		if len(w.sizes) != 3 || w.sizes[0] != c.first || h.noPlan.Load() != 0 || w.body.String() != want {
			t.Errorf("text of %d bytes: write sizes %v, noPlan %d, want first %d, bytes equal %v", c.n, w.sizes, h.noPlan.Load(), c.first, w.body.String() == want)
		}
	}
	b2 := tmplBundle(t, []trapSpec{{"t0", "hidden-p", "x {{.Token}}"}, {"t1", "hidden-p", "y {{.Token}}"}},
		map[string][]route{"example.com": {{"/t", "t.tmpl", html, `<p>{{index .Trap "t0"}}</p><p>{{index .Trap "t1"}}</p>`}}})
	for _, n := range []int{32, 33} {
		toks := []string{"first-token", strings.Repeat("b", n)}
		w := serveSizes(planHandler(t, b2), b2, toks)
		want, err := execOf(b2, tmplName, toks)
		mustOK(t, err)
		if w.body.String() != want || !strings.Contains(want, "x first-token") {
			t.Errorf("second text of %d bytes: page %q, want %q", n, w.body.String(), want)
		}
	}
}

// TestTS28PlanNoAction checks a page with a plan and no trap action. It
// renders from its plan in one write. Execute writes the two text nodes of this
// template apart, because a template comment splits the text.
func TestTS28PlanNoAction(t *testing.T) {
	b := tmplBundle(t, []trapSpec{{"t0", "hidden-p", "x {{.Token}}"}},
		map[string][]route{"example.com": {{"/t", "t.tmpl", html, `<p>a</p>{{/* c */}}<p>b</p>`}}})
	h := planHandler(t, b)
	if h.siteOf(b).hosts["example.com"]["/t"].plan == nil {
		t.Fatal("the page has no plan")
	}
	w := serveSizes(h, b, []string{"unused"})
	if w.body.String() != "<p>a</p><p>b</p>" || len(w.sizes) != 1 || h.noPlan.Load() != 0 {
		t.Errorf("page %q, write sizes %v, noPlan %d, want one write", w.body.String(), w.sizes, h.noPlan.Load())
	}
	var sb strings.Builder
	mustOK(t, b.Execute(&sb, tmplName, bundle.Page{}))
	if sb.String() != w.body.String() {
		t.Errorf("Execute gives %q", sb.String())
	}
}

// TestTS28PlanFilters checks the filters of html/template that look at the
// whole value. In an attribute name and in a CSS value, the page must have the
// Execute bytes for tokens that a filter refuses. The template gets no plan.
// Each page counts one in noPlan.
func TestTS28PlanFilters(t *testing.T) {
	pad := func(s string) string { return s + strings.Repeat("b", 26-len(s)) }
	for _, c := range []struct{ name, tmpl, trap, tok string }{
		{"on event name", `<p {{index .Trap "t0"}}=1>x</p>`, "o{{.Token}}", pad("nerror")},
		{"on at the start", `<p {{index .Trap "t0"}}>x</p>`, "{{.Token}}", pad("onx")},
		{"url in a name", `<p {{index .Trap "t0"}}>x</p>`, "{{.Token}}", pad("xxurl")},
		{"src in a name", `<p {{index .Trap "t0"}}>x</p>`, "{{.Token}}", pad("xsrc")},
		{"uri in a name", `<p {{index .Trap "t0"}}="v">x</p>`, "{{.Token}}", pad("xuri")},
		{"expression after text", `<p style="color: {{index .Trap "t0"}}">x</p>`, "expressio{{.Token}}", pad("n")},
		{"mozbinding after text", `<style>p{color: {{index .Trap "t0"}}}</style>`, "mozbindin{{.Token}}", pad("g")},
		{"expression before text", `<style>p{color:{{index .Trap "t0"}}}</style>`, "{{.Token}}xpression", strings.Repeat("b", 25) + "e"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := tmplBundle(t, []trapSpec{{"t0", "hidden-p", c.trap}}, map[string][]route{"example.com": {{"/t", "t.tmpl", html, c.tmpl}}})
			h := planHandler(t, b)
			if h.siteOf(b).hosts["example.com"]["/t"].plan != nil {
				t.Fatal("the template has a plan")
			}
			want, err := execOf(b, tmplName, []string{c.tok})
			mustOK(t, err)
			setTokens(h, []string{c.tok})
			got := serve(t, h, get("/t", "example.com")).Body.String()
			if got != want || !strings.Contains(want, "ZgotmplZ") || h.noPlan.Load() != 1 {
				t.Errorf("page %q, want %q, noPlan %d", got, want, h.noPlan.Load())
			}
		})
	}
}

// TestTS28PlanMarkers checks the form of a marker. Each marker has the three
// words that the filters of html/template refuse. The first and last character
// of a marker in run 1 are hex digits of the token alphabet. Those of a marker
// in run 2 are letters that are not hex digits.
func TestTS28PlanMarkers(t *testing.T) {
	for run := range 2 {
		for _, act := range []int{0, 1, 31, 32, 63} {
			m := markerOf(act, run)
			for _, w := range []string{"src", "expression", "mozbinding", alphabet} {
				if !strings.Contains(m, w) {
					t.Errorf("run %d action %d: marker %q has no %q", run, act, m, w)
				}
			}
			first, last := m[0], m[len(m)-1]
			isHex := func(c byte) bool { return strings.IndexByte(hexSet, c) >= 0 }
			isOther := func(c byte) bool { return strings.IndexByte(letterSet, c) >= 0 }
			if run == 0 && !(isHex(first) && isHex(last)) || run == 1 && !(isOther(first) && isOther(last)) {
				t.Errorf("run %d: edges %q and %q", run, first, last)
			}
		}
	}
}

// TestTS28PlanWriteString checks writeString for texts around the size of the
// scratch array: the bytes written are the text.
func TestTS28PlanWriteString(t *testing.T) {
	b := newBundle(t)
	for _, n := range []int{0, 1, 31, 32, 33, 100} {
		rec, text := httptest.NewRecorder(), strings.Repeat("k", n)
		cw := capWriter{w: rec, h: planHandler(t, b), sess: &reqSession{}, code: 200}
		if err := cw.writeString(text); err != nil || rec.Body.String() != text {
			t.Errorf("%d bytes: error %v, wrote %d bytes", n, err, rec.Body.Len())
		}
	}
}

// TestTS28PlanEdges checks a page that starts and ends with a token. Its plan
// exists and the page is equal to Execute.
func TestTS28PlanEdges(t *testing.T) {
	b := tmplBundle(t, []trapSpec{{"t0", "hidden-p", "{{.Token}}"}},
		map[string][]route{"example.com": {{"/t", "t.tmpl", html, `{{index .Trap "t0"}}`}}})
	h := planHandler(t, b)
	p := h.siteOf(b).hosts["example.com"]["/t"].plan
	if p == nil {
		t.Fatal("the page has no plan")
	}
	// The plan has no fixed bytes and one cut. Its arrays are under 16 bytes.
	if len(p.fixed) != 0 || len(p.offs) != 1 || p.size() != planCount(p) || p.size() != 80+16+16 {
		t.Errorf("plan size %d, count %d, %d fixed bytes, %d cuts", p.size(), planCount(p), len(p.fixed), len(p.offs))
	}
	tok := []string{tokOf(rand.New(rand.NewPCG(7, 8)), tokClasses[0])}
	setTokens(h, tok)
	if got := serve(t, h, get("/t", "example.com")).Body.String(); got != tok[0] || h.noPlan.Load() != 0 {
		t.Errorf("page %q, noPlan %d, want %q", got, h.noPlan.Load(), tok[0])
	}
}

// TestTS28PlanMintFails checks a page with a plan when the mint fails. The
// page renders with Execute and empty trap texts. The plan is not used and
// nothing counts in noPlan. A page with no action does the same with no map.
func TestTS28PlanMintFails(t *testing.T) {
	for _, c := range []struct{ tmpl, want string }{{`<p>{{index .Trap "t0"}}</p>`, "<p></p>"}, {"<p>fixed</p>", "<p>fixed</p>"}} {
		b := tmplBundle(t, []trapSpec{{"t0", "hidden-p", "x {{.Token}}"}},
			map[string][]route{"example.com": {{"/t", "t.tmpl", html, c.tmpl}}})
		h := planHandler(t, b)
		if h.siteOf(b).hosts["example.com"]["/t"].plan == nil {
			t.Fatal("the page has no plan")
		}
		h.keys = func(*bundle.Bundle) *token.KeySet { return nil }
		w := serve(t, h, get("/t", "example.com"))
		wantKeys := int64(1)
		if c.tmpl == "<p>fixed</p>" {
			wantKeys = 0
		}
		if w.Body.String() != c.want || h.noKeys.Load() != wantKeys || h.noPlan.Load() != 0 {
			t.Errorf("%q: body %q, noKeys %d, noPlan %d", c.tmpl, w.Body.String(), h.noKeys.Load(), h.noPlan.Load())
		}
	}
}

// TestTS28PlanOverBudget checks a plan that passes the cap of its run but has a
// size over the budget left. The page has 1007 bytes, and the plan counts 1104.
func TestTS28PlanOverBudget(t *testing.T) {
	b := bundleFiles(t, "", map[string]string{
		"vhosts/b.example/routes.json": `{"routes":[{"path":"/1","template":"vhosts/b.example/x.tmpl","type":"text/html; charset=utf-8"}]}`,
		"vhosts/b.example/x.tmpl":      "<p>" + strings.Repeat("f", 1000) + "</p>",
	})
	pl := newPlanner(b, b.Traps(), 1010)
	if p := pl.of("vhosts/b.example/x.tmpl", nil); p != nil || pl.left != 1010 || pl.w.peak != 1007 {
		t.Errorf("plan %t, left %d, peak %d, want no plan, 1010 and 1007", p != nil, pl.left, pl.w.peak)
	}
	pl = newPlanner(b, b.Traps(), 1110)
	if p := pl.of("vhosts/b.example/x.tmpl", nil); p == nil || p.size() != 1104 || pl.left != 6 {
		t.Errorf("plan %t, left %d, want a plan of 1104", p != nil, pl.left)
	}
}

// TestTS28PlanOneTry checks that a template gets one try. A template on three
// routes runs two marker runs, and the three entries share one plan. A template
// with no plan runs one marker run, and the three entries have none. The
// bundle has the template of example.com too: two runs.
func TestTS28PlanOneTry(t *testing.T) {
	for _, c := range []struct {
		trap, tmpl string
		runs       int
		plan       bool
	}{{"x {{.Token}}", `<p>{{index .Trap "t0"}}</p>`, 4, true}, {"js:{{.Token}}", `<a href="{{index .Trap "t0"}}">`, 3, false}} {
		var routes []string
		for _, p := range []string{"/1", "/2", "/3"} {
			routes = append(routes, `{"path":"`+p+`","template":"vhosts/b.example/x.tmpl","type":"text/html; charset=utf-8"}`)
		}
		b := bundleFiles(t, "", map[string]string{
			"traps/traps.json":             trapsJSON([]trapSpec{{"t0", "hidden-p", c.trap}}),
			"vhosts/b.example/routes.json": `{"routes":[` + strings.Join(routes, ",") + `]}`,
			"vhosts/b.example/x.tmpl":      c.tmpl,
		})
		pl := newPlanner(b, b.Traps(), planBudget)
		paths := makeSite(b, pl).hosts["b.example"]
		first := paths["/1"].plan
		if pl.runs != c.runs || (first != nil) != c.plan || paths["/2"].plan != first || paths["/3"].plan != first {
			t.Errorf("%q: %d runs, want %d; plans %p %p %p", c.trap, pl.runs, c.runs, first, paths["/2"].plan, paths["/3"].plan)
		}
	}
}

// TestTS28PlanWork checks the cap of the work. In this shape the two marker
// runs of each template differ, because the last trap is in a CSS string. No
// plan is made, and each template costs two runs. The runs stop at the work
// cap. The next templates get no run.
func TestTS28PlanWork(t *testing.T) {
	kinds := make([]rune, pageActions)
	for i := range kinds {
		kinds[i] = '<'
		if i < 37 {
			kinds[i] = 0
		}
	}
	page := mixPage(37, pageActions-1) + `<style>p{content:"{{index .Trap "t63"}}"}</style>`
	files := map[string]string{"traps/traps.json": rawTraps(kinds)}
	for i := range mostVhosts {
		dir := fmt.Sprintf("vhosts/v%d.example/", i)
		files[dir+"routes.json"] = fmt.Sprintf(`{"routes":[{"path":"/p","template":"%sp.tmpl","type":"text/html; charset=utf-8"}]}`, dir)
		files[dir+"p.tmpl"] = page
	}
	b := bundleFiles(t, "", files)
	pl := newPlanner(b, b.Traps(), planBudget)
	s := makeSite(b, pl)
	kept := 0
	for name, p := range plansOf(s) {
		if p != nil && name != tmplName {
			kept++
		}
	}
	t.Logf("%d marker runs, %d bytes of run output, %d plans", pl.runs, pl.runBytes, kept)
	if kept != 0 || pl.runBytes > planWork || pl.work != 0 || pl.runs < 20 || pl.runs > 60 {
		t.Errorf("runs %d, run bytes %d (work %d), work left %d, plans %d", pl.runs, pl.runBytes, planWork, pl.work, kept)
	}
}

// TestTS28PlanRunCap checks that a marker run stops at the budget that is left:
// its output never passes the cap.
func TestTS28PlanRunCap(t *testing.T) {
	b := orderBundle(t)
	pl := newPlanner(b, b.Traps(), 300)
	got := plansOf(makeSite(b, pl))
	if pl.w.peak == 0 || pl.w.peak > 300 {
		t.Errorf("peak of a run = %d, want from 1 to 300", pl.w.peak)
	}
	for name, p := range got {
		if p != nil && name != tmplName {
			t.Errorf("%s has a plan", name)
		}
	}
}

// TestTS28PlanNotKept checks that a site that the handler does not keep has no
// plan. It checks both ways of siteOf. They are a retired bundle, and a bundle
// with a lower load sequence than the kept one.
func TestTS28PlanNotKept(t *testing.T) {
	planOf := func(s *site) *plan { return s.hosts["example.com"]["/t"].plan }
	low, older, newer := bundleAt(t, "-0", "2026.11.01-1"), bundleAt(t, "-1", "2026.11.01-1"), bundleAt(t, "-2", "2026.11.01-2")
	h := planHandler(t, newer)
	h.siteOf(older)
	if planOf(h.siteOf(newer)) == nil {
		t.Fatal("the kept site has no plan")
	}
	if planOf(h.siteOf(older)) != nil {
		t.Error("the site of a retired bundle has a plan")
	}
	if planOf(h.siteOf(low)) != nil {
		t.Error("the site of a bundle with a lower sequence has a plan")
	}
}

// rawTraps makes traps/traps.json by hand: "<" stays raw and U+0000 is \u0000.
// Trap i has the rune of kinds[i], repeated to fill 1 KiB with one token.
func rawTraps(kinds []rune) string {
	parts := make([]string, len(kinds))
	for i, r := range kinds {
		enc := string(r)
		if r == 0 {
			enc = `\u0000`
		}
		parts[i] = fmt.Sprintf(`{"id":"t%d","slot":"hidden-p","surface":"path","visibility":"human-visible","instruction_template":"%s{{.Token}}"}`,
			i, strings.Repeat(enc, (1<<10-10)/utf8.RuneLen(r)))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// mixPage puts the actions t0 to t(nul-1) in an unquoted attribute and the
// others of n in a JS string.
func mixPage(nul, n int) string {
	var a, b strings.Builder
	for i := range n {
		w := &a
		if i >= nul {
			w = &b
		}
		fmt.Fprintf(w, `{{index .Trap "t%d"}}`, i)
	}
	return `<p title=` + a.String() + `>x</p><script>var a="` + b.String() + `";</script>`
}

// fillShape makes the files of the fill shape. It has 9 vhosts with a template
// of the largest escape growth. Then it has 600 templates with one trap
// action. The size of these falls by about 2 bytes from one to the next. So
// the budget fills to within a few bytes. A bundle has 512 KiB of templates at
// most.
func fillShape(vhostShape func(int, string, string) map[string]string, kinds []rune) map[string]string {
	small := `{"id":"s0","slot":"hidden-p","surface":"path","visibility":"human-visible","instruction_template":"{{.Token}}"}`
	files := vhostShape(9, mixPage(37, pageActions), strings.TrimSuffix(rawTraps(kinds), "]")+","+small+"]")
	var routes [3][]string
	for j := range 600 {
		host := fmt.Sprintf("vhosts/w%d.example/", j/200)
		files[fmt.Sprintf("%sp%d.tmpl", host, j)] = "<p>" + strings.Repeat("f", 1300-13*j/6) + `{{index .Trap "s0"}}</p>`
		routes[j/200] = append(routes[j/200], fmt.Sprintf(`{"path":"/p%d","template":"%sp%d.tmpl","type":"text/html; charset=utf-8"}`, j, host, j))
	}
	for i, rs := range routes {
		files[fmt.Sprintf("vhosts/w%d.example/routes.json", i)] = `{"routes":[` + strings.Join(rs, ",") + `]}`
	}
	return files
}

// TestTS28PlanBudget checks the plans of one site at three shapes: the largest
// escape growth, the most cuts and a fill. The count of the plans is at most
// 4 MiB. The heap of the plans is at most 4 MiB, with no margin. The templates
// past the budget have no plan. The size of a plan is the count of the test.
// The measure uses two collections before each read, so the memory of a pool
// does not count. The heap is near the count, and it can differ by a few KB.
func TestTS28PlanBudget(t *testing.T) {
	kinds, dense := make([]rune, pageActions), make([]trapSpec, pageActions)
	for i := range kinds {
		kinds[i] = '<'
		if i < 37 {
			kinds[i] = 0
		}
		dense[i] = trapSpec{fmt.Sprint("t", i), "hidden-p", strings.Repeat("{{.Token}}", 102)}
	}
	vhostShape := func(k int, page, traps string) map[string]string {
		files := map[string]string{"traps/traps.json": traps}
		for i := range k {
			dir := fmt.Sprintf("vhosts/v%d.example/", i)
			files[dir+"routes.json"] = fmt.Sprintf(`{"routes":[{"path":"/p","template":"%sp.tmpl","type":"text/html; charset=utf-8"}]}`, dir)
			files[dir+"p.tmpl"] = page
		}
		return files
	}
	for _, sh := range []struct {
		name  string
		files map[string]string
		full  int // the budget is full to within this many bytes, or 0
	}{
		{"escape growth", vhostShape(mostVhosts, mixPage(37, pageActions), rawTraps(kinds)), 480000},
		{"most cuts", vhostShape(153, actionsPage(pageActions), trapsJSON(dense)), 0},
		{"fill", fillShape(vhostShape, kinds), 128},
	} {
		t.Run(sh.name, func(t *testing.T) {
			bd := bundleFiles(t, "", sh.files)
			// The first Execute of a template escapes it. No plan does this.
			for name := range plansOf(buildSite(bd)) {
				_ = bd.Execute(io.Discard, name, bundle.Page{Trap: map[string]string{}})
			}
			base, _ := retainedBy(bd, buildSite)
			heap, s := retainedBy(bd, buildPlannedSite)
			counted, biggest, kept, all := 0, 0, 0, plansOf(s)
			for _, p := range all {
				if p != nil {
					if p.size() != planCount(p) {
						t.Fatalf("size %d, count %d", p.size(), planCount(p))
					}
					counted, biggest, kept = counted+planCount(p), max(biggest, planCount(p)), kept+1
				}
			}
			t.Logf("%d of %d templates have a plan: %d counted bytes, %d bytes of heap, largest plan %d", kept, len(all), counted, int64(heap)-int64(base), biggest)
			// A run writes 59 bytes for a cut that counts 5. A template near
			// the end of the budget can fail at the cap of its run. So the
			// budget is not always full.
			// The build counts against 4 MiB less 16 KiB (planSlack).
			const counts = 4<<20 - 16<<10
			if counted > counts || sh.full > 0 && counted < counts-sh.full {
				t.Errorf("counted bytes = %d, want at most %d and at least %d", counted, counts, counts-sh.full)
			}
			if kept == 0 || kept == len(all) {
				t.Errorf("%d of %d templates have a plan, want some but not all", kept, len(all))
			}
			// The count is near the heap of the plans. The limit of the heap
			// is exactly 4 MiB. The floor is the fixed bytes. The heap holds
			// these.
			floor := 0
			for _, p := range all {
				if p != nil {
					floor += len(p.fixed)
				}
			}
			if d := int64(heap) - int64(base); d > 4<<20 || d < int64(floor) {
				t.Errorf("plans keep %d bytes of heap, want from %d to %d", d, floor, 4<<20)
			}
		})
	}
}
