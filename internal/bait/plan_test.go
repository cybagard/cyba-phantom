package bait

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

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
}

// noPlanContexts are the contexts whose two marker runs differ. In a CSS
// string, the escape of the byte before a token depends on the token.
var noPlanContexts = map[string]bool{
	"style css dq": true, "style attr css sq": true, "style attr unq css dq": true,
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

// planCount is the size of p against the budget, with the record size of 5.
func planCount(p *plan) int { return len(p.fixed) + 5*len(p.offs) }

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
				for _, pre := range affixes {
					for _, suf := range affixes {
						id := fmt.Sprint("t", len(specs))
						specs = append(specs, trapSpec{id, "hidden-p", pre + "{{.Token}}" + suf})
						acts.WriteString(act(id))
					}
				}
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
		{"marker in a trap text", `<p>{{index .Trap "t0"}}</p>`, markerOf(0, 1) + "{{.Token}}", false},
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
	// Four templates with no action, 100 bytes each, and a budget of 200.
	// The first two plans fill it. No marker run follows.
	files := map[string]string{}
	var routes []string
	for i := range 4 {
		files[fmt.Sprintf("vhosts/b.example/%d.tmpl", i)] = strings.Repeat("f", 100)
		routes = append(routes, fmt.Sprintf(`{"path":"/%d","template":"vhosts/b.example/%d.tmpl","type":"text/html; charset=utf-8"}`, i, i))
	}
	files["vhosts/b.example/routes.json"] = `{"routes":[` + strings.Join(routes, ",") + `]}`
	fb := bundleFiles(t, "", files)
	pl = newPlanner(fb, fb.Traps(), 200)
	got = plansOf(makeSite(fb, pl))
	if pl.runs != 4 || pl.left != 0 || got["vhosts/b.example/1.tmpl"] == nil || got["vhosts/b.example/2.tmpl"] != nil {
		t.Errorf("runs = %d, left = %d, plans %v, want 4 runs, left 0, plans for the first two", pl.runs, pl.left, got)
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

// TestTS28PlanBudget checks the plans of one site at the shapes of the largest
// escape growth and of the most cuts. The plans keep at most 4 MiB of heap, and
// their count is at most 4 MiB. The budget is nearly full, and the templates
// past it have no plan.
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
	}{
		{"escape growth", vhostShape(mostVhosts, mixPage(37, pageActions), rawTraps(kinds))},
		{"most cuts", vhostShape(153, actionsPage(pageActions), trapsJSON(dense))},
	} {
		t.Run(sh.name, func(t *testing.T) {
			bd := bundleFiles(t, "", sh.files)
			// The first Execute of a template escapes it. This is no plan.
			for name := range plansOf(buildSite(bd)) {
				_ = bd.Execute(io.Discard, name, bundle.Page{Trap: map[string]string{}})
			}
			base, _ := retainedBy(bd, buildSite)
			heap, s := retainedBy(bd, buildPlannedSite)
			counted, biggest, kept, all := 0, 0, 0, plansOf(s)
			for _, p := range all {
				if p != nil {
					counted, biggest, kept = counted+planCount(p), max(biggest, planCount(p)), kept+1
				}
			}
			t.Logf("%d of %d templates have a plan: %d counted bytes, %d bytes of heap, largest plan %d", kept, len(all), counted, int64(heap)-int64(base), biggest)
			// A run writes 36 bytes for a cut that counts 5. A template near
			// the end of the budget can fail at the cap of its run. So the
			// budget is not full to the byte.
			if counted > 4<<20 || counted <= 4<<20-8*biggest {
				t.Errorf("counted bytes = %d, want from %d to %d", counted, 4<<20-8*biggest, 4<<20)
			}
			if kept == 0 || kept == len(all) {
				t.Errorf("%d of %d templates have a plan, want some but not all", kept, len(all))
			}
			// The heap of a plan has its counted bytes, the size classes of
			// its slices and its header. This is about 1 % more.
			if d := int64(heap) - int64(base); d > 4<<20+4<<20/50 || d < int64(counted) {
				t.Errorf("plans keep %d bytes of heap, want from %d to %d", d, counted, 4<<20+4<<20/50)
			}
		})
	}
}
