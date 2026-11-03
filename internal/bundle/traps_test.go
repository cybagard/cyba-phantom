package bundle

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/event"
)

const (
	mID   = `"id":"a"`
	mSlot = `"slot":"hidden-p"`
	mSur  = `"surface":"path"`
	mVis  = `"visibility":"human-visible"`
	mTpl  = `"instruction_template":"x"`
)

func obj(members ...string) string { return "{" + strings.Join(members, ",") + "}" }

func arr(objs ...string) string { return "[" + strings.Join(objs, ",") + "]" }

// tj gives a trap object with this id and this instruction template.
func tj(id, tmpl string) string {
	b, _ := json.Marshal(tmpl)
	return obj(fmt.Sprintf("%q:%q", "id", id), mSlot, mSur, mVis, `"instruction_template":`+string(b))
}

// trapEnts gives a bundle with one vhost and this trap file.
func trapEnts(text string) []ent {
	return append(withRoutes([]ent{tf(vhostFile, "i")}), tf(trapsName, text))
}

// T-U-08: each refused form of the trap file gives content_invalid.
func TestTU08TrapsRefused(t *testing.T) {
	good := obj(mID, mSlot, mSur, mVis, mTpl)
	forms := []string{"", "[]", "null", "{}", `"x"`, "[null]", "[1]", "[[]]", good, arr(good) + "x", arr(good) + arr(good),
		arr(good, good), arr(tj("a", "x"), tj("a", "y")), arr(obj(mID, mSlot, mSur, mVis, mTpl, `"x":1`)),
		arr(obj(mID, mSlot, mSur, mVis, mTpl, mID)), arr(obj(`"ID":"a"`, mSlot, mSur, mVis, mTpl)),
		arr(obj(mID, mSlot, mSur, mVis, `"Instruction_template":"x"`)), arr(obj(`"id":1`, mSlot, mSur, mVis, mTpl)),
		arr(obj(mID, mSlot, mSur, mVis, `"instruction_template":null`)), arr(obj(mID, mSlot, mSur, mVis, `"instruction_template":1`)),
		arr(obj(mID, mSlot, mSur, mVis, `"instruction_template":"\ud800"`)),
	}
	for i, m := range []string{mID, mSlot, mSur, mVis, mTpl} {
		parts := []string{mID, mSlot, mSur, mVis, mTpl}
		forms = append(forms, arr(obj(append(append([]string{}, parts[:i]...), parts[i+1:]...)...)))
		parts[i] = strings.SplitN(m, ":", 2)[0] + ":null"
		forms = append(forms, arr(obj(parts...)))
	}
	for _, id := range []string{"", strings.Repeat("a", 65), "A", "a_b", "a b", "a.b", "é"} {
		forms = append(forms, arr(tj(id, "x")))
	}
	for _, v := range [][2]string{{"slot", "hidden"}, {"slot", "Hidden-p"}, {"slot", ""}, {"surface", "Path"}, {"surface", "cookie"},
		{"surface", ""}, {"visibility", "visible"}, {"visibility", "human_visible"}, {"visibility", ""}} {
		forms = append(forms, strings.Replace(arr(tj("a", "x")), `"`+v[0]+`":"`+map[string]string{
			"slot": "hidden-p", "surface": "path", "visibility": "human-visible"}[v[0]]+`"`, `"`+v[0]+`":"`+v[1]+`"`, 1))
	}
	var many []string
	for i := range 1025 {
		many = append(many, tj(fmt.Sprintf("t%d", i), "x"))
	}
	forms = append(forms, arr(many...), spaced(arr(good), 262145))
	for _, text := range forms {
		t.Run(fmt.Sprintf("%.120s", text), func(t *testing.T) { loadRaw(t, ErrContentInvalid, nil, trapEnts(text)...) })
	}
}

// T-U-08: the edges of the trap file hold, and each value of each list is
// accepted. A bundle with no trap file has no trap.
func TestTU08TrapsAccepted(t *testing.T) {
	var many []string
	for i := range 1024 {
		many = append(many, tj(fmt.Sprintf("t%d", i), "x"))
	}
	if b := loadRaw(t, nil, nil, trapEnts(arr(many...))...); len(b.Traps()) != 1024 {
		t.Errorf("%d traps; want 1024", len(b.Traps()))
	}
	loadRaw(t, nil, nil, trapEnts(spaced(arr(tj("a", "x")), 262144))...)
	loadRaw(t, nil, nil, trapEnts(arr(tj(strings.Repeat("a", 64), "x"), tj("0-z", "x")))...)
	var all []string
	for i, s := range trapSlots {
		all = append(all, strings.Replace(tj(fmt.Sprintf("s%d", i), "x"), `"hidden-p"`, `"`+s+`"`, 1))
	}
	for i, s := range trapSurfaces {
		all = append(all, strings.Replace(tj(fmt.Sprintf("u%d", i), "x"), `"path"`, `"`+string(s)+`"`, 1))
	}
	for i, s := range trapVisibilities {
		all = append(all, strings.Replace(tj(fmt.Sprintf("v%d", i), "x"), `"human-visible"`, `"`+s+`"`, 1))
	}
	b := loadRaw(t, nil, nil, trapEnts(arr(all...))...)
	if got := b.Traps(); len(got) != len(all) || got[0].Slot != "hidden-p" || got[11].Slot != "header" ||
		got[15].Surface != event.SurfaceBody || got[16].Visibility != "human-invisible" {
		t.Errorf("traps %+v", got)
	}
	if n := loadWith(t, nil, tf(vhostFile, "i")).Traps(); len(n) != 0 {
		t.Errorf("a bundle with no trap file has traps %v", n)
	}
}

// T-U-08: a caller of Traps cannot change the kept list.
func TestTU08TrapsIsACopy(t *testing.T) {
	b := loadRaw(t, nil, nil, trapEnts(arr(tj("a", "x{{.Token}}y"), tj("b", "z")))...)
	got := b.Traps()
	got[0].ID, got[0].parts[0] = "changed", "changed"
	got[1] = Trap{}
	if again := b.Traps(); again[0].ID != "a" || again[1].ID != "b" || again[0].Render("T") != "xTy" {
		t.Errorf("the kept list changed: %+v", again)
	}
}

// T-U-08: the template of a trap holds only text and {{.Token}}. The engine
// renders the text and the token, joined in order, with no execution.
func TestTU08TrapTemplates(t *testing.T) {
	for tmpl, want := range map[string]string{
		"": "", "plain": "plain", "a{{.Token}}b": "aTb", "{{.Token}}": "T", "{{.Token}}{{.Token}}": "TT",
		"a {{- .Token -}} b": "aTb", "{{.Token}}<b>&": "T<b>&", "x{{ .Token }}": "xT",
	} {
		b := loadRaw(t, nil, nil, trapEnts(arr(tj("a", tmpl)))...)
		if got := b.Traps()[0].Render("T"); got != want {
			t.Errorf("%q renders %q; want %q", tmpl, got, want)
		}
	}
	for _, tmpl := range []string{
		"{{/* c */}}", "a{{/* c */}}b", "{{- /* c */ -}}", "{{.Other}}", "{{.}}", "{{.Token.X}}", "{{.token}}", `{{.Token | printf "%s"}}`,
		"{{$x := .Token}}", "{{$x := 1}}{{.Token}}", `{{printf "a"}}`, "{{index .A 1}}", "{{.Token.X}}", "{{(.Token)}}", "{{1}}", `{{"s"}}`,
		"{{if .Token}}a{{end}}", "{{range .A}}{{end}}", "{{with .A}}{{end}}", `{{template "x"}}`, `{{block "x" .}}{{end}}`,
		`{{define "x"}}{{printf "a"}}{{end}}`, `{{define "x"}}a{{end}}b`, `{{define "x"}}{{.Token}}{{end}}`, "{{", "{{.Token", "{{if}}",
		"{{.Token}}{{break}}", "{{shell `id`}}",
	} {
		t.Run(tmpl, func(t *testing.T) { loadRaw(t, ErrTemplateParse, nil, trapEnts(arr(tj("a", tmpl)))...) })
	}
}

// T-U-08: a template string of 1 024 bytes loads. One of 1 025 bytes gives
// template_parse with no constructor call. The edges of the bundle sums count
// the strings, also the "{{" of them.
func TestTU08TrapTemplateCaps(t *testing.T) {
	trapFile := func(tmpl string) ent { return tf(trapsName, arr(tj("a", tmpl))) }
	act := strings.Repeat("{{1}}", 2048)
	big := strings.Repeat("a", 64<<10)
	for _, c := range []struct {
		name string
		ents []ent
		n    int // files that load at the cap
	}{
		{"string at cap", []ent{trapFile(strings.Repeat("a", 1024))}, 0},
		{"string over", []ent{trapFile(strings.Repeat("a", 1025))}, -1},
		{"sum of bytes, at cap", append(files(7, big), tf("vhosts/h.example/z.tmpl", strings.Repeat("a", 64<<10-1)), trapFile("a")), 8},
		{"sum of bytes, over", append(files(8, big), trapFile("a")), -1},
		{"sum of actions, at cap", append(files(8, act), trapFile("a")), 8},
		{"sum of actions, over", append(files(8, act), trapFile("{{.Token}}")), -1},
	} {
		t.Run(c.name, func(t *testing.T) {
			calls, set, err := parseCount(t, c.ents...)
			if c.n < 0 && (err != ErrTemplateParse || calls != 0 || set != nil) {
				t.Errorf("got %d calls, %v; want no constructor call and %v", calls, err, ErrTemplateParse)
			}
			if c.n >= 0 && (err != nil || calls != max(c.n, len(set))) {
				t.Errorf("got %d calls, %v", calls, err)
			}
		})
	}
	loadRaw(t, nil, nil, trapEnts(arr(tj("a", strings.Repeat("a", 1024))))...)
	loadRaw(t, ErrTemplateParse, nil, trapEnts(arr(tj("a", strings.Repeat("a", 1025))))...)
}

// T-U-08: the form check of the trap file runs before the template step.
// The template step runs before the route step. Each failure has one code.
func TestTU08TrapsOrder(t *testing.T) {
	bad := tf(vhostFile, "{{if}}")
	badTrap := tf(trapsName, arr(tj("a", "{{.Other}}")))
	badForm := tf(trapsName, "[]")
	slots := doc(pa, ti, ty, `"headers":[{"name":"X-A","trap":"gone"}]`)
	rm := tf(hostDir+routeMapName, slots)
	loadRaw(t, ErrContentInvalid, nil, bad, badForm, rm)
	loadRaw(t, ErrContentInvalid, func(e *env) { e.l.template = stubParse }, tf(vhostFile, "i"), badForm)
	loadRaw(t, ErrTemplateParse, nil, tf(vhostFile, "i"), badTrap, rm)
	loadRaw(t, ErrTemplateParse, nil, bad, tf(trapsName, arr(tj("a", "x"))), rm)
	loadRaw(t, ErrContentInvalid, nil, tf(vhostFile, "i"), tf(trapsName, arr(tj("a", "x"))), rm)
	// A nil template step keeps the traps and checks the header slots.
	none := func(e *env) { e.l.template = nil }
	b := loadRaw(t, nil, none, tf(hostDir+"a.png", "p"), tf(trapsName, arr(tj("a", "x{{.Token}}"))),
		tf(hostDir+routeMapName, doc(pa, png, ty, `"headers":[{"name":"X-A","trap":"a"}]`)))
	if got := b.Traps(); len(got) != 1 || got[0].Render("T") != "xT" {
		t.Errorf("traps %+v", got)
	}
	loadRaw(t, ErrTemplateParse, none, tf(trapsName, arr(tj("a", "{{.Other}}"))))
}

// T-U-08: a header slot has a name and the id of a trap. The name is "X-" and
// 1 to 32 bytes of A-Z a-z 0-9 -. The slot of the trap does not matter.
func TestTU08HeaderSlots(t *testing.T) {
	l32 := strings.Repeat("a", 32)
	for name, ok := range map[string]bool{
		"X-A": true, "X-" + l32: true, "X-a-Z9": true, "X-" + l32 + "a": false, "X-": false, "x-A": false, "x-a": false,
		"A": false, "": false, "XX-a": false, "X_A": false, "X-a_b": false, "X-a b": false, "X-é": false, " X-A": false,
	} {
		want := ErrContentInvalid
		if ok {
			want = nil
		}
		t.Run(name, func(t *testing.T) {
			text := doc(pa, ti, ty, fmt.Sprintf(`"headers":[{"name":%q,"trap":"t"}]`, name))
			loadRaw(t, want, nil, site(text)...)
		})
	}
	for _, id := range []string{"gone", "", "T", "t "} {
		loadRaw(t, ErrContentInvalid, nil, site(doc(pa, ti, ty, `"headers":[{"name":"X-A","trap":"`+id+`"}]`))...)
	}
	// Only the last slot has an unknown trap. A bundle with no trap file has
	// no trap id.
	loadRaw(t, ErrContentInvalid, nil, site(doc(pa, ti, ty, `"headers":[{"name":"X-A","trap":"t"},{"name":"X-B","trap":"gone"}]`))...)
	noFile := site(doc(pa, ti, ty, `"headers":[{"name":"X-A","trap":"t"}]`))
	loadRaw(t, ErrContentInvalid, nil, noFile[:len(noFile)-1]...)
}

// T-U-08, SEC-23: no error of the trap file or of an instruction template
// holds a byte of the archive.
func TestTU08TrapErrorsHoldNoText(t *testing.T) {
	for _, c := range []struct {
		text string
		want error
	}{
		{arr(tj("a", "{{markerdata77 .Token}}")), ErrTemplateParse},
		{arr(tj("markerdata77", "x"), tj("markerdata77", "y")), ErrContentInvalid},
	} {
		e := running(t)
		arch := build(append([]ent{tf("manifest.json", mf(ver(3)))}, trapEnts(c.text)...)...)
		e.write("bundle/current.cbnd", arch)
		e.write("bundle/current.sig", e.sign(arch))
		if _, err := e.l.Load(false); err != c.want || strings.Contains(err.Error(), "markerdata77") {
			t.Errorf("load gave %q; want %q", err, c.want)
		}
	}
}
