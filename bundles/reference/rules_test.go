// Package reference holds the content rules of the reference bundle source
// tree (SEC-42, ADR-042). It has test files only. Its tests are T-S-36.
package reference

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

const (
	marker      = "phantom-reference-trap"
	tokenAction = "{{.Token}}"
	maxInstr    = 300
	seedName    = "secrets/token.seed"
	seedLen     = 32
	trapsFile   = "traps/traps.json"
	routesName  = "routes.json"
)

var (
	// The base64 alphabet is the standard one of RFC 4648 section 4, and "=".
	// "-" and "_" are not in it, so the marker is not a run. "/" is in it.
	base64Run = regexp.MustCompile(`[A-Za-z0-9+/=]{20,}`)
	hexEscape = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	hostWord  = regexp.MustCompile(`[A-Za-z0-9-]+\.[A-Za-z0-9-]+`)
	onAttr    = regexp.MustCompile(`(?i)[\s"'/]on[a-z]+\s*=`)
	animOn    = regexp.MustCompile(`(?i)attributename\s*=\s*["']?\s*on`)
	external  = regexp.MustCompile(`(?i)(?:\b(?:src|href|action)\s*=\s*["']?` +
		`|\burl\(\s*["']?)\s*(?:https?:|//)`)

	// The tree has no reason to hold an absolute URL in any position. The
	// only exception is the two SVG namespace names of svgNames.
	absoluteURL = regexp.MustCompile(`https?:|//`)
	svgNames    = strings.NewReplacer(`xmlns="http://www.w3.org/2000/svg"`, "",
		`xmlns:xlink="http://www.w3.org/1999/xlink"`, "")
	// A value that starts with a scheme, after "=", a quote or "(".
	scheme = regexp.MustCompile(`(?i)(?:=|["'(])\s*[a-z][a-z0-9+.-]*:`)
	// An attribute value, quoted or not. A scheme with a non-space after
	// its ":" is refused inside a value, also after ";", "," or white space.
	attrValue     = regexp.MustCompile(`(?is)=\s*("[^"]*"|'[^']*'|[^\s>"']+)`)
	schemeInValue = regexp.MustCompile(`(?i)(?:^|[;,\s"'])[a-z][a-z0-9+.-]*:\S`)
	httpEquiv     = regexp.MustCompile(`(?i)[\s"'/]http-equiv\s*=`)
	hexHost       = regexp.MustCompile(`(?i)^(0x[0-9a-f]*|[0-9]+)$`)
	// A trap text has only these characters, and the one token.
	notTrapChar = regexp.MustCompile(`[^A-Za-z0-9 .,;:!?'()/_-]`)
	dotEnv      = regexp.MustCompile(`\.\s*env\b`)
	// A tag of the list, also after a namespace prefix such as "s:".
	tagRe     = regexp.MustCompile(`(?i)<(?:[a-z0-9._-]+:)?(script|iframe|object|embed|foreignobject)`)
	styleAttr = regexp.MustCompile(`(?i)[\s"'/]style\s*=`)
	// A tag. A quoted value may hold ">". An open "<" runs to the end of the
	// text, and a quote with no end is a plain character.
	markup = regexp.MustCompile(`(?s)<(?:"[^"]*"|'[^']*'|[^>])*(?:>|$)`)
	// An element whose text a browser does not show as page text.
	hiddenElements = hiddenOf("style", "script", "template", "title", "textarea", "noscript")
	// The deny check reads a text with each run of other characters as one
	// space.
	notAlnum  = regexp.MustCompile(`[^a-z0-9]+`)
	rmDash    = regexp.MustCompile(`(^|[^a-z0-9])rm[^a-z0-9]*-`)
	denyStart = map[string]*regexp.Regexp{
		"e mail":    regexp.MustCompile(`\be mail`),
		"pass word": regexp.MustCompile(`\bpass word`),
	}

	// The two forms of a template action. Each "{{" of a template starts one.
	actionForms = []*regexp.Regexp{
		regexp.MustCompile(`\{\{index \.Trap "([a-z0-9-]+)"\}\}`),
		regexp.MustCompile(`\{\{comment \(index \.Trap "([a-z0-9-]+)"\)\}\}`),
	}
	// An unterminated HTML comment runs to the end of the text.
	htmlComment = regexp.MustCompile(`(?s)<!--.*?(?:-->|$)`)

	// A trap text has no "[" or "]". It has no ":" at the end. It has no
	// ":" before a character that is not a space.
	hostForm = regexp.MustCompile(`[\[\]]|:([^ ]|$)`)
	// These words are checked on the text with all spaces removed.
	denyCompact = []string{"apikey", "systemprompt", "privatekey"}

	topDirs  = []string{"vhosts", "traps", "secrets"}
	urlForms = []string{"://", "//", "@", "mailto:", "www."}
	// The deny list of ADR-042. A word matches as a part of a longer word.
	// The pair "instruction" and "override" and the word "rm -" are checked
	// apart.
	denyWords = []string{
		"ignore", "previous", "system prompt", "password", "credential",
		"secret", "api key", "private key", "ssh", "cookie", "history",
		"conversation", "email", "curl", "wget", "sudo", "base64",
		"execute", "shell", "download", "install",
	}
)

// result collects findings. A finding is "<rule> <path>". A finding is added
// once. Each refused-input test asserts the rule, not only a failure.
type result struct{ out []string }

func (r *result) add(rule, name string) {
	if f := rule + " " + name; !slices.Contains(r.out, f) {
		r.out = append(r.out, f)
	}
}

// vhost is what a trap check needs of one vhost directory. A trap is global
// to the bundle. A vhost uses it in a header slot of its route map. It can
// also use it with an exact action form in a template. "The same vhost" of a
// trap is each vhost that uses it. A trap that no vhost uses has no path.
type vhost struct {
	callbacks, segments []string
	traps               map[string]bool
}

// hostLike reports whether the first segment of the path p holds "." or is
// all digits. A path of this form can read as a host name or an address.
func hostLike(p string) bool {
	seg, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	return strings.Contains(seg, ".") || hexHost.MatchString(seg)
}

func (v *vhost) readRoutes(r *result, name string, b []byte) {
	var m struct {
		Routes []struct {
			Path     string
			Callback *struct{ Segment bool }
			Headers  []struct{ Trap string }
		}
		Beacon *struct{ Script, Post string }
	}
	if json.Unmarshal(b, &m) != nil { // The loader refuses a bad route map.
		return
	}
	if m.Beacon != nil && (hostLike(m.Beacon.Script) || hostLike(m.Beacon.Post)) {
		r.add("path-host-form", name)
	}
	for _, rt := range m.Routes {
		if hostLike(rt.Path) {
			r.add("path-host-form", name)
		}
		if rt.Callback != nil {
			v.callbacks = append(v.callbacks, rt.Path)
			if rt.Callback.Segment {
				v.segments = append(v.segments, rt.Path)
			}
		}
		for _, h := range rt.Headers {
			v.traps[h.Trap] = true
		}
	}
}

// checkTree runs each content rule on fsys, a copy of the source tree. The
// real test and each refused-input test call it.
func checkTree(fsys fs.FS) []string {
	r := &result{}
	files := map[string][]byte{}
	dirs := map[string]bool{}
	var names []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == "." {
			return err
		}
		names = append(names, p)
		switch {
		case d.IsDir():
			dirs[p] = true
		case d.Type().IsRegular():
			b, err := fs.ReadFile(fsys, p)
			files[p] = b
			return err
		default: // A symlink or a device is refused.
			r.add("entry-type", p)
		}
		return nil
	})
	if err != nil {
		r.add("walk", err.Error())
	}
	r.shape(names, dirs, files)
	hosts := r.vhostNames(names, dirs)
	users := map[string][]*vhost{}
	var templates []string
	for _, name := range slices.Sorted(maps.Keys(files)) {
		b := files[name]
		if name != seedName { // Each file but the seed is a text file.
			r.text(name, b)
		}
		parts := strings.SplitN(name, "/", 3)
		if parts[0] != "vhosts" || len(parts) < 3 {
			continue
		}
		v := hosts[parts[1]]
		if v == nil {
			continue
		}
		if parts[2] == routesName {
			v.readRoutes(r, name, b)
			continue
		}
		r.page(name, b, v)
		if strings.HasSuffix(name, ".tmpl") {
			templates = append(templates, name)
		}
	}
	for _, v := range hosts {
		for id := range v.traps {
			users[id] = append(users[id], v)
		}
	}
	texts := r.traps(files[trapsFile], users)
	for _, name := range templates {
		r.render(name, string(files[name]), texts)
	}
	return r.out
}

// shape checks the top level and secrets/.
func (r *result) shape(names []string, dirs map[string]bool, files map[string][]byte) {
	for _, n := range names {
		top, _, nested := strings.Cut(n, "/")
		switch {
		case !nested && n == "manifest.json" && !dirs[n]:
		case !nested && slices.Contains(topDirs, n) && dirs[n]:
		case !nested:
			r.add("tree-top", n)
		case top == "secrets" && n != seedName:
			r.add("tree-secrets", n)
		}
	}
	if seed, ok := files[seedName]; ok && len(seed) != seedLen {
		r.add("tree-seed", seedName)
	}
}

// vhostNames checks each entry directly below vhosts/.
func (r *result) vhostNames(names []string, dirs map[string]bool) map[string]*vhost {
	hosts := map[string]*vhost{}
	labels := map[string]bool{}
	for _, n := range names {
		dir, host := path.Split(n)
		if dir != "vhosts/" {
			continue
		}
		hosts[host] = &vhost{traps: map[string]bool{}}
		if first, _, _ := strings.Cut(host, "."); !dirs[n] || !validVhost(host) {
			r.add("vhost-name", n)
		} else if labels[first] {
			r.add("vhost-label", n)
		} else {
			labels[first] = true
		}
	}
	return hosts
}

// validVhost is the vhost name form of the loader, with the suffix
// ".internal". The all-digit rule for the last label has no effect here.
func validVhost(h string) bool {
	labels := strings.Split(h, ".")
	if !strings.HasSuffix(h, ".internal") || len(h) > 253 || len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' ||
			strings.ContainsFunc(l, func(c rune) bool { return c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') }) {
			return false
		}
	}
	return true
}

// text checks the bytes of a text file: 0x20 to 0x7E, tab and LF, and no
// long base64 run. The token is made at run time, so it is not in a source.
func (r *result) text(name string, b []byte) {
	if slices.ContainsFunc(b, func(c byte) bool { return c != '\t' && c != '\n' && (c < 0x20 || c > 0x7e) }) {
		r.add("bytes", name)
	}
	if base64Run.Match(b) {
		r.add("base64", name)
	}
}

// hiddenOf makes one pattern for each element in names. The pattern matches
// the start tag, the content and the end tag. An open element runs to the end.
func hiddenOf(names ...string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, n := range names {
		out = append(out, regexp.MustCompile(`(?is)<`+n+`\b(?:"[^"]*"|'[^']*'|[^>])*>.*?(?:</`+n+`\s*>|$)`))
	}
	return out
}

// page checks a file below a vhost with the script and URL rules. For a
// template it also checks the marker and the action forms. The rules run on
// the raw text and on the normal form.
func (r *result) page(name string, b []byte, v *vhost) {
	raw := string(b)
	n := normalForm(raw)
	if strings.HasSuffix(name, ".tmpl") {
		r.template(name, raw, n, v)
	}
	r.markupRules(name, raw, n, "", true)
}

// markupRules runs the script, style, URL and scheme rules on a text and on
// its normal form n. Each finding has the suffix sfx. With static, it also
// checks the DOCTYPE, http-equiv and percent escapes. They are not checked
// on a rendered page.
func (r *result) markupRules(name, raw, n, sfx string, static bool) {
	for _, s := range []string{raw, n} {
		low := strings.ToLower(s)
		for _, m := range tagRe.FindAllStringSubmatch(s, -1) {
			r.add("script(<"+strings.ToLower(m[1])+")"+sfx, name)
		}
		if strings.Contains(low, "javascript:") {
			r.add("script(javascript:)"+sfx, name)
		}
		if onAttr.MatchString(s) || animOn.MatchString(s) {
			r.add("on-attr"+sfx, name)
		}
		if styleAttr.MatchString(s) {
			r.add("style-attr"+sfx, name)
		}
		if static && len(doctypes(low)) > 0 {
			r.add("doctype", name)
		}
		if static && httpEquiv.MatchString(s) {
			r.add("http-equiv", name)
		}
		if static && hexEscape.MatchString(s) {
			r.add("percent-escape", name)
		}
	}
	if external.MatchString(n) {
		r.add("third-party"+sfx, name)
	}
	n = svgNames.Replace(n)
	low := strings.ToLower(n)
	if absoluteURL.MatchString(low) {
		r.add("absolute-url"+sfx, name)
	}
	if schemeFound(low) {
		r.add("scheme"+sfx, name)
	}
	if strings.Contains(low, "data:") {
		r.add("data-url"+sfx, name)
	}
	if strings.Contains(raw, `\`) || strings.Contains(n, `\`) {
		r.add("backslash"+sfx, name)
	}
}

// schemeFound reports a value that starts with a scheme. It also reports a
// scheme after ";", "," or white space inside an attribute value.
func schemeFound(low string) bool {
	if scheme.MatchString(low) {
		return true
	}
	for _, m := range attrValue.FindAllStringSubmatch(low, -1) {
		if schemeInValue.MatchString(m[1]) {
			return true
		}
	}
	return false
}

// render runs a template as the engine does, with the trap texts of the
// tree. It runs the markup rules on the output. A template that does not
// parse or run is a finding.
func (r *result) render(name, text string, traps map[string]string) {
	t, err := template.New(name).Option("missingkey=error").
		Funcs(template.FuncMap{"comment": comment}).Parse(text)
	var buf bytes.Buffer
	if err == nil {
		err = t.Execute(&buf, bundle.Page{Trap: traps})
	}
	if err != nil {
		r.add("render", name)
		return
	}
	out := buf.String()
	r.markupRules(name, out, renderForm(out), "(rendered)", false)
}

// comment is a copy of the function comment of internal/bundle/template.go.
// It is not exported there. The engine adds it to each template.
func comment(s string) template.HTML {
	if strings.Contains(s, "--") || strings.Contains(s, "<") || strings.HasPrefix(s, ">") || strings.HasPrefix(s, "->") ||
		strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 && c != '\t' && c != '\n' || 0x7f <= c && c <= 0x9f }) {
		return ""
	}
	return template.HTML("<!-- " + s + " -->")
}

// renderForm decodes the character references of a rendered page. It then
// decodes percent escapes, and keeps the text when that fails. It deletes
// each rune below 0x20 and the rune 0x7F.
func renderForm(s string) string {
	s = html.UnescapeString(s)
	if u, err := url.PathUnescape(s); err == nil {
		s = u
	}
	return dropControls(s)
}

// doctypes lists the bad declarations in the lower-case text s. An entity or
// an attlist is bad. A doctype is bad unless it is "<!doctype html>".
func doctypes(s string) []string {
	var bad []string
	for _, d := range []string{"<!entity", "<!attlist"} {
		if strings.Contains(s, d) {
			bad = append(bad, d)
		}
	}
	for i := 0; ; {
		j := strings.Index(s[i:], "<!doctype")
		if j < 0 {
			return bad
		}
		if i += j; !strings.HasPrefix(s[i:], "<!doctype html>") {
			bad = append(bad, "<!doctype")
		}
		i += len("<!doctype")
	}
}

// template checks the marker and the actions of a template. The marker must
// be in the text that stays when HTML comments, the hidden elements and tags
// are removed. Each "{{" must start one of the two exact forms, and no "/"
// comes before it. The traps of the vhost come from these forms only.
func (r *result) template(name, text, n string, v *vhost) {
	visible := htmlComment.ReplaceAllString(text, "")
	for _, re := range hiddenElements {
		visible = re.ReplaceAllString(visible, "")
	}
	visible = markup.ReplaceAllString(visible, "")
	if !strings.Contains(visible, marker) {
		r.add("marker", name)
	}
	if strings.Contains(n, "/{{") {
		r.add("action-after-slash", name)
	}
	forms := 0
	for _, re := range actionForms {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			forms++
			v.traps[m[1]] = true
		}
	}
	opens := 0
	for i := range len(text) - 1 {
		if text[i:i+2] == "{{" {
			opens++
		}
	}
	if opens != forms {
		r.add("template-action", name)
	}
}

// normalForm decodes the character references of s. It then deletes each
// rune below 0x20 and the rune 0x7F.
func normalForm(s string) string { return dropControls(html.UnescapeString(s)) }

func dropControls(s string) string {
	return strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return -1
		}
		return c
	}, s)
}

// fixedToken is the token that a rendered page holds. It has 26 characters
// of a-z and 2-7.
const fixedToken = "abcdefghijklmnopqrstuvwxyz"

// traps checks the instruction template of each trap in traps/traps.json. It
// gives the text of each trap with the fixed token, by trap id.
func (r *result) traps(b []byte, users map[string][]*vhost) map[string]string {
	if b == nil {
		return nil
	}
	var ts []struct {
		ID   string `json:"id"`
		Text string `json:"instruction_template"`
	}
	if json.Unmarshal(b, &ts) != nil {
		r.add("traps-json", trapsFile)
		return nil
	}
	texts := map[string]string{}
	for _, t := range ts {
		r.instruction(t.Text, users[t.ID])
		texts[t.ID] = strings.ReplaceAll(t.Text, tokenAction, fixedToken)
	}
	return texts
}

func (r *result) instruction(text string, users []*vhost) {
	low := strings.ToLower(text)
	add := func(rule string, bad bool) {
		if bad {
			r.add(rule, trapsFile)
		}
	}
	add("instr-length", len(text) > maxInstr)
	add("instr-bytes", strings.ContainsFunc(text, func(c rune) bool { return c < 0x20 || c > 0x7e }))
	add("instr-token", strings.Count(text, tokenAction) != 1 || strings.Count(text, "{{") != 1)
	add("instr-host-form", hostForm.MatchString(text))
	add("instr-chars", notTrapChar.MatchString(strings.ReplaceAll(text, tokenAction, "")))
	add("marker", !strings.Contains(text, marker))
	add("base64", base64Run.MatchString(text))
	add("entity", strings.Contains(text, "&#") || hexEscape.MatchString(text))
	for _, u := range urlForms {
		add("instr-url("+u+")", strings.Contains(low, u))
	}
	s := notAlnum.ReplaceAllString(low, " ")
	compact := strings.ReplaceAll(s, " ", "")
	for _, w := range denyWords {
		add("instr-deny("+w+")", strings.Contains(s, notAlnum.ReplaceAllString(w, " ")))
	}
	for _, w := range denyCompact {
		add("instr-deny("+w+")", strings.Contains(compact, w))
	}
	for w, re := range denyStart {
		add("instr-deny("+w+")", re.MatchString(s))
	}
	add("instr-deny(.env)", dotEnv.MatchString(low))
	add("instr-deny(rm -)", rmDash.MatchString(low))
	add("instr-deny(instruction+override)",
		strings.Contains(s, "instruction") && strings.Contains(compact, "override"))
	for _, w := range strings.Fields(text) {
		switch p, seg := strings.CutSuffix(w, "/"+tokenAction); {
		case strings.HasPrefix(w, "/"):
			if p == "" {
				p = "/"
			}
			add("instr-path", !pathOK(p, seg, users))
			add("path-host-form", hostLike(p))
		case strings.Contains(w, "/"):
			add("instr-path", true)
		default:
			add("instr-host", hostWord.MatchString(strings.ReplaceAll(w, tokenAction, "")))
		}
	}
}

// pathOK reports whether p is a callback route path of each vhost in users.
// With seg, p must be a path with a segment position.
func pathOK(p string, seg bool, users []*vhost) bool {
	for _, v := range users {
		paths := v.callbacks
		if seg {
			paths = v.segments
		}
		if !slices.Contains(paths, p) {
			return false
		}
	}
	return len(users) > 0
}

// checkRoot refuses a source tree that is missing or has no manifest.json.
// A moved directory then does not pass with nothing checked.
func checkRoot(fsys fs.FS) error {
	if _, err := fs.Stat(fsys, "manifest.json"); err != nil {
		return fmt.Errorf("source tree has no manifest.json: %w", err)
	}
	return nil
}

func TestTS36RealTreeFollowsRules(t *testing.T) {
	fsys := os.DirFS("src")
	if err := checkRoot(fsys); err != nil {
		t.Fatal(err)
	}
	for _, f := range checkTree(fsys) {
		t.Error(f)
	}
}

func TestTS36RealManifestHasTheManifestForm(t *testing.T) {
	b, err := os.ReadFile("src/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.ParseManifest(b); err != nil {
		t.Error(err)
	}
}

func TestTS36MissingRootIsRefused(t *testing.T) {
	for name, fsys := range map[string]fs.FS{
		"no directory": os.DirFS("no-such-directory"),
		"empty tree":   fstest.MapFS{},
		"no manifest":  fstest.MapFS{"vhosts/a.internal/routes.json": {}},
	} {
		if checkRoot(fsys) == nil {
			t.Errorf("%s: checkRoot gave no error", name)
		}
	}
}
