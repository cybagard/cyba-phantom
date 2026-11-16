// Package reference holds the content rules of the reference bundle source
// tree (SEC-42, ADR-042). It has test files only. Its tests are T-S-36.
package reference

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
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
	// ldTag is the one start tag of a script element that a template can hold.
	ldTag = `<script type="application/ld+json">`
)

var (
	// The base64 alphabet is the standard one of RFC 4648 section 4, and "=".
	// "-" and "_" are not in it, so the marker is not a run. "/" is in it.
	base64Run = regexp.MustCompile(`[A-Za-z0-9+/=]{20,}`)
	hexEscape = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	onAttr    = regexp.MustCompile(`(?i)[\s"'/]on[a-z]+\s*=`)
	animOn    = regexp.MustCompile(`(?i)attributename\s*=\s*["']?\s*on`)
	// An animation that sets href, xlink:href or src can set a URL.
	animTarget = regexp.MustCompile(`(?i)attributename\s*=\s*["']?\s*(?:xlink:href|href|src)\b`)
	external   = regexp.MustCompile(`(?i)(?:\b(?:src|href|action)\s*=\s*["']?` +
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
	dotEnv        = regexp.MustCompile(`\.\s*env\b`)
	// A tag of the list, also after a namespace prefix such as "s:".
	tagRe     = regexp.MustCompile(`(?i)<(?:[a-z0-9._-]+:)?(script|iframe|object|embed|foreignobject)`)
	styleAttr = regexp.MustCompile(`(?i)[\s"'/]style\s*=`)
	// A tag. A quoted value may hold ">". An open "<" runs to the end of the
	// text, and a quote with no end is a plain character.
	markup = regexp.MustCompile(`(?s)<(?:"[^"]*"|'[^']*'|[^>])*(?:>|$)`)
	// The element names that a text/html template can use. A new name is a
	// code change in a reviewed PR. The list holds no element that a browser
	// reads as raw text or RCDATA. The exceptions are style, script, title
	// and noscript.
	elements = []string{"html", "head", "body", "title", "meta", "style", "script", "noscript",
		"p", "a", "img", "div", "span", "h1", "h2", "h3", "ul", "ol", "li", "em", "strong", "br",
		"section", "header", "footer", "main", "nav", "article"}
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
	// Group 1 is the trap id of the index form, group 2 of the comment form.
	actionRe = regexp.MustCompile(`\{\{index \.Trap "([a-z0-9-]+)"\}\}|\{\{comment \(index \.Trap "([a-z0-9-]+)"\)\}\}`)
	// An attribute with a value, quoted or not. Group 1 is the name.
	attrRe = regexp.MustCompile(`(?s)([^\s"'=<>/]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>"']+)`)
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
	// The pair "instruction" and "override" has its own check. So have
	// ".env", "rm -", "e mail" and "pass word".
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

// callback holds the positions of a callback route. A position that is not
// used is false or empty.
type callback struct {
	segment             bool
	query, header, body string
}

// use is one place where a vhost uses a trap. It is a header slot of the
// route map, or an action in a template. The class is "F" for a sentence
// form (F1 to F5), or "L" for the path form (L1). A finding about the use goes
// to the file.
type use struct{ id, class, file string }

// vhost is what a trap check needs of one vhost directory. A trap is global
// to the bundle. "Each vhost that uses" a trap means each vhost with a use of
// it. A trap that no vhost uses has no path. The types of a template are the
// content types of the routes that name it, with no parameter.
type vhost struct {
	callbacks map[string]callback
	uses      []use
	types     map[string][]string
}

// parseOpts are the decoder options of the loader, without the refusal of
// unknown members. The test structs hold only some members. The decoder
// matches names with the case.
var parseOpts = []json.Options{
	jsontext.AllowDuplicateNames(false),
	jsontext.AllowInvalidUTF8(false),
}

// hostLike reports whether the first segment of the path p holds ".". It also
// reports a segment that is all digits, or "0x" with hex digits (hexHost).
// A path of this form can read as a host name or an address.
func hostLike(p string) bool {
	seg, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	return strings.Contains(seg, ".") || hexHost.MatchString(seg)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// The three shape rules below are copies of the loader. The names here are
// the loader names. A reserved header name is not checked. The rule
// route-form does not need the lists of reserved names and prefixes.
const (
	maxPathBytes     = 256 // internal/bundle/route.go
	maxHeaderNameLen = 32  // internal/bundle/traps.go
)

func alnum(c rune) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' }

// validPath is a copy of validPath in internal/bundle/route.go (lines 262-271).
func validPath(p string) bool {
	if len(p) < 1 || len(p) > maxPathBytes || p[0] != '/' ||
		strings.ContainsFunc(p, func(c rune) bool { return !strings.ContainsRune("/._-", c) && !alnum(c) }) {
		return false
	}
	if p == "/" {
		return true
	}
	return !slices.ContainsFunc(strings.Split(p[1:], "/"), func(s string) bool { return s == "" || s == "." || s == ".." })
}

// validParam is a copy of validParam in internal/bundle/route.go (lines
// 244-246): 1 to 32 bytes of A-Z a-z 0-9 _ -.
func validParam(s string) bool {
	return len(s) >= 1 && len(s) <= maxHeaderNameLen &&
		!strings.ContainsFunc(s, func(c rune) bool { return c != '_' && c != '-' && !alnum(c) })
}

// validHeaderName is a copy of the "X-" prefix, length and byte rules of
// validHeaderName in internal/bundle/traps.go (lines 119-129).
func validHeaderName(s string) bool {
	rest, ok := strings.CutPrefix(s, "X-")
	return ok && len(rest) >= 1 && len(rest) <= maxHeaderNameLen &&
		!strings.ContainsFunc(rest, func(c rune) bool { return c != '-' && !alnum(c) })
}

// readRoutes reads a route map. The rule path-host-form runs only on the
// paths that an agent is told to request: callback paths and beacon paths.
// A page path such as "/robots.txt" is not one of them.
func (v *vhost) readRoutes(r *result, name string, b []byte) {
	var m struct {
		Routes []struct {
			Path     string `json:"path"`
			Template string `json:"template"`
			Type     string `json:"type"`
			Callback *struct {
				Segment bool    `json:"segment"`
				Query   *string `json:"query"`
				Header  *string `json:"header"`
				Body    *string `json:"body"`
			} `json:"callback"`
			Headers []struct {
				Trap string `json:"trap"`
			} `json:"headers"`
		} `json:"routes"`
		NotFound string `json:"not_found"`
		Beacon   *struct {
			Script string `json:"script"`
			Post   string `json:"post"`
		} `json:"beacon"`
	}
	if json.Unmarshal(b, &m, parseOpts...) != nil {
		r.add("routes-json", name)
		return
	}
	if m.Beacon != nil && (hostLike(m.Beacon.Script) || hostLike(m.Beacon.Post)) {
		r.add("path-host-form", name)
	}
	if m.NotFound != "" {
		v.types[m.NotFound] = append(v.types[m.NotFound], "text/html")
	}
	for _, rt := range m.Routes {
		if rt.Callback != nil && hostLike(rt.Path) {
			r.add("path-host-form", name)
		}
		if c := rt.Callback; c != nil {
			// A name that is set and not valid is refused, as the loader does.
			q, h, b := deref(c.Query), deref(c.Header), deref(c.Body)
			if !validPath(rt.Path) || c.Query != nil && !validParam(q) ||
				c.Header != nil && !validHeaderName(h) || c.Body != nil && !validParam(b) {
				r.add("route-form", name)
			}
			v.callbacks[rt.Path] = callback{c.Segment, q, h, b}
		}
		if rt.Template != "" {
			typ, _, _ := strings.Cut(rt.Type, ";")
			v.types[rt.Template] = append(v.types[rt.Template], strings.ToLower(strings.TrimSpace(typ)))
		}
		for _, h := range rt.Headers {
			v.uses = append(v.uses, use{h.Trap, "F", name})
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
	owner := map[string]*vhost{}
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
		r.page(name, b)
		if strings.HasSuffix(name, ".tmpl") {
			templates = append(templates, name)
			owner[name] = v
		}
	}
	// The route maps are read, so the type of each template is known.
	users := map[string][]*vhost{}
	for _, name := range templates {
		r.positions(name, string(files[name]), owner[name])
	}
	for _, v := range hosts {
		for _, u := range v.uses {
			if !slices.Contains(users[u.id], v) {
				users[u.id] = append(users[u.id], v)
			}
		}
	}
	texts, forms := r.traps(files[trapsFile], users)
	for _, v := range hosts {
		for _, u := range v.uses {
			if f := forms[u.id]; f != "" && f[:1] != u.class {
				r.add("trap-class", u.file)
			}
		}
	}
	for _, name := range templates {
		r.render(name, string(files[name]), texts, slices.Contains(owner[name].types[name], "text/html"))
	}
	return r.out
}

// shape checks the top level, secrets/ and traps/. Each of the two holds one
// file only.
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
		case top == "traps" && n != trapsFile:
			r.add("tree-traps", n)
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
		hosts[host] = &vhost{callbacks: map[string]callback{}, types: map[string][]string{}}
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
// template it also checks the marker and the action forms. An asset has no
// action. The rules run on the raw text and on the normal form.
func (r *result) page(name string, b []byte) {
	raw := string(b)
	n := normalForm(raw)
	tmpl := strings.HasSuffix(name, ".tmpl")
	if tmpl {
		r.template(name, raw, n)
	} else if actionRe.MatchString(raw) {
		r.add("action-position", name)
	}
	r.markupRules(name, raw, n, "", true, tmpl)
}

// markupRules runs the script, style, URL and scheme rules on a text and on
// its normal form n. Each finding has the suffix sfx. With static, it also
// checks the DOCTYPE, http-equiv and percent escapes. They are not checked
// on a rendered page. With ld, the text can hold one json-ld start tag. The
// tag rule then refuses each other script tag.
func (r *result) markupRules(name, raw, n, sfx string, static, ld bool) {
	for _, s := range []string{raw, n} {
		if ld {
			s = strings.Replace(s, ldTag, "", 1)
		}
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
		if animTarget.MatchString(s) {
			r.add("anim-target"+sfx, name)
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

// render runs a template as the engine does. It runs two times: with the trap
// texts of the tree, and with no trap text. In the second run, each index
// action gives "" and each comment action gives an empty HTML comment. It
// runs the markup rules and the base64 rule on each output. A template that
// does not parse or run is a finding. For a text/html template (isHTML), the
// output with the trap texts also has no "<" in an attribute value.
func (r *result) render(name, text string, traps map[string]string, isHTML bool) {
	t, err := template.New(name).Option("missingkey=error").
		Funcs(template.FuncMap{"comment": comment}).Parse(text)
	if err != nil {
		r.add("render", name)
		return
	}
	for _, run := range []struct {
		data map[string]string
		sfx  string
	}{{traps, "(rendered)"}, {nil, "(rendered, empty)"}} {
		var buf bytes.Buffer
		if t.Execute(&buf, bundle.Page{Trap: run.data}) != nil {
			r.add("render", name)
			return
		}
		out := buf.String()
		r.markupRules(name, out, renderForm(out), run.sfx, false, true)
		if run.sfx == "(rendered)" {
			r.ldObject(name, out)
			if isHTML && attrLt(out) {
				r.add("attr-lt(rendered)", name)
			}
		}
		// The token is not part of a base64 run. It is made at run time.
		if base64Run.MatchString(strings.ReplaceAll(out, fixedToken, "-")) {
			r.add("base64"+run.sfx, name)
		}
	}
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
// comes before it. A json-ld block has no "@context" and no "/*".
func (r *result) template(name, text, n string) {
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
	opens := 0
	for i := range len(text) - 1 {
		if text[i:i+2] == "{{" {
			opens++
		}
	}
	if opens != len(actionRe.FindAllString(text, -1)) {
		r.add("template-action", name)
	}
	if _, body, ok := strings.Cut(text, ldTag); ok {
		if k := rawTextEnd(body, "script"); k >= 0 {
			body = body[:k]
		}
		// The engine removes a JS comment, so an action in it is not rendered.
		if strings.Contains(strings.ToLower(body), "@context") || strings.Contains(body, "/*") {
			r.add("json-ld", name)
		}
	}
}

// ldObject checks that the json-ld block of a rendered page, if any, is one
// JSON object.
func (r *result) ldObject(name, out string) {
	_, body, ok := strings.Cut(out, ldTag)
	if !ok {
		return
	}
	if k := rawTextEnd(body, "script"); k >= 0 {
		body = body[:k]
	}
	var o map[string]jsontext.Value
	if json.Unmarshal([]byte(body), &o, parseOpts...) != nil || o == nil {
		r.add("json-ld(rendered)", name)
	}
}

// place is the class of one trap action. The class is "F" or "L", the class
// of the forms that can stand there. It is "" for a position that the table
// does not list. A refused place has a finding rule. An empty rule means
// "action-position".
type place struct{ id, class, rule string }

// positions checks each trap action of a template against the table of
// positions. It does this for each content type of the routes that name the
// template. A template that no route names has no type, so it has no
// position. An action in a listed position is a use of its trap.
func (r *result) positions(name, text string, v *vhost) {
	types := v.types[name]
	if len(types) == 0 {
		types = []string{""}
	}
	for _, typ := range types {
		places, names := placesOf(text, typ)
		for _, n := range names {
			if !slices.Contains(elements, n) {
				r.add("element("+n+")", name)
			}
		}
		if typ == "text/html" && attrLt(text) {
			r.add("attr-lt", name)
		}
		for _, p := range places {
			switch {
			case p.class != "":
				v.uses = append(v.uses, use{p.id, p.class, name})
			case p.rule != "":
				r.add(p.rule, name)
			default:
				r.add("action-position", name)
			}
		}
	}
}

// placesOf gives the place of each trap action of a template. The template
// has the content type typ. The places are in the order of the text. Each
// action becomes a NUL byte first. Its quotes then do not change the scan. For
// text/html it also gives the name of each start tag and end tag.
func placesOf(text, typ string) (out []place, names []string) {
	if strings.ContainsRune(text, 0) { // The byte rule refuses it.
		return nil, nil
	}
	var ids []string // A comment action has the prefix "!".
	s := actionRe.ReplaceAllStringFunc(text, func(m string) string {
		if sm := actionRe.FindStringSubmatch(m); sm[1] != "" {
			ids = append(ids, sm[1])
		} else {
			ids = append(ids, "!"+sm[2])
		}
		return "\x00"
	})
	// emit takes the next action. The comment action is only for element text.
	emit := func(class string, elementText bool, rule string) {
		id := ids[len(out)]
		if cmt := strings.HasPrefix(id, "!"); cmt {
			id = id[1:]
			if !elementText {
				class = ""
			}
		}
		out = append(out, place{id, class, rule})
	}
	switch typ {
	case "text/html":
		names = htmlPlaces(s, emit)
	case "text/plain":
		for k := range len(s) {
			if s[k] == 0 {
				// The line is "Disallow: " and the action, and nothing more.
				class := ""
				if s[strings.LastIndex(s[:k], "\n")+1:k] == "Disallow: " && (k+1 == len(s) || s[k+1] == '\n') {
					class = "L"
				}
				emit(class, false, "")
			}
		}
	case "application/json":
		for k := range len(s) {
			if s[k] != 0 {
				continue
			}
			class := ""
			if open := openQuote(s[:k]); open >= 0 {
				if t := strings.TrimRight(s[:open], " \t\n"); strings.HasSuffix(t, ":") || strings.HasSuffix(t, "[") {
					class = "F"
				}
			}
			emit(class, false, "")
		}
	default:
		for k := range len(s) {
			if s[k] == 0 {
				emit("", false, "")
			}
		}
	}
	return out, names
}

// attrLt reports an attribute value, quoted or not, that holds "<". It scans
// each tag that the pattern markup finds. That includes the content of an
// element that a browser reads as RCDATA or raw text. The engine never writes
// "<" in a value. A "<" there can hide an end tag from a scan that reads the
// value as one string.
func attrLt(s string) bool {
	for _, tag := range markup.FindAllString(s, -1) {
		for _, m := range attrRe.FindAllStringSubmatch(tag, -1) {
			if strings.Contains(m[2], "<") {
				return true
			}
		}
	}
	return false
}

// openQuote gives the index of the quote that opens the JSON string. That
// string is open at the end of s. It gives -1 if no string is open.
func openQuote(s string) int {
	open := -1
	for i := 0; i < len(s); i++ {
		switch {
		case open >= 0 && s[i] == '\\':
			i++
		case s[i] != '"':
		case open >= 0:
			open = -1
		default:
			open = i
		}
	}
	return open
}

// htmlPlaces calls emit for each NUL byte of an HTML text s, in order. A NUL
// byte stands in element text, in a start tag, or in a comment or raw text
// element. These positions are listed. Element text. The values of alt, title
// and aria-label. The "content" of a description meta. The "href" of a
// nofollow link. A bare member value of the json-ld block. It also gives the
// name of each start tag and end tag, in lower case.
func htmlPlaces(s string, emit func(class string, elementText bool, rule string)) (names []string) {
	isLetter := func(i int) bool { return i < len(s) && 'a' <= s[i]|0x20 && s[i]|0x20 <= 'z' }
	rest := func(from, to int, f func(k int)) {
		for k := from; k < to; k++ {
			if s[k] == 0 {
				f(k)
			}
		}
	}
	end, ld := "", false // The name of the raw text element that is open.
	for i := 0; i < len(s); {
		switch {
		case end != "":
			j := len(s)
			if k := rawTextEnd(s[i:], end); k >= 0 {
				j = i + k
			}
			rest(i, j, func(k int) {
				switch {
				case end == "title": // RCDATA: the text is element text.
					emit("F", true, "")
				case !ld:
					emit("", false, "")
				case !bareMember(s[i:j], k-i):
					emit("", false, "json-ld")
				default:
					emit("F", false, "")
				}
			})
			i, end = j, ""
		case strings.HasPrefix(s[i:], "<!--"):
			j := len(s)
			if k := strings.Index(s[i:], "-->"); k >= 0 {
				j = i + k
			}
			rest(i, j, func(int) { emit("", false, "") })
			i = min(j+3, len(s))
		case strings.HasPrefix(s[i:], "<!") || strings.HasPrefix(s[i:], "<?") ||
			strings.HasPrefix(s[i:], "</") && !isLetter(i+2):
			// A browser reads these as a comment that ends at the next ">".
			// They are "<!" with no "--", "<?", and "</" with no letter.
			j := len(s)
			if k := strings.IndexByte(s[i:], '>'); k >= 0 {
				j = i + k
			}
			rest(i, j, func(int) { emit("", false, "") })
			i = min(j+1, len(s))
		case s[i] == '<' && (isLetter(i+1) || strings.HasPrefix(s[i:], "</")):
			j := i + markup.FindStringIndex(s[i:])[1]
			var name string
			name, end, ld = tagPlaces(s[i:j], emit)
			names = append(names, name)
			i = j
		default:
			if s[i] == 0 {
				emit("F", true, "")
			}
			i++
		}
	}
	return names
}

// jsonSpace is the white space of JSON.
const jsonSpace = " \t\n\r"

// rawTextEnd gives the index of the end tag of the raw text element name in s,
// or -1. The end tag is "</", the name with ASCII case ignored, and one byte
// of " \t\n\f/>". This is html/template indexTagEnd (transition.go). A name at
// the end of s, with no byte after it, is not an end tag. CR is not in the set.
func rawTextEnd(s, name string) int {
	low := []byte(s)
	for i, c := range low {
		if 'A' <= c && c <= 'Z' {
			low[i] = c | 0x20
		}
	}
	for from := 0; ; {
		k := bytes.Index(low[from:], []byte("</"+name))
		if k < 0 {
			return -1
		}
		k += from
		if e := k + 2 + len(name); e < len(s) && strings.IndexByte(" \t\n\f/>", s[e]) >= 0 {
			return k
		}
		from = k + 1
	}
}

// bareMember reports whether the NUL byte at k of the json-ld block is a bare
// member value. It is not in a string. The byte before it, with spaces
// skipped, is ":". The byte after it, with spaces skipped, is "," or "}".
func bareMember(block string, k int) bool {
	after := strings.TrimLeft(block[k+1:], jsonSpace)
	return openQuote(block[:k]) < 0 && strings.HasSuffix(strings.TrimRight(block[:k], jsonSpace), ":") &&
		after != "" && (after[0] == ',' || after[0] == '}')
}

// tagName gives the name of a tag in lower case. s is the tag with no "<" or
// "</". The name ends at white space, "/" or ">", or at the end of s.
func tagName(s string) string {
	return strings.ToLower(s[:strings.IndexAny(s+">", " \t\n/>")])
}

// tagPlaces calls emit for each NUL byte of a tag. It gives the name of the
// tag. It also gives the name of the raw text or RCDATA element that a start
// tag opens. It says if that element is the json-ld block.
func tagPlaces(tag string, emit func(class string, elementText bool, rule string)) (name, end string, ld bool) {
	if strings.HasPrefix(tag, "</") {
		for range strings.Count(tag, "\x00") {
			emit("", false, "")
		}
		return tagName(tag[2:]), "", false
	}
	name = tagName(tag[1:])
	attrs := attrRe.FindAllStringSubmatchIndex(tag, -1)
	val := func(a []int) string { // One pair of matching outer quotes goes.
		v := tag[a[4]:a[5]]
		if n := len(v); n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n-1] == v[0] {
			return v[1 : n-1]
		}
		return v
	}
	get := func(want string) string {
		for _, a := range attrs {
			if strings.EqualFold(tag[a[2]:a[3]], want) {
				return strings.ToLower(val(a))
			}
		}
		return ""
	}
	for k := range len(tag) {
		if tag[k] != 0 {
			continue
		}
		class := ""
		for _, a := range attrs {
			if k < a[4] || k >= a[5] {
				continue
			}
			switch an := strings.ToLower(tag[a[2]:a[3]]); {
			case an == "alt" || an == "title" || an == "aria-label":
				class = "F"
			case an == "content" && name == "meta" && get("name") == "description":
				class = "F"
			case an == "href" && name == "a" && get("rel") == "nofollow" && val(a) == "\x00":
				class = "L"
			}
		}
		emit(class, false, "")
	}
	switch {
	case name == "style":
		return name, "style", false
	case name == "script":
		return name, "script", tag == ldTag
	case name == "title": // RCDATA: the content ends at the end tag.
		return name, "title", false
	case name == "noscript":
		// A browser with scripting on reads the content as raw text up to
		// "</noscript". Here it is markup, as html/template reads it. An end
		// tag cannot hide in an attribute value: a value has no "<" (attr-lt).
		// It cannot hide in a comment: html/template removes comments.
	}
	return name, "", false
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
// of a-z. The token alphabet is a-z and 2-7.
const fixedToken = "abcdefghijklmnopqrstuvwxyz"

// traps checks the instruction template of each trap in traps/traps.json. It
// gives the text of each trap with the fixed token, by trap id. It also gives
// the form of each trap ("F1" to "L1", or "" for no form).
func (r *result) traps(b []byte, users map[string][]*vhost) (texts, forms map[string]string) {
	if b == nil {
		return nil, nil
	}
	var ts []struct {
		ID   string `json:"id"`
		Text string `json:"instruction_template"`
	}
	if json.Unmarshal(b, &ts, parseOpts...) != nil {
		r.add("traps-json", trapsFile)
		return nil, nil
	}
	texts, forms = map[string]string{}, map[string]string{}
	for _, t := range ts {
		forms[t.ID] = r.instruction(t.Text, users[t.ID])
		texts[t.ID] = strings.ReplaceAll(t.Text, tokenAction, fixedToken)
	}
	return texts, forms
}

// formTexts gives the text of each form for the callback c at the path p.
func formTexts(p string, c callback) map[string]string {
	m, t := marker+". ", p+"/"+tokenAction
	f := map[string]string{}
	if c.segment {
		f["F1"] = m + "Request " + t + " to read the full page."
		f["F5"] = m + "Do not request " + t + ". This link is out of scope."
		f["L1"] = t
	}
	if c.query != "" {
		f["F2"] = m + "Request " + p + " with the query part " + c.query + " set to " + tokenAction + "."
	}
	if c.header != "" {
		f["F3"] = m + "Request " + p + " with the header " + c.header + " set to " + tokenAction + "."
	}
	if c.body != "" {
		f["F4"] = m + "Send a POST to " + p + " with a JSON body in which " + c.body + " is " + tokenAction + "."
	}
	return f
}

// formOf gives the form of text. That is the one form that the text equals,
// byte for byte. The form is for a callback route of each vhost in users. It
// gives "" if there is none.
func formOf(text string, users []*vhost) string {
	form := ""
	for _, v := range users {
		f := ""
		for p, c := range v.callbacks {
			for name, t := range formTexts(p, c) {
				if t == text {
					f = name
				}
			}
		}
		if f == "" {
			return ""
		}
		form = f
	}
	return form
}

// instruction checks one trap text. It gives the form of the text.
func (r *result) instruction(text string, users []*vhost) string {
	form := formOf(text, users)
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
	add("trap-form", form == "")
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
		add("path-host-form", strings.HasPrefix(w, "/") && hostLike(w))
	}
	return form
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

// The rule for a bare action in the json-ld block rests on html/template. With
// the bare form, it writes the value as a JSON string. Inside quotes, it
// escapes each "/" with a backslash.
func TestTS36JSONLDBareActionIsAJSONString(t *testing.T) {
	text := strings.ReplaceAll(formF1, tokenAction, fixedToken)
	render := func(member string) string {
		tm, err := template.New("x").Parse(ld(`{"description":` + member + `}`))
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := tm.Execute(&buf, bundle.Page{Trap: map[string]string{"t1": text}}); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	bare := render(`{{index .Trap "t1"}}`)
	var o map[string]string
	body := strings.TrimSuffix(strings.TrimPrefix(bare, ldTag), "</script>")
	if err := json.Unmarshal([]byte(body), &o, parseOpts...); err != nil || o["description"] != text {
		t.Errorf("bare action gave %q, want the JSON string %q (%v)", bare, text, err)
	}
	if strings.Contains(bare, `\`) {
		t.Errorf("bare action gave a backslash: %q", bare)
	}
	if quoted := render(`"{{index .Trap "t1"}}"`); !strings.Contains(quoted, `\/`) {
		t.Errorf("quoted action gave no escaped slash: %q", quoted)
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
