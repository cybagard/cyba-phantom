// Package reference holds the content rules of the reference bundle source
// tree (SEC-42, ADR-042). It has test files only. Its tests are T-S-36.
package reference

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	xhtml "golang.org/x/net/html"
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
	// The name of a tag that the pattern markup found.
	tagStart = regexp.MustCompile(`(?i)^</?([a-z][^\s/>]*)`)
	// The content of an element that a browser reads as raw text, or RCDATA.
	rawElements = hiddenOf("style", "script", "title")
	styleBody   = bodyRe("style")
	noscript    = bodyRe("noscript")
	// The content of the json-ld block: group 1 is the text up to its end tag.
	ldBody = regexp.MustCompile(`(?s)` + regexp.QuoteMeta(ldTag) + `(.*?)(?:(?i:</script)[ \t\n\f/>]|$)`)
	// A start tag that a browser does not read as text in noscript.
	noscriptInner = regexp.MustCompile(`(?i)<(?:style|script|title)(?:[\s/>]|$)`)

	// A trap text has no "[" or "]". It has no ":" at the end. It has no
	// ":" before a character that is not a space.
	hostForm = regexp.MustCompile(`[\[\]]|:([^ ]|$)`)
	// A word is a run of ASCII letters. It must be in wordList.
	letters = regexp.MustCompile(`[A-Za-z]+`)
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

	// wordList is the closed list of words of the files below vhosts/.
	// A file is read after the decode of its character references.
	// Each run of ASCII letters in it is a word. A word is compared in lower
	// case. The tags, attribute values, JSON keys, CSS and template actions
	// are part of the text. Each run of letters in the name of a callback
	// position is a word too. The list holds the words of the 6 trap forms.
	// It also holds the names of the elements, attributes, CSS properties,
	// JSON keys and content types that the tree uses. A new word is a code
	// change in a reviewed PR. A word of one letter is in the list only when
	// a form or an element needs it. "a" is a word of F4 and an element.
	// "p" is an element. "x" starts each header name.
	wordList = strings.Fields(`
		phantom reference trap request to read the full page with query part set
		header send a post body in which is do not this link out of scope
		x ref cb p internal vhosts index tmpl routes path template type callback segment
		asset headers name text html charset utf true plain json found comment
		href src alt img svg logo title noscript div rel nofollow aria label meta
		description content script application ld style class hidden display none
		background url animate attributename values robots disallow plugin doctype
		shop docs lang en head footer nav main ul li h em b guide each short here home about us our
		team small tea we sell cups and open day fresh from hills notfound beacon js css txt
		well known ai note openapi schema version v for human model auth api legal info image xml
		user agent font family serif margin auto max width color viewbox height fill rect navy gray
	`)
	wordSet = func() map[string]bool {
		m := map[string]bool{}
		for _, w := range wordList {
			m[w] = true
		}
		return m
	}()
)

// result collects findings. A finding is "<rule> <path>". A finding is added
// once. Each refused-input test asserts the rule, not only a failure.
type result struct{ out []string }

func (r *result) add(rule, name string) {
	if f := rule + " " + name; !slices.Contains(r.out, f) {
		r.out = append(r.out, f)
	}
}

// secondLayer is true when the second layer runs. The second layer checks the
// template source, the rendered output (attr-lt) and the element names of the
// parsed pages. Its checks only add findings. The check of the
// rendered page gives the class of each trap action. A test sets the variable
// to false, to see what the rendered page alone refuses.
var secondLayer = true

// layer adds a finding of the second layer.
func (r *result) layer(rule, name string) {
	if secondLayer {
		r.add(rule, name)
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
// it. A trap that no vhost uses has no path. The types of a template or an
// asset are the content types of the routes that name it. They have no
// parameter.
type vhost struct {
	callbacks map[string]callback
	uses      []use
	types     map[string][]string
	// The grammar reads the next five fields. The first two are the vhost
	// directory and its route paths and asset base names. The third holds the
	// route paths of its templates and assets. The last two are the rendered
	// trap texts of a form, and those of the form L1.
	host    string
	names   map[string]bool
	pages   map[string]bool
	renders []string
	l1      []string
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

// readRoutes reads a route map. The name grammar reads each path and each
// file value of it. So no rule of the host form runs on the paths here.
func (v *vhost) readRoutes(r *result, name string, b []byte) {
	r.grammar(name, "routes", string(b), v)
	var m struct {
		Routes []struct {
			Path     string `json:"path"`
			Template string `json:"template"`
			Asset    string `json:"asset"`
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
	}
	if json.Unmarshal(b, &m, parseOpts...) != nil {
		r.add("routes-json", name)
		return
	}
	if m.NotFound != "" {
		v.types[m.NotFound] = append(v.types[m.NotFound], "text/html")
	}
	for _, rt := range m.Routes {
		v.names[rt.Path] = true
		if rt.Asset != "" {
			v.names[path.Base(rt.Asset)] = true
		}
		if rt.Template != "" || rt.Asset != "" {
			v.pages[rt.Path] = true
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
		for _, file := range []string{rt.Template, rt.Asset} {
			if file != "" {
				typ, _, _ := strings.Cut(rt.Type, ";")
				v.types[file] = append(v.types[file], strings.ToLower(strings.TrimSpace(typ)))
			}
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
	var templates, assets []string
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
		owner[name] = v
		if strings.HasSuffix(name, ".tmpl") {
			templates = append(templates, name)
		} else {
			assets = append(assets, name)
		}
	}
	r.vhostFiles(files)
	// The route maps are read, so the type of each file is known.
	for _, name := range assets {
		types := owner[name].types[name]
		if slices.Contains(types, "text/html") && !visibleMarker("html", string(files[name])) {
			r.add("marker", name)
		}
		if (slices.Contains(types, "text/html") || slices.Contains(types, "image/svg+xml") ||
			strings.HasSuffix(name, ".svg")) && attrLt(string(files[name])) {
			r.add("attr-lt(asset)", name)
		}
	}
	defs := r.readTraps(files[trapsFile])
	raw, texts := map[string]string{}, map[string]string{}
	for _, t := range defs {
		raw[t.ID] = t.Text
		texts[t.ID] = strings.ReplaceAll(t.Text, tokenAction, fixedToken)
	}
	users := map[string][]*vhost{}
	for _, name := range templates {
		r.positions(name, string(files[name]), owner[name], raw)
	}
	for _, v := range hosts {
		for _, u := range v.uses {
			if !slices.Contains(users[u.id], v) {
				users[u.id] = append(users[u.id], v)
			}
		}
	}
	forms := r.trapForms(defs, users)
	for _, v := range hosts {
		for _, u := range v.uses {
			if f := forms[u.id]; f != "" && f[:1] != u.class {
				r.add("trap-class", u.file)
			}
		}
	}
	for _, v := range hosts {
		for _, t := range defs {
			if f := forms[t.ID]; f != "" {
				v.renders = append(v.renders, texts[t.ID])
				if f[0] == 'L' {
					v.l1 = append(v.l1, texts[t.ID])
				}
			}
		}
	}
	for _, name := range assets {
		kinds := kindsOf(name, owner[name].types[name])
		if len(kinds) == 0 { // No grammar reads the file.
			r.add("grammar-kind", name)
		}
		for _, kind := range kinds {
			r.grammar(name, kind, string(files[name]), owner[name])
		}
	}
	for _, name := range templates {
		r.render(name, string(files[name]), texts, owner[name])
	}
	r.out = append(r.out, listDeny(wordList)...)
	return r.out
}

// pageWord is the list word that stands for a token in a rendered page.
const pageWord = "page"

// vhostFiles runs the text rules on each file below vhosts/, the route maps
// too. The rules are the word list and the deny list. The byte and base64
// rules run on the decoded forms.
func (r *result) vhostFiles(files map[string][]byte) {
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if parts := strings.SplitN(name, "/", 3); parts[0] != "vhosts" || len(parts) < 2 {
			continue
		}
		raw := string(files[name])
		r.decoded(name, raw)
		r.textRules(name, raw)
	}
}

// textRules runs the word rule and the deny list on the readings of s.
func (r *result) textRules(name, s string) {
	r.words(name, s)
	for _, d := range readings(s) {
		for _, w := range denied(d) {
			r.add("text-deny("+w+")", name)
		}
	}
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
		hosts[host] = &vhost{callbacks: map[string]callback{}, types: map[string][]string{},
			host: host, names: map[string]bool{}, pages: map[string]bool{}}
		bad := !dirs[n] || !validVhost(host)
		if bad || !lists.in("vhosts", host) {
			r.add("vhost-name", n)
		}
		if first, _, _ := strings.Cut(host, "."); bad {
			continue
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
	if slices.ContainsFunc(b, badByte) {
		r.add("bytes", name)
	}
	if base64Run.Match(b) {
		r.add("base64", name)
	}
}

func badByte(c byte) bool { return c != '\t' && c != '\n' && (c < 0x20 || c > 0x7e) }

// has reports a finding of the rule, also with a suffix, for the file name.
func (r *result) has(rule, name string) bool {
	return slices.ContainsFunc(r.out, func(f string) bool {
		return strings.HasPrefix(f, rule) && strings.HasSuffix(f, " "+name)
	})
}

// words checks each run of letters in the readings of s against wordList. The
// two SVG namespace names are not words.
func (r *result) words(name, s string) {
	for _, d := range readings(svgNames.Replace(s)) {
		for _, w := range letters.FindAllString(d, -1) {
			if w = strings.ToLower(w); !wordSet[w] {
				r.add("word("+w+")", name)
			}
		}
	}
}

// tagless removes the comments and the tags of s.
func tagless(s string) string {
	return markup.ReplaceAllString(htmlComment.ReplaceAllString(s, ""), "")
}

// readings gives the forms of a text that the text rules read. They are the
// decoded text, and the decoded text with the tags and comments removed.
// A "&lt;i&gt;" can make a tag. So the removal runs before the decode and
// after it.
func readings(s string) []string {
	d := html.UnescapeString(s)
	return []string{d, tagless(d), html.UnescapeString(tagless(s))}
}

// decoded runs the byte rule and the base64 rule on the readings of s. A rule
// that already found the raw text of the file does not run again. So a file
// has one finding for each rule.
func (r *result) decoded(name, s string) {
	for _, v := range readings(s) {
		if !r.has("bytes", name) && slices.ContainsFunc([]byte(v), badByte) {
			r.add("bytes(decoded)", name)
		}
		if !r.has("base64", name) && base64Run.MatchString(v) {
			r.add("base64(decoded)", name)
		}
	}
}

// denied gives the entries of the deny list that the text matches.
func denied(text string) (out []string) {
	low := strings.ToLower(text)
	s := notAlnum.ReplaceAllString(low, " ")
	compact := strings.ReplaceAll(s, " ", "")
	for _, w := range denyWords {
		if strings.Contains(s, notAlnum.ReplaceAllString(w, " ")) {
			out = append(out, w)
		}
	}
	for _, w := range denyCompact {
		if strings.Contains(compact, w) {
			out = append(out, w)
		}
	}
	for w, re := range denyStart {
		if re.MatchString(s) {
			out = append(out, w)
		}
	}
	for w, bad := range map[string]bool{
		".env":                 dotEnv.MatchString(low),
		"rm -":                 rmDash.MatchString(low),
		"instruction+override": strings.Contains(s, "instruction") && strings.Contains(compact, "override"),
	} {
		if bad {
			out = append(out, w)
		}
	}
	return out
}

// listDeny runs the deny code of the trap texts on each word of a list. It
// also runs it on the list as one text, for the pair "instruction" and
// "override".
func listDeny(list []string) []string {
	r := &result{}
	for _, w := range list {
		for _, d := range denied(w) {
			r.add("list-deny("+d+")", w)
		}
	}
	if slices.Contains(denied(strings.Join(list, " ")), "instruction+override") {
		r.add("list-deny(instruction+override)", "list")
	}
	return r.out
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
// template it also checks the action forms. An asset has no action. The
// rules run on the raw text and on the normal form.
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
// runs the markup rules and the base64 rule on each output. It also runs the
// text rules on it, with each token as pageWord. A template that does not
// parse or run is a finding. For a text/html template, the output with the
// trap texts also has no "<" in an attribute value. The grammar of each kind
// of the template runs on each output.
func (r *result) render(name, text string, traps map[string]string, v *vhost) {
	isHTML := slices.Contains(v.types[name], "text/html")
	// The output with no trap text decides the marker of a text/html template.
	marked := hasMarker(text)
	t, err := template.New(name).Option("missingkey=error").
		Funcs(template.FuncMap{"comment": comment}).Parse(text)
	if err != nil {
		r.add("render", name)
		if !marked {
			r.add("marker", name)
		}
		return
	}
	var outs, pages []string
	defer func() {
		if !marked {
			r.add("marker", name)
		}
		for _, o := range outs {
			r.decoded(name, o)
		}
		for _, o := range pages {
			r.textRules(name, o)
		}
	}()
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
		if isHTML && run.data == nil {
			marked = visibleMarker("html", out)
		}
		for _, kind := range kindsOf(name, v.types[name]) {
			r.grammar(name, kind, out, v)
		}
		outs = append(outs, strings.ReplaceAll(out, fixedToken, "-"))
		pages = append(pages, strings.ReplaceAll(out, fixedToken, pageWord))
		r.markupRules(name, out, renderForm(out), run.sfx, false, true)
		if run.sfx == "(rendered)" {
			r.ldObject(name, out)
			if isHTML && attrLt(out) {
				r.layer("attr-lt(rendered)", name)
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

// hasMarker reports the marker in the text that stays when HTML comments, the
// hidden elements and tags are removed. It is the marker rule of a template
// that is not text/html, and of a template that does not render. A text/html
// output has visibleMarker.
func hasMarker(text string) bool {
	visible := htmlComment.ReplaceAllString(text, "")
	for _, re := range hiddenElements {
		visible = re.ReplaceAllString(visible, "")
	}
	return strings.Contains(markup.ReplaceAllString(visible, ""), marker)
}

// template checks the actions of a template. Each "{{" must
// start one of the two exact forms, and no "/" comes before it. A json-ld
// block has no "@context" and no "/*".
func (r *result) template(name, text, n string) {
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
	if m := ldBody.FindStringSubmatch(text); m != nil {
		// The engine removes a JS comment, so an action in it is not rendered.
		if strings.Contains(strings.ToLower(m[1]), "@context") || strings.Contains(m[1], "/*") {
			r.add("json-ld", name)
		}
		if strings.Contains(m[1], "<!--") || strings.Contains(m[1], "-->") {
			r.layer("json-ld(comment)", name)
		}
	}
}

// ldObject checks that the json-ld block of a rendered page, if any, is one
// JSON object.
func (r *result) ldObject(name, out string) {
	m := ldBody.FindStringSubmatch(out)
	if m == nil {
		return
	}
	body := m[1]
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
func (r *result) positions(name, text string, v *vhost, defs map[string]string) {
	types := v.types[name]
	if len(types) == 0 {
		types = []string{""}
	}
	for _, typ := range types {
		var places []place
		if typ == "text/html" {
			var names []string
			var err error
			if places, names, err = htmlPlaces(text, defs); err != nil {
				r.add("render", name)
			}
			r.sourceRules(name, text)
			for _, n := range append(sourceNames(text), names...) {
				if !slices.Contains(elements, n) {
					r.layer("element("+n+")", name)
				}
			}
			if attrLt(text) {
				r.layer("attr-lt", name)
			}
		} else {
			places = placesOf(text, typ)
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

// placesOf gives the place of each trap action of a template that is not
// text/html. The template has the content type typ. The places are in the
// order of the text. Each action becomes a NUL byte first. Its quotes then do
// not change the scan. The comment action is only for an HTML comment, so it
// has no class here.
func placesOf(text, typ string) (out []place) {
	if strings.ContainsRune(text, 0) { // The byte rule refuses it.
		return nil
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
	// emit takes the next action.
	emit := func(class string) {
		id := ids[len(out)]
		if cmt := strings.HasPrefix(id, "!"); cmt {
			id, class = id[1:], ""
		}
		out = append(out, place{id, class, ""})
	}
	switch typ {
	case "text/plain":
		for k := range len(s) {
			if s[k] == 0 {
				// The line is "Disallow: " and the action, and nothing more.
				class := ""
				if s[strings.LastIndex(s[:k], "\n")+1:k] == "Disallow: " && (k+1 == len(s) || s[k+1] == '\n') {
					class = "L"
				}
				emit(class)
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
			emit(class)
		}
	default:
		for k := range len(s) {
			if s[k] == 0 {
				emit("")
			}
		}
	}
	return out
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

// The tokens of the rendered page. A token has the 22 letters of tokenBase and
// 4 letters for the number of the action. Its letters are a-z, a part of the
// token alphabet of the engine (a-z and 2-7). A token has the length of a
// token of the engine.
const (
	tokenBase = "xqzjkvwxqzjkvwxqzjkvwx"
	tokenLen  = len(tokenBase) + 4
)

// tokenOf gives the token of the action number n.
func tokenOf(n int) string {
	d := []byte("aaaa")
	for i := len(d) - 1; i >= 0; i, n = i-1, n/26 {
		d[i] += byte(n % 26)
	}
	return tokenBase + string(d)
}

// action is one trap action of a template. Its token is in the text that the
// page holds for it.
type action struct {
	id      string
	comment bool   // The comment action.
	text    string // The trap text, with the token of the action.
}

// htmlPlaces gives the place of each trap action of a text/html template.
// The places are in the order of the text. The check renders the template
// with html/template. Each action has its own key "<id>#<n>". Its trap text
// has a token of its own.
//
// The check parses the output as a browser does, with scripting on and with
// scripting off. A token has a class only at one listed tree place.
// These places are element text and the value of alt, title or aria-label.
// They are the content of a description meta and the href of a nofollow
// link. They are a member value of the json-ld block and the comment of the
// comment action. Each other place has no class.
//
// A token has no class if it is not in the tree. It has none if it is there
// more than once, or if its two places in the two modes differ. The function
// also gives the name of each element of the two trees. The error is a
// template that does not render.
func htmlPlaces(text string, defs map[string]string) (places []place, names []string, err error) {
	var acts []action
	keyed := actionRe.ReplaceAllStringFunc(text, func(m string) string {
		sm := actionRe.FindStringSubmatch(m)
		a := action{id: sm[1]}
		if a.id == "" {
			a.id, a.comment = sm[2], true
		}
		raw, ok := defs[a.id]
		if !ok || !strings.Contains(raw, tokenAction) {
			// A trap that is not there, or has no token, has the token only.
			// The trap check refuses the text of such a trap.
			raw = tokenAction
		}
		a.text = strings.ReplaceAll(raw, tokenAction, tokenOf(len(acts)))
		acts = append(acts, a)
		return strings.Replace(m, `"`+a.id+`"`, `"`+a.id+"#"+strconv.Itoa(len(acts)-1)+`"`, 1)
	})
	data := map[string]string{}
	for i, a := range acts {
		data[a.id+"#"+strconv.Itoa(i)] = a.text
	}
	t, err := template.New("page").Option("missingkey=error").
		Funcs(template.FuncMap{"comment": comment}).Parse(keyed)
	if err != nil {
		return nil, nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, bundle.Page{Trap: data}); err != nil {
		return nil, nil, err
	}
	places = make([]place, len(acts))
	for _, scripting := range []bool{true, false} {
		root, err := xhtml.ParseWithOptions(strings.NewReader(buf.String()), xhtml.ParseOptionEnableScripting(scripting))
		if err != nil {
			return nil, nil, err
		}
		hits := tokenHits(root, func(n string) { names = append(names, n) })
		for i, a := range acts {
			p := place{id: a.id}
			if h := hits[i]; len(h) == 1 {
				p.class, p.rule = placeOf(h[0], a)
			}
			if scripting {
				places[i] = p
			} else if places[i] != p {
				places[i] = place{id: a.id}
			}
		}
	}
	return places, names, nil
}

// hit is the place of a token in a parse tree. It is a string of a node. The
// string is the name or the text of the node, or the name or value of an
// attribute.
type hit struct {
	node *xhtml.Node
	attr *xhtml.Attribute // The attribute, or nil.
	name bool             // The token is in the name of the attribute.
	text string           // The string that holds the token.
}

// tokenHits gives the hits of each token of a tree, by the number of the
// action. A token twice in one string is one hit. It calls elem with the name
// of each element in lower case.
func tokenHits(root *xhtml.Node, elem func(string)) map[int][]hit {
	hits := map[int][]hit{}
	find := func(s string, h hit) {
		h.text = s
		seen := map[int]bool{}
		for rest := s; ; {
			i := strings.Index(rest, tokenBase)
			if i < 0 || len(rest) < i+tokenLen {
				return
			}
			n, ok := 0, true
			for _, c := range rest[i+len(tokenBase) : i+tokenLen] {
				n, ok = n*26+int(c-'a'), ok && 'a' <= c && c <= 'z'
			}
			if ok && !seen[n] {
				seen[n] = true
				hits[n] = append(hits[n], h)
			}
			rest = rest[i+len(tokenBase):]
		}
	}
	var walk func(n *xhtml.Node)
	walk = func(n *xhtml.Node) {
		find(n.Data, hit{node: n})
		if n.Type == xhtml.ElementNode {
			elem(strings.ToLower(n.Data))
		}
		for i := range n.Attr {
			find(n.Attr[i].Key, hit{node: n, attr: &n.Attr[i], name: true})
			find(n.Attr[i].Val, hit{node: n, attr: &n.Attr[i]})
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return hits
}

// placeOf gives the class and the rule of the action a at the hit h. The
// class is "" for a place that the table does not list.
func placeOf(h hit, a action) (class, rule string) {
	n := h.node
	switch {
	case h.name:
	case h.attr != nil && n.Namespace == "":
		switch k := h.attr.Key; {
		case k == "alt" || k == "title" || k == "aria-label":
			class = "F"
		case k == "content" && n.Data == "meta" && strings.EqualFold(attrOf(n, "name"), "description"):
			class = "F"
		case k == "href" && n.Data == "a" && strings.EqualFold(attrOf(n, "rel"), "nofollow") && h.attr.Val == a.text:
			class = "L"
		}
	case n.Type == xhtml.CommentNode:
		if a.comment && n.Data == " "+a.text+" " {
			class = "F"
		}
	case n.Type == xhtml.TextNode && !a.comment && n.Parent != nil &&
		n.Parent.Type == xhtml.ElementNode && n.Parent.Namespace == "":
		switch p := n.Parent; {
		case p.Data == "script" && len(p.Attr) == 1 && p.Attr[0].Key == "type" && p.Attr[0].Val == "application/ld+json":
			if memberValue(n.Data, a.text) {
				class = "F"
			} else {
				rule = "json-ld"
			}
		case p.Data != "style" && p.Data != "script" && slices.Contains(elements, p.Data):
			class = "F"
		}
	}
	return class, rule
}

// attrOf gives the value of the attribute key of the element n.
func attrOf(n *xhtml.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// memberValue reports whether the JSON text s has a member of an object whose
// value is the string want. An array element is not a member value.
func memberValue(s, want string) bool {
	var v any
	return json.Unmarshal([]byte(s), &v, parseOpts...) == nil && hasMember(v, want)
}

func hasMember(v any, want string) bool {
	switch v := v.(type) {
	case map[string]any:
		for _, m := range v {
			if s, ok := m.(string); ok && s == want || hasMember(m, want) {
				return true
			}
		}
	case []any:
		for _, e := range v {
			if hasMember(e, want) {
				return true
			}
		}
	}
	return false
}

// bodyRe gives the pattern for the content of the element name. A start tag
// can hold a quoted ">". An end tag is "</", the name and one byte of
// " \t\n\f/>" (html/template indexTagEnd). Group 1 is the content.
func bodyRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?is)<` + name + `(?:[\s/](?:"[^"]*"|'[^']*'|[^>])*)?>(.*?)(?:</` + name + `[ \t\n\f/>]|$)`)
}

// sourceNames gives the name of each tag of a template source, in lower case.
// It skips comments and the content of style, script and title.
func sourceNames(text string) (names []string) {
	s := htmlComment.ReplaceAllString(text, "")
	for _, re := range rawElements {
		s = re.ReplaceAllString(s, "")
	}
	for _, tag := range markup.FindAllString(s, -1) {
		if m := tagStart.FindStringSubmatch(tag); m != nil {
			names = append(names, strings.ToLower(m[1]))
		}
	}
	return names
}

// badLt reports a "<" of a text/html template that is not allowed. A "<" is
// allowed before a letter, before "/" and a letter, and in "<!--". It is also
// allowed in "<!doctype html>", with the case ignored. html/template writes
// each other "<" as "&lt;". A source scan reads a comment there, but the
// page has markup.
func badLt(s string) bool {
	letter := func(c byte) bool { return 'a' <= c|0x20 && c|0x20 <= 'z' }
	for i := range len(s) {
		if s[i] != '<' {
			continue
		}
		rest := s[i:]
		switch {
		case len(rest) > 1 && letter(rest[1]):
		case len(rest) > 2 && rest[1] == '/' && letter(rest[2]):
		case strings.HasPrefix(rest, "<!--"):
		case len(rest) >= 15 && strings.EqualFold(rest[:15], "<!doctype html>"):
		default:
			return true
		}
	}
	return false
}

// sourceRules checks the source of a text/html template. It refuses a "<"
// that is not a tag, and a "<" in raw text. It refuses a raw text element in
// noscript. It also refuses a comment that html/template ends at another
// place than a browser does.
func (r *result) sourceRules(name, text string) {
	if badLt(text) {
		r.layer("lt-text", name)
	}
	for _, m := range append(styleBody.FindAllStringSubmatch(text, -1), ldBody.FindAllStringSubmatch(text, -1)...) {
		if strings.Contains(m[1], "<") {
			r.layer("lt-raw", name)
		}
	}
	for _, m := range noscript.FindAllStringSubmatch(text, -1) {
		if noscriptInner.MatchString(m[1]) {
			r.layer("noscript-raw", name)
		}
	}
	if strings.Contains(text, "<!-->") || strings.Contains(text, "<!--->") {
		r.layer("comment-empty", name)
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
// of a-z. The token alphabet is a-z and 2-7.
const fixedToken = "abcdefghijklmnopqrstuvwxyz"

// trapDef is the id and the instruction template of a trap.
type trapDef struct {
	ID   string `json:"id"`
	Text string `json:"instruction_template"`
}

// readTraps reads traps/traps.json. It gives nil if the file is absent or is
// not JSON.
func (r *result) readTraps(b []byte) []trapDef {
	if b == nil {
		return nil
	}
	var ts []trapDef
	if json.Unmarshal(b, &ts, parseOpts...) != nil {
		r.add("traps-json", trapsFile)
		return nil
	}
	return ts
}

// trapForms checks the instruction template of each trap. It gives the form
// of each trap ("F1" to "L1", or "" for no form), by trap id.
func (r *result) trapForms(ts []trapDef, users map[string][]*vhost) map[string]string {
	forms := map[string]string{}
	for _, t := range ts {
		forms[t.ID] = r.instruction(t.Text, users[t.ID])
	}
	return forms
}

// formTexts gives the text of each form for the callback c at the path p.
func formTexts(p string, c callback) map[string]string {
	m, t := marker+". ", p+"/"+tokenAction
	f := map[string]string{}
	if c.segment {
		f["F1"] = m + "Request " + t + " to read the full page."
		f["F5"] = m + "Do not request " + t + ". This link is out of scope."
		// The form L1 is valid only when the marker is one segment of the
		// path.
		if slices.Contains(strings.Split(p, "/"), marker) {
			f["L1"] = t
		}
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
	for _, w := range denied(text) {
		add("instr-deny("+w+")", true)
	}
	for _, w := range strings.Fields(text) {
		add("path-host-form", strings.HasPrefix(w, "/") && hostLike(w))
	}
	return form
}

// set makes a set of the words of s.
func set(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// listFile is the data file with the closed lists of the content rules. The
// tests read these lists only from it. listPin is its SHA-256 (ADR-044).
const (
	listFile = "testdata/lists.txt"
	listName = "lists.txt" // The name in a finding.
	listPin  = "0d16887ea50c21450ab36b51b3ce5d8cd62e054a8e610c583b1bd052ec523ea5"
)

// listSections are the sections of the file, in their order.
var listSections = []string{"templates", "sentences", "nouns", "adjectives", "names", "prefixes",
	"extensions", "paths", "vhosts", "headers", "classes", "members-routes", "members-plugin", "members-ld"}

// actionWords are the action words of the trap forms. Only a trap render
// holds them.
var actionWords = set("request send post query header body set")

// A listSet holds the entries of each section of the data file.
type listSet map[string][]string

// lists is the data file as the rules read it. A test that edits the file
// bytes in memory swaps it with useLists.
var lists = func() listSet {
	b, _ := os.ReadFile(listFile) // The guard test reports a missing file.
	return loadLists(b)
}()

// A listLine is a line of the data file, with the section that it is in. A
// line "[name]" is a head: it starts the section name.
type listLine struct {
	text, section string
	head          bool
}

// parseLists splits the bytes b into lines. Each reader of the file format
// uses it.
func parseLists(b []byte) []listLine {
	var out []listLine
	cur := ""
	for _, ln := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		n, ok := strings.CutPrefix(ln, "[")
		head := ok && strings.HasSuffix(n, "]")
		if head {
			cur = strings.TrimSuffix(n, "]")
		}
		out = append(out, listLine{ln, cur, head})
	}
	return out
}

// loadLists reads the sections of the bytes b.
func loadLists(b []byte) listSet {
	l := listSet{}
	for _, ln := range parseLists(b) {
		if !ln.head && ln.section != "" && ln.text != "" {
			l[ln.section] = append(l[ln.section], ln.text)
		}
	}
	return l
}

func (l listSet) in(section, v string) bool { return slices.Contains(l[section], v) }

// useLists makes the rules read the lists of the bytes b, until the test ends.
func useLists(t *testing.T, b []byte) {
	old := lists
	t.Cleanup(func() { lists = old })
	lists = loadLists(b)
}

// sentence reports a fixed sentence or an instance of a template. An
// instance has a noun in each NOUN slot and an adjective in each ADJ slot.
// The check splits the words at one space.
func (l listSet) sentence(e string) bool {
	if l.in("sentences", e) {
		return true
	}
	w := strings.Split(e, " ")
	return slices.ContainsFunc(l["templates"], func(t string) bool {
		tw := strings.Split(t, " ")
		return len(tw) == len(w) && l.fits(tw, w)
	})
}

// fits reports that the words w are an instance of the template words tw.
// The last word of a sentence has a "." after it, also a slot.
func (l listSet) fits(tw, w []string) bool {
	for i, s := range tw {
		x := w[i]
		if dot := strings.HasSuffix(s, "."); dot != strings.HasSuffix(x, ".") {
			return false
		} else if dot {
			s, x = strings.TrimSuffix(s, "."), strings.TrimSuffix(x, ".")
		}
		switch {
		case s == "NOUN" && !l.in("nouns", x), s == "ADJ" && !l.in("adjectives", x),
			s != "NOUN" && s != "ADJ" && s != x:
			return false
		}
	}
	return true
}

// wordForm is a word of a dictionary: 1 to 12 letters a-z.
var wordForm = regexp.MustCompile(`^[a-z]{1,12}$`)

// listFindings checks the bytes b of the data file: the format, the bound of
// each entry, and the pin. A finding is "<rule> lists.txt".
func listFindings(b []byte, pin string) []string {
	r := &result{}
	add := func(rule string) { r.add(rule, listName) }
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != pin {
		add("list-pin")
	}
	// A tab has its own rule.
	if slices.ContainsFunc(b, func(c byte) bool { return c != '\n' && c != '\t' && (c < 0x20 || c > 0x7e) }) {
		add("list-byte")
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		add("list-final-lf")
	}
	var heads []string
	prev, seen := "", map[string]bool{}
	for _, l := range parseLists(b) {
		ln := l.text
		switch {
		case ln == "":
			add("list-empty-line")
			continue
		case strings.Contains(ln, "\t"):
			add("list-tab")
		case ln[0] == ' ' || ln[len(ln)-1] == ' ':
			add("list-space")
		}
		if l.head {
			heads = append(heads, l.section)
			prev, seen = "", map[string]bool{}
			continue
		}
		switch {
		case l.section == "":
			add("list-outside")
		case seen[ln]:
			add("list-duplicate")
		case ln < prev:
			add("list-order")
		}
		seen[ln], prev = true, ln
	}
	if !slices.Equal(heads, listSections) {
		add("list-section")
	}
	loadLists(b).bound(r)
	return r.out
}

// bound adds the findings of the shape of the entries. A template, a fixed
// sentence and a dictionary word hold no action word and no deny word. An
// action word is also a part of a longer word, with the case ignored.
func (l listSet) bound(r *result) {
	add := func(rule string) { r.add(rule, listName) }
	for _, sec := range []string{"nouns", "adjectives", "names"} {
		for _, w := range l[sec] {
			if !wordForm.MatchString(w) {
				add("list-word")
			}
		}
	}
	for _, sec := range []string{"templates", "sentences", "nouns", "adjectives", "names"} {
		for _, e := range l[sec] {
			for a := range actionWords {
				if strings.Contains(strings.ToLower(e), a) {
					add("list-action")
					break
				}
			}
			if len(denied(e)) > 0 {
				add("list-deny")
			}
		}
	}
	for _, t := range l["templates"] {
		first, _, _ := strings.Cut(t, " ")
		if first = strings.TrimSuffix(first, "."); first == "NOUN" || first == "ADJ" {
			add("list-template-first")
		}
		if strings.Contains(strings.TrimSuffix(t, "."), ".") {
			add("list-template-dot")
		}
	}
}

// These tables are test code. A table entry is an exact value.
var (
	// svgElements is the element list of an SVG asset. A page has no svg.
	svgElements = set("svg title g rect")
	// blocks start and end a unit of text. The html, head, body, title and
	// noscript elements are not blocks.
	blocks = set("p div h1 h2 h3 ul ol li section header footer main nav article br svg")
	voids  = set("meta img br")
	// frame gives the tags of a document frame in their order. An end tag has
	// "/" before its name.
	frame = []string{"html", "head", "/head", "body", "/body", "/html"}
	// headElems are the elements that the head of a document can hold.
	headElems = set("meta title style script")
	// attrClass gives the value class of an attribute, for its element or
	// for each element ("*"). The key of an SVG attribute is in lower case.
	attrClass = map[string]string{
		"*.class": "class", "*.title": "prose", "*.aria-label": "prose", "*.hidden": "empty",
		"html.lang": "fixed", "meta.charset": "fixed", "meta.name": "fixed", "meta.content": "prose",
		"a.href": "link", "a.rel": "fixed", "img.src": "page", "img.alt": "prose", "script.type": "fixed",
		"svg.xmlns": "fixed", "svg.viewbox": "fixed",
		"rect.width": "fixed", "rect.height": "fixed", "rect.fill": "fixed",
	}
	fixedValues = map[string][]string{
		"html.lang": {"en"}, "meta.charset": {"utf-8"}, "meta.name": {"description"}, "a.rel": {"nofollow"},
		"script.type": {"application/ld+json"}, "svg.xmlns": {"http://www.w3.org/2000/svg"},
		"svg.viewbox": {"0 0 24 24"}, "rect.width": {"24"}, "rect.height": {"24"}, "rect.fill": {"navy"},
	}
	// declarations are the CSS declarations. The value says if it hides.
	declarations = map[string]bool{
		"display:none": true, "font-family:serif": false, "margin:auto": false,
		"max-width:40em": false, "color:gray": false,
	}
	fixedLines = []string{"User-agent: *", "# " + marker}
	// jsonClass gives the class of the string value of a member, for each
	// kind of JSON file. A member that is not here has no string value.
	// A "path" member holds a path. A "word" member holds one name word.
	jsonClass = map[string]string{
		"routes.asset": "file", "routes.template": "file", "routes.not_found": "file",
		"routes.body": "word", "routes.path": "path", "routes.post": "path", "routes.query": "word",
		"routes.script": "path", "routes.header": "header", "routes.name": "header", "routes.trap": "id",
		"routes.type":           "fixed",
		"plugin.name_for_model": "word", "plugin.url": "path", "plugin.logo_url": "path",
		"plugin.legal_info_url": "path", "plugin.schema_version": "fixed", "plugin.type": "fixed",
		"plugin.name_for_human": "prose", "plugin.description_for_human": "prose",
		"plugin.description_for_model": "prose", "ld.description": "prose",
	}
	jsonFixed = map[string][]string{
		"routes.type": {"text/html; charset=utf-8", "text/plain; charset=utf-8", "text/css; charset=utf-8",
			"application/json", "image/svg+xml"},
		"plugin.schema_version": {"v1"}, "plugin.type": {"none", "openapi"},
	}
	// typeKinds and extKinds give the kind of an output. A route type is
	// read without its parameter.
	typeKinds = map[string]string{"text/html": "html", "text/plain": "text", "text/css": "css",
		"application/json": "plugin", "image/svg+xml": "svg"}
	extKinds = map[string]string{".tmpl": "html", ".html": "html", ".txt": "text", ".css": "css",
		".json": "plugin", ".svg": "svg"}
)

// isName reports a name. It is an entry of [paths]. It can also be one word
// of [names]. The word can have "/" before it and an extension after.
func isName(v string) bool {
	stem := v
	if i := strings.LastIndexByte(v, '.'); i > 0 && lists.in("extensions", v[i+1:]) {
		stem = v[:i]
	}
	return lists.in("paths", v) || lists.in("names", strings.TrimPrefix(stem, "/"))
}

// isPath reports a path: a name that starts with "/".
func isPath(v string) bool { return strings.HasPrefix(v, "/") && isName(v) }

// isID reports a trap id: an entry of [prefixes] and one word of [names].
func isID(v string) bool {
	return slices.ContainsFunc(lists["prefixes"], func(p string) bool {
		w, ok := strings.CutPrefix(v, p)
		return ok && lists.in("names", w)
	})
}

// isFile reports a file value below the vhost host: "vhosts/", the vhost,
// "/" and a file name.
func isFile(host, v string) bool {
	f, ok := strings.CutPrefix(v, "vhosts/"+host+"/")
	return ok && lists.in("vhosts", host) && !strings.Contains(f, "/") && isName(f)
}

// kindsOf gives the kinds of a served file. The types of the routes that
// name it decide. A kind can repeat. A file with no known type has the kind
// of its extension.
func kindsOf(file string, types []string) (kinds []string) {
	for _, t := range types {
		if k := typeKinds[t]; k != "" {
			kinds = append(kinds, k)
		}
	}
	if k := extKinds[path.Ext(file)]; len(kinds) == 0 && k != "" {
		kinds = []string{k}
	}
	return kinds
}

// gram is the state of the grammar on one served output of a vhost.
type gram struct {
	r    *result
	name string
	v    *vhost
}

func (g gram) add(rule string) { g.r.add("grammar-"+rule, g.name) }

// grammar runs the grammar of the kind on the output out of a file. The
// kinds are html, svg, css, text, plugin (a JSON file) and routes.
func (r *result) grammar(name, kind, out string, v *vhost) {
	g := gram{r, name, v}
	if strings.Contains(out, "&") {
		g.add("reference")
	}
	switch kind {
	case "html", "svg":
		g.markup(kind, out)
		if kind == "html" {
			g.roundTrip(out)
		}
	case "css":
		g.css(out)
	case "text":
		g.lines(out)
	case "plugin", "routes":
		g.json(kind, out)
	default:
		g.add("kind")
	}
}

// letter reports an ASCII letter.
func letter(c byte) bool { return 'a' <= c|0x20 && c|0x20 <= 'z' }

// unpaid reports a special byte of the unit u that no place pays. The exact
// trap renders are cut first. A "." is paid only as the end of a sentence.
func (v *vhost) unpaid(u string) bool {
	rest := " " + strings.Join(strings.Fields(u), " ") + " "
	for _, e := range v.renders {
		for strings.Contains(rest, " "+e+" ") {
			rest = strings.Replace(rest, " "+e+" ", "  ", 1)
		}
	}
	for i := range len(rest) {
		switch c := rest[i]; {
		case c == '.':
			if !letter(rest[i-1]) || rest[i+1] != ' ' {
				return true
			}
		case '0' <= c && c <= '9' || strings.IndexByte(`:[]/\@%#;?`, c) >= 0:
			return true
		}
	}
	return false
}

// chars adds a finding for a markup byte in the text s.
func (g gram) chars(where, s string) {
	if strings.ContainsAny(s, "<>\"'`") {
		g.add("char(" + where + ")")
	}
}

// entry reports an entry of a prose string: the marker, an exact trap render
// or a sentence of the lists.
func (v *vhost) entry(e string) bool {
	return e == marker || slices.Contains(v.renders, e) || lists.sentence(e)
}

// entries reports a sequence of entries with one space between them. The
// text u is split at each space, so a double space is not in a sequence.
func (v *vhost) entries(u string) bool {
	if u == "" {
		return true
	}
	w := strings.Split(u, " ")
	ok := make([]bool, len(w)+1)
	ok[len(w)] = true
	for i := len(w) - 1; i >= 0; i-- {
		for j := i + 1; j <= len(w) && !ok[i]; j++ {
			ok[i] = ok[j] && v.entry(strings.Join(w[i:j], " "))
		}
	}
	return ok[0]
}

// prose checks a prose string: a unit of text, an attribute value, a comment
// or a JSON string. It is a sequence of entries. A unit of text or a comment
// has each white space run read as one space.
func (g gram) prose(where, s string) {
	if where != "text" {
		g.chars(where, s)
	}
	if where == "text" || where == "comment" {
		s = strings.Join(strings.Fields(s), " ")
	}
	if g.v.unpaid(s) {
		g.add("special(" + where + ")")
	}
	if !g.v.entries(s) {
		g.add("prose(" + where + ")")
	}
}

// canonical gives the canonical form of a start tag: <name a="v">. An empty
// hidden attribute has no value.
func canonical(t xhtml.Token, selfClose bool) string {
	s := "<" + t.Data
	for _, a := range t.Attr {
		key := strings.Replace(a.Key, "viewbox", "viewBox", 1)
		s += " " + key
		if a.Val != "" || a.Key != "hidden" {
			s += `="` + a.Val + `"`
		}
	}
	if selfClose {
		return s + "/>"
	}
	return s + ">"
}

// markup runs the token grammar on an HTML or SVG output.
func (g gram) markup(kind, s string) {
	elems := set(strings.Join(elements, " "))
	if kind == "svg" {
		elems = svgElements
	}
	toks, raws := tokenize(s)
	// The tokenizer drops the bytes of a start tag that has no end.
	if strings.Join(raws, "") != s {
		g.add("cover")
	}
	if kind == "html" && !frameOK(toks) {
		g.add("tag-place")
	}
	var stack []string
	for i, t := range toks {
		raw, top := raws[i], ""
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t.Type {
		case xhtml.DoctypeToken:
			if raw != "<!doctype html>" || i != 0 || kind != "html" {
				g.add("doctype")
			}
		case xhtml.CommentToken:
			if len(raw) < 7 || !strings.HasPrefix(raw, "<!--") || !strings.HasSuffix(raw, "-->") {
				g.add("comment")
			} else {
				g.prose("comment", raw[4:len(raw)-3])
			}
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			if !elems[t.Data] {
				g.add("element")
			}
			// The tokenizer drops a duplicate attribute, so the raw tag has
			// more bytes than the canonical form.
			if raw != canonical(t, t.Type == xhtml.SelfClosingTagToken && kind == "svg") {
				g.add("tag-form")
			}
			for _, a := range t.Attr {
				g.attr(t.Data, a)
			}
			if t.Type == xhtml.StartTagToken && !(kind == "html" && voids[t.Data]) {
				stack = append(stack, t.Data)
			}
		case xhtml.EndTagToken:
			if raw != "</"+t.Data+">" {
				g.add("end-form")
			}
			if top != t.Data {
				g.add("nesting")
			} else {
				stack = stack[:len(stack)-1]
			}
		case xhtml.TextToken:
			switch top {
			case "style":
				g.chars("text", raw)
				g.css(raw)
			case "script":
				g.json("ld", raw)
			default:
				g.chars("text", raw)
			}
		}
	}
	if len(stack) > 0 {
		g.add("nesting")
	}
	units, strip := tokenReadings(kind, toks, raws)
	for _, reading := range units {
		for _, u := range reading {
			g.prose("text", u)
		}
	}
	if stripDot(strip) {
		g.add("strip")
	}
}

// tokenize cuts s into tokens, with the raw bytes of each.
func tokenize(s string) (toks []xhtml.Token, raws []string) {
	z := xhtml.NewTokenizer(strings.NewReader(s))
	for z.Next() != xhtml.ErrorToken {
		raws = append(raws, string(z.Raw()))
		toks = append(toks, z.Token())
	}
	return toks, raws
}

// readFrame is an open element of a reading. Its two flags say that the
// element or an ancestor hides its text, with scripting on and off.
type readFrame struct {
	name          string
	hidOn, hidOff bool
}

// hiddenText are the elements whose text a reader does not show. The list
// has template and textarea too, but the element list has neither.
var hiddenText = set("head title style script template textarea")

// tokenReadings gives the readings of the text tokens of an HTML or SVG
// output. The first three values hold the units of three readings. They are
// all text, the text visible with scripting on, and the text visible with
// scripting off. A block element ends a unit. A hidden element gives no text
// and no break to a visible reading. The last value is the strip reading, all
// text with no break. The text of style and script elements is in no reading,
// also not in the strip reading.
func tokenReadings(kind string, toks []xhtml.Token, raws []string) (units [3][]string, strip string) {
	// The element names and ".class" values that a style hides.
	hide := map[string]bool{}
	for i, t := range toks {
		if t.Type == xhtml.TextToken && i > 0 && toks[i-1].Type == xhtml.StartTagToken && toks[i-1].Data == "style" {
			for _, h := range hiders(t.Data) {
				hide[h] = true
			}
		}
	}
	var stack []readFrame
	var cur [3]strings.Builder
	var out strings.Builder
	end := func(f readFrame) {
		for i, hidden := range [3]bool{false, f.hidOn, f.hidOff} {
			if !hidden {
				units[i] = append(units[i], cur[i].String())
				cur[i].Reset()
			}
		}
	}
	for i, t := range toks {
		var top readFrame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t.Type {
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			hid := hide[t.Data] || hiddenText[t.Data]
			for _, a := range t.Attr {
				hid = hid || a.Key == "hidden" || a.Key == "aria-hidden" || a.Key == "class" && hide["."+a.Val]
			}
			f := readFrame{t.Data, top.hidOn || hid || t.Data == "noscript", top.hidOff || hid}
			if blocks[t.Data] {
				end(f)
			}
			if t.Type == xhtml.StartTagToken && !(kind == "html" && voids[t.Data]) {
				stack = append(stack, f)
			}
		case xhtml.EndTagToken:
			if top.name == t.Data {
				stack = stack[:len(stack)-1]
				if blocks[t.Data] {
					end(top)
				}
			}
		case xhtml.TextToken:
			if top.name == "style" || top.name == "script" {
				continue
			}
			out.WriteString(raws[i])
			cur[0].WriteString(raws[i])
			if !top.hidOn {
				cur[1].WriteString(raws[i])
			}
			if !top.hidOff {
				cur[2].WriteString(raws[i])
			}
		}
	}
	end(readFrame{})
	return units, out.String()
}

// hiders gives the selectors of the rules of a style text that have a
// declaration with the hide flag.
func hiders(s string) (out []string) {
	for {
		sel, rest, ok := strings.Cut(s, "{")
		body, rest, ok2 := strings.Cut(rest, "}")
		if !ok || !ok2 {
			return out
		}
		if slices.ContainsFunc(strings.Split(body, ";"), func(d string) bool { return declarations[d] }) {
			out = append(out, strings.Split(strings.TrimSpace(sel), ",")...)
		}
		s = rest
	}
}

// stripDot reports a "." in the strip reading with no white space after it.
func stripDot(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '.' && !strings.ContainsRune(" \t\n\r\f", rune(s[i+1])) {
			return true
		}
	}
	return false
}

// visibleMarker reports the marker as an entry of a unit. Both visible
// readings need it: with scripting on, and with scripting off.
func visibleMarker(kind, s string) bool {
	toks, raws := tokenize(s)
	units, _ := tokenReadings(kind, toks, raws)
	seen := func(us []string) bool {
		return slices.ContainsFunc(us, func(u string) bool {
			return strings.Contains(" "+strings.Join(strings.Fields(u), " ")+" ", " "+marker+" ")
		})
	}
	return seen(units[1]) && seen(units[2])
}

// tagKey gives the name of a start tag, "/" and the name of an end tag, or "".
func tagKey(t xhtml.Token) string {
	switch t.Type {
	case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
		return t.Data
	case xhtml.EndTagToken:
		return "/" + t.Data
	}
	return ""
}

// frameOK checks the frame of an HTML output. An output with no html, head or
// body tag is a fragment. Any other output has the six tags of frame in order.
// A doctype can come first, but it is not necessary. Only white space is
// between the tags. The head holds only elements of headElems, the text in
// them, comments and white space.
func frameOK(toks []xhtml.Token) bool {
	if !slices.ContainsFunc(toks, func(t xhtml.Token) bool { return slices.Contains(frame, tagKey(t)) }) {
		return true
	}
	// The next tag of frame, and the open element of the head.
	next, open := 0, ""
	for _, t := range toks {
		key := tagKey(t)
		space := t.Type == xhtml.TextToken && strings.TrimSpace(t.Data) == ""
		switch {
		case next < len(frame) && key == frame[next]:
			next++
		case slices.Contains(frame, key):
			return false
		case next == 4: // The body holds any other token.
		case next == 2:
			switch {
			case t.Type == xhtml.CommentToken || space || t.Type == xhtml.TextToken && open != "":
			case open != "" && key == "/"+open:
				open = ""
			case key == t.Data && headElems[t.Data]:
				if !voids[t.Data] {
					open = t.Data
				}
			default:
				return false
			}
		case !space && !(t.Type == xhtml.DoctypeToken && next == 0):
			return false
		}
	}
	return next == len(frame)
}

// attr checks the name and the value of an attribute of the element el.
func (g gram) attr(el string, a xhtml.Attribute) {
	key := el + "." + a.Key
	class, ok := attrClass[key]
	if !ok {
		key = "*." + a.Key
		if class, ok = attrClass[key]; !ok {
			g.add("attr")
			return
		}
	}
	good := false
	switch class {
	case "fixed":
		good = slices.Contains(fixedValues[key], a.Val)
	case "class":
		good = lists.in("classes", a.Val)
	case "empty":
		good = a.Val == ""
	case "page":
		good = g.v.pages[a.Val]
	case "link":
		good = a.Val == "" || g.v.names[a.Val] || slices.Contains(g.v.l1, a.Val)
	case "prose":
		g.prose("value", a.Val)
		good = true
	}
	if !good {
		g.add("value")
	}
}

// css checks a style text. It has only rules "selector{decl;decl}". A part
// of a selector is one element or one class. A declaration is an entry.
// White space before, between and after the rules is free.
func (g gram) css(s string) {
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		sel, rest, ok := strings.Cut(s, "{")
		body, rest, ok2 := strings.Cut(rest, "}")
		if !ok || !ok2 {
			g.add("css-form")
			return
		}
		for _, p := range strings.Split(sel, ",") {
			c, isClass := strings.CutPrefix(p, ".")
			if !(isClass && lists.in("classes", c)) && !slices.Contains(elements, p) {
				g.add("css-selector")
			}
		}
		for _, d := range strings.Split(body, ";") {
			if _, ok := declarations[d]; !ok {
				g.add("css-declaration")
			}
		}
		s = rest
	}
}

// lines checks a text/plain output. A line is empty or fixed. It can also be
// "Disallow: " with nothing, a vhost name or a render of the form L1.
func (g gram) lines(s string) {
	for _, l := range strings.Split(s, "\n") {
		rest, dis := strings.CutPrefix(l, "Disallow: ")
		if l != "" && !slices.Contains(fixedLines, l) &&
			!(dis && (rest == "" || g.v.names[rest] || slices.Contains(g.v.l1, rest))) {
			g.add("line")
		}
	}
}

// json reads a JSON text with jsontext. The kind is routes, plugin or ld.
// It has no backslash and no number. A member name is on the list of the
// kind. A string value has the class of its member.
func (g gram) json(kind, s string) {
	if strings.Contains(s, `\`) {
		g.add("json-backslash")
	}
	d := jsontext.NewDecoder(strings.NewReader(s))
	for n := 0; ; n++ {
		// The text has one value. The decoder reads a stream of values.
		if n > 0 && d.StackDepth() == 0 {
			if _, err := d.ReadToken(); err != io.EOF {
				g.add("json-syntax")
			}
			return
		}
		tok, err := d.ReadToken()
		if err != nil {
			g.add("json-syntax")
			return
		}
		switch tok.Kind() {
		case '0':
			g.add("json-number")
		case '"':
			if k, count := d.StackIndex(d.StackDepth()); k == '{' && count%2 == 1 {
				if !lists.in("members-"+kind, tok.String()) {
					g.add("json-member")
				}
				continue
			}
			// A string in an array has an index for its key: it has no class.
			key := kind + "." + d.StackPointer().LastToken()
			if !g.jsonValue(jsonClass[key], key, tok.String()) {
				g.add("json-value")
			}
		}
	}
}

// jsonValue reports whether the string v has the class of its member.
func (g gram) jsonValue(class, key, v string) bool {
	switch class {
	case "path":
		// A route map names the paths. Other files use the path of a template
		// or an asset route.
		return isPath(v) && (strings.HasPrefix(key, "routes.") || g.v.pages[v])
	case "word":
		return lists.in("names", v)
	case "file":
		return isFile(g.v.host, v)
	case "header":
		return lists.in("headers", v)
	case "id":
		return isID(v)
	case "fixed":
		return slices.Contains(jsonFixed[key], v)
	case "prose":
		g.prose("json", v)
		return true
	}
	return false
}

// roundTrip compares the tokens of an HTML output with those of the render
// of its parse. It does this with scripting on and off.
func (g gram) roundTrip(s string) {
	want := tokenSeq(s)
	for _, scripting := range []bool{true, false} {
		var b bytes.Buffer
		doc, err := xhtml.ParseWithOptions(strings.NewReader(s), xhtml.ParseOptionEnableScripting(scripting))
		if err == nil {
			err = xhtml.Render(&b, doc)
		}
		if err != nil || !slices.Equal(want, tokenSeq(b.String())) {
			g.add(map[bool]string{true: "round-trip-on", false: "round-trip-off"}[scripting])
		}
	}
}

// tokenSeq gives the tokens of s for the round trip. It drops the tags of
// frame and the white-space text. A start tag has its attributes as a sorted
// set. A self-closing tag of a void element is a start tag.
func tokenSeq(s string) (seq []string) {
	z := xhtml.NewTokenizer(strings.NewReader(s))
	for z.Next() != xhtml.ErrorToken {
		t := z.Token()
		switch t.Type {
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken, xhtml.EndTagToken:
			if slices.Contains(frame, tagKey(t)) {
				continue
			}
			attrs := make([]string, len(t.Attr))
			for i, a := range t.Attr {
				attrs[i] = a.Key + "=" + a.Val
			}
			slices.Sort(attrs)
			p := "<"
			if t.Type == xhtml.EndTagToken {
				p = "</"
			}
			seq = append(seq, p+t.Data+" "+strings.Join(attrs, "\n"))
			if t.Type == xhtml.SelfClosingTagToken && !voids[t.Data] {
				seq = append(seq, "</"+t.Data+" ")
			}
		case xhtml.CommentToken:
			seq = append(seq, "--"+t.Data)
		case xhtml.TextToken:
			if strings.TrimSpace(t.Data) != "" {
				seq = append(seq, "#"+t.Data)
			}
		case xhtml.DoctypeToken:
			seq = append(seq, "!"+strings.ToLower(t.Data))
		}
	}
	return seq
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

// The guard test of the data file. A change of one byte changes the hash.
// So a change of the lists is a decision of the spec, not a content change.
func TestTS36ListFileIsPinned(t *testing.T) {
	b, err := os.ReadFile(listFile)
	if err != nil {
		t.Fatal(err)
	}
	// The pin finding of listFindings has no hash: report it here, once.
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != listPin {
		t.Errorf("SHA-256 of %s is %x, want %s", listFile, sum, listPin)
	}
	for _, f := range listFindings(b, listPin) {
		if f != "list-pin "+listName {
			t.Error(f)
		}
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
