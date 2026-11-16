// Package reference holds the content rules of the reference bundle source
// tree (SEC-42, ADR-042). It has test files only. Its tests are T-S-36.
package reference

import (
	"encoding/json"
	"fmt"
	"html"
	"io/fs"
	"maps"
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

	// The tree has no reason to hold an absolute URL in any position.
	absoluteURL = regexp.MustCompile(`https?:|://|(?:^|[\s="'(,])//`)

	// The two forms of a template action. Each "{{" of a template starts one.
	actionForms = []*regexp.Regexp{
		regexp.MustCompile(`\{\{index \.Trap "([a-z0-9-]+)"\}\}`),
		regexp.MustCompile(`\{\{comment \(index \.Trap "([a-z0-9-]+)"\)\}\}`),
	}
	// An unterminated HTML comment runs to the end of the text.
	htmlComment = regexp.MustCompile(`(?s)<!--.*?(?:-->|$)`)

	// A trap text has no "[" or "]", and no ":" before a character that is
	// not a space.
	hostForm = regexp.MustCompile(`[\[\]]|:[^ ]`)
	// The deny words are also checked with a run of separators as one space.
	separators = regexp.MustCompile(`[ \t_-]+`)
	rmDash     = regexp.MustCompile(`\brm\s*-`)
	// These forms are checked on the text with the separators replaced.
	denyJoined = []string{"apikey", "systemprompt", "privatekey", "e mail", "pass word"}

	topDirs  = []string{"vhosts", "traps", "secrets"}
	urlForms = []string{"://", "//", "@", "mailto:", "www."}
	tags     = []string{"<script", "javascript:", "<iframe", "<object", "<embed", "<foreignobject"}
	// The deny list of ADR-042. A word matches as a part of a longer word.
	// The pair "instruction" and "override" and the word "rm -" are checked
	// apart.
	denyWords = []string{
		"ignore", "previous", "system prompt", "password", "credential",
		"secret", "api key", "private key", "ssh", ".env", "cookie", "history",
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

func (v *vhost) readRoutes(b []byte) {
	var m struct {
		Routes []struct {
			Path     string
			Callback *struct{ Segment bool }
			Headers  []struct{ Trap string }
		}
	}
	if json.Unmarshal(b, &m) != nil { // The loader refuses a bad route map.
		return
	}
	for _, rt := range m.Routes {
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
			v.readRoutes(b)
			continue
		}
		r.page(name, b, v)
	}
	for _, v := range hosts {
		for id := range v.traps {
			users[id] = append(users[id], v)
		}
	}
	r.traps(files[trapsFile], users)
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

// page checks a file below a vhost with the script and URL rules. For a
// template it also checks the marker and the action forms. The tag and
// on-attribute rules run on the raw text and on the normal form.
func (r *result) page(name string, b []byte, v *vhost) {
	raw := string(b)
	n := normalForm(raw)
	if strings.HasSuffix(name, ".tmpl") {
		r.template(name, raw, v)
	}
	for _, s := range []string{raw, n} {
		low := strings.ToLower(s)
		for _, t := range tags {
			if strings.Contains(low, t) {
				r.add("script("+t+")", name)
			}
		}
		if onAttr.MatchString(s) || animOn.MatchString(s) {
			r.add("on-attr", name)
		}
	}
	if external.MatchString(n) {
		r.add("third-party", name)
	}
	if absoluteURL.MatchString(strings.ToLower(n)) {
		r.add("absolute-url", name)
	}
	if strings.Contains(raw, `\`) || strings.Contains(n, `\`) {
		r.add("backslash", name)
	}
}

// template checks the marker (outside an HTML comment) and the actions of a
// template. Each "{{" must start one of the two exact forms. The traps of
// the vhost come from these forms only.
func (r *result) template(name, text string, v *vhost) {
	if !strings.Contains(htmlComment.ReplaceAllString(text, ""), marker) {
		r.add("marker", name)
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
func normalForm(s string) string {
	return strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return -1
		}
		return c
	}, html.UnescapeString(s))
}

// traps checks the instruction template of each trap in traps/traps.json.
func (r *result) traps(b []byte, users map[string][]*vhost) {
	if b == nil {
		return
	}
	var ts []struct {
		ID   string `json:"id"`
		Text string `json:"instruction_template"`
	}
	if json.Unmarshal(b, &ts) != nil {
		r.add("traps-json", trapsFile)
		return
	}
	for _, t := range ts {
		r.instruction(t.Text, users[t.ID])
	}
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
	add("marker", !strings.Contains(text, marker))
	add("base64", base64Run.MatchString(text))
	add("entity", strings.Contains(text, "&#") || hexEscape.MatchString(text))
	for _, u := range urlForms {
		add("instr-url("+u+")", strings.Contains(low, u))
	}
	joined := separators.ReplaceAllString(low, " ")
	for _, w := range denyWords {
		add("instr-deny("+w+")", strings.Contains(low, w) ||
			strings.Contains(joined, separators.ReplaceAllString(w, " ")))
	}
	for _, w := range denyJoined {
		add("instr-deny("+w+")", regexp.MustCompile(`\b`+w).MatchString(joined))
	}
	add("instr-deny(rm -)", rmDash.MatchString(low))
	add("instr-deny(instruction+override)", strings.Contains(low, "instruction") &&
		(strings.Contains(low, "override") || regexp.MustCompile(`\bover ride`).MatchString(joined)))
	for _, w := range strings.Fields(text) {
		switch p, seg := strings.CutSuffix(w, "/"+tokenAction); {
		case strings.HasPrefix(w, "/"):
			if p == "" {
				p = "/"
			}
			add("instr-path", !pathOK(p, seg, users))
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
