// Package reference holds the content rules of the reference bundle source
// tree (SEC-42, ADR-042). It has test files only. Its tests are T-S-36.
package reference

import (
	"encoding/json"
	"fmt"
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
	trapUse   = regexp.MustCompile(`index \.Trap "([a-z0-9-]+)"`)
	onAttr    = regexp.MustCompile(`(?i)[\s"'/]on[a-z]+\s*=`)
	external  = regexp.MustCompile(`(?i)(?:\b(?:src|href|action)\s*=\s*["']?` +
		`|\burl\(\s*["']?)\s*(?:https?:|//)`)

	topDirs  = []string{"vhosts", "traps", "secrets"}
	urlForms = []string{"://", "//", "@", "mailto:", "www."}
	tags     = []string{"<script", "javascript:", "<iframe", "<object", "<embed", "<foreignobject"}
	// The deny list of ADR-042. A word matches as a part of a longer word.
	// The pair "instruction" and "override" is checked apart.
	denyWords = []string{
		"ignore", "previous", "system prompt", "password", "credential",
		"secret", "api key", "private key", "ssh", ".env", "cookie", "history",
		"conversation", "email", "curl", "wget", "sudo", "rm -", "base64",
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
// to the bundle. A vhost uses it in a header slot of its route map, or with
// {{index .Trap "id"}} in a template. "The same vhost" of a trap is each
// vhost that uses it. A trap that no vhost uses has no valid path.
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
		case d.Type().IsRegular(): // A symlink or a device is refused.
			b, err := fs.ReadFile(fsys, p)
			files[p] = b
			return err
		default:
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

// page checks a file below a vhost: the marker of a template, and the script
// and URL rules. A template also names the traps of its vhost.
func (r *result) page(name string, b []byte, v *vhost) {
	low := strings.ToLower(string(b))
	if strings.HasSuffix(name, ".tmpl") {
		if !strings.Contains(string(b), marker) {
			r.add("marker", name)
		}
		for _, m := range trapUse.FindAllStringSubmatch(string(b), -1) {
			v.traps[m[1]] = true
		}
	}
	for _, t := range tags {
		if strings.Contains(low, t) {
			r.add("script("+t+")", name)
		}
	}
	if onAttr.Match(b) {
		r.add("on-attr", name)
	}
	if external.Match(b) {
		r.add("third-party", name)
	}
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
	add("instr-token", strings.Count(text, tokenAction) != 1)
	add("marker", !strings.Contains(text, marker))
	add("base64", base64Run.MatchString(text))
	add("entity", strings.Contains(text, "&#") || hexEscape.MatchString(text))
	for _, u := range urlForms {
		add("instr-url("+u+")", strings.Contains(low, u))
	}
	for _, w := range denyWords {
		add("instr-deny("+w+")", strings.Contains(low, w))
	}
	add("instr-deny(instruction+override)",
		strings.Contains(low, "instruction") && strings.Contains(low, "override"))
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
		if !slices.Contains(map[bool][]string{true: v.segments, false: v.callbacks}[seg], p) {
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
