package bundle

import (
	"encoding/json/v2"
	"html/template"
	"slices"
	"strings"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// The name and the caps of the trap file, and the cap of one instruction
// template, in bytes (SEC-29).
const (
	trapsName        = "traps/traps.json"
	maxTrapsBytes    = 256 << 10
	maxTraps         = 1024
	maxTrapIDBytes   = 64
	maxTrapTemplate  = 1 << 10
	maxHeaderNameLen = 32
)

// trapSlots, trapSurfaces and trapVisibilities are the values that a trap
// member can have. The match is exact.
var (
	trapSlots = []string{
		"hidden-p", "html-comment", "meta-description", "alt", "aria-label",
		"nofollow-link", "robots-disallow", "ai-plugin", "json-ld", "noscript",
		"not-found", "header",
	}
	trapSurfaces = []event.Surface{
		event.SurfacePath, event.SurfaceHeader, event.SurfaceQuery, event.SurfaceBody,
	}
	trapVisibilities = []string{"human-invisible", "human-visible"}
)

// Trap is one trap of traps/traps.json.
type Trap struct {
	ID, Slot, Visibility, InstructionTemplate string
	Surface                                   event.Surface
	// parts are the texts of the template around each token. The loader sets
	// them when it parses the template.
	parts []string
}

// Render gives the text of the template and the token, joined in order. It
// runs no template and escapes nothing.
func (t Trap) Render(token string) string { return strings.Join(t.parts, token) }

type rawTrap struct {
	ID         maybe[string]        `json:"id"`
	Slot       maybe[string]        `json:"slot"`
	Surface    maybe[event.Surface] `json:"surface"`
	Visibility maybe[string]        `json:"visibility"`
	Template   maybe[string]        `json:"instruction_template"`
}

// readTraps parses traps/traps.json of the archive. A bundle with no such file
// has no trap. The error is ErrContentInvalid and holds no byte of the file.
func readTraps(a *Archive) ([]Trap, error) {
	b, ok := a.File(trapsName)
	if !ok {
		return nil, nil
	}
	var raw []rawTrap
	if len(b) > maxTrapsBytes || json.Unmarshal(b, &raw, parseOpts...) != nil ||
		len(raw) < 1 || len(raw) > maxTraps {
		return nil, ErrContentInvalid
	}
	seen := map[string]bool{}
	out := make([]Trap, 0, len(raw))
	for _, r := range raw {
		if !r.ID.set || !r.Slot.set || !r.Surface.set || !r.Visibility.set || !r.Template.set ||
			!validTrapID(r.ID.v) || seen[r.ID.v] || !slices.Contains(trapSlots, r.Slot.v) ||
			!slices.Contains(trapSurfaces, r.Surface.v) || !slices.Contains(trapVisibilities, r.Visibility.v) {
			return nil, ErrContentInvalid
		}
		seen[r.ID.v] = true
		out = append(out, Trap{ID: r.ID.v, Slot: r.Slot.v, Visibility: r.Visibility.v,
			InstructionTemplate: r.Template.v, Surface: r.Surface.v})
	}
	return out, nil
}

// validTrapID reports whether s is 1 to 64 bytes of a-z 0-9 -.
func validTrapID(s string) bool {
	return len(s) >= 1 && len(s) <= maxTrapIDBytes &&
		!strings.ContainsFunc(s, func(c rune) bool { return c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') })
}

// validHeaderName reports whether s is "X-" and 1 to 32 bytes of A-Z a-z 0-9 -.
func validHeaderName(s string) bool {
	rest, ok := strings.CutPrefix(s, "X-")
	return ok && len(rest) >= 1 && len(rest) <= maxHeaderNameLen &&
		!strings.ContainsFunc(rest, func(c rune) bool { return c != '-' && !alnum(c) })
}

// compileTraps parses the instruction template of each trap with the
// constructor mk and keeps its text parts. A template that holds a node other
// than text or {{.Token}} gives ErrTemplateParse. It executes nothing. The size
// cap is checked before, with the caps of the other templates.
func compileTraps(traps []Trap, mk func(string) *template.Template) error {
	for i := range traps {
		text := traps[i].InstructionTemplate
		t, err := mk(trapsName + "#" + traps[i].ID).Parse(text)
		if err != nil {
			return ErrTemplateParse
		}
		parts, ok := trapParts(t, text)
		if !ok {
			return ErrTemplateParse
		}
		traps[i].parts = parts
	}
	return nil
}

// trapParts gives the texts around each token in the parse tree of t. It is
// false for a node that is not text, and for an action that is not one
// {{.Token}}. A text node holds no "{{", and the string of an action node is
// its source without the trim markers. The parse drops a comment and keeps no
// node of it. So it is also false when text holds more "{{" than tokens. A
// define adds a "{{" in the same way.
func trapParts(t *template.Template, text string) ([]string, bool) {
	var parts []string
	var cur strings.Builder
	if t.Tree != nil {
		for _, n := range t.Tree.Root.Nodes {
			switch s := n.String(); {
			case s == "{{.Token}}":
				parts = append(parts, cur.String())
				cur.Reset()
			case strings.Contains(s, "{{"):
				return nil, false
			default:
				cur.WriteString(s)
			}
		}
	}
	if strings.Count(text, "{{") != len(parts) {
		return nil, false
	}
	return append(parts, cur.String()), true
}
