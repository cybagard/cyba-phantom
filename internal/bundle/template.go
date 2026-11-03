package bundle

import (
	"bytes"
	"html/template"
	"strings"
	"text/template/parse"
)

const (
	// templateDir is the archive directory whose .tmpl files are templates.
	templateDir = "vhosts/"
	// templateSuffix ends the name of a template. The match is exact.
	templateSuffix = ".tmpl"
)

// The caps of the templates, in bytes and in "{{" counts (SEC-29). The loader
// checks them before it parses the first template.
const (
	maxTemplateBytes   = 64 << 10
	maxTemplateActions = 2048
	maxBundleBytes     = 512 << 10
	maxBundleActions   = 16384
)

// Page is the data of a template. Trap maps a trap id to its text.
type Page struct{ Trap map[string]string }

// engineFuncs is the only function set that the engine adds. The load check
// refuses each call of a function but index and comment (SEC-32).
var engineFuncs = template.FuncMap{"comment": comment}

// comment gives s as one HTML comment. It gives "" for an unsafe text.
// A text is unsafe if it holds "--". This also covers "<!--", "-->" and
// "--!>". A text is also unsafe if it starts with ">" or "->". Last, a text is
// unsafe if it holds a byte below 0x20 other than tab and LF.
func comment(s string) template.HTML {
	if strings.Contains(s, "--") || strings.HasPrefix(s, ">") || strings.HasPrefix(s, "->") ||
		strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 && c != '\t' && c != '\n' }) {
		return ""
	}
	return template.HTML("<!-- " + s + " -->")
}

// newTemplate makes each template of the loader, for the parse and for the
// templates that the loader keeps.
func newTemplate(name string) *template.Template {
	return template.New(name).Option("missingkey=error").Funcs(engineFuncs)
}

// parseTemplates parses each .tmpl file below vhosts/ and returns the parsed
// templates by name. It executes no template.
func parseTemplates(a *Archive) (map[string]*template.Template, error) {
	return parseWith(a, newTemplate)
}

// parseWith is parseTemplates with the constructor mk. It checks the caps of
// all templates before the first Parse, with the instruction templates of
// traps/traps.json. A trap file of a bad form gives ErrContentInvalid. Else the
// error is ErrTemplateParse. That error holds no template text, because a parse
// error can quote the input. parseWith parses no instruction template.
func parseWith(a *Archive, mk func(string) *template.Template) (map[string]*template.Template, error) {
	var names []string
	var sumBytes, sumActions int
	for _, name := range a.Names() {
		if !strings.HasPrefix(name, templateDir) || !strings.HasSuffix(name, templateSuffix) {
			continue
		}
		text, _ := a.File(name)
		n := bytes.Count(text, []byte("{{"))
		sumBytes += len(text)
		sumActions += n
		if len(text) > maxTemplateBytes || n > maxTemplateActions ||
			sumBytes > maxBundleBytes || sumActions > maxBundleActions {
			return nil, ErrTemplateParse
		}
		names = append(names, name)
	}
	// The instruction templates of the traps count in the bundle sums.
	traps, err := readTraps(a)
	if err != nil {
		return nil, err
	}
	for _, tr := range traps {
		n := strings.Count(tr.InstructionTemplate, "{{")
		sumBytes += len(tr.InstructionTemplate)
		sumActions += n
		if len(tr.InstructionTemplate) > maxTrapTemplate || sumBytes > maxBundleBytes || sumActions > maxBundleActions {
			return nil, ErrTemplateParse
		}
	}
	set := make(map[string]*template.Template, len(names))
	for _, name := range names {
		text, _ := a.File(name)
		t, err := mk(name).Parse(string(text))
		if err != nil {
			return nil, ErrTemplateParse
		}
		set[name] = t
	}
	return set, nil
}

// maxTemplateIDs is the number of trap ids that one template can use.
const maxTemplateIDs = 64

// checkExec checks each kept template (SEC-32). A tree holds text, comments and
// two forms of action: {{index .Trap "id"}} and {{comment (index .Trap "id")}}.
// The id is the id of a trap of traps.json. A template uses an id at most one
// time. A set of more than one template, and a template with no tree, are
// refused. The check matches the shape at the first level only. It does not
// walk into the arguments, so a deep nesting costs no deep walk. The error
// holds no byte of the archive.
func checkExec(set map[string]*template.Template, traps []Trap) error {
	known := make(map[string]bool, len(traps))
	for _, tr := range traps {
		known[tr.ID] = true
	}
	for _, t := range set {
		if !execOK(t, known) {
			return ErrTemplateParse
		}
	}
	return nil
}

// execOK reports whether t passes the check with the known trap ids.
func execOK(t *template.Template, known map[string]bool) bool {
	if t.Tree == nil || t.Tree.Root == nil || len(t.Templates()) != 1 {
		return false
	}
	used := map[string]bool{}
	for _, n := range t.Tree.Root.Nodes {
		switch n := n.(type) {
		case *parse.TextNode, *parse.CommentNode:
		case *parse.ActionNode:
			id, ok := actionID(n)
			if !ok || !known[id] || used[id] || len(used) >= maxTemplateIDs {
				return false
			}
			used[id] = true
		default:
			return false
		}
	}
	return true
}

// actionID gives the trap id of an action of one of the two permitted forms.
func actionID(n *parse.ActionNode) (string, bool) {
	cmd, ok := oneCmd(n.Pipe)
	if !ok {
		return "", false
	}
	if len(cmd.Args) == 2 && isIdent(cmd.Args[0], "comment") {
		inner, ok := cmd.Args[1].(*parse.PipeNode)
		if !ok {
			return "", false
		}
		if cmd, ok = oneCmd(inner); !ok {
			return "", false
		}
	}
	if len(cmd.Args) != 3 || !isIdent(cmd.Args[0], "index") {
		return "", false
	}
	f, ok := cmd.Args[1].(*parse.FieldNode)
	if !ok || len(f.Ident) != 1 || f.Ident[0] != "Trap" {
		return "", false
	}
	s, ok := cmd.Args[2].(*parse.StringNode)
	if !ok {
		return "", false
	}
	return s.Text, true
}

// oneCmd gives the one command of a pipe that has no declaration.
func oneCmd(p *parse.PipeNode) (*parse.CommandNode, bool) {
	if p == nil || len(p.Decl) != 0 || p.IsAssign || len(p.Cmds) != 1 {
		return nil, false
	}
	return p.Cmds[0], true
}

// isIdent reports whether n is the function name name.
func isIdent(n parse.Node, name string) bool {
	id, ok := n.(*parse.IdentifierNode)
	return ok && id.Ident == name
}
