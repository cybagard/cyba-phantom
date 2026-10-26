package bundle

import (
	"bytes"
	"html/template"
	"strings"
)

const (
	// templateDir is the archive directory whose .tmpl files are templates.
	templateDir = "vhosts/"
	// templateSuffix ends the name of a template. The match is exact.
	templateSuffix = ".tmpl"
)

// The caps of the templates, in bytes and in "{{" counts. The loader checks
// them before it parses the first template.
const (
	maxTemplateBytes   = 64 << 10
	maxTemplateActions = 4096
	maxBundleBytes     = 512 << 10
	maxBundleActions   = 16384
)

// engineFuncs is the only function set that the engine adds. A template can
// call no other engine function. The built-in functions of text/template stay
// callable. The map has no entry in this version.
var engineFuncs = template.FuncMap{}

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
// all templates before the first Parse. The error is ErrTemplateParse. That
// error holds no template text, because a parse error can quote the input.
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
