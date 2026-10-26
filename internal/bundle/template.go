package bundle

import (
	"html/template"
	"strings"
)

// templateDir is the archive directory whose files are templates.
const templateDir = "vhosts/"

// engineFuncs is the fixed function map of the open engine. A template can call
// no other function. It has no entry in this version.
var engineFuncs = template.FuncMap{}

// parseTemplates parses each file below vhosts/ as a template with only
// engineFuncs. It executes no template. The error is ErrTemplateParse. It holds
// no template text, because the text of a parse error can quote the input.
func parseTemplates(a *Archive) error {
	for _, name := range a.Names() {
		if !strings.HasPrefix(name, templateDir) {
			continue
		}
		text, _ := a.File(name)
		_, err := template.New(name).Option("missingkey=error").Funcs(engineFuncs).Parse(string(text))
		if err != nil {
			return ErrTemplateParse
		}
	}
	return nil
}
