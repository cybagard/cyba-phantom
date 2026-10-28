package config

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// listKey is one list key (04 section 3). Each item is a mapping. Its type key selects
// the schema, which holds the other keys of the item. A list key has no PHANTOM_ override.
type listKey struct {
	path     string
	min, max int
	req      bool             // req marks a required list: the file must set it.
	schemas  map[string][]key // schemas holds the keys of an item by type. The path of a key is its name in the item.
	fields   []key            // fields is the schema of an untyped item.
	item     *key             // item, if set, makes the list a list of scalars: each entry has this key and no schemas.
	unique   bool             // unique marks a list of scalars with no duplicate entry.
}

// lists is the production list table. The key table holds the scalar keys.
var lists = []listKey{
	// An acme.names entry may be an internal name. decoyCheck refuses
	// it unless acme.ca is an https URL.
	{path: "acme.names", min: 0, max: 16, unique: true, item: &key{kind: kindString, check: checkDecoyName}},
	{path: "tls.certs", min: 0, max: 16, fields: []key{
		{path: "name", kind: kindString, req: true, check: checkDecoyName},
		{path: "cert_file", kind: kindPath, req: true, check: checkAbsPath},
		{path: "key_file", kind: kindPath, req: true, check: checkAbsPath},
	}},
	{path: "tlog.publish", min: 1, max: 4, req: true, schemas: map[string][]key{
		"https-put": {
			{path: "url", kind: kindURL, req: true, check: checkHTTPS},
			{path: "token_env", kind: kindString, req: true, secret: true, check: checkSecretEnv(1)},
		},
	}},
	{path: "alerts.sinks", min: 0, max: 8, schemas: map[string][]key{
		"webhook": {
			{path: "url", kind: kindURL, req: true, check: checkHTTPS, endpoint: urlEndpoint},
			{path: "hmac_secret_env", kind: kindString, req: true, secret: true, check: checkSecretEnv(32)}, // SEC-06
		},
		"syslog": {
			{path: "addr", kind: kindURL, req: true, check: checkSyslogAddr, endpoint: syslogEndpoint},
		},
		"smtp": {
			{path: "host", kind: kindString, req: true, check: checkSMTPHost, endpoint: smtpEndpoint},
			{path: "from", kind: kindString, req: true, check: checkEmail},
			{path: "to", kind: kindString, req: true, maxItems: 16, check: checkEmail},
		},
	}},
}

// isListPath reports whether p is a list key or a node below one.
func isListPath(p string) bool {
	return slices.ContainsFunc(lists, func(l listKey) bool { return p == l.path || strings.HasPrefix(p, l.path+"[") })
}

// count returns the number of entries of the list at p.
func count(doc *Doc, p string) int {
	n := 0
	for {
		if _, ok := doc.Lines[fmt.Sprintf("%s[%d]", p, n)]; !ok {
			return n
		}
		n++
	}
}

// failer returns a function that adds an Error for the key at p to errs.
func failer(doc *Doc, file string, errs *[]error) func(p, detail string) {
	return func(p, detail string) {
		*errs = append(*errs, &Error{Key: p, Source: file, Line: doc.Lines[p], Detail: detail})
	}
}

// expandLists reads the lists in doc. It returns one key for each scalar node that the
// item schemas allow, with the full path (for example "alerts.sinks[1].url"), and the
// errors in the shape of the lists. The loader then handles these keys like scalar keys.
func expandLists(doc *Doc, file string, table []listKey) (out []key, errs []error) {
	fail := failer(doc, file, &errs)
	for _, l := range table {
		if _, present := doc.Lines[l.path]; !present {
			if l.req {
				errs = append(errs, &Error{Key: l.path, Source: file, Detail: "the key is required"})
			}
			continue
		}
		if !doc.Sequences[l.path] {
			fail(l.path, "the key needs a list")
			continue
		}
		n := count(doc, l.path)
		if n < l.min || n > l.max {
			fail(l.path, "the list needs "+strconv.Itoa(l.min)+" to "+strconv.Itoa(l.max)+" entries")
			continue
		}
		if l.item != nil {
			k, e := expandScalars(doc, file, l, n)
			out, errs = append(out, k...), append(errs, e...)
			continue
		}
		for i := range n {
			k, e := expandItem(doc, file, l, fmt.Sprintf("%s[%d]", l.path, i))
			out, errs = append(out, k...), append(errs, e...)
		}
	}
	return out, errs
}

// expandScalars expands the entries of the list of scalars l. Each entry is a key with the
// check of l.item. An entry that is not a scalar is an error on the entry. A duplicate entry is an error on the list key.
func expandScalars(doc *Doc, file string, l listKey, n int) (out []key, errs []error) {
	fail := failer(doc, file, &errs)
	seen := make(map[string]int, n)
	for i := range n {
		k := *l.item
		k.path = fmt.Sprintf("%s[%d]", l.path, i)
		leaf, ok := doc.Leaves[k.path]
		if !ok {
			fail(k.path, "the key needs a scalar value")
			continue
		}
		seen[leaf.Value]++
		// The error is for the second copy of a value only.
		if l.unique && seen[leaf.Value] == 2 {
			fail(l.path, "the list must not hold an entry two times")
		}
		out = append(out, k)
	}
	return out, errs
}

// expandItem expands the item at ip.
func expandItem(doc *Doc, file string, l listKey, ip string) (out []key, errs []error) {
	fail := failer(doc, file, &errs)
	if !doc.Mappings[ip] {
		fail(ip, "the item needs a mapping")
		return
	}
	// A list with fields has no type key, so a type key is an unknown key.
	schema, typePath := l.fields, ""
	if schema == nil {
		names := slices.Sorted(maps.Keys(l.schemas))
		typeKey := key{path: ip + ".type", kind: kindString, req: true, check: func(_ *loader, raw string) string {
			if _, ok := l.schemas[raw]; !ok {
				return "the type must be " + strings.Join(names, ", ")
			}
			return ""
		}}
		if _, present := doc.Lines[typeKey.path]; present && !isScalar(doc, typeKey.path) {
			fail(typeKey.path, "the key needs a scalar value")
			return
		}
		out = append(out, typeKey)
		var ok bool
		schema, ok = l.schemas[doc.Leaves[typeKey.path].Value]
		if !ok {
			// The type key reports the error. Without a type, the
			// loader does not know the other keys.
			return
		}
		typePath = typeKey.path
	}
	for _, c := range children(doc, ip) {
		if c != typePath && !slices.ContainsFunc(schema, func(f key) bool { return ip+"."+f.path == c }) {
			fail(c, "unknown key")
		}
	}
	for _, f := range schema {
		f.path = ip + "." + f.path
		_, present := doc.Lines[f.path]
		switch {
		case f.maxItems > 0 && !present:
			errs = append(errs, &Error{Key: f.path, Source: file, Line: doc.Lines[ip], Detail: "the key is required"})
		case f.maxItems > 0 && !doc.Sequences[f.path]:
			fail(f.path, "the key needs a list")
		case f.maxItems > 0:
			n := count(doc, f.path)
			if n < 1 || n > f.maxItems {
				fail(f.path, "the list needs 1 to "+strconv.Itoa(f.maxItems)+" entries")
				continue
			}
			for j := range n {
				e := f
				e.path, e.req, e.maxItems = fmt.Sprintf("%s[%d]", f.path, j), false, 0
				if !isScalar(doc, e.path) {
					fail(e.path, "the key needs a scalar value")
					continue
				}
				out = append(out, e)
			}
		case present && !isScalar(doc, f.path):
			fail(f.path, "the key needs a scalar value")
		default: // An absent key stays in the list: the required check reports it.
			out = append(out, f)
		}
	}
	return out, errs
}

func isScalar(doc *Doc, p string) bool { _, ok := doc.Leaves[p]; return ok }

// children returns the paths of the keys directly below the mapping at p, in file order.
func children(doc *Doc, p string) []string {
	var out []string
	for q := range doc.Lines {
		if rest, ok := strings.CutPrefix(q, p+"."); ok && !strings.ContainsAny(rest, ".[") {
			out = append(out, q)
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		return cmp.Or(cmp.Compare(doc.Lines[a], doc.Lines[b]), cmp.Compare(a, b))
	})
	return out
}

// envVarName is the rule for the name in a *_env key (SEC-13).
var envVarName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// checkSecretEnv returns a check for a *_env key. The value is the name of a variable
// that must be set in the environment of the loader, with at least minBytes bytes. The
// detail never holds the variable name, because an operator can paste a secret in place of
// a name. The error names the key path and the file line only (04 section 3). The detail
// never holds the value of the variable or its length either (SEC-13).
func checkSecretEnv(minBytes int) func(*loader, string) string {
	return func(l *loader, raw string) string {
		switch {
		case !envVarName.MatchString(raw):
			return "the value must be a variable name that matches ^[A-Z_][A-Z0-9_]*$"
		case strings.HasPrefix(envFold(raw), "PHANTOM"):
			return "the variable name must not start with PHANTOM"
		}
		v, n := "", 0
		for _, kv := range l.env { // os.Environ holds one entry for each name.
			if name, val, found := strings.Cut(kv, "="); found && name == raw {
				v, n = val, n+1
			}
		}
		ok := n > 0
		switch {
		case n > 1:
			return "the environment has more than one entry for the variable that the key names"
		case !ok || v == "":
			return "the variable that the key names is not set or is empty"
		case len(v) < minBytes:
			return "the variable that the key names must hold at least " + strconv.Itoa(minBytes) + " bytes"
		}
		return ""
	}
}
