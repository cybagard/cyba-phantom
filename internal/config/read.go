// Package config provides a strict YAML configuration loader.
//
// The sensor reads the config one time at start, with Load. The package has
// no reload function. SIGHUP and the reload request reload the bundle, not
// the config. A config change needs a restart. The package is unix only: on
// another system, unix_only.go makes the build fail with a clear name.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

const (
	maxConfigSize = 64 * 1024
	maxDepth      = 8
)

// The fixed texts of the key rule and the tag rules. The tests use them.
const (
	keyRule       = "the key must be 1 or more characters of a-z, 0-9 and _ only"
	scalarTagRule = "the tag of a scalar must be str, int, bool, float or null"
	plainTagRule  = "the value resolves to a tag that is not str, int, bool, float or null"
	mapTagRule    = "the tag of a mapping must be map"
	seqTagRule    = "the tag of a sequence must be seq"
)

// Leaf represents a scalar value in the configuration.
type Leaf struct {
	Value string
	Tag   string // Tag is the resolved tag.
	Line  int
}

// Doc represents the parsed configuration.
type Doc struct {
	Leaves    map[string]Leaf // Leaves hold scalar values.
	Mappings  map[string]bool // Mappings holds the paths of mapping nodes; "" is the root
	Sequences map[string]bool // Sequences holds the paths of sequence nodes
	Lines     map[string]int  // Lines holds the line of each node by path; for a mapping entry, the line of the key
}

// ReadFile reads the configuration file at path and returns a Doc.
func ReadFile(path string) (*Doc, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, formatOSError(path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, formatOSError(path, err)
	}

	if info.Mode()&os.ModeType != 0 {
		return nil, fmt.Errorf("config: %s: not a regular file", formatFilePath(path))
	}

	mode := info.Mode()
	if mode&0022 != 0 {
		return nil, fmt.Errorf("config: %s: group or other writable", formatFilePath(path))
	}

	uid, err := getUid(info)
	if err != nil {
		return nil, formatOSError(path, err)
	}

	if uid != 0 && uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("config: %s: the owner must be root or the current user", formatFilePath(path))
	}

	lr := io.LimitReader(f, maxConfigSize+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, formatOSError(path, err)
	}

	if len(b) > maxConfigSize {
		return nil, fmt.Errorf("config: %s: the file is larger than 64 KiB", formatFilePath(path))
	}

	return ReadBytes(b)
}

var getUid = func(info os.FileInfo) (uint32, error) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid, nil
	}
	return 0, errors.New("failed to get owner uid")
}

// ReadBytes parses the configuration from a byte slice and returns a Doc.
func ReadBytes(b []byte) (*Doc, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, errors.New("config: empty document")
	}
	if len(b) > maxConfigSize {
		return nil, errors.New("config: the input is larger than 64 KiB")
	}
	if !utf8.Valid(b) {
		return nil, errors.New("config: invalid UTF-8 encoding")
	}

	if bytes.Contains(b, []byte("\x00")) {
		return nil, errors.New("config: contains NUL byte")
	}

	if bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) {
		return nil, errors.New("config: contains UTF-8 BOM")
	}

	// The YAML parser reads each of these as a line break. An editor shows
	// them as one line, so a second key can hide in it.
	for _, sep := range []rune{0x85, 0x2028, 0x2029} {
		if bytes.ContainsRune(b, sep) {
			return nil, errors.New("config: contains U+0085, U+2028 or U+2029")
		}
	}

	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config: empty document")
		}
		return nil, wrapYamlError(err)
	}

	if doc.Kind != yaml.DocumentNode {
		return nil, errors.New("config: not a YAML document")
	}

	var doc2 yaml.Node
	if err := dec.Decode(&doc2); err != io.EOF {
		return nil, errors.New("config: contains more than one document")
	}

	if len(doc.Content) == 0 {
		return nil, errors.New("config: empty document")
	}

	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("config: root must be a mapping")
	}

	res := &Doc{
		Leaves:    make(map[string]Leaf),
		Mappings:  make(map[string]bool),
		Sequences: make(map[string]bool),
		Lines:     make(map[string]int),
	}

	if err := walkNode(root, nil, "", res, 0); err != nil {
		return nil, err
	}

	return res, nil
}

// walkNode walks the node n at path. For a mapping entry, key is the key node;
// it is nil for the root and for a sequence item.
func walkNode(n, key *yaml.Node, path string, doc *Doc, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("config: %s: line %d column %d: nesting exceeds limit of %d", formatPath(path), n.Line, n.Column, maxDepth)
	}

	if key != nil {
		if _, exists := doc.Leaves[path]; exists || doc.Mappings[path] || doc.Sequences[path] {
			return fmt.Errorf("config: %s: line %d column %d: duplicate key", formatPath(path), key.Line, key.Column)
		}
	}

	if n.Alias != nil {
		return fmt.Errorf("config: %s: line %d column %d: alias nodes are rejected", formatPath(path), n.Line, n.Column)
	}

	if n.Anchor != "" {
		return fmt.Errorf("config: %s: line %d column %d: anchors are rejected", formatPath(path), n.Line, n.Column)
	}

	if !isCoreTag(n.Tag, n.Kind) {
		return fmt.Errorf("config: %s: line %d column %d: %s", formatPath(path), n.Line, n.Column, tagRuleText(n.Kind, n.Style&yaml.TaggedStyle != 0))
	}

	line := n.Line
	if key != nil {
		line = key.Line
	}
	doc.Lines[path] = line
	switch n.Kind {
	case yaml.MappingNode:
		doc.Mappings[path] = true
		for i := 0; i < len(n.Content); i += 2 {
			keyNode := n.Content[i]
			valNode := n.Content[i+1]

			if keyNode.Kind != yaml.ScalarNode {
				return fmt.Errorf("config: %s: line %d column %d: mapping keys must be scalars", formatPath(path), keyNode.Line, keyNode.Column)
			}

			key := keyNode.Value
			if key == "<<" {
				return fmt.Errorf("config: %s: line %d column %d: merge keys are rejected", formatPath(path), keyNode.Line, keyNode.Column)
			}

			if !isValidKey(key) {
				return fmt.Errorf("config: %s: line %d column %d: %s", formatPath(path), keyNode.Line, keyNode.Column, keyRule)
			}

			if keyNode.Tag != "" && keyNode.Tag != "!!str" {
				return fmt.Errorf("config: %s: line %d column %d: mapping key tag is rejected: a key must be a string, not a number, bool or null", formatPath(path), keyNode.Line, keyNode.Column)
			}

			if keyNode.Anchor != "" {
				return fmt.Errorf("config: %s: line %d column %d: mapping key anchor is rejected", formatPath(path), keyNode.Line, keyNode.Column)
			}

			newPath := key
			if path != "" {
				newPath = path + "." + key
			}

			if err := walkNode(valNode, keyNode, newPath, doc, depth+1); err != nil {
				return err
			}
		}

	case yaml.SequenceNode:
		doc.Sequences[path] = true
		for i, child := range n.Content {
			newPath := fmt.Sprintf("%s[%d]", path, i)
			if path == "" {
				newPath = fmt.Sprintf("[%d]", i)
			}
			if err := walkNode(child, nil, newPath, doc, depth+1); err != nil {
				return err
			}
		}

	case yaml.ScalarNode:
		if path == "" {
			return errors.New("config: root must be a mapping")
		}

		doc.Leaves[path] = Leaf{
			Value: n.Value,
			Tag:   n.Tag,
			Line:  n.Line,
		}

	default:
		return fmt.Errorf("config: %s: line %d column %d: unsupported node type", formatPath(path), n.Line, n.Column)
	}

	return nil
}

func isCoreTag(tag string, kind yaml.Kind) bool {
	switch kind {
	case yaml.ScalarNode:
		return tag == "" || tag == "!!str" || tag == "!!int" || tag == "!!bool" || tag == "!!float" || tag == "!!null"
	case yaml.MappingNode:
		return tag == "" || tag == "!!map"
	case yaml.SequenceNode:
		return tag == "" || tag == "!!seq"
	case yaml.DocumentNode:
		return tag == "" || tag == "!!doc"
	default:
		return false
	}
}

// tagRuleText gives the fixed text of the tag rule for a node kind.
// The kinds here and in isCoreTag go together: change both.
// written is true if the file has the tag.
func tagRuleText(kind yaml.Kind, written bool) string {
	switch {
	case kind == yaml.MappingNode:
		return mapTagRule
	case kind == yaml.SequenceNode:
		return seqTagRule
	case !written:
		return plainTagRule // For example, a plain date resolves to timestamp.
	default:
		// The parser sends no document, alias or zero-kind node here.
		return scalarTagRule
	}
}

func cut(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

func isValidKey(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func formatFilePath(path string) string {
	return fmt.Sprintf("%q", path)
}

func formatPath(path string) string {
	if path == "" {
		return "(root)"
	}
	return fmt.Sprintf("%q", cut(path))
}

func formatOSError(path string, err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("config: %s: %w", formatFilePath(pathErr.Path), errors.Unwrap(pathErr))
	}
	return fmt.Errorf("config: %s: %w", formatFilePath(path), err)
}

func wrapYamlError(err error) error {
	var line int
	if n, parseErr := fmt.Sscanf(err.Error(), "yaml: line %d", &line); n < 1 || parseErr != nil {
		return errors.New("config: invalid YAML")
	}
	return fmt.Errorf("config: line %d: invalid YAML", line)
}
