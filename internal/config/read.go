// Package config provides a strict YAML configuration loader.
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

// ReadOptions is removed as per requirement.

// Leaf represents a scalar value in the configuration.
type Leaf struct {
	Value string
	Tag   string // Tag is the resolved tag.
	Line  int
}

// Doc represents the parsed configuration.
type Doc struct {
	Leaves    map[string]Leaf // Leaves hold scalar values.
	Mappings  map[string]bool // Mappings hold the paths of container nodes.
	Sequences map[string]bool // Sequences hold the paths of container nodes.
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
		return nil, fmt.Errorf("config: %s: not a regular file", formatPath(path))
	}

	mode := info.Mode()
	if mode&0022 != 0 {
		return nil, fmt.Errorf("config: %s: group or other writable", formatPath(path))
	}

	uid, err := getUid(info)
	if err != nil {
		return nil, formatOSError(path, err)
	}

	if uid != 0 && uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("config: %s: owner must be root or current user", formatPath(path))
	}

	lr := io.LimitReader(f, maxConfigSize+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, formatOSError(path, err)
	}

	if len(b) > maxConfigSize {
		return nil, fmt.Errorf("config: %s: config file exceeds 64 KiB limit", formatPath(path))
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
		return nil, errors.New("config: config file exceeds 64 KiB limit")
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

	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
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
	}

	if err := walkNode(root, "", res, 0); err != nil {
		return nil, err
	}

	return res, nil
}

func walkNode(n *yaml.Node, path string, doc *Doc, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("config: %s: nesting exceeds limit of %d", formatPath(path), maxDepth)
	}

	if n.Alias != nil {
		return fmt.Errorf("config: %s: line %d column %d: alias nodes are rejected", formatPath(path), n.Line, n.Column)
	}

	if n.Anchor != "" {
		return fmt.Errorf("config: %s: line %d column %d: anchors are rejected", formatPath(path), n.Line, n.Column)
	}

	if !isCoreTag(n.Tag, n.Kind) {
		return fmt.Errorf("config: %s: line %d column %d: custom tag %q is rejected", formatPath(path), n.Line, n.Column, cut(n.Tag))
	}

	switch n.Kind {
	case yaml.MappingNode:
		if _, exists := doc.Leaves[path]; exists || doc.Mappings[path] || doc.Sequences[path] {
			return fmt.Errorf("config: %s: line %d column %d: duplicate key", formatPath(path), n.Line, n.Column)
		}
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
				return fmt.Errorf("config: %s: line %d column %d: mapping key %q is invalid", formatPath(path), keyNode.Line, keyNode.Column, cut(key))
			}

			if keyNode.Tag != "" && keyNode.Tag != "!!str" {
				return fmt.Errorf("config: %s: line %d column %d: mapping key tag %q is rejected", formatPath(path), keyNode.Line, keyNode.Column, cut(keyNode.Tag))
			}

			if keyNode.Anchor != "" {
				return fmt.Errorf("config: %s: line %d column %d: mapping key anchor is rejected", formatPath(path), keyNode.Line, keyNode.Column)
			}

			newPath := key
			if path != "" {
				newPath = path + "." + key
			}

			if _, exists := doc.Leaves[newPath]; exists || doc.Mappings[newPath] || doc.Sequences[newPath] {
				return fmt.Errorf("config: %s: line %d column %d: duplicate key %q", formatPath(path), keyNode.Line, keyNode.Column, cut(newPath))
			}

			if err := walkNode(valNode, newPath, doc, depth+1); err != nil {
				return err
			}
		}

	case yaml.SequenceNode:
		if _, exists := doc.Leaves[path]; exists || doc.Mappings[path] || doc.Sequences[path] {
			return fmt.Errorf("config: %s: line %d column %d: duplicate key", formatPath(path), n.Line, n.Column)
		}
		doc.Sequences[path] = true
		for i, child := range n.Content {
			newPath := fmt.Sprintf("%s[%d]", path, i)
			if path == "" {
				newPath = fmt.Sprintf("[%d]", i)
			}
			if err := walkNode(child, newPath, doc, depth+1); err != nil {
				return err
			}
		}

	case yaml.ScalarNode:
		if path == "" {
			return errors.New("config: root must be a mapping")
		}

		if _, exists := doc.Leaves[path]; exists || doc.Mappings[path] || doc.Sequences[path] {
			return fmt.Errorf("config: %s: line %d column %d: duplicate key %q", formatPath(path), n.Line, n.Column, cut(path))
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

func cut(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

func containsDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
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

func formatPath(path string) string {
	if path == "" {
		return "(root)"
	}
	return fmt.Sprintf("%q", cut(path))
}

func formatOSError(path string, err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("config: %s: %v", formatPath(pathErr.Path), errors.Unwrap(pathErr))
	}
	return fmt.Errorf("config: %s: %w", formatPath(path), err)
}

func wrapYamlError(err error) error {
	s := err.Error()
	var line, col int
	n, parseErr := fmt.Sscanf(s, "yaml: line %d column %d", &line, &col)
	if n < 1 || parseErr != nil {
		n, parseErr = fmt.Sscanf(s, "yaml: line %d", &line)
		if n < 1 || parseErr != nil {
			return errors.New("config: invalid YAML")
		}
	}

	if n == 2 {
		return fmt.Errorf("config: line %d column %d: invalid YAML", line, col)
	}
	return fmt.Errorf("config: line %d: invalid YAML", line)
}
