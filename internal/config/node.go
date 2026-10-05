package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"
)

const maxConfigSize = 64 * 1024

type leaf struct {
	line  int
	value string
	style yaml.Style
}

func readFileCapped(path string, opts *Options) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat config file: %w", err)
	}
	if info.Mode()&0022 != 0 {
		return nil, fmt.Errorf("config file %q must not be group or world writable", path)
	}

	// Read capped at 64 KiB + 1 byte
	buf := make([]byte, maxConfigSize+1)
	n, err := io.ReadFull(f, buf)
	if err == nil {
		return nil, errors.New("config file exceeds 64 KiB limit")
	}
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}

	if n > maxConfigSize {
		return nil, errors.New("config file exceeds 64 KiB limit")
	}

	data := buf[:n]

	// Reject BOM
	if bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
		return nil, errors.New("config file must not contain a BOM")
	}

	// Reject NUL
	if bytes.Contains(data, []byte("\x00")) {
		return nil, errors.New("config file must not contain NUL bytes")
	}

	// Reject non-UTF-8 (implicitly handled by yaml.v3, but we could check here)
	return data, nil
}

func parseCapped(data []byte) (map[string]leaf, map[string]bool, map[string]bool, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, nil, fmt.Errorf("yaml parse error: %w", err)
	}

	// Reject second document
	if doc.Kind != yaml.DocumentNode {
		return nil, nil, nil, errors.New("config must be a YAML document")
	}

	var doc2 yaml.Node
	if err := dec.Decode(&doc2); err != io.EOF {
		return nil, nil, nil, errors.New("config must contain only one document")
	}

	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, nil, nil, errors.New("config root must be a mapping")
	}

	leaves := make(map[string]leaf)
	nonLeaves := make(map[string]bool)
	allPaths := make(map[string]bool)

	if err := walkNode(root, "", leaves, nonLeaves, allPaths, 0); err != nil {
		return nil, nil, nil, err
	}

	return leaves, nonLeaves, allPaths, nil
}

func walkNode(n *yaml.Node, path string, leaves map[string]leaf, nonLeaves map[string]bool, allPaths map[string]bool, depth int) error {
	// Nesting > 8
	if depth > 8 {
		return errors.New("config nesting exceeds limit of 8")
	}

	// Reject aliases and anchors
	if n.Alias != nil {
		return fmt.Errorf("config at %q contains an alias", path)
	}
	if n.Anchor != "" {
		return fmt.Errorf("config at %q contains an anchor", path)
	}

	// Reject custom tags (only core schema allowed)
	if n.Tag != "" && !isCoreTag(n.Tag, n.Kind) {
		return fmt.Errorf("config at %q contains custom tag %q", path, n.Tag)
	}

	switch n.Kind {
	case yaml.MappingNode:
		// Duplicate mapping keys
		seen := make(map[string]bool)
		for i := 0; i < len(n.Content); i += 2 {
			keyNode := n.Content[i]
			valNode := n.Content[i+1]

			if keyNode.Kind != yaml.ScalarNode {
				return fmt.Errorf("config at %q has a non-scalar key", path)
			}

			key := keyNode.Value
			if key == "<<" {
				return fmt.Errorf("config at %q contains merge key", path)
			}

			if seen[key] {
				return fmt.Errorf("config at %q contains duplicate key %q", path, key)
			}
			seen[key] = true

			newPath := key
			if path != "" {
				newPath = path + "." + key
			}

			allPaths[newPath] = true
			if err := walkNode(valNode, newPath, leaves, nonLeaves, allPaths, depth+1); err != nil {
				return err
			}
		}

	case yaml.SequenceNode:
		nonLeaves[path] = true
		for _, child := range n.Content {
			if err := walkNode(child, path, leaves, nonLeaves, allPaths, depth+1); err != nil {
				return err
			}
		}

	case yaml.ScalarNode:
		// Reject tags outside core schema (implicitly handled by yaml.v3 mostly, but we check)
		// M4: Strict scalars (bool, int, duration) are checked during apply/validate
		// Here we just capture the raw value and line.

		if path == "" {
			return errors.New("config must be a mapping")
		}

		leaves[path] = leaf{
			line:  n.Line,
			value: n.Value,
			style: n.Style,
		}

	default:
		return fmt.Errorf("config at %q contains unsupported node type", path)
	}

	return nil
}

func isCoreTag(tag string, kind yaml.Kind) bool {
	// Basic core tags for common types
	switch kind {
	case yaml.ScalarNode:
		return tag == "" || tag == "!!str" || tag == "!!int" || tag == "!!float" || tag == "!!bool" || tag == "!!null"
	case yaml.MappingNode:
		return tag == "" || tag == "!!map"
	case yaml.SequenceNode:
		return tag == "" || tag == "!!seq"
	case yaml.DocumentNode:
		return tag == "" || tag == "!!doc"
	}
	return false
}
