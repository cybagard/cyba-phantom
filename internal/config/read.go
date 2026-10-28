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
	"strconv"
	"syscall"
	"unicode/utf8"

	"github.com/cybagard/cyba-phantom/internal/safefile"
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

// ReadError is an error of ReadFile or ReadBytes.
// The fields hold the parts of the error, so a caller does not parse the text.
// Error escapes the key path and the file path.
// Path can name a key below a secret key. Do not print a ReadError.
// Use the errors of Load.
type ReadError struct {
	File   string // File is the path of the file for a file error, or "".
	Path   string // Path is the key path for a node error (Column > 0).
	Line   int    // Line is the line in the text, or 0.
	Column int    // Column is the column in the text, or 0.
	Detail string // Detail is a fixed text. It never holds text of the input.
	Err    error  // Err is the system error for a file error, or nil.
}

func (e *ReadError) Error() string {
	s := "config: "
	if e.File != "" || e.Err != nil {
		s += formatFilePath(e.File) + ": "
	}
	if e.Column > 0 {
		s += formatPath(e.Path) + ": "
	}
	if e.Line > 0 {
		s += "line " + strconv.Itoa(e.Line)
		if e.Column > 0 {
			s += " column " + strconv.Itoa(e.Column)
		}
		s += ": "
	}
	if e.Err != nil {
		return s + e.Err.Error()
	}
	return s + e.Detail
}

func (e *ReadError) Unwrap() error { return e.Err }

// readErr returns a ReadError that has a detail only.
func readErr(detail string) error { return &ReadError{Detail: detail} }

// nodeError returns a ReadError for the node at the key path.
func nodeError(path string, line, col int, detail string) error {
	return &ReadError{Path: path, Line: line, Column: col, Detail: detail}
}

// Leaf represents a scalar value in the configuration.
type Leaf struct {
	Value string
	Tag   string // Tag is the resolved tag, or "!" for a refused written tag.
	Line  int
}

// Doc represents the parsed configuration.
type Doc struct {
	Leaves    map[string]Leaf // Leaves hold scalar values.
	Mappings  map[string]bool // Mappings holds the paths of mapping nodes; "" is the root
	Sequences map[string]bool // Sequences holds the paths of sequence nodes
	Lines     map[string]int  // Lines holds the line of each node by path; for a mapping entry, the line of the key
}

// configRule is the rule for the config file. A symlink at the path is
// followed. The owner must be root or the current user. The file must have
// no group or other write bit.
var configRule = safefile.Rule{
	Type:      safefile.Regular,
	Owner:     safefile.OwnerSelfOrRoot,
	Forbid:    0o022,
	MaxSize:   maxConfigSize,
	FollowEnd: true,
}

// ReadFile reads the configuration file at path and returns a Doc.
// The shared safe-file package opens the file. It refuses a FIFO or a device
// before the open. It also refuses a file that changes between the check and
// the open. A file with a wrong owner and a wrong mode gets the owner text.
func ReadFile(path string) (*Doc, error) {
	abs, err := absolute(path)
	if err != nil {
		return nil, formatOSError(path, err)
	}
	f, fi, err := safefile.OpenPath(abs, configRule)
	if err != nil {
		return nil, fileError(path, abs, err)
	}
	defer f.Close()

	b, err := safefile.ReadAll(f, fi, configRule)
	if err != nil {
		return nil, fileError(path, abs, err)
	}

	return ReadBytes(b)
}

// absolute gives path as an absolute path for the safe-file package. A relative
// path gets the working directory in front of it. It does not clean the path,
// so the kernel resolves each dot-dot and symlink. The walk from "/" needs
// search permission on each parent of the working directory. A plain
// relative open does not need it. The full path must also fit the length
// limit of the kernel.
func absolute(path string) (string, error) {
	if path == "" {
		return "", &os.PathError{Op: "open", Path: path, Err: syscall.ENOENT}
	}
	if path[0] == '/' {
		return path, nil
	}
	// os.Getwd can return $PWD, which can be a symlink path. The kernel
	// resolves a relative open against the inode of the working directory.
	wd, err := syscall.Getwd()
	if err != nil {
		return "", err
	}
	return wd + "/" + path, nil
}

// nameError gives the ReadError for a path that ends in "/", "/." or "/..".
// The text is the text of a plain open of the path. The limits in the comment
// of absolute also apply. A stat of abs gives the system error, or "not a
// regular file" for a directory. The error shows the path that the user gave.
func nameError(path, abs string) error {
	if _, err := os.Stat(abs); err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return formatOSError(path, err)
	}
	return &ReadError{File: path, Detail: "not a regular file"}
}

// fileError gives the ReadError for a refusal of the safe-file package. The
// path is the one that the user gave. abs is the path that the package got.
func fileError(path, abs string, err error) error {
	var se *safefile.Error
	if !errors.As(err, &se) {
		return formatOSError(path, err)
	}
	switch {
	case errors.Is(err, safefile.ErrName):
		return nameError(path, abs)
	case errors.Is(err, safefile.ErrType):
		return &ReadError{File: path, Detail: "not a regular file"}
	case errors.Is(err, safefile.ErrMode):
		return &ReadError{File: path, Detail: "group or other writable"}
	case errors.Is(err, safefile.ErrOwner):
		return &ReadError{File: path, Detail: "the owner must be root or the current user"}
	case errors.Is(err, safefile.ErrSize):
		return &ReadError{File: path, Detail: "the file is larger than 64 KiB"}
	case errors.Is(err, safefile.ErrChanged):
		return &ReadError{File: path, Detail: "the file changed during the read"}
	case se.Cause != nil:
		return formatOSError(path, se.Cause)
	}
	return &ReadError{File: path, Detail: "the file cannot be read"}
}

// ReadBytes parses the configuration from a byte slice and returns a Doc.
func ReadBytes(b []byte) (*Doc, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, readErr("empty document")
	}
	if len(b) > maxConfigSize {
		return nil, readErr("the input is larger than 64 KiB")
	}
	if !utf8.Valid(b) {
		return nil, readErr("invalid UTF-8 encoding")
	}

	if bytes.Contains(b, []byte("\x00")) {
		return nil, readErr("contains NUL byte")
	}

	if bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) {
		return nil, readErr("contains UTF-8 BOM")
	}

	// The YAML parser reads each of these as a line break. An editor or a
	// terminal can show the line as one line, so a second key can hide there.
	for _, sep := range []rune{0x85, 0x2028, 0x2029} {
		if bytes.ContainsRune(b, sep) {
			return nil, readErr("contains U+0085, U+2028 or U+2029")
		}
	}

	// The parser also reads a CR as a line break. A terminal moves the cursor
	// to the line start at a CR. A CR with an LF after it is a normal line
	// break.
	for rest := b; ; {
		i := bytes.IndexByte(rest, '\r')
		if i < 0 {
			break
		}
		if i+1 == len(rest) || rest[i+1] != '\n' {
			return nil, readErr("contains a CR without an LF after it")
		}
		rest = rest[i+2:]
	}

	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, readErr("empty document")
		}
		return nil, wrapYamlError(err)
	}

	if doc.Kind != yaml.DocumentNode {
		return nil, readErr("not a YAML document")
	}

	var doc2 yaml.Node
	if err := dec.Decode(&doc2); err != io.EOF {
		return nil, readErr("contains more than one document")
	}

	if len(doc.Content) == 0 {
		return nil, readErr("empty document")
	}

	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, readErr("root must be a mapping")
	}

	res := &Doc{
		Leaves:    make(map[string]Leaf),
		Mappings:  make(map[string]bool),
		Sequences: make(map[string]bool),
		Lines:     make(map[string]int),
	}

	if err := walkNode(root, nil, "", res, 0, &lineCursor{lines: bytes.Split(b, []byte("\n"))}); err != nil {
		return nil, err
	}

	return res, nil
}

// walkNode walks the node n at path. For a mapping entry, key is the key node;
// it is nil for the root and for a sequence item.
// src holds the lines of the file.
func walkNode(n, key *yaml.Node, path string, doc *Doc, depth int, src *lineCursor) error {
	if depth > maxDepth {
		return nodeError(path, n.Line, n.Column, "nesting exceeds limit of "+strconv.Itoa(maxDepth))
	}

	if key != nil {
		if _, exists := doc.Leaves[path]; exists || doc.Mappings[path] || doc.Sequences[path] {
			return nodeError(path, key.Line, key.Column, "duplicate key")
		}
	}

	if n.Alias != nil {
		return nodeError(path, n.Line, n.Column, "alias nodes are rejected")
	}

	if n.Anchor != "" {
		return nodeError(path, n.Line, n.Column, "anchors are rejected")
	}

	if !isCoreTag(n.Tag, n.Kind) {
		return nodeError(path, n.Line, n.Column, tagRuleText(n.Kind, n.Style&yaml.TaggedStyle != 0))
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
				return nodeError(path, keyNode.Line, keyNode.Column, "mapping keys must be scalars")
			}

			key := keyNode.Value
			if key == "<<" {
				return nodeError(path, keyNode.Line, keyNode.Column, "merge keys are rejected")
			}

			if !isValidKey(key) {
				return nodeError(path, keyNode.Line, keyNode.Column, keyRule)
			}

			if keyNode.Tag != "" && keyNode.Tag != "!!str" {
				return nodeError(path, keyNode.Line, keyNode.Column, "mapping key tag is rejected: a key must be a string, not a number, bool or null")
			}

			if keyNode.Anchor != "" {
				return nodeError(path, keyNode.Line, keyNode.Column, "mapping key anchor is rejected")
			}

			newPath := key
			if path != "" {
				newPath = path + "." + key
			}

			if err := walkNode(valNode, keyNode, newPath, doc, depth+1, src); err != nil {
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
			if err := walkNode(child, nil, newPath, doc, depth+1, src); err != nil {
				return err
			}
		}

	case yaml.ScalarNode:
		if path == "" {
			return readErr("root must be a mapping")
		}

		tag := n.Tag
		if bareTag(n, src) || n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 && tag != "!!str" {
			tag = "!"
		}
		doc.Leaves[path] = Leaf{
			Value: n.Value,
			Tag:   tag,
			Line:  n.Line,
		}

	default:
		return nodeError(path, n.Line, n.Column, "unsupported node type")
	}

	return nil
}

// bareTag reports whether the file has the non-specific tag "!" before the
// scalar n. The parser drops it. Style is that of the scalar without the tag.
// Tag is "!!str" for a quoted or block scalar. The node starts at the tag.
// A plain, quoted or block scalar cannot start with "!". An empty value can
// have the position of the next node. If that node starts with "!", the
// empty value gets the tag "!". Load refuses an empty value for each kind
// in any case. Column counts runes, so the function skips runes and does
// not copy the line.
// The scalars of one line come in rising column order. So src resumes where
// the last call stopped, and the cost for a line is linear.
func bareTag(n *yaml.Node, src *lineCursor) bool {
	if n.Style&yaml.TaggedStyle != 0 || n.Line < 1 || n.Line > len(src.lines) || n.Column < 1 {
		return false
	}
	line := src.lines[n.Line-1]
	if src.line != n.Line || n.Column < src.col {
		src.line, src.col, src.off = n.Line, 1, 0
	}
	for src.col < n.Column && src.off < len(line) {
		_, size := utf8.DecodeRune(line[src.off:])
		src.col, src.off, src.steps = src.col+1, src.off+size, src.steps+1
	}
	return src.off < len(line) && line[src.off] == '!'
}

// lineCursor holds the lines of the file. It also holds the last position
// that bareTag read: line, column and byte offset. steps counts the runes read.
type lineCursor struct {
	lines                 [][]byte
	line, col, off, steps int
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
		return &ReadError{File: pathErr.Path, Err: errors.Unwrap(pathErr)}
	}
	return &ReadError{File: path, Err: err}
}

func wrapYamlError(err error) error {
	var line int
	if n, parseErr := fmt.Sscanf(err.Error(), "yaml: line %d", &line); n < 1 || parseErr != nil {
		return readErr("invalid YAML")
	}
	return &ReadError{Line: line, Detail: "invalid YAML"}
}
