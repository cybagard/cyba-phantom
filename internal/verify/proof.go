package verify

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"strconv"

	modtlog "golang.org/x/mod/sumdb/tlog"
)

// The most hashes in one proof (04 §7).
const (
	maxInclusionHashes   = 48
	maxConsistencyHashes = 96
)

// jsonOpts sets each parse rule in the code. It does not depend on defaults.
var jsonOpts = json.JoinOptions(
	jsontext.AllowDuplicateNames(false),
	json.MatchCaseInsensitiveNames(false),
	json.RejectUnknownMembers(true),
)

// InclusionProof is a parsed inclusion proof file. Root and Consistency are
// both set or both nil.
type InclusionProof struct {
	Index, TreeSize int64
	Hashes          []modtlog.Hash
	Root            *modtlog.Hash
	Consistency     []modtlog.Hash
}

// proofFile is the wire form. A Value keeps null and a missing member apart
// from a real value; a missing member has length 0.
type proofFile struct {
	Index       jsontext.Value `json:"index"`
	TreeSize    jsontext.Value `json:"tree_size"`
	Hashes      jsontext.Value `json:"hashes"`
	Root        jsontext.Value `json:"root"`
	Consistency jsontext.Value `json:"consistency"`
}

// ParseInclusionProof parses a proof file with the rules of 04 §7. The input
// is one JSON object of at most 16 KiB. It has no duplicate, unknown or
// wrong-case member and no null value. index, tree_size and hashes are
// required. root and consistency are both present or both absent.
func ParseInclusionProof(b []byte) (InclusionProof, error) {
	var p InclusionProof
	if len(b) > MaxProofBytes {
		return p, ErrTooLarge
	}
	var f proofFile
	if json.Unmarshal(b, &f, jsonOpts) != nil { // also refuses a second value
		return p, ErrProof
	}
	var err error
	if p.Index, err = parseSize(f.Index); err != nil {
		return InclusionProof{}, err
	}
	if p.TreeSize, err = parseSize(f.TreeSize); err != nil {
		return InclusionProof{}, err
	}
	if p.Hashes, err = parseHashes(f.Hashes, maxInclusionHashes); err != nil {
		return InclusionProof{}, err
	}
	if (len(f.Root) == 0) != (len(f.Consistency) == 0) {
		return InclusionProof{}, ErrProof
	}
	if len(f.Root) > 0 {
		var s string // null gives "", which is not a hash
		if json.Unmarshal(f.Root, &s, jsonOpts) != nil {
			return InclusionProof{}, ErrProof
		}
		root, err := parseHash(s)
		if err != nil {
			return InclusionProof{}, err
		}
		p.Root = &root
		if p.Consistency, err = parseHashes(f.Consistency, maxConsistencyHashes); err != nil {
			return InclusionProof{}, err
		}
	}
	return p, nil
}

// ReadInclusionProof reads a proof file with the size cap, then calls
// ParseInclusionProof.
func ReadInclusionProof(r io.Reader) (InclusionProof, error) {
	b, err := readCapped(r, MaxProofBytes)
	if err != nil {
		return InclusionProof{}, err
	}
	return ParseInclusionProof(b)
}

// parseSize reads a JSON number that is a plain decimal integer from 0 to 2^48.
// A missing member, null, a sign, a fraction and an exponent are refused. The
// range is checked before the cast to int64.
func parseSize(v jsontext.Value) (int64, error) {
	if len(v) == 0 {
		return 0, ErrProof
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, ErrProof
		}
	}
	n, err := strconv.ParseUint(string(v), 10, 64)
	if err != nil || n > maxSize {
		return 0, ErrRange
	}
	return int64(n), nil
}

// parseHashes reads an array of at most limit canonical standard base64
// strings of 32 bytes. A missing member and null are refused.
func parseHashes(v jsontext.Value, limit int) ([]modtlog.Hash, error) {
	var ss []string
	if len(v) == 0 || json.Unmarshal(v, &ss, jsonOpts) != nil || ss == nil || len(ss) > limit {
		return nil, ErrProof
	}
	out := make([]modtlog.Hash, len(ss))
	for i, s := range ss {
		var err error
		if out[i], err = parseHash(s); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parseHash reads canonical standard base64 of exactly 32 bytes. The decoder
// skips CR and LF, so the encoded form must also equal the input.
func parseHash(s string) (h modtlog.Hash, err error) {
	raw, derr := base64.StdEncoding.Strict().DecodeString(s)
	if derr != nil || len(raw) != len(h) || base64.StdEncoding.EncodeToString(raw) != s {
		return h, ErrProof
	}
	copy(h[:], raw)
	return h, nil
}
