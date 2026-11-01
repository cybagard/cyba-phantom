package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"strings"
)

// SigMessage returns the 54 bytes that a signature covers (SEC-24). They are
// the prefix "phantom-bundle-sig-v1\n" and the SHA-256 of the archive.
func SigMessage(archive []byte) []byte {
	sum := sha256.Sum256(archive)
	return append([]byte("phantom-bundle-sig-v1\n"), sum[:]...)
}

type sigLine struct {
	keyID string
	sig   [ed25519.SignatureSize]byte
}

// parseSig reads a signature file of one or two lines. Each line is
// "<key_id> <base64>\n". The key ID has the form of a manifest key ID. The
// base64 text is the canonical form of 64 bytes. No key ID is on two lines.
// Any other byte makes the file not valid.
func parseSig(b []byte) ([]sigLine, bool) {
	text, ok := strings.CutSuffix(string(b), "\n")
	rows := strings.Split(text, "\n")
	if !ok || len(rows) > 2 {
		return nil, false
	}
	enc := base64.StdEncoding
	var lines []sigLine
	for _, row := range rows {
		id, text, found := strings.Cut(row, " ")
		if !found || !validKeyID(id) {
			return nil, false
		}
		raw, err := enc.DecodeString(text)
		if err != nil || len(raw) != ed25519.SignatureSize || enc.EncodeToString(raw) != text ||
			slices.ContainsFunc(lines, func(l sigLine) bool { return l.keyID == id }) {
			return nil, false
		}
		lines = append(lines, sigLine{keyID: id, sig: [ed25519.SignatureSize]byte(raw)})
	}
	return lines, true
}

// SigKeyIDs gives the key IDs of the lines of a signature file, in order. It
// checks the form only, not a signature. ok is false when the file is not
// valid.
func SigKeyIDs(sig []byte) (ids []string, ok bool) {
	lines, ok := parseSig(sig)
	for _, l := range lines {
		ids = append(ids, l.keyID)
	}
	return ids, ok
}

// CheckSigned applies the signature and key rule of the loader (SEC-24). It
// checks an archive and its signature file against the trust set. It does not
// check min_engine against the engine version or the expiry against the clock.
// It does not check the version state, the seed or the transition records.
// The order is: signature, archive, manifest, then rotation or key ID. A
// transition bundle needs the line of the old key, which is trusted, and the
// line of the new key. Any other bundle needs a valid line of its manifest key
// ID. CheckSigned gives the key IDs that verified. For a transition bundle,
// the list ends with the new key ID. A failed step gives ErrBadSig,
// ErrArchiveInvalid or ErrManifestInvalid.
func CheckSigned(archive, sig []byte, trust TrustSet) ([]string, error) {
	ids, err := VerifySig(archive, sig, trust)
	if err != nil {
		return nil, ErrBadSig
	}
	arch, err := ReadArchive(archive)
	if err != nil {
		return nil, ErrArchiveInvalid
	}
	raw, _ := arch.File("manifest.json")
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, ErrManifestInvalid
	}
	if m.Rotation != nil {
		if _, _, ok := (chain{trust: trust}).rotate(m, archive, sig, ids); !ok {
			return nil, ErrBadSig
		}
		return append(ids, m.KeyID), nil
	}
	if trust.index(m.KeyID) < 0 || !slices.Contains(ids, m.KeyID) {
		return nil, ErrBadSig
	}
	return ids, nil
}

// VerifySig checks the signature file sig over the archive. It returns the key
// IDs of the valid lines in order. It skips a line whose key ID is not in the
// trust set. A line whose key ID is in the set and whose signature does not
// verify gives ErrBadSig. A file that is not valid, or that has no valid line,
// gives ErrBadSig too. The caller checks that the key IDs are the ones that it
// needs. The function takes no key from the bundle.
func VerifySig(archive, sig []byte, trust TrustSet) ([]string, error) {
	lines, ok := parseSig(sig)
	if !ok {
		return nil, ErrBadSig
	}
	msg := SigMessage(archive)
	var valid []string
	for _, l := range lines {
		i := slices.IndexFunc(trust, func(k TrustKey) bool { return k.KeyID == l.keyID })
		if i < 0 {
			continue
		}
		if !ed25519.Verify(trust[i].PublicKey[:], msg, l.sig[:]) {
			return nil, ErrBadSig
		}
		valid = append(valid, l.keyID)
	}
	if len(valid) == 0 {
		return nil, ErrBadSig
	}
	return valid, nil
}
