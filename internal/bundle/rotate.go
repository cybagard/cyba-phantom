package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"

	"github.com/cybagard/cyba-phantom/internal/safefile"
)

// maxRotations is the most transition records that the bundle directory
// holds (SEC-24).
const maxRotations = 8

// recordName gives the name of a file of transition record n. The "json" file
// holds the manifest. The "sig" file holds the signature record.
func recordName(n int, ext string) string { return fmt.Sprintf("rotation-%d.%s", n, ext) }

// index gives the position of the key with this ID, or -1.
func (t TrustSet) index(id string) int {
	return slices.IndexFunc(t, func(k TrustKey) bool { return k.KeyID == id })
}

// rotated checks the rotation of a transition bundle against the trust set t.
// m is its manifest and has a rotation member. sum is the SHA-256 of its
// archive, and lines are its signature lines. The old key must be in t and the
// new key ID must not be in t. This also refuses a rotation from a key ID to
// itself. The old key and the new key each need a line that verifies. The new
// key has the class of the old key. rotated gives the set after the rotation:
// the old key is gone and the new key is in its place.
func (t TrustSet) rotated(m *Manifest, sum [32]byte, lines []sigLine) (TrustSet, bool) {
	r := m.Rotation
	i := t.index(r.From)
	if i < 0 || t.index(m.KeyID) >= 0 {
		return nil, false
	}
	msg := append([]byte("phantom-bundle-sig-v1\n"), sum[:]...)
	verifies := func(id string, key [32]byte) bool {
		j := slices.IndexFunc(lines, func(l sigLine) bool { return l.keyID == id })
		return j >= 0 && ed25519.Verify(key[:], msg, lines[j].sig[:])
	}
	if !verifies(r.From, t[i].PublicKey) || !verifies(m.KeyID, r.Key) {
		return nil, false
	}
	next := slices.Clone(t)
	next[i] = TrustKey{KeyID: m.KeyID, PublicKey: r.Key, Class: t[i].Class}
	return next, true
}

// readChain reads the transition records 1, 2, ... in the bundle directory.
// It applies each one to the compiled trust set. It gives the effective set
// and the archive SHA-256 of each record in order. ErrStateFault is the result
// for a record that is not valid. It is also the result for a file without its
// pair. A gap in the numbers gives it. So does a file that the state file rule
// refuses. readChain changes nothing on disk.
func readChain(root *os.Root, trust TrustSet) (TrustSet, [][32]byte, error) {
	eff := slices.Clone(trust)
	var sums [][32]byte
	ended := false
	for n := 1; n <= maxRotations; n++ {
		raw, errM := safefile.ReadFile(root, recordName(n, "json"), stateRule)
		rec, errS := safefile.ReadFile(root, recordName(n, "sig"), stateRule)
		if errors.Is(errM, fs.ErrNotExist) && errors.Is(errS, fs.ErrNotExist) {
			ended = true
			continue
		}
		if ended || errM != nil || errS != nil {
			return nil, nil, ErrStateFault
		}
		m, sum, lines, ok := parseRecord(raw, rec)
		if !ok {
			return nil, nil, ErrStateFault
		}
		if eff, ok = eff.rotated(m, sum, lines); !ok {
			return nil, nil, ErrStateFault
		}
		sums = append(sums, sum)
	}
	return eff, sums, nil
}

// parseRecord reads a record: the manifest of a transition bundle, and the
// signature record. The signature record is a line with the archive SHA-256 in
// lower-case hex, and then the signature file bytes.
func parseRecord(raw, rec []byte) (m *Manifest, sum [32]byte, lines []sigLine, ok bool) {
	line, sig, found := bytes.Cut(rec, []byte("\n"))
	if !found || len(line) != hex.EncodedLen(len(sum)) {
		return nil, sum, nil, false
	}
	if _, err := hex.Decode(sum[:], line); err != nil || hex.EncodeToString(sum[:]) != string(line) {
		return nil, sum, nil, false
	}
	m, err := ParseManifest(raw)
	if err != nil || m.Rotation == nil {
		return nil, sum, nil, false
	}
	lines, ok = parseSig(sig)
	return m, sum, lines, ok
}

// writeRecord writes transition record n: the manifest bytes and the signature
// record. If the second file fails, it removes the first.
func writeRecord(root *os.Root, n int, manifest []byte, sum [32]byte, sig []byte) error {
	if err := writeFile(root, recordName(n, "json"), manifest); err != nil {
		return err
	}
	err := writeFile(root, recordName(n, "sig"), append(fmt.Appendf(nil, "%x\n", sum), sig...))
	if err != nil {
		_ = root.Remove(recordName(n, "json"))
	}
	return err
}
