package bundle

import (
	"crypto/sha256"
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

// recordName gives the name of a file of transition record n. ext is "cbnd"
// for the archive of the transition bundle and "sig" for its signature file.
func recordName(n int, ext string) string { return fmt.Sprintf("rotation-%d.%s", n, ext) }

// isRecordName tells if base is the archive name of a transition record, or
// of record maxRotations+1, which readChain also reads. The ASCII case of the
// letters does not count.
func isRecordName(base string) bool {
	b := []byte(base)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	for n := 1; n <= maxRotations+1; n++ {
		if string(b) == recordName(n, "cbnd") {
			return true
		}
	}
	return false
}

// index gives the position of the key with this ID, or -1.
func (t TrustSet) index(id string) int {
	return slices.IndexFunc(t, func(k TrustKey) bool { return k.KeyID == id })
}

// chain is the result of a chain check: the compiled trust set with each
// record applied. retired holds the keys that the records removed. sums holds
// the archive SHA-256 of each record in order.
type chain struct {
	trust   TrustSet
	retired TrustSet
	sums    [][32]byte
}

// rotate checks the rotation of a transition bundle against the chain c. m is
// its manifest. archive and sig are its files. ids are the key IDs that
// VerifySig gave for sig over archive with the set c.trust. The old key must be
// one of them. rotate refuses a new key ID or a new key that is in the set
// or that a record removed. The new key needs a line that verifies. rotate
// gives the chain after the rotation, with the new key in the place of the
// old key. It also gives the class of the old key. rotate refuses a new key of
// small order.
func (c chain) rotate(m *Manifest, archive, sig []byte, ids []string) (next chain, class Class, ok bool) {
	r := m.Rotation
	if r == nil || smallOrder(r.Key) || !slices.Contains(ids, r.From) {
		return chain{}, 0, false
	}
	i := c.trust.index(r.From)
	if c.trust.index(m.KeyID) >= 0 || c.retired.index(m.KeyID) >= 0 ||
		slices.ContainsFunc(slices.Concat(c.retired, c.trust), func(k TrustKey) bool { return k.PublicKey == r.Key }) {
		return chain{}, 0, false
	}
	if _, err := VerifySig(archive, sig, TrustSet{{KeyID: m.KeyID, PublicKey: r.Key}}); err != nil {
		return chain{}, 0, false
	}
	next = chain{trust: slices.Clone(c.trust), retired: append(slices.Clone(c.retired), c.trust[i]), sums: c.sums}
	next.trust[i] = TrustKey{KeyID: m.KeyID, PublicKey: r.Key, Class: c.trust[i].Class}
	return next, c.trust[i].Class, true
}

// record applies one transition record to the chain. VerifySig hashes the
// archive and verifies a line of a key of the set before the decompress. Only
// the manifest of the archive stays. No expiry rule applies.
func (c chain) record(archive, sig []byte, decompress func([]byte) (*Archive, error)) (chain, bool) {
	ids, err := VerifySig(archive, sig, c.trust)
	if err != nil {
		return c, false
	}
	arch, err := decompress(archive)
	if err != nil {
		return c, false
	}
	raw, _ := arch.File("manifest.json")
	m, err := ParseManifest(raw)
	if err != nil {
		return c, false
	}
	next, _, ok := c.rotate(m, archive, sig, ids)
	if !ok {
		return c, false
	}
	next.sums = append(next.sums, sha256.Sum256(archive))
	return next, true
}

// readChain reads the transition records 1, 2, ... in the bundle directory,
// one at a time, with the read rule of a bundle file. It applies each one to
// the compiled trust set. A bad record, a lone file, or a gap gives
// ErrStateFault. So does a file that the read rule refuses. So does an entry at
// the name of record 9. readChain changes nothing on disk.
func readChain(root *os.Root, trust TrustSet, decompress func([]byte) (*Archive, error)) (chain, error) {
	c := chain{trust: slices.Clone(trust)}
	ended := false
	for n := 1; n <= maxRotations; n++ {
		archive, errA := safefile.ReadFile(root, recordName(n, "cbnd"), fileRule(MaxBundleBytes))
		sig, errS := safefile.ReadFile(root, recordName(n, "sig"), fileRule(MaxSigBytes))
		if errors.Is(errA, fs.ErrNotExist) && errors.Is(errS, fs.ErrNotExist) {
			ended = true
			continue
		}
		if ended || errA != nil || errS != nil {
			return chain{}, ErrStateFault
		}
		var ok bool
		if c, ok = c.record(archive, sig, decompress); !ok {
			return chain{}, ErrStateFault
		}
	}
	for _, ext := range []string{"cbnd", "sig"} {
		if _, err := root.Lstat(recordName(maxRotations+1, ext)); !errors.Is(err, fs.ErrNotExist) {
			return chain{}, ErrStateFault
		}
	}
	return c, nil
}

// writeRecord writes transition record n: the archive and the signature file of
// the transition bundle. If a write fails, it removes the record.
func writeRecord(root *os.Root, n int, archive, sig []byte) error {
	err := writeFile(root, recordName(n, "cbnd"), archive)
	if err == nil {
		err = writeFile(root, recordName(n, "sig"), sig)
	}
	if err != nil {
		removeRecord(root, n)
	}
	return err
}

// removeRecord removes the two files of transition record n.
func removeRecord(root *os.Root, n int) {
	for _, ext := range []string{"cbnd", "sig"} {
		_ = root.Remove(recordName(n, ext))
	}
}
