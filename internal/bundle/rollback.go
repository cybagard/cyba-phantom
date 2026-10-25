package bundle

import (
	"os"
	"time"
)

// Rollback checks a bundle against the version state in a bundle directory
// (SEC-24) and records an accepted bundle. It keeps no state in memory: each
// call reads the file, so a fault stays until an operator acts.
type Rollback struct {
	root *os.Root
}

// NewRollback gives a Rollback for the bundle directory root. The caller keeps
// root open.
func NewRollback(root *os.Root) *Rollback { return &Rollback{root: root} }

// Check decides if a bundle can load. m is its manifest, sum the SHA-256 of its
// archive bytes, and class the class of its signing key. A state fault gives
// ErrStateFault, for every bundle. The expiry check comes before the rollback
// check. An expired bundle gives ErrExpired, with one exception. At start, the
// bundle whose SHA-256 equals the version state is accepted after expires, and
// expired is true. A lower version gives ErrRollback. So do the same version
// with another SHA-256, and a reference bundle after a proprietary one. The
// same SHA-256 is accepted. Check writes nothing.
func (r *Rollback) Check(m *Manifest, sum [32]byte, class Class, now time.Time, start bool) (expired bool, err error) {
	st, err := readState(r.root)
	if err != nil {
		return false, err
	}
	if err := m.CheckExpiry(now); err != nil {
		if !start || st == nil || st.SHA256 != sum {
			return false, err
		}
		expired = true
	}
	return expired, st.allows(m.Version, sum, class)
}

// Record stores an accepted bundle as the version state. The loader calls it
// after the swap. A bundle with the SHA-256 of the state causes no write. A
// state fault, or a bundle that Check would refuse as a rollback, gives an
// error and no write.
func (r *Rollback) Record(m *Manifest, sum [32]byte, class Class) error {
	st, err := readState(r.root)
	if err != nil {
		return err
	}
	if err := st.allows(m.Version, sum, class); err != nil {
		return err
	}
	if st != nil && st.SHA256 == sum {
		return nil
	}
	return writeState(r.root, state{Version: m.Version, SHA256: sum, Class: class})
}

// Healthy is false after a state fault. It changes nothing on disk.
func (r *Rollback) Healthy() bool {
	_, err := readState(r.root)
	return err == nil
}

// allows applies the rollback rule. A nil state is a first start.
func (st *state) allows(version string, sum [32]byte, class Class) error {
	if st == nil || st.SHA256 == sum {
		return nil
	}
	if compareVersion(version, st.Version) <= 0 || (class == ClassReference && st.Class == ClassProprietary) {
		return ErrRollback
	}
	return nil
}

// compareVersion orders two valid versions: the date first, then N as a number.
func compareVersion(a, b string) int {
	if a[:10] != b[:10] {
		if a[:10] < b[:10] {
			return -1
		}
		return 1
	}
	na, _ := decimal(a[11:], 3)
	nb, _ := decimal(b[11:], 3)
	return na - nb
}
