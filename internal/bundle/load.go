package bundle

import (
	"crypto/sha256"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybagard/cyba-phantom/internal/safefile"
)

// The caps of the bundle file and of the signature file, in bytes (SEC-23).
const (
	MaxBundleBytes = 8 << 20
	MaxSigBytes    = 1 << 10
)

// dirRule is the rule of the bundle directory. It refuses a symlink and adds
// no owner rule and no mode rule.
var dirRule = safefile.Rule{Type: safefile.Dir, Owner: safefile.OwnerAny}

// fileRule is the rule of a bundle file or a signature file. The file has no
// group write bit, no other write bit, and no other read bit.
func fileRule(max int64) safefile.Rule {
	return safefile.Rule{Type: safefile.Regular, Owner: safefile.OwnerSelfOrRoot, Forbid: 0o026, OneLink: true, MaxSize: max}
}

// loadMu is the one lock of all loads. Check and Record of Rollback lose
// updates when they run at the same time. So two loads never run together.
var loadMu sync.Mutex

// Bundle is an accepted bundle. It does not change after the loader makes it.
type Bundle struct {
	sum      [32]byte
	manifest Manifest
	archive  *Archive
	class    Class
	expired  bool
}

// SHA256 returns the SHA-256 of the archive bytes. It is the identity of the
// bundle.
func (b *Bundle) SHA256() [32]byte { return b.sum }

// Manifest returns a copy of the manifest.
func (b *Bundle) Manifest() Manifest {
	m := b.manifest
	if m.Rotation != nil {
		r := *m.Rotation
		m.Rotation = &r
	}
	return m
}

// Class returns the class of the key that signed the bundle.
func (b *Bundle) Class() Class { return b.class }

// Expired is true for a bundle that loaded at start after its expiry time.
func (b *Bundle) Expired() bool { return b.expired }

// File returns a copy of the bytes of an archive entry.
func (b *Bundle) File(name string) ([]byte, bool) {
	data, ok := b.archive.File(name)
	return slices.Clone(data), ok
}

// Loader loads the bundle at one path and holds the running bundle.
type Loader struct {
	state *os.Root
	path  string
	trust TrustSet
	cur   atomic.Pointer[Bundle]

	// Hooks for tests. A nil hook is off. now and decompress must not be nil.
	now        func() time.Time
	decompress func([]byte) (*Archive, error)
	afterRead  func()
	template   func(*Archive) error
}

// NewLoader gives a Loader for the bundle at path below the state root. The
// path is in slash form, as "bundle/current.cbnd". The signature file has the
// same name with ".sig" in place of ".cbnd". The caller keeps state open.
func NewLoader(state *os.Root, path string, trust TrustSet) *Loader {
	return &Loader{state: state, path: path, trust: trust, now: time.Now, decompress: ReadArchive}
}

// Current returns the running bundle, or nil before the first accept.
func (l *Loader) Current() *Bundle { return l.cur.Load() }

// Load reads the bundle and the signature file. It checks the bundle and makes
// it the running bundle (FR-02, SEC-23, SEC-24, SEC-25). The order is: read,
// SHA-256, signature, archive, manifest, key ID, engine, expiry and rollback,
// templates. The first failed check gives the one error. A rejected bundle
// changes no file and not the running bundle. start is true for the load at
// start: an accepted bundle that expired then loads, and Expired is true.
// The errors are fixed errors of this package. None holds a path or a byte.
func (l *Loader) Load(start bool) (*Bundle, error) {
	loadMu.Lock()
	defer loadMu.Unlock()
	dirName, base := ".", l.path
	if i := strings.LastIndexByte(l.path, '/'); i >= 0 {
		dirName, base = l.path[:i], l.path[i+1:]
	}
	name, ok := strings.CutSuffix(base, ".cbnd")
	if !ok || name == "" {
		return nil, ErrArchiveInvalid
	}
	dir := l.state
	if dirName != "." {
		d, err := safefile.OpenRoot(l.state, dirName, dirRule)
		if err != nil {
			return nil, ErrArchiveInvalid
		}
		defer d.Close()
		dir = d
	}
	archive, err := safefile.ReadFile(dir, base, fileRule(MaxBundleBytes))
	var sig []byte
	if err == nil {
		sig, err = safefile.ReadFile(dir, name+".sig", fileRule(MaxSigBytes))
	}
	if err != nil {
		return nil, ErrArchiveInvalid
	}
	if l.afterRead != nil {
		l.afterRead()
	}
	sum := sha256.Sum256(archive)
	ids, err := VerifySig(archive, sig, l.trust)
	if err != nil {
		return nil, ErrBadSig
	}
	arch, err := l.decompress(archive)
	if err != nil {
		return nil, ErrArchiveInvalid
	}
	raw, _ := arch.File("manifest.json")
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, ErrManifestInvalid
	}
	i := slices.IndexFunc(l.trust, func(k TrustKey) bool { return k.KeyID == m.KeyID })
	if i < 0 || !slices.Contains(ids, m.KeyID) {
		return nil, ErrBadSig
	}
	// A transition bundle is refused until rotation support exists.
	if m.Rotation != nil {
		return nil, ErrBadSig
	}
	class := l.trust[i].Class
	if err := m.CheckEngine(); err != nil {
		return nil, ErrMinEngine
	}
	rb := NewRollback(dir)
	expired, err := rb.Check(m, sum, class, l.now(), start)
	if err != nil {
		return nil, fixed(err)
	}
	if l.template != nil && l.template(arch) != nil {
		return nil, ErrTemplateParse
	}
	cand := &Bundle{sum: sum, manifest: *m, archive: arch, class: class, expired: expired}
	// Record comes before Store: a failed write leaves the running bundle.
	if err := rb.Record(m, sum, class); err != nil {
		return nil, fixed(err)
	}
	l.cur.Store(cand)
	return cand, nil
}

// fixed maps an error of Rollback to a fixed error of this package. The error
// of a failed write can hold a path, so it becomes ErrStateFault.
func fixed(err error) error {
	for _, e := range []error{ErrExpired, ErrRollback} {
		if errors.Is(err, e) {
			return e
		}
	}
	return ErrStateFault
}
