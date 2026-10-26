package bundle

import (
	"crypto/sha256"
	"errors"
	"html/template"
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
	// templates holds the parsed .tmpl files. No template runs at load.
	templates map[string]*template.Template
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

// Template returns a copy of the kept template with this archive name. A caller
// can run the copy and cannot change the kept template.
func (b *Bundle) Template(name string) (*template.Template, bool) {
	t, ok := b.templates[name]
	if !ok {
		return nil, false
	}
	c, err := t.Clone()
	return c, err == nil
}

// Loader loads the bundle at one path and holds the running bundle.
type Loader struct {
	state *os.Root
	path  string
	trust TrustSet
	cur   atomic.Pointer[Bundle]

	// now, decompress and template are steps of the load. NewLoader sets
	// them, and a test can replace one. now and decompress must not be nil.
	// A nil template step keeps no template. afterRead is a hook for tests.
	now        func() time.Time
	decompress func([]byte) (*Archive, error)
	afterRead  func()
	template   func(*Archive) (map[string]*template.Template, error)
}

// NewLoader gives a Loader for the bundle at path below the state root. The
// path is in slash form, as "bundle/current.cbnd". The signature file has the
// same name with ".sig" in place of ".cbnd". The caller keeps state open.
func NewLoader(state *os.Root, path string, trust TrustSet) *Loader {
	return &Loader{state: state, path: path, trust: trust, now: time.Now, decompress: ReadArchive, template: parseTemplates}
}

// Current returns the running bundle, or nil before the first accept.
func (l *Loader) Current() *Bundle { return l.cur.Load() }

// openDir opens the bundle directory of the path and gives the file name of the
// bundle in it. The caller calls the func to close the directory.
func (l *Loader) openDir() (dir *os.Root, base string, closeDir func(), err error) {
	dirName, base := ".", l.path
	if i := strings.LastIndexByte(l.path, '/'); i >= 0 {
		dirName, base = l.path[:i], l.path[i+1:]
	}
	if dirName == "." {
		return l.state, base, func() {}, nil
	}
	d, err := safefile.OpenRoot(l.state, dirName, dirRule)
	if err != nil {
		return nil, "", nil, ErrArchiveInvalid
	}
	return d, base, func() { d.Close() }, nil
}

// Healthy is false when the version state or a transition record is a fault.
// It is also false when the bundle directory does not open. It changes
// nothing on disk.
func (l *Loader) Healthy() bool {
	loadMu.Lock()
	defer loadMu.Unlock()
	dir, _, closeDir, err := l.openDir()
	if err != nil {
		return false
	}
	defer closeDir()
	_, _, err = readChain(dir, l.trust)
	return err == nil && NewRollback(dir).Healthy()
}

// Load reads the bundle and the signature file. It checks the bundle and makes
// it the running bundle (FR-02, SEC-23, SEC-24, SEC-25). The order is: read,
// transition records, SHA-256, signature, archive, manifest, key ID or
// rotation, engine, expiry and rollback, templates. The transition records
// in the bundle directory change the compiled trust set. Each record removes
// an old key and adds a new key with the class of the old key. A transition
// bundle has a signature line of the old key and one of the new key. Its
// rotation member is checked at the place of the key ID. An accepted new
// transition bundle writes its record before the version state. The first
// failed check gives the one error. A rejected bundle changes no file and not
// the running bundle. start is true for the load at start. An accepted bundle
// that expired then loads, and Expired is true.
// The errors are fixed errors of this package. None holds a path or a byte.
func (l *Loader) Load(start bool) (*Bundle, error) {
	loadMu.Lock()
	defer loadMu.Unlock()
	dir, base, closeDir, err := l.openDir()
	if err != nil {
		return nil, err
	}
	defer closeDir()
	name, ok := strings.CutSuffix(base, ".cbnd")
	if !ok || name == "" {
		return nil, ErrArchiveInvalid
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
	trust, sums, err := readChain(dir, l.trust)
	if err != nil {
		return nil, ErrStateFault
	}
	sum := sha256.Sum256(archive)
	ids, err := VerifySig(archive, sig, trust)
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
	// A transition bundle that a record already holds loads by the normal rule.
	newRotation := m.Rotation != nil && !slices.Contains(sums, sum)
	var class Class
	if newRotation {
		lines, _ := parseSig(sig)
		if _, ok := trust.rotated(m, sum, lines); !ok || len(sums) >= maxRotations {
			return nil, ErrBadSig
		}
		class = trust[trust.index(m.Rotation.From)].Class
	} else {
		i := trust.index(m.KeyID)
		if i < 0 || !slices.Contains(ids, m.KeyID) {
			return nil, ErrBadSig
		}
		class = trust[i].Class
	}
	if err := m.CheckEngine(); err != nil {
		return nil, ErrMinEngine
	}
	rb := NewRollback(dir)
	expired, err := rb.Check(m, sum, class, l.now(), start)
	if err != nil {
		return nil, fixed(err)
	}
	var set map[string]*template.Template
	if l.template != nil {
		if set, err = l.template(arch); err != nil {
			return nil, ErrTemplateParse
		}
	}
	cand := &Bundle{sum: sum, manifest: *m, archive: arch, class: class, expired: expired, templates: set}
	// The record and the version state come before Store. A failed write
	// leaves the running bundle.
	if newRotation {
		if err := writeRecord(dir, len(sums)+1, raw, sum, sig); err != nil {
			return nil, ErrStateFault
		}
	}
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
