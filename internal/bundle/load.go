package bundle

import (
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
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
	// seed is the token seed. fmt prints a pointer field as an address, not as
	// the bytes. It is nil only when a test turns the seed step off.
	seed *seedBytes
}

// Format prints the version and the SHA-256 of the bundle for each verb. It
// prints no seed. The value receiver covers Bundle and *Bundle.
func (b Bundle) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "bundle{version:%s sha256:%x}", b.manifest.Version, b.sum)
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

// File returns a copy of the bytes of an archive entry. It gives nil and false
// for each name below "secrets/", as the bundle owns the seed in memory.
func (b *Bundle) File(name string) ([]byte, bool) {
	if strings.HasPrefix(name, "secrets/") {
		return nil, false
	}
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
	// install opens the sealed seed of a proprietary bundle. It can be nil.
	install hpke.PrivateKey
	cur     atomic.Pointer[Bundle]

	// chain and chainErr hold the last chain check. loadMu guards them.
	chain    *chain
	chainErr error

	// now, decompress, template and seed are steps of the load. NewLoader sets
	// them, and a test can replace one. now and decompress must not be nil.
	// A nil template step keeps no template, and a nil seed step keeps no seed.
	// afterRead is a hook for tests.
	now        func() time.Time
	decompress func([]byte) (*Archive, error)
	afterRead  func()
	template   func(*Archive) (map[string]*template.Template, error)
	seed       func(*Archive, Class, *Manifest) (*seedBytes, error)
}

// NewLoader gives a Loader for the bundle at path below the state root. The
// path is in slash form, as "bundle/current.cbnd". The signature file has the
// same name with ".sig" in place of ".cbnd". The caller keeps state open.
// install is the install key, which opens the sealed seed of a proprietary
// bundle. With a nil install key, Load rejects each proprietary bundle.
func NewLoader(state *os.Root, path string, trust TrustSet, install hpke.PrivateKey) *Loader {
	l := &Loader{state: state, path: path, trust: trust, install: install, now: time.Now, decompress: ReadArchive, template: parseTemplates}
	l.seed = func(a *Archive, c Class, m *Manifest) (*seedBytes, error) { return openSeed(a, c, m, l.install) }
	return l
}

// Current returns the running bundle, or nil before the first accept.
func (l *Loader) Current() *Bundle { return l.cur.Load() }

// openDir opens the bundle directory of the path and gives the file name of the
// bundle in it. The caller calls closeDir to close the directory. The error is
// the error of the open, and Load turns it into ErrArchiveInvalid.
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
		return nil, "", nil, err
	}
	return d, base, func() { d.Close() }, nil
}

// check runs the chain check and keeps the result in memory.
func (l *Loader) check(dir *os.Root) error {
	c, err := readChain(dir, l.trust, l.decompress)
	if err != nil {
		l.chain, l.chainErr = nil, err
		return err
	}
	l.chain, l.chainErr = &c, nil
	return nil
}

// Healthy is false when the last chain check failed or the version state is a
// fault. It reads no record. A bundle directory that does not exist is healthy,
// as at a first start. Any other error at the open of the directory is not
// healthy. It changes nothing on disk.
func (l *Loader) Healthy() bool {
	loadMu.Lock()
	defer loadMu.Unlock()
	if l.chainErr != nil {
		return false
	}
	dir, _, closeDir, err := l.openDir()
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	defer closeDir()
	return NewRollback(dir).Healthy()
}

// Load reads the bundle and the signature file. It checks the bundle and makes
// it the running bundle (FR-02, SEC-23, SEC-24, SEC-25). The order is: chain
// check, read, SHA-256, signature, archive, manifest, key ID or rotation,
// engine, expiry and rollback, templates, seed.
// The seed is the plain file of a reference bundle. In a proprietary bundle it
// is the sealed file, opened with the install key. Another form, both, none,
// or a size other than 32 bytes gives ErrSeedInvalid. The seed stays in memory.
// After a swap, Load zeroes the seed of the replaced bundle. A candidate that
// fails a later step keeps no seed.
// A transition record is the archive and the signature file of an accepted
// transition bundle. The files are rotation-<n>.cbnd and rotation-<n>.sig in
// the bundle directory, n from 1 to 8. The chain check starts with the
// compiled trust set. For each record, it verifies a line of a key of the set
// before it decompresses the archive. Then it verifies the line of the new key.
// The new key replaces the old key and has its class. The check applies no
// expiry, engine, rollback, template or seed rule to a record. It runs when
// start is true or when no check ran before. It also runs after Load writes a
// record. Other loads use the trust set in memory and read no record. The next
// start finds a record that changes after a check. A failed check gives
// ErrStateFault, also when no bundle file exists.
// A transition bundle has a signature line of the old key and one of the new
// key. Load checks its rotation member where it checks the key ID of a normal
// bundle. An accepted new transition bundle writes its record before the
// version state. If the check of the records or the write of the version state
// fails, Load removes the record. It gives ErrStateFault. A failed check keeps
// its fault. A failed write of the version state restores the trust set.
// The first failed check gives the one error. A rejected bundle changes no file
// and not the running bundle. start is true for the load at start. An accepted
// bundle that expired then loads, and Expired is true.
// The errors are fixed errors of this package. None holds a path or a byte.
func (l *Loader) Load(start bool) (*Bundle, error) {
	loadMu.Lock()
	defer loadMu.Unlock()
	dir, base, closeDir, err := l.openDir()
	if err != nil {
		return nil, ErrArchiveInvalid
	}
	defer closeDir()
	name, ok := strings.CutSuffix(base, ".cbnd")
	if !ok || name == "" {
		return nil, ErrArchiveInvalid
	}
	if start || (l.chain == nil && l.chainErr == nil) {
		_ = l.check(dir)
	}
	if l.chainErr != nil {
		return nil, ErrStateFault
	}
	c := *l.chain
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
	ids, err := VerifySig(archive, sig, c.trust)
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
	newRotation := m.Rotation != nil && !slices.Contains(c.sums, sum)
	var class Class
	if newRotation {
		var ok bool
		if _, class, ok = c.rotate(m, archive, sig, ids); !ok || len(c.sums) >= maxRotations {
			return nil, ErrBadSig
		}
	} else {
		i := c.trust.index(m.KeyID)
		if i < 0 || !slices.Contains(ids, m.KeyID) {
			return nil, ErrBadSig
		}
		class = c.trust[i].Class
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
	var seed *seedBytes
	if l.seed != nil {
		if seed, err = l.seed(arch, class, m); err != nil {
			return nil, ErrSeedInvalid
		}
	}
	cand := &Bundle{sum: sum, manifest: *m, archive: arch, class: class, expired: expired, templates: set, seed: seed}
	// A candidate that fails a later step keeps no seed. Only an accepted
	// candidate does.
	reject := func(err error) (*Bundle, error) {
		if seed != nil {
			clear(*seed)
		}
		return nil, err
	}
	// The record and the version state come before Swap. A failed write leaves
	// the running bundle. A failed check or version-state write removes the
	// record. Only a failed version-state write restores the trust set.
	n := len(c.sums) + 1
	if newRotation {
		if err := writeRecord(dir, n, archive, sig); err != nil {
			return reject(ErrStateFault)
		}
		if l.check(dir) != nil {
			removeRecord(dir, n)
			return reject(ErrStateFault)
		}
	}
	if err := rb.Record(m, sum, class); err != nil {
		if newRotation {
			l.dropRecord(dir, n, &c)
		}
		return reject(fixed(err))
	}
	// Zero the seed of the replaced bundle, as far as Go memory allows.
	if old := l.cur.Swap(cand); old != nil && old.seed != nil {
		clear(*old.seed)
	}
	return cand, nil
}

// dropRecord removes record n and restores the chain prev in memory.
func (l *Loader) dropRecord(dir *os.Root, n int, prev *chain) {
	removeRecord(dir, n)
	l.chain, l.chainErr = prev, nil
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
