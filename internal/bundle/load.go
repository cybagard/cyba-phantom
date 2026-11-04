package bundle

import (
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/token"
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

// loadSeq counts the bundles that a loader swapped in, in this process. It is
// guarded by loadMu, so all loaders share it.
var loadSeq uint64

// swapGap is the least time from a swap to the next load that is not a start
// load. seedDelay is the time from a swap until the loader zeroes the replaced
// seed. A request ends within 20 s, so 30 s is longer than a request that
// holds the replaced bundle (ADR-037).
const (
	swapGap   = 30 * time.Second
	seedDelay = 30 * time.Second
)

// Bundle is an accepted bundle. It does not change after the loader makes it.
type Bundle struct {
	sum      [32]byte
	manifest Manifest
	archive  *Archive
	// sig holds the bytes of the signature file that verified.
	sig     []byte
	class   Class
	expired bool
	// templates holds the parsed .tmpl files. No template runs at load.
	templates map[string]*template.Template
	// routes holds the route map of each vhost, by host name.
	routes map[string]RouteMap
	// traps holds the traps of traps/traps.json. It is nil without that file.
	traps []Trap
	// seed is the token seed, behind a pointer to a seedRef. A Bundle value
	// in an unexported struct field then prints no seed byte. It is nil only
	// when a test turns the seed step off.
	seed *seedRef
	// tokens is the key set of the token seed. It is nil without a seed or
	// without a trap. It holds no seed byte.
	tokens *token.KeySet
	// seq is the load sequence. The loader sets it at the swap, before any
	// reader can see the bundle. It is 0 for a bundle never swapped in.
	seq uint64
}

// Sequence gives the load sequence of the bundle. A loader gives each bundle
// that it swaps in a number higher than all earlier numbers in the process.
// This holds for a load of the same archive and for a second loader.
func (b *Bundle) Sequence() uint64 { return b.seq }

// Format prints the version and the SHA-256 of the bundle. It prints no seed.
// The value receiver covers Bundle and *Bundle. fmt does not call Format under
// %w or for a Bundle value in an unexported struct field. In that field, the
// *seedRef keeps the seed out of the print.
func (b Bundle) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "bundle{version:%s sha256:%x}", b.manifest.Version, b.sum)
}

// SHA256 returns the SHA-256 of the archive bytes. It is the identity of the
// bundle.
func (b *Bundle) SHA256() [32]byte { return b.sum }

// Signature returns a copy of the bytes of the signature file that verified for
// this bundle. A start, signal, reload, fetch or roll-forward load sets it.
func (b *Bundle) Signature() []byte { return slices.Clone(b.sig) }

// Manifest returns a copy of the manifest.
func (b *Bundle) Manifest() Manifest {
	m := b.manifest
	if m.Rotation != nil {
		r := *m.Rotation
		m.Rotation = &r
	}
	return m
}

// Routes returns a copy of the route map of a vhost. A caller cannot change the
// kept map.
func (b *Bundle) Routes(host string) (RouteMap, bool) {
	rm, ok := b.routes[host]
	rm.Routes = slices.Clone(rm.Routes)
	for i := range rm.Routes {
		rm.Routes[i].Headers = slices.Clone(rm.Routes[i].Headers)
		if cb := rm.Routes[i].Callback; cb != nil {
			c := *cb
			rm.Routes[i].Callback = &c
		}
	}
	if rm.Beacon != nil {
		bc := *rm.Beacon
		rm.Beacon = &bc
	}
	return rm, ok
}

// Traps returns a copy of the traps. A caller cannot change the kept list.
func (b *Bundle) Traps() []Trap {
	out := slices.Clone(b.traps)
	for i := range out {
		out[i].parts = slices.Clone(out[i].parts)
	}
	return out
}

// Tokens returns the key set of the bundle. It is nil when the seed step is off
// (a test seam) or the bundle has no trap. No call gives the seed or the key.
func (b *Bundle) Tokens() *token.KeySet { return b.tokens }

// Vhosts returns the sorted names of the vhosts that have a route map.
func (b *Bundle) Vhosts() []string { return slices.Sorted(maps.Keys(b.routes)) }

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

// ErrNoTemplate is the error of Execute for a name that is not a kept template.
var ErrNoTemplate = errors.New("bundle: no template")

// Execute runs the kept template with this archive name and writes the page to
// w. It makes no copy of the template. html/template permits parallel calls on
// one template. The first call escapes the tree. After it, a Clone fails.
// An unknown name gives ErrNoTemplate and writes no byte.
func (b *Bundle) Execute(w io.Writer, name string, data Page) error {
	t, ok := b.templates[name]
	if !ok {
		return ErrNoTemplate
	}
	return t.Execute(w, data)
}

// Asset is a view of the bytes of an archive entry. It has no method that
// changes or returns the bytes. The only access is WriteTo, which hands the
// kept bytes to a writer.
type Asset struct{ data []byte }

// Len returns the number of bytes of the entry.
func (a Asset) Len() int { return len(a.data) }

// WriteTo writes the bytes of the entry to w. It makes no copy: it passes the
// kept bytes themselves to w.Write. The io.Writer contract says that Write
// must not change these bytes or store them. A writer that breaks the contract
// can change the kept bytes.
func (a Asset) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(a.data)
	return int64(n), err
}

// Asset returns a view of the bytes of an archive entry below "vhosts/" whose
// name does not end in ".tmpl". It checks only that prefix and that suffix. It
// does not check which vhost the name is below. So it also gives a file of any
// vhost and the routes.json of each vhost. The asset rule of a route map
// accepts only a file below the directory of its own vhost. A caller must take
// asset names from the route map of the vhost. Asset gives false for each
// other name. A call copies no byte.
func (b *Bundle) Asset(name string) (Asset, bool) {
	if !strings.HasPrefix(name, templateDir) || strings.HasSuffix(name, templateSuffix) {
		return Asset{}, false
	}
	data, ok := b.archive.File(name)
	return Asset{data}, ok
}

// Loader loads the bundle at one path and holds the running bundle.
type Loader struct {
	state *os.Root
	path  string
	trust TrustSet
	// install opens the sealed seed of a proprietary bundle. It can be nil.
	install hpke.PrivateKey
	cur     atomic.Pointer[Bundle]
	// ring holds the key sets of the running bundle and of the bundle that it
	// replaced. A new Loader has an empty ring.
	ring *token.Ring

	// chain and chainErr hold the last chain check. loadMu guards them.
	chain    *chain
	chainErr error

	// swapAt is the time of the last swap, or zero before the first swap.
	// swapMu guards it, so a load can read it while it waits without loadMu.
	swapMu sync.Mutex
	swapAt time.Time

	// now, decompress, template, seed and keySet are steps of the load.
	// NewLoader sets them, and a test can replace one. now, decompress and
	// keySet must not be nil. A nil template step keeps no template, and a nil
	// seed step keeps no seed. afterRead is a hook for tests. sleep waits for
	// the swap gap, and afterFunc runs the delayed zero of a seed. They are
	// seams for tests and must not be nil.
	now        func() time.Time
	sleep      func(time.Duration)
	afterFunc  func(time.Duration, func())
	decompress func([]byte) (*Archive, error)
	afterRead  func()
	template   func(*Archive) (map[string]*template.Template, error)
	seed       func(*Archive, Class, *Manifest) (*seedBytes, error)
	keySet     func([]byte, [32]byte, []string, bool) (*token.KeySet, error)

	// events and log are set by SetEvents. loadMu guards them. Each can be nil.
	events *event.Queue
	log    *slog.Logger
}

// NewLoader gives a Loader for the bundle at path below the state root. The
// path is in slash form, as "bundle/current.cbnd". The signature file has the
// same name with ".sig" in place of ".cbnd". The caller keeps state open.
// install is the install key, which opens the sealed seed of a proprietary
// bundle. With a nil install key, Load rejects each proprietary bundle.
func NewLoader(state *os.Root, path string, trust TrustSet, install hpke.PrivateKey) *Loader {
	l := &Loader{state: state, path: path, trust: trust, install: install, now: time.Now, sleep: time.Sleep, decompress: ReadArchive, template: parseTemplates, keySet: token.NewKeySet}
	l.afterFunc = func(d time.Duration, f func()) { time.AfterFunc(d, f) }
	// The ring reads l.now at each call, so a test can replace the clock.
	l.ring = token.NewRing(func() time.Time { return l.now() })
	l.seed = func(a *Archive, c Class, m *Manifest) (*seedBytes, error) { return openSeed(a, c, m, l.install) }
	return l
}

// Current returns the running bundle, or nil before the first accept.
func (l *Loader) Current() *Bundle { return l.cur.Load() }

// Ring returns the token ring of the loader. At each accepted load of another
// bundle, the key set of the new bundle becomes current. The replaced key set
// stays until the next such load or the 25 h end of the ring. A load of the
// same bundle does not change the ring. A bundle with no key set puts no key
// set in the current place.
func (l *Loader) Ring() *token.Ring { return l.ring }

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
// engine, expiry and rollback. Then: trap file, templates, route maps, seed.
// With a seed and a trap, Load makes the key set of the tokens. It uses the
// seed, the SHA-256 and the trap ids in file order. A failure of the key set
// step gives ErrSeedInvalid. The key set is nil when the seed step is off (a
// test seam) or the bundle has no trap.
// A trap file of a bad form gives ErrContentInvalid. A bundle with no trap file
// has no trap. A route header slot then gives ErrContentInvalid.
// A host name that is the second name part of a file below vhosts/ is a vhost.
// Each vhost has a routes.json file. A file directly in vhosts/, a bad vhost
// name or a bad route map gives ErrContentInvalid.
// The seed is the plain file of a reference bundle. In a proprietary bundle it
// is the sealed file, opened with the install key. Another form, both, none,
// or a size other than 32 bytes gives ErrSeedInvalid. The seed stays in memory.
// After a swap, a timer zeroes the seed of the replaced bundle 30 s later. A
// request that holds the replaced bundle then reads no zero seed. A candidate
// that fails a later step keeps no seed. A load with a source other than
// SourceStart starts at least 30 s after the last swap. It waits without
// loadMu. A start load does not wait. A rejection starts no wait.
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
// A path with the archive name of a record gives ErrArchiveInvalid. The name is
// "rotation-<n>.cbnd" with n from 1 to 9. The ASCII case does not count. Load
// checks this before the chain check and before any read.
// A start load that gives bad_sig tries once more with <name>.sig.tmp. The
// file must be there and pass the file rule. The try has each check. The start
// load then removes each install temporary file. LoadFetched has the install.
// The errors are fixed errors of this package. None holds a path or a byte.
func (l *Loader) Load(start bool) (*Bundle, error) {
	if start {
		return l.LoadFrom(SourceStart)
	}
	return l.LoadFrom(SourceReload)
}

// load is Load without the lock and without the event. loadMu is held. It sets
// rd when it has read the bundle file and the signature file.
func (l *Loader) load(start bool, rd *digest) (*Bundle, error) {
	dir, name, c, closeDir, err := l.prepare(start)
	if err != nil {
		return nil, err
	}
	defer closeDir()
	if start {
		defer removeInstallTemps(dir, name)
	}
	archive, err := safefile.ReadFile(dir, name+".cbnd", fileRule(MaxBundleBytes))
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
	b, err := l.loadBytes(dir, c, archive, sig, start, rd, nil)
	if start && errors.Is(err, ErrBadSig) {
		return l.rollForward(dir, name, c, archive, rd, err)
	}
	return b, err
}

// prepare runs the checks that come before any read of a bundle file. They are
// the directory part, the state-file name and the chain check. It gives the
// open directory, the name of the bundle without ".cbnd", and the chain. The
// caller calls closeDir. On an error, prepare has closed the directory.
func (l *Loader) prepare(start bool) (dir *os.Root, name string, c chain, closeDir func(), err error) {
	dir, base, closeDir, err := l.openDir()
	if err != nil {
		return nil, "", chain{}, nil, ErrArchiveInvalid
	}
	name, ok := strings.CutSuffix(base, ".cbnd")
	if !ok || name == "" || isRecordName(base) {
		closeDir()
		return nil, "", chain{}, nil, ErrArchiveInvalid
	}
	if start || (l.chain == nil && l.chainErr == nil) {
		_ = l.check(dir)
	}
	if l.chainErr != nil {
		closeDir()
		return nil, "", chain{}, nil, ErrStateFault
	}
	return dir, name, *l.chain, closeDir, nil
}

// loadBytes runs each check on the archive and signature bytes, and then the
// record, the version state and the swap. install, when it is not nil, runs
// before the record of a transition bundle. When it fails, loadBytes gives
// ErrInstallFault. loadMu is held. It sets rd.
func (l *Loader) loadBytes(dir *os.Root, c chain, archive, sig []byte, start bool, rd *digest, install func() error) (*Bundle, error) {
	sum := sha256.Sum256(archive)
	*rd = digest{sum, true}
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
	// The form check of the trap file runs before the template caps and parses.
	traps, err := readTraps(arch)
	if err != nil {
		return nil, err
	}
	var set map[string]*template.Template
	if l.template != nil {
		if set, err = l.template(arch); err != nil {
			return nil, ErrTemplateParse
		}
	}
	if err := compileTraps(traps, newTemplate); err != nil {
		return nil, err
	}
	if err := checkExec(set, traps); err != nil {
		return nil, err
	}
	// The route step runs also when the template step is nil. The set is then
	// empty.
	routes, err := parseRoutes(arch, set, traps)
	if err != nil {
		return nil, err
	}
	var seed *seedBytes
	if l.seed != nil {
		if seed, err = l.seed(arch, class, m); err != nil {
			return nil, ErrSeedInvalid
		}
	}
	// A candidate that fails a later step keeps no seed. Only an accepted
	// candidate does.
	reject := func(err error) (*Bundle, error) {
		if seed != nil {
			clear(*seed)
		}
		return nil, err
	}
	var ref *seedRef
	var tokens *token.KeySet
	if seed != nil {
		ref = &seedRef{seed}
		// A bundle with no trap has no key set. It has no trap to mint for.
		if len(traps) > 0 {
			ids := make([]string, len(traps))
			for i, t := range traps {
				ids[i] = t.ID
			}
			if tokens, err = l.keySet(*seed, sum, ids, class == ClassReference); err != nil {
				return reject(ErrSeedInvalid)
			}
		}
	}
	cand := &Bundle{sum: sum, manifest: *m, archive: arch, sig: slices.Clone(sig), class: class, expired: expired, templates: set, routes: routes, traps: traps, seed: ref, tokens: tokens}
	// The install of a fetched pair comes first. Then the record, the version
	// state and Swap. A failed write leaves the running bundle. A failed
	// install leaves the files that the next start can load. A failed check or
	// version-state write removes the record. Only a failed version-state write
	// restores the trust set.
	if install != nil {
		if err := install(); err != nil {
			return reject(ErrInstallFault)
		}
	}
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
	// A load of the same bundle keeps its key set and the ring. A swap would
	// drop the key set of the bundle that the running bundle replaced. For
	// another bundle, the ring changes before the loader replaces the running
	// bundle.
	if run := l.cur.Load(); run != nil && run.sum == cand.sum {
		cand.tokens = run.tokens
	} else {
		l.ring.Swap(cand.tokens)
	}
	// The stamp is under loadMu, so numbers are unique and rise in swap order.
	loadSeq++
	cand.seq = loadSeq
	// A request can still hold the replaced bundle. A timer zeroes its seed
	// later, as far as Go memory allows.
	if old := l.cur.Swap(cand); old != nil && old.seed != nil {
		seed := old.seed.p
		l.afterFunc(seedDelay, func() { clear(*seed) })
	}
	l.swapMu.Lock()
	l.swapAt = l.now()
	l.swapMu.Unlock()
	return cand, nil
}

// gapLeft gives the time to wait before a load that is not a start load can
// start. It is zero or less when the gap has passed or no swap has happened.
func (l *Loader) gapLeft() time.Duration {
	l.swapMu.Lock()
	at := l.swapAt
	l.swapMu.Unlock()
	if at.IsZero() {
		return 0
	}
	return at.Add(swapGap).Sub(l.now())
}

// lock takes loadMu for a load of this source. A source other than SourceStart
// first waits for the swap gap, without loadMu. It checks the gap again after
// it takes loadMu, because another load can swap while this one waits. The
// caller unlocks loadMu.
func (l *Loader) lock(src Source) {
	for {
		if src != SourceStart {
			if d := l.gapLeft(); d > 0 {
				l.sleep(d)
				continue
			}
		}
		loadMu.Lock()
		if src == SourceStart || l.gapLeft() <= 0 {
			return
		}
		loadMu.Unlock()
	}
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
