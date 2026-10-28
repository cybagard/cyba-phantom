// The certificate cache (FR-01, SEC-21) is a certmagic.Storage that keeps
// its keys as files in one directory below the state directory. It does not use
// certmagic.FileStorage. Every access goes through an os.Root of the cache
// directory, and the store checks each directory on the path of a key.

package listener

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"

	"github.com/cybagard/cyba-phantom/internal/safefile"
)

const (
	maxValue  = 64 << 10 // the size cap of a stored value
	maxParts  = 8        // the most parts in a key
	maxPart   = 255      // the most bytes in a part of a key
	maxList   = 4096     // the most names that List reads
	loadTries = 3        // the most tries of Load when a Store replaces the key file
	dirMode   = 0o700
	fileMode  = 0o600
	otherBit  = 0o077 // group and other permission bits

	// tmpPrefix starts the name of a temporary file. No key part can start with it.
	tmpPrefix = ".tmp-"
)

// The rules in the text of an Error. The text is fixed. It never holds a key or
// the bytes of a file.
const (
	ruleKey     = "key is not valid"
	ruleSize    = "value is above the size cap"
	ruleLink    = "path part is a link"
	ruleType    = "file is not a regular file"
	ruleNotDir  = "path part is not a directory"
	ruleOwner   = "directory has another owner"
	ruleMode    = "directory allows access for group or other"
	ruleSpecial = "directory has a setuid, setgid or sticky bit"
	ruleMissing = "key is missing"
	ruleIO      = "file cannot be accessed below the cache directory"
	ruleMany    = "directory listing has too many names"
	ruleNotHeld = "lock is not held"
	ruleStopped = "operation was stopped by its context"

	ruleLinks     = "file has more than one link"
	ruleChanged   = "file changed during the read"
	ruleFileOwner = "file has another owner"

	ruleCachePath   = "cache directory path is not valid"
	ruleFileMode    = "file allows access for group or other"
	ruleFileSpecial = "file has a setuid, setgid or sticky bit"
)

// forbidden is the set of mode bits that a file or directory must not have.
const forbidden = otherBit | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

// The rules of the shared file checks. A key file has its size cap in
// keyNameRule, and keyOpenRule is a copy of it. A check of a name finds a link
// count above 1 with OneLink. The rule of the open file does not use OneLink.
// A count of 0 is a file that a rename or a Delete removed after the open.
// The shared rule refuses 0, so moreThanOneLink checks the open file.
var (
	cacheDirRule = safefile.Rule{Type: safefile.Dir, Owner: safefile.OwnerSelf, Forbid: forbidden}
	keyNameRule  = safefile.Rule{Type: safefile.Regular, Owner: safefile.OwnerSelf, Forbid: forbidden,
		OneLink: true, MaxSize: maxValue}
	keyOpenRule = func() safefile.Rule { r := keyNameRule; r.OneLink = false; return r }()
)

// texts holds the rule texts of a directory or of a key file. For a key file,
// links is true. Then a file with more than one link gives the text for links.
// This text comes before the text for the owner or the mode.
type texts struct {
	notRegular, owner, mode, special, changed string
	links                                     bool
}

var (
	dirTexts  = texts{ruleNotDir, ruleOwner, ruleMode, ruleSpecial, ruleLink, false}
	fileTexts = texts{ruleType, ruleFileOwner, ruleFileMode, ruleFileSpecial, ruleChanged, true}
)

// refusal gives the Error for err. A nil err gives nil. An err that is not a
// refusal of package safefile gives wrap(op, err). For a safefile refusal, the
// shared package decides the refusal. The listener chooses the text from t.
// For a key file with more than one link, an owner or mode refusal gives the
// link text. A mode refusal has two texts. The first path of paths
// below r with a forbidden bit chooses the text. The text comes from a second
// Lstat, so in a race it can describe another file. The refusal stays.
func refusal(op string, err error, t texts, r *os.Root, paths ...string) error {
	var se *safefile.Error
	if !errors.As(err, &se) {
		return wrap(op, err)
	}
	if t.links && (se.Reason == safefile.ErrOwner || se.Reason == safefile.ErrMode) {
		if fi, err := r.Lstat(paths[0]); err == nil && moreThanOneLink(fi) {
			return fail(op, ruleLinks)
		}
	}
	switch se.Reason {
	case safefile.ErrSymlink:
		return fail(op, ruleLink)
	case safefile.ErrType:
		return fail(op, t.notRegular)
	case safefile.ErrOwner:
		return fail(op, t.owner)
	case safefile.ErrMode:
		for _, p := range paths {
			if fi, err := r.Lstat(p); err == nil && fi.Mode()&forbidden != 0 {
				if fi.Mode().Perm()&otherBit == 0 {
					return fail(op, t.special)
				}
				break
			}
		}
		return fail(op, t.mode)
	case safefile.ErrLinks:
		return fail(op, ruleLinks)
	case safefile.ErrSize:
		return fail(op, ruleSize)
	case safefile.ErrChanged:
		return fail(op, t.changed)
	}
	if se.Cause == nil {
		return fail(op, ruleIO)
	}
	return wrap(op, se.Cause)
}

// dirError is wrap for an error of the directories on the path of a key. A file
// in place of a directory means that the key cannot exist.
func dirError(op string, err error) error {
	if e := new(Error); errors.As(err, &e) && e.Rule == ruleNotDir {
		return &Error{Op: op, Rule: ruleMissing, err: fs.ErrNotExist}
	}
	return wrap(op, err)
}

// Error names the operation that failed and the rule that failed. The text is
// fixed. It never holds a key, a path, or the bytes of a file.
type Error struct {
	Op   string
	Rule string
	err  error // fs.ErrNotExist for a missing key, ctx.Err() for an ended context, else nil
}

func (e *Error) Error() string { return "listener: cert cache: " + e.Op + ": " + e.Rule }

// Unwrap lets errors.Is(err, fs.ErrNotExist) find a missing key.
func (e *Error) Unwrap() error { return e.err }

func fail(op, rule string) error { return &Error{Op: op, Rule: rule} }

// wrap turns an error of the file system into an Error. It does not keep the
// text of err. An err that is an Error already gets the operation op.
func wrap(op string, err error) error {
	var e *Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &e):
		return &Error{Op: op, Rule: e.Rule, err: e.err}
	case errors.Is(err, fs.ErrNotExist):
		return &Error{Op: op, Rule: ruleMissing, err: fs.ErrNotExist}
	case isLoop(err):
		return fail(op, ruleLink)
	}
	return fail(op, ruleIO)
}

// stopped returns an Error if ctx has ended. The Error wraps ctx.Err(), so
// errors.Is finds context.Canceled and context.DeadlineExceeded.
func stopped(ctx context.Context, op string) error {
	if err := ctx.Err(); err != nil {
		return &Error{Op: op, Rule: ruleStopped, err: err}
	}
	return nil
}

// Store is a certmagic.Storage and certmagic.Locker. It is safe for use by many
// goroutines. The locks are in memory, so they work for one process only.
type Store struct {
	root  *os.Root
	hooks storeHooks

	mu    sync.Mutex
	locks map[string]chan struct{} // one channel for each held lock; Unlock closes it
}

var _ certmagic.Storage = (*Store)(nil)

// storeHooks are the calls that make a write durable. A Store calls them
// through its own value, so that a test can record their order on one Store
// with no effect on another Store. osHooks gives the real functions.
type storeHooks struct {
	syncFile    func(*os.File) error
	syncDirFile func(*os.File) error
	renameFile  func(*os.Root, string, string) error
}

// osHooks returns the real functions of the os package.
func osHooks() storeHooks {
	return storeHooks{
		syncFile:    (*os.File).Sync,
		syncDirFile: (*os.File).Sync,
		renameFile:  (*os.Root).Rename,
	}
}

// betweenSizeCheckAndRead is a test hook. Load calls it after the size checks of
// the open file and before it reads the file. It is nil in production. The
// shared package has no hook at this place.
var betweenSizeCheckAndRead func()

// beforeListChild is a test hook. List calls it with the key of a child
// directory, before it goes into the directory. It is nil in production.
var beforeListChild func(key string)

// Open opens the cache directory dir below the state directory. The path dir is
// relative to state. Open makes the directories of dir (mode 0700) if they do
// not exist. Each directory of dir must be a real directory, not a symbolic
// link. The effective user must own it. It must have no group or other
// permission bit and no setuid, setgid or sticky bit.
//
// Open removes the leftover temporary files of an earlier Store that stopped, for
// example in a crash. This is best effort. Open removes the names that start with
// tmpPrefix through the cache root, in the cache directory and in the key
// directories below it. A name that Open cannot remove stays. A directory that
// Open cannot open, or that fails the directory rules, stays and Open does not
// go into it. In each case Open goes on.
//
// One Open for each cache directory at a time is the rule. A second Open of the
// same cache during a Store removes the temporary file of that Store, and that
// Store then fails.
//
// Open walks dir one part at a time. It checks a part in the root of the part
// before it, and then opens the part as a root. The opened directory must be the
// directory that the check passed, else Open gives the link rule. The next part
// is checked in the root that Open just opened, so the walk does not resolve an
// earlier part again.
//
// Open keeps the root of each part open until the walk ends. Then it calls fsync
// on each of these roots, from the cache directory up to the state directory.
// For each root, it opens the "." entry of that root and calls fsync on it. It
// does not open a directory by a path from the state root. Open does this for
// every part, also when the part existed before, so the directories on the path
// are durable when Open returns.
func Open(state *os.Root, dir string) (*Store, error) {
	return openWith(state, dir, osHooks())
}

// openWith is Open with the durable-write calls of hooks. The Store keeps
// hooks, and Open itself calls them. A test sets them through openWith.
func openWith(state *os.Root, dir string, hooks storeHooks) (*Store, error) {
	const op = "open"
	if !fs.ValidPath(dir) || dir == "." {
		return nil, fail(op, ruleCachePath)
	}
	parts := strings.Split(dir, "/")
	roots := make([]*os.Root, 1, len(parts)+1) // roots[i] is the directory of parts[:i]
	roots[0] = state
	closeOpened := func() {
		for _, r := range roots[1:] {
			r.Close()
		}
	}
	for _, part := range parts {
		next, err := openPart(roots[len(roots)-1], part)
		if err != nil {
			closeOpened()
			return nil, wrap(op, err)
		}
		roots = append(roots, next)
	}
	root := roots[len(roots)-1]
	s := &Store{root: root, hooks: hooks, locks: map[string]chan struct{}{}}
	if err := s.dirs(nil, false); err != nil {
		closeOpened()
		return nil, wrap(op, err)
	}
	s.removeTemporary(nil)
	for i := len(roots) - 1; i >= 0; i-- {
		if err := hooks.syncPath(roots[i], nil); err != nil {
			closeOpened()
			return nil, wrap(op, err)
		}
	}
	for _, r := range roots[1 : len(roots)-1] {
		r.Close()
	}
	return s, nil
}

// Close closes the cache directory.
func (s *Store) Close() error { return wrap("close", s.root.Close()) }

// removeTemporary removes the names that start with tmpPrefix in the directory
// at the path parts. That directory is the cache directory or a directory below
// it. The walk is best effort and returns no error. A name that it cannot remove
// stays. The walk goes into a child that is a directory, not a symbolic link,
// down to maxParts levels. For a child, it does these steps in order. It makes
// an Lstat. It applies the directory rule by Lstat. It opens the child through
// the root. It compares the open directory with the Lstat. A child that fails a
// step stays and the walk skips it. The walk does not find a mode change of the
// same directory after the rule check. A ReadDir error ends the walk of that
// directory only. The walk reads a directory 256 names at a time and keeps no
// list of names. So the number of names does not matter. It calls fsync on a
// directory only if it removed a name in it, and it ignores an fsync error.
// The walk does not find a swap back around the rule check. Another directory
// is there for the check, and the first one comes back for the open.
func (s *Store) removeTemporary(parts []string) {
	li, err := s.root.Lstat(rel(parts))
	if err != nil || s.checkDirs(parts) != nil {
		return
	}
	d, err := s.root.OpenFile(rel(parts), readFlags, 0)
	if err != nil {
		return
	}
	defer d.Close()
	if fi, err := d.Stat(); err != nil || !os.SameFile(li, fi) {
		return
	}
	removed := false
	for {
		entries, err := d.ReadDir(256)
		for _, e := range entries {
			name := e.Name()
			child := slices.Concat(parts, []string{name})
			switch {
			case strings.HasPrefix(name, tmpPrefix):
				if s.root.Remove(rel(child)) == nil {
					removed = true
				}
			case e.IsDir() && len(child) <= maxParts:
				s.removeTemporary(child)
			}
		}
		if err != nil {
			break
		}
	}
	if removed {
		_ = s.hooks.syncDirFile(d)
	}
}

// openPart makes the directory part in r with mode 0700. This Mkdir runs first,
// at each call. Then safefile.OpenRoot checks the part and opens it. The
// opened directory must be the directory that the check passed.
func openPart(r *os.Root, part string) (*os.Root, error) {
	// Another Open can make the same directory first. Then the checks below
	// apply to the directory that it made.
	if err := r.Mkdir(part, dirMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	next, err := safefile.OpenRoot(r, part, cacheDirRule)
	return next, refusal("check", err, dirTexts, r, part)
}

// dirPaths gives "." and the path of each directory of parts below it.
func dirPaths(parts []string) []string {
	ps := []string{"."}
	for i := range parts {
		ps = append(ps, strings.Join(parts[:i+1], "/"))
	}
	return ps
}

// checkDirs checks the cache directory and the directories of parts below it.
func (s *Store) checkDirs(parts []string) error {
	// The last part is a placeholder. CheckParents does not check it.
	name := strings.Join(slices.Concat(parts, []string{"-"}), "/")
	err := safefile.CheckParents(s.root, name, cacheDirRule)
	return refusal("check", err, dirTexts, s.root, dirPaths(parts)...)
}

// dirs checks the directories of parts. When create is true, it also makes each
// missing one with mode 0700. It checks the parents of a directory first.
func (s *Store) dirs(parts []string, create bool) error {
	for i := 0; create && i < len(parts); i++ {
		if err := s.checkDirs(parts[:i]); err != nil {
			return err
		}
		// Another Store can make the same directory first.
		if err := s.root.Mkdir(rel(parts[:i+1]), dirMode); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return s.checkDirs(parts)
}

// parent opens the directory of the last part of parts, after the check of the
// cache directory. The caller closes the root that it gets. changed is true
// when another directory replaced a part after its check. A link to another
// directory in the cache also gives changed true.
func (s *Store) parent(parts []string) (r *os.Root, changed bool, err error) {
	if err := s.dirs(nil, false); err != nil {
		return nil, false, err
	}
	dir := parts[:len(parts)-1]
	if len(dir) == 0 {
		r, err = s.root.OpenRoot(".")
		return r, false, err
	}
	r, err = safefile.OpenRoot(s.root, strings.Join(dir, "/"), cacheDirRule)
	return r, errors.Is(err, safefile.ErrChanged), refusal("check", err, dirTexts, s.root, dirPaths(dir)...)
}

// syncPath calls fsync on the directory r and on each directory of parts below
// it, the deepest first. It opens each directory by its path below r. The path
// of r itself is ".". Open calls syncPath with no parts on each root of its walk.
// This includes roots[0], the state root of the caller.
func (h storeHooks) syncPath(r *os.Root, parts []string) error {
	for i := len(parts); i >= 0; i-- {
		f, err := r.OpenFile(rel(parts[:i]), readFlags, 0)
		if err != nil {
			return err
		}
		err = h.syncDirFile(f)
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// rel returns the path of parts below the cache directory.
func rel(parts []string) string { return path.Join(slices.Concat([]string{"."}, parts)...) }

// parseKey splits key into parts. Each part has only A-Z a-z 0-9 @ . _ -, is not
// empty, "." or "..", and has at most maxPart bytes. A part must not start with
// .tmp-. A key has at most maxParts parts. When empty is true, the key "" gives
// no parts.
func parseKey(op, key string, empty bool) ([]string, error) {
	if key == "" && empty {
		return nil, nil
	}
	parts := strings.Split(key, "/")
	if len(parts) > maxParts {
		return nil, fail(op, ruleKey)
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || len(p) > maxPart || strings.HasPrefix(p, tmpPrefix) {
			return nil, fail(op, ruleKey)
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
				c == '@' || c == '.' || c == '_' || c == '-') {
				return nil, fail(op, ruleKey)
			}
		}
	}
	return parts, nil
}

// info checks the directories on the path of key and returns the facts of the
// key, a file or a directory. It does not follow a link.
func (s *Store) info(ctx context.Context, op, key string) (fs.FileInfo, []string, error) {
	if err := stopped(ctx, op); err != nil {
		return nil, nil, err
	}
	parts, err := parseKey(op, key, false)
	if err != nil {
		return nil, nil, err
	}
	if err := s.dirs(parts[:len(parts)-1], false); err != nil {
		return nil, nil, dirError(op, err)
	}
	fi, err := s.root.Lstat(rel(parts))
	if err != nil {
		return nil, nil, wrap(op, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, fail(op, ruleLink)
	}
	if !fi.Mode().IsRegular() && !fi.IsDir() {
		return nil, nil, fail(op, ruleType)
	}
	return fi, parts, nil
}

// Store writes value at key: a temporary file in the directory of the key, fsync,
// rename, then fsync of the directories. It makes missing directories. A Delete
// can remove a directory of the key during the Store. Then the Store gives the
// rule for a file that cannot be accessed. It does not give the rule for a
// missing key.
func (s *Store) Store(ctx context.Context, key string, value []byte) error {
	const op = "store"
	if err := stopped(ctx, op); err != nil {
		return err
	}
	parts, err := parseKey(op, key, false)
	if err != nil {
		return err
	}
	if len(value) > maxValue {
		return fail(op, ruleSize)
	}
	dir := parts[:len(parts)-1]
	if err := s.dirs(dir, true); err != nil {
		return wrap(op, err)
	}
	name := rel(parts)
	if fi, err := s.root.Lstat(name); err == nil {
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fail(op, ruleLink)
		} else if !fi.Mode().IsRegular() {
			return fail(op, ruleType)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return wrap(op, err)
	}
	tmp := path.Join(rel(dir), tmpPrefix+rand.Text())
	f, err := s.root.OpenFile(tmp, createFlags, fileMode)
	if err != nil {
		return wrapAfterDirs(op, err)
	}
	_, err = f.Write(value)
	if err == nil {
		err = s.hooks.syncFile(f)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = s.hooks.renameFile(s.root, tmp, name)
	}
	if err != nil {
		s.root.Remove(tmp)
		return wrapAfterDirs(op, err)
	}
	return wrapAfterDirs(op, s.hooks.syncPath(s.root, dir))
}

// wrapAfterDirs is wrap for a call that runs after the check of the directories
// of a key. There, a missing name means that a Delete removed a directory at the
// same time. The key itself is not missing. So the error gets the rule for a file
// that cannot be accessed, and it does not wrap fs.ErrNotExist.
func wrapAfterDirs(op string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fail(op, ruleIO)
	}
	return wrap(op, err)
}

// Load returns the value at key. A file above the size cap is an error. If a
// key file or key directory changes after its check, Load starts again,
// at most loadTries times in all. If the file still changes, Load gives the rule
// "file changed during the read". A replacement after the open does not matter:
// Load returns the value of the open file.
// Load also starts again when safefile.Open refuses a file that has left the
// name.
//
// A write in place of the key file (the same file) can change its size during
// the Load. Then Load gives the rule "file changed during the read". When the
// file grows above 64 KiB, Load gives the rule "value is above the size cap".
// Load does not start again then. A write in place that keeps the size is not
// detected. This is a limit of Load.
func (s *Store) Load(ctx context.Context, key string) ([]byte, error) {
	const op = "load"
	for i := 0; i < loadTries; i++ {
		b, changed, err := s.load(ctx, op, key)
		if !changed {
			return b, err
		}
	}
	return nil, fail(op, ruleChanged)
}

// load makes one try to read the value at key. It returns changed true when the
// key file or a key directory changed after its check. A file that
// safefile.Open refuses and that has left the name gives it too.
func (s *Store) load(ctx context.Context, op, key string) (b []byte, changed bool, err error) {
	if err := stopped(ctx, op); err != nil {
		return nil, false, err
	}
	parts, err := parseKey(op, key, false)
	if err != nil {
		return nil, false, err
	}
	dir, dirChanged, err := s.parent(parts)
	if dirChanged {
		return nil, true, nil
	} else if err != nil {
		return nil, false, dirError(op, err)
	}
	defer dir.Close()
	name := parts[len(parts)-1]
	fi, err := safefile.Check(dir, name, keyNameRule)
	if err != nil {
		return nil, false, refusal(op, err, fileTexts, dir, name)
	}
	f, of, err := safefile.Open(dir, name, keyOpenRule)
	if errors.Is(err, safefile.ErrChanged) {
		return nil, true, nil
	} else if err != nil {
		if li, lerr := dir.Lstat(name); lerr != nil || !os.SameFile(fi, li) {
			return nil, true, nil
		}
		return nil, false, refusal(op, err, fileTexts, dir, name)
	}
	defer f.Close()
	// The open file must be the file that the Lstat gave. If it is not, a Store
	// has replaced the key file between the two calls.
	if !os.SameFile(fi, of) {
		return nil, true, nil
	}
	if moreThanOneLink(of) {
		return nil, false, fail(op, ruleLinks)
	}
	// A write in place can change the size after the open. The size of the open
	// file must be the size that Lstat gave, and the read must give that size.
	// This is not a new try: a new try would read the changed file with no error.
	if of.Size() != fi.Size() {
		return nil, false, fail(op, ruleChanged)
	}
	if betweenSizeCheckAndRead != nil {
		betweenSizeCheckAndRead()
	}
	b, err = safefile.ReadAll(f, of, keyOpenRule)
	return b, false, refusal(op, err, fileTexts, dir, name)
}

// Delete deletes key. A directory key deletes every key below it. A missing key
// is not an error, as the certmagic.Storage contract says. A symbolic link is
// an error. Delete removes a key file also when Load refuses it, so a bad name
// does not stay in the cache.
func (s *Store) Delete(ctx context.Context, key string) error {
	const op = "delete"
	_, parts, err := s.info(ctx, op, key)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := s.root.RemoveAll(rel(parts)); err != nil {
		return wrap(op, err)
	}
	return wrap(op, s.hooks.syncPath(s.root, parts[:len(parts)-1]))
}

// checkedInfo is info. For a key file it also applies the rules of Load: hard
// links, owner, mode, the setuid, setgid or sticky bit, and size.
func (s *Store) checkedInfo(ctx context.Context, op, key string) (fs.FileInfo, error) {
	fi, parts, err := s.info(ctx, op, key)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return fi, nil
	}
	dir, _, err := s.parent(parts)
	if err != nil {
		return nil, dirError(op, err)
	}
	defer dir.Close()
	name := parts[len(parts)-1]
	fi, err = safefile.Check(dir, name, keyNameRule)
	return fi, refusal(op, err, fileTexts, dir, name)
}

// Exists reports whether key is a file or a directory. A bad key, a symbolic
// link, and a key file that Load refuses give false.
func (s *Store) Exists(ctx context.Context, key string) bool {
	_, err := s.checkedInfo(ctx, "exists", key)
	return err == nil
}

// Stat returns the facts of key. A directory key has IsTerminal false. A key file
// that Load refuses gives an error. Load refuses a key file for its hard links,
// owner, mode, setuid, setgid or sticky bit, or size.
func (s *Store) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	fi, err := s.checkedInfo(ctx, "stat", key)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	return certmagic.KeyInfo{Key: key, Modified: fi.ModTime(), Size: fi.Size(), IsTerminal: !fi.IsDir()}, nil
}

// List returns the keys below prefix. With recursive false, it returns the
// direct children, directories too. With recursive true, it returns the keys of
// files below prefix. The prefix "" is the cache directory. A missing prefix
// gives fs.ErrNotExist. A prefix below a file gives the rule "path part is not a
// directory". List reads at most maxList names. A name that is not a valid key
// makes the whole List fail. So does a symbolic link, and so does a file that is
// not a regular file or a directory. This is on purpose. A Delete can remove a
// child directory during a recursive List. List then skips that directory.
func (s *Store) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	const op = "list"
	if err := stopped(ctx, op); err != nil {
		return nil, err
	}
	parts, err := parseKey(op, prefix, true)
	if err != nil {
		return nil, err
	}
	var keys []string
	n := 0
	if err := s.list(op, parts, recursive, &keys, &n); err != nil {
		return nil, err
	}
	return keys, nil
}

func (s *Store) list(op string, parts []string, recursive bool, keys *[]string, n *int) error {
	if err := s.dirs(parts, false); err != nil {
		return wrap(op, err)
	}
	d, err := s.root.OpenFile(rel(parts), readFlags, 0)
	if err != nil {
		return wrap(op, err)
	}
	defer d.Close()
	for {
		entries, err := d.ReadDir(256)
		for _, e := range entries {
			if *n++; *n > maxList {
				return fail(op, ruleMany)
			}
			name := e.Name()
			if strings.HasPrefix(name, tmpPrefix) {
				continue
			}
			child, perr := parseKey(op, path.Join(slices.Concat(parts, []string{name})...), false)
			switch {
			case perr != nil:
				return perr
			case e.Type()&fs.ModeSymlink != 0:
				return fail(op, ruleLink)
			case !e.IsDir() && !e.Type().IsRegular():
				return fail(op, ruleType)
			case e.IsDir() && recursive:
				if beforeListChild != nil {
					beforeListChild(strings.Join(child, "/"))
				}
				// A Delete can remove the child after the read of its parent. Then
				// the child is skipped, as if List did not read it.
				if err := s.list(op, child, true, keys, n); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return err
				}
			default:
				*keys = append(*keys, strings.Join(child, "/"))
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return wrap(op, err)
		}
	}
}

// Lock waits until it holds the lock name, or until ctx ends. The lock is in
// memory, so it works for one process only.
func (s *Store) Lock(ctx context.Context, name string) error {
	const op = "lock"
	for {
		if err := stopped(ctx, op); err != nil {
			return err
		}
		s.mu.Lock()
		held, ok := s.locks[name]
		if !ok {
			s.locks[name] = make(chan struct{})
		}
		s.mu.Unlock()
		if !ok {
			return nil
		}
		select {
		case <-held:
		case <-ctx.Done():
			return stopped(ctx, op)
		}
	}
}

// Unlock releases the lock name. A lock that is not held is an error.
func (s *Store) Unlock(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	held, ok := s.locks[name]
	if !ok {
		return fail("unlock", ruleNotHeld)
	}
	delete(s.locks, name)
	close(held)
	return nil
}
