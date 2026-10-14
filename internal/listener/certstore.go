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

	ruleCachePath = "cache directory path is not valid"
	ruleFileMode  = "file allows access for group or other"
)

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
	root *os.Root

	mu    sync.Mutex
	locks map[string]chan struct{} // one channel for each held lock; Unlock closes it
}

var _ certmagic.Storage = (*Store)(nil)

// The calls that make a write durable. The code calls them through these
// variables, so that a test can record their order. A test must restore the
// real functions.
var (
	syncFile    = (*os.File).Sync
	syncDirFile = (*os.File).Sync
	renameFile  = (*os.Root).Rename
)

// beforeCheck is a test hook. Open calls it for each part of the path, before
// the check of the part. It is nil in production.
var beforeCheck func(part string)

// betweenCheckAndOpen is a test hook. Open calls it for each part of the path,
// after the check of the part and before it opens the part. It is nil in
// production.
var betweenCheckAndOpen func(part string)

// betweenLstatAndOpen is a test hook. Load calls it after the Lstat of the key
// file and before it opens the file. It is nil in production.
var betweenLstatAndOpen func()

// Open opens the cache directory dir below the state directory. The path dir is
// relative to state. Open makes the directories of dir (mode 0700) if they do
// not exist. Each directory of dir must be a real directory, not a link, owned
// by the effective user, with no group or other permission bit and no setuid,
// setgid or sticky bit.
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
	s := &Store{root: root, locks: map[string]chan struct{}{}}
	if err := s.dirs(nil, false); err != nil {
		closeOpened()
		return nil, wrap(op, err)
	}
	for i := len(roots) - 1; i >= 0; i-- {
		if err := syncPath(roots[i], nil); err != nil {
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

// openPart checks the directory part in r, makes it with mode 0700 if it is
// missing, and opens it as a root. The opened directory must be the directory
// that the check passed.
func openPart(r *os.Root, part string) (*os.Root, error) {
	if beforeCheck != nil {
		beforeCheck(part)
	}
	fi, err := r.Lstat(part)
	if errors.Is(err, fs.ErrNotExist) {
		// Another Open can make the same directory first. Then the checks
		// below apply to the directory that it made.
		if err = r.Mkdir(part, dirMode); err == nil || errors.Is(err, fs.ErrExist) {
			fi, err = r.Lstat(part)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := dirRule(fi); err != nil {
		return nil, err
	}
	if betweenCheckAndOpen != nil {
		betweenCheckAndOpen(part)
	}
	next, err := r.OpenRoot(part)
	if err != nil {
		return nil, err
	}
	opened, err := next.Stat(".")
	if err != nil {
		next.Close()
		return nil, err
	}
	if !os.SameFile(fi, opened) {
		next.Close()
		return nil, fail("check", ruleLink)
	}
	return next, nil
}

// checkPath checks each directory on the path parts below r. When create is
// true, it makes a missing directory with mode 0700 first.
func checkPath(r *os.Root, parts []string, create bool) error {
	p := ""
	for _, part := range parts {
		p = path.Join(p, part)
		fi, err := r.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) && create {
			// Another Store can make the same directory first. Then the checks
			// below apply to the directory that it made.
			if err = r.Mkdir(p, dirMode); err == nil || errors.Is(err, fs.ErrExist) {
				fi, err = r.Lstat(p)
			}
		}
		if err != nil {
			return err
		}
		if err := dirRule(fi); err != nil {
			return err
		}
	}
	return nil
}

// dirRule returns the error for a directory that the store must not use.
func dirRule(fi fs.FileInfo) error {
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return fail("check", ruleLink)
	case !fi.IsDir():
		return fail("check", ruleNotDir)
	case !ownedByUs(fi):
		return fail("check", ruleOwner)
	case fi.Mode().Perm()&otherBit != 0:
		return fail("check", ruleMode)
	case fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0:
		return fail("check", ruleSpecial)
	}
	return nil
}

// dirs checks the cache directory and the directories of parts below it.
func (s *Store) dirs(parts []string, create bool) error {
	fi, err := s.root.Lstat(".")
	if err != nil {
		return err
	}
	if err := dirRule(fi); err != nil {
		return err
	}
	return checkPath(s.root, parts, create)
}

// syncPath calls fsync on the directory r and on each directory of parts below
// it, the deepest first. It opens each directory by its path below r. The path
// of r itself is ".", so Open calls syncPath with no parts to call fsync on a
// root that it opened.
func syncPath(r *os.Root, parts []string) error {
	for i := len(parts); i >= 0; i-- {
		f, err := r.OpenFile(rel(parts[:i]), readFlags, 0)
		if err != nil {
			return err
		}
		err = syncDirFile(f)
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
		// A file in place of a directory on the path: the key cannot exist.
		if e := new(Error); errors.As(err, &e) && e.Rule == ruleNotDir {
			return nil, nil, &Error{Op: op, Rule: ruleMissing, err: fs.ErrNotExist}
		}
		return nil, nil, wrap(op, err)
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
// rename, then fsync of the directories. It makes missing directories.
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
		return wrap(op, err)
	}
	_, err = f.Write(value)
	if err == nil {
		err = syncFile(f)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = renameFile(s.root, tmp, name)
	}
	if err != nil {
		s.root.Remove(tmp)
		return wrap(op, err)
	}
	return wrap(op, syncPath(s.root, dir))
}

// Load returns the value at key. A file above the size cap is an error. If a
// Store replaces the key file between the Lstat and the open, Load starts again,
// at most loadTries times in all. If the file still changes, Load gives the rule
// "file changed during the read". A replacement after the open does not matter:
// Load returns the value of the open file.
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
// open file is not the file that Lstat gave.
func (s *Store) load(ctx context.Context, op, key string) (b []byte, changed bool, err error) {
	fi, parts, err := s.info(ctx, op, key)
	if err != nil {
		return nil, false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fail(op, ruleType)
	}
	if fi.Size() > maxValue {
		return nil, false, fail(op, ruleSize)
	}
	if n, ok := linkCount(fi); !ok || n > 1 {
		return nil, false, fail(op, ruleLinks)
	}
	if betweenLstatAndOpen != nil {
		betweenLstatAndOpen()
	}
	f, err := s.root.OpenFile(rel(parts), readFlags, 0)
	if err != nil {
		return nil, false, wrap(op, err)
	}
	defer f.Close()
	// The open file must be the file that Lstat gave. If it is not, a Store has
	// replaced the key file between the two calls.
	of, err := f.Stat()
	if err != nil {
		return nil, false, wrap(op, err)
	}
	if !os.SameFile(fi, of) {
		return nil, true, nil
	}
	// The key file must have one link only, and only the owner of the store may
	// have access to it. A count of 0 is a file that a rename or a Delete removed
	// after the open. The open file still holds the whole value.
	if n, ok := linkCount(of); !ok || n > 1 {
		return nil, false, fail(op, ruleLinks)
	}
	if !ownedByUs(of) {
		return nil, false, fail(op, ruleFileOwner)
	}
	if of.Mode().Perm()&otherBit != 0 {
		return nil, false, fail(op, ruleFileMode)
	}
	b, err = io.ReadAll(io.LimitReader(f, maxValue+1))
	if err != nil {
		return nil, false, wrap(op, err)
	}
	if len(b) > maxValue {
		return nil, false, fail(op, ruleSize)
	}
	return b, false, nil
}

// Delete deletes key. A directory key deletes every key below it. A missing key
// is not an error, as the certmagic.Storage contract says. A link is an error.
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
	return wrap(op, syncPath(s.root, parts[:len(parts)-1]))
}

// Exists reports whether key is a file or a directory. A bad key and a link give
// false.
func (s *Store) Exists(ctx context.Context, key string) bool {
	_, _, err := s.info(ctx, "exists", key)
	return err == nil
}

// Stat returns the facts of key. A directory key has IsTerminal false.
func (s *Store) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	fi, _, err := s.info(ctx, "stat", key)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	return certmagic.KeyInfo{Key: key, Modified: fi.ModTime(), Size: fi.Size(), IsTerminal: !fi.IsDir()}, nil
}

// List returns the keys below prefix. With recursive false, it returns the
// direct children, directories too. With recursive true, it returns the keys of
// files below prefix. The prefix "" is the cache directory. A missing prefix
// gives fs.ErrNotExist. A prefix below a file gives the rule "path part is not a
// directory". List reads at most maxList names.
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
				if err := s.list(op, child, true, keys, n); err != nil {
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
