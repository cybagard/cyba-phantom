// Package store holds the event store of the sensor: a SQLite database below
// the state directory (SEC-20, ADR-022). This file has the open step only.
package store

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	_ "modernc.org/sqlite" // the CGO-free driver
)

// softHeapLimit is the SQLite heap limit for the process: 16 MiB (C2, ADR-022).
const softHeapLimit = 16777216

// The fixed error classes. An Error holds one of them and never the text of the
// driver, a row value, or the connection string.
const (
	rulePathForm   = "must be a clean relative path with no empty, . or .. part"
	ruleChars      = "may have only the characters A-Z a-z 0-9 . _ - in each part"
	ruleReserved   = "must not be a reserved state path"
	ruleStateChars = "must not have a question mark or a hash sign in its path"
	ruleParent     = "parent must be a real directory and not a symlink"
	ruleType       = "must be a regular file and not a symlink"
	ruleLinks      = "must have one hard link"
	ruleOwner      = "must be owned by the user that runs the sensor"
	ruleMode       = "must have no group or other permission bits"
	ruleExamine    = "cannot be examined"
	ruleCreate     = "cannot be made"
	ruleChanged    = "changed between the check and the open"
	ruleOpen       = "cannot be opened as a database"
	ruleSetting    = "does not use the required connection settings"
	ruleLocation   = "opened at a path other than the checked path"
)

// Error is a refused store operation. Name is the file, the config key, or the
// directory. It can also be a store part such as the writer, "reserved
// directory" or "database schema". Rule is one of the fixed classes. The error
// never wraps another error, so no driver text can reach its string.
type Error struct{ Name, Rule string }

func (e *Error) Error() string { return "store: " + e.Name + " " + e.Rule }

func fail(name, rule string) error { return &Error{Name: name, Rule: rule} }

// Options holds the paths that the caller knows from the config.
type Options struct {
	// Reserved lists the directories that the database must not be in:
	// tlog.dir, acme.cache_dir, and the directory of bundle.path. Each entry is a
	// clean path relative to the state directory; "." is the state directory
	// itself. The directories keys and checkpoints and the names
	// checkpoint.state, checkpoint.state.tmp and writer.stop are fixed (ADR-020,
	// ADR-022), so the store adds them itself. The match folds A-Z to a-z in
	// the path and in each reserved path. No other byte changes. The store does
	// not import internal/config.
	Reserved []string
}

var (
	fixedDirs  = []string{"keys", "checkpoints"}
	fixedNames = []string{"checkpoint.state", "checkpoint.state.tmp", "writer.stop"}
)

// pragmas are the 03 pragmas. Each is in the connection string, so SQLite
// applies it to each new connection.
var pragmas = []string{
	"journal_mode(WAL)", "synchronous(NORMAL)", "cache_size(-8000)",
	"temp_store(MEMORY)", "mmap_size(0)", "foreign_keys(OFF)",
	"busy_timeout(5000)", "journal_size_limit(67108864)", "trusted_schema(OFF)",
}

// afterChecks is a test hook. Production code leaves it nil. A test sets it to
// change the file system between the file checks and the open of SQLite.
var afterChecks func()

// afterVerify is a test hook. Production code leaves it nil. A test sets it to
// change the file system between the open of SQLite and the second checks.
var afterVerify func()

// onHeld is a test hook. Production code leaves it nil. A test sets it to get
// the descriptor that Open holds open for the pool.
var onHeld func(*os.File)

// beforeRefuse is a test hook. Production code leaves it nil. A test sets it to
// change the file system before refuse looks at the file at rel.
var beforeRefuse func()

// heap guards soft_heap_limit, which is a setting of the process.
var heap struct {
	sync.Mutex
	set bool
}

// Open opens the database at rel below root, the state directory that the
// caller opened one time. rel is the store.path relative to root.
//
// SQLite opens a file by path and not through root. So Open checks these:
//   - Before the open: the path text, the directories, and the database, -wal,
//     -shm and -journal files. A directory is real, owned by the sensor user,
//     with no group or other bits. A file is absent or safe. A new database
//     file is made through root with mode 0600.
//   - After the open, and on each new connection: database_list, the
//     directories, the four files, and the identity of the database file. The
//     file is the same file as before, and the path that SQLite opens leads to it.
//     Open keeps the database file open until the pool closes, so that it stays
//     the same file.
//
// A failed check gives a fixed error and closes the database or connection.
// A change that is made and undone between two checks is not found.
//
// The caller must end each use of the pool before it calls DB.Close: each
// query, transaction and Rows. DB.Close closes only the free connections. Then
// it closes the held descriptor, and this drops the locks of the process.
//
// The returned pool has one connection. An error is an *Error with a fixed rule.
func Open(root *os.Root, rel string, opt Options) (*sql.DB, error) {
	if err := checkPath(rel, opt); err != nil {
		return nil, err
	}
	base, err := stateBase(root)
	if err != nil {
		return nil, err
	}
	if err := checkParents(root, rel); err != nil {
		return nil, err
	}
	checked, err := checkFiles(root, rel)
	if err != nil {
		return nil, err
	}
	absent := checked == nil
	// The descriptor stays open until the pool closes. While it is open, the
	// inode of the file cannot be given to a new file.
	var held *os.File
	if absent {
		held, err = root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				return nil, fail(rel, ruleChanged)
			}
			return nil, fail(rel, ruleCreate)
		}
	} else if held, err = openHeld(root, rel); err != nil {
		return nil, fail(rel, ruleChanged)
	}
	if onHeld != nil {
		onHeld(held)
	}
	fi, statErr := held.Stat()
	// Each failed step calls refuse before it closes anything. While held is
	// open, the inode of the new file is not free, so os.SameFile cannot match
	// another file. Refuse removes the entry at rel only when it is the
	// database file that this call made. If the Stat of the new file failed,
	// refuse removes nothing.
	refuse := func(err error) error {
		if beforeRefuse != nil {
			beforeRefuse()
		}
		if absent && statErr == nil {
			if cur, lerr := root.Lstat(rel); lerr == nil && os.SameFile(cur, fi) {
				_ = root.Remove(rel)
			}
		}
		return err
	}
	id, err := identityOf(rel, fi, statErr)
	if err == nil && !absent {
		if cid, _ := identityOf(rel, checked, nil); cid != id {
			err = fail(rel, ruleChanged)
		}
	}
	if err != nil {
		err = refuse(err)
		held.Close()
		return nil, err
	}
	if afterChecks != nil {
		afterChecks()
	}
	path := filepath.Join(base, filepath.FromSlash(rel))
	conn, err := newConnector(root, rel, path, dsn(path, absent), held, id)
	if err != nil {
		err = refuse(err)
		held.Close()
		return nil, err
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(1)
	if err := verify(db, rel); err != nil {
		err = refuse(err)
		db.Close()
		return nil, err
	}
	if afterVerify != nil {
		afterVerify()
	}
	if err := conn.check(); err != nil {
		err = refuse(err)
		db.Close()
		return nil, err
	}
	return db, nil
}

// checkPath applies the path rules to the text of rel. The error names the
// config key and never the value, which can have any character.
func checkPath(rel string, opt Options) error {
	const key = "store.path"
	if !fs.ValidPath(rel) || rel == "." {
		return fail(key, rulePathForm)
	}
	for i := 0; i < len(rel); i++ {
		c := rel[i]
		if c != '/' && c != '.' && c != '_' && c != '-' &&
			(c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return fail(key, ruleChars)
		}
	}
	for _, d := range opt.Reserved {
		if !fs.ValidPath(d) {
			return fail("reserved directory", rulePathForm)
		}
	}
	low := foldASCII(rel)
	for _, n := range fixedNames {
		if low == n {
			return fail(key, ruleReserved)
		}
	}
	for _, d := range append(append([]string{}, fixedDirs...), opt.Reserved...) {
		d = foldASCII(d)
		if d == "." || low == d || strings.HasPrefix(low, d+"/") {
			return fail(key, ruleReserved)
		}
	}
	return nil
}

// foldASCII changes the letters A-Z in s to a-z. No other byte changes, so a
// non-ASCII letter never matches an ASCII letter.
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// stateBase returns the absolute state directory with its symlinks resolved.
// SQLite resolves the symlinks of the whole path, so the expected path must
// have the same form. Only this prefix is resolved: the parts below it are
// checked to be real directories.
func stateBase(root *os.Root) (string, error) {
	const name = "state directory"
	base, err := filepath.Abs(root.Name())
	if err == nil {
		base, err = filepath.EvalSymlinks(base)
	}
	if err != nil {
		return "", fail(name, ruleExamine)
	}
	if strings.ContainsAny(base, "?#") { // the driver reads ? as the start of parameters
		return "", fail(name, ruleStateChars)
	}
	return base, nil
}

// checkParents checks the state directory and each directory above rel. Each
// must exist and be a real directory: Lstat does not follow a link. The owner
// must be the user that runs the sensor. The mode must have no group or other
// permission bits and no setuid, setgid or sticky bit.
func checkParents(root *os.Root, rel string) error {
	parts := strings.Split(rel, "/")
	for i := 0; i < len(parts); i++ {
		dir, name := ".", "state directory"
		if i > 0 {
			dir = strings.Join(parts[:i], "/")
			name = dir
		}
		fi, err := root.Lstat(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist), err == nil && !fi.IsDir():
			return fail(name, ruleParent)
		case err != nil:
			return fail(name, ruleExamine)
		}
		if err := checkOwnerMode(name, fi); err != nil {
			return err
		}
	}
	return nil
}

// checkFiles checks the database file and its -wal, -shm and -journal files.
// Each is absent or a safe file. It returns the FileInfo of the database file
// that it checked, or nil when that file is absent.
func checkFiles(root *os.Root, rel string) (db fs.FileInfo, err error) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		name := rel + suffix
		fi, err := root.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fail(name, ruleExamine)
		}
		if err := checkFile(name, fi); err != nil {
			return nil, err
		}
		if suffix == "" {
			db = fi
		}
	}
	return db, nil
}

// checkFile returns the error for an existing file that is not safe, or nil.
func checkFile(name string, fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() { // also a symlink: Lstat does not follow it
		return fail(name, ruleType)
	}
	if nlink, _, ok := fileFacts(fi); ok && nlink != 1 {
		return fail(name, ruleLinks)
	}
	return checkOwnerMode(name, fi)
}

// checkOwnerMode checks the owner and the mode of a file or a directory. It
// returns nil when both are safe, and an error when they are not.
func checkOwnerMode(name string, fi fs.FileInfo) error {
	_, uid, ok := fileFacts(fi)
	switch {
	case !ok:
		return fail(name, ruleExamine) // fail closed
	case int64(uid) != euid():
		return fail(name, ruleOwner)
	case fi.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky)&^0o700 != 0:
		return fail(name, ruleMode)
	}
	return nil
}

// dsn makes the connection string from fixed text and the checked path. The
// path has no ? or #: checkPath and stateBase refuse them. For a file that Open
// made, auto_vacuum comes first: journal_mode(WAL) writes page 1 when the
// connection opens, and after that auto_vacuum cannot change.
func dsn(path string, created bool) string {
	var b strings.Builder
	b.WriteString(path)
	b.WriteString("?_defensive=1&_txlock=immediate")
	if created {
		b.WriteString("&_pragma=auto_vacuum(INCREMENTAL)")
	}
	for _, p := range pragmas {
		b.WriteString("&_pragma=")
		b.WriteString(p)
	}
	return b.String()
}

// verify reads back the journal mode of the first connection and sets the
// process settings. The connector checks the location. It returns the *Error of
// the connector as it is, or a fixed error for rel.
func verify(db *sql.DB, rel string) error {
	ctx := context.Background()
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		var e *Error // the connector refused the first connection
		if errors.As(err, &e) {
			return e
		}
		return fail(rel, ruleOpen)
	}
	if mode != "wal" {
		return fail(rel, ruleSetting)
	}
	heap.Lock()
	defer heap.Unlock()
	if !heap.set {
		if _, err := db.ExecContext(ctx, "PRAGMA soft_heap_limit="+strconv.Itoa(softHeapLimit)); err != nil {
			return fail(rel, ruleSetting)
		}
		heap.set = true
	}
	return nil
}
