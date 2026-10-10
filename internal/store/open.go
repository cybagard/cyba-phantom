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

// Error is a refused open. Name is the file, or the config key or directory
// that broke the rule; Rule is one of the fixed classes. The error never wraps
// another error, so no driver text can reach its string.
type Error struct{ Name, Rule string }

func (e *Error) Error() string { return "store: " + e.Name + " " + e.Rule }

func fail(name, rule string) error { return &Error{Name: name, Rule: rule} }

// Options holds the paths that the caller knows from the config.
type Options struct {
	// Reserved lists the directories that the database must not be in:
	// tlog.dir, acme.cache_dir, and the directory of bundle.path. Each entry is a
	// clean path relative to the state directory; "." is the state directory
	// itself. The directories keys and checkpoints and the names
	// checkpoint.state and writer.stop are fixed (ADR-020, ADR-022), so the
	// store adds them itself. Names match exactly, with the case of the path.
	// The store does not import internal/config.
	Reserved []string
}

var (
	fixedDirs  = []string{"keys", "checkpoints"}
	fixedNames = []string{"checkpoint.state", "writer.stop"}
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

// heap guards soft_heap_limit, which is a setting of the process.
var heap struct {
	sync.Mutex
	set bool
}

// Open opens the database at rel below root, the state directory that the
// caller opened one time. rel is the store.path relative to root.
//
// SQLite opens a file by path and not through root. So Open checks the path
// text, and then, through root, each parent directory and each of the database,
// -wal, -shm and -journal files, before SQLite opens anything. A new database
// file is made through root with mode 0600. After the open, the file that SQLite
// reports must be the checked path. A short window stays between the checks and
// the open of SQLite. Open does not stop a symlink that is put in place in this
// window. If the symlink changes the path, the database_list check finds it.
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
	absent, err := checkFiles(root, rel)
	if err != nil {
		return nil, err
	}
	if absent {
		f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				return nil, fail(rel, ruleChanged)
			}
			return nil, fail(rel, ruleCreate)
		}
		if f.Close() != nil {
			return nil, fail(rel, ruleCreate)
		}
	}
	// A failed open removes the file that this call made, so a refused open
	// leaves no new entry. If someone put a link there, Remove deletes the link
	// and not its target.
	refuse := func(rule string) error {
		if absent {
			root.Remove(rel)
		}
		return fail(rel, rule)
	}
	if afterChecks != nil {
		afterChecks()
	}
	path := filepath.Join(base, filepath.FromSlash(rel))
	db, err := sql.Open("sqlite", dsn(path, absent))
	if err != nil {
		return nil, refuse(ruleOpen)
	}
	db.SetMaxOpenConns(1)
	if rule := verify(db, path); rule != "" {
		db.Close()
		return nil, refuse(rule)
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
	for _, n := range fixedNames {
		if rel == n {
			return fail(key, ruleReserved)
		}
	}
	for _, d := range append(append([]string{}, fixedDirs...), opt.Reserved...) {
		if d == "." || rel == d || strings.HasPrefix(rel, d+"/") {
			return fail(key, ruleReserved)
		}
	}
	return nil
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

// checkParents checks that each directory above rel exists, is a directory,
// and is not a symlink. Lstat does not follow a link.
func checkParents(root *os.Root, rel string) error {
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		dir := strings.Join(parts[:i], "/")
		fi, err := root.Lstat(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist), err == nil && !fi.IsDir():
			return fail(dir, ruleParent)
		case err != nil:
			return fail(dir, ruleExamine)
		}
	}
	return nil
}

// checkFiles checks the database file and its -wal, -shm and -journal files.
// Each is absent or a safe file. It reports whether the database file is absent.
func checkFiles(root *os.Root, rel string) (absent bool, err error) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		name := rel + suffix
		fi, err := root.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			absent = absent || suffix == ""
			continue
		}
		if err != nil {
			return false, fail(name, ruleExamine)
		}
		if rule := checkFile(fi); rule != "" {
			return false, fail(name, rule)
		}
	}
	return absent, nil
}

// checkFile returns the failed rule for an existing file, or an empty string.
func checkFile(fi fs.FileInfo) string {
	if !fi.Mode().IsRegular() { // also a symlink: Lstat does not follow it
		return ruleType
	}
	nlink, uid, ok := fileFacts(fi)
	switch {
	case !ok:
		return ruleExamine // fail closed
	case nlink != 1:
		return ruleLinks
	case int64(uid) != euid():
		return ruleOwner
	case fi.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky)&^0o700 != 0:
		return ruleMode
	}
	return ""
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

// verify checks the first connection and sets the process settings. It returns
// the failed rule, or an empty string.
func verify(db *sql.DB, want string) string {
	ctx := context.Background()
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return ruleOpen
	}
	if mode != "wal" {
		return ruleSetting
	}
	file, rule := mainFile(ctx, db)
	switch {
	case rule != "":
		return rule
	case file != want:
		return ruleLocation
	}
	heap.Lock()
	defer heap.Unlock()
	if !heap.set {
		if _, err := db.ExecContext(ctx, "PRAGMA soft_heap_limit="+strconv.Itoa(softHeapLimit)); err != nil {
			return ruleSetting
		}
		heap.set = true
	}
	return ""
}

// mainFile returns the file that SQLite opened for the main database.
func mainFile(ctx context.Context, db *sql.DB) (string, string) {
	rows, err := db.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		return "", ruleOpen
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name string
		var file sql.NullString
		if rows.Scan(&seq, &name, &file) != nil {
			return "", ruleOpen
		}
		if name == "main" {
			return file.String, ""
		}
	}
	return "", ruleOpen
}
