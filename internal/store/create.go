package store

import (
	"errors"
	"io/fs"
	"os"

	"github.com/cybagard/cyba-phantom/internal/safefile"
)

// tempSuffix is added to the last part of store.path. A new database has this
// name until the rename. A killed start can leave the file.
const tempSuffix = ".new"

// suffixes are the names of a database file and the files that SQLite makes
// from it.
var suffixes = []string{"", "-wal", "-shm", "-journal"}

// syncFile calls fsync on a file and on a directory. A test replaces it to see
// the order of the steps, or to make a sync fail.
var syncFile = (*os.File).Sync

// beforeRename is a test hook. Production code leaves it nil. A test sets it to
// change the file system, or to stop the process, before Open renames the file.
var beforeRename func()

// removeIfMade removes each of names in dir that is the file with the identity
// made. An entry that is another file stays.
func removeIfMade(dir *os.Root, made fs.FileInfo, names ...string) {
	for _, n := range names {
		if cur, err := dir.Lstat(n); err == nil && os.SameFile(cur, made) {
			_ = dir.Remove(n)
		}
	}
}

// renamed replaces the name from with the name to in an error. So an error of
// the temporary file names the file of store.path. An error of a side file of
// the temporary file keeps its name.
func renamed(err error, from, to string) error {
	var e *Error
	if errors.As(err, &e) && e.Name == from {
		return fail(to, e.Rule)
	}
	return err
}

// newDatabase checks the files that a killed start left under the temporary
// name. If one fails fileRule, it refuses and removes nothing. If the database
// file is absent, it refuses when a -wal, -shm or -journal file is at the real
// name. Then it removes the leftover files. If the database file is absent, it
// makes the database under the temporary name. It does the first write and
// closes the pool. It syncs the file, renames it to the real name, and syncs
// dir. All of this is before Open opens the database for use.
//
// It returns the identity of the file that it made, and a read-only descriptor
// of that file. The caller closes the descriptor. Both are nil when the
// database file was there before.
//
// A file that is at the real name before the call is never renamed or removed.
// A file that appears there before the rename is kept, and the call fails. The
// Lstat of the real name and the rename are two calls. If someone puts a file
// at the real name in that window, the rename replaces it. Only the sensor user
// can write in the checked directory. A failure removes the file that this call
// made, but only when the entry is that file. If someone replaces the entry
// after the Lstat and before the Remove, removeIfMade removes the new file.
// The descriptor holds the inode of the made file from the read-only reopen.
// The inode is not held from the close of the first pool to that reopen.
func newDatabase(root, dir *os.Root, rel, last string, opt Options) (fs.FileInfo, *os.File, error) {
	tmp, tmpLast := rel+tempSuffix, last+tempSuffix
	if _, err := checkFiles(dir, tmpLast, tmp); err != nil {
		return nil, nil, err
	}
	_, err := dir.Lstat(last)
	absent := errors.Is(err, fs.ErrNotExist)
	if err != nil && !absent {
		return nil, nil, fail(rel, ruleExamine)
	}
	if absent {
		for _, s := range suffixes[1:] {
			if _, err := dir.Lstat(last + s); !errors.Is(err, fs.ErrNotExist) {
				if err != nil {
					return nil, nil, fail(rel+s, ruleExamine)
				}
				return nil, nil, fail(rel+s, ruleOrphan)
			}
		}
	}
	for _, s := range suffixes {
		if err := dir.Remove(tmpLast + s); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fail(tmp+s, ruleRemove)
		}
	}
	if !absent {
		return nil, nil, nil // open checks the file
	}
	var made fs.FileInfo
	db, err := open(root, tmp, opt, &made, true, nil)
	if err != nil {
		return nil, nil, renamed(err, tmp, rel)
	}
	var f *os.File
	// drop removes the file that this call made, at either name. Then it
	// closes the descriptor.
	drop := func(rule string) (fs.FileInfo, *os.File, error) {
		removeIfMade(dir, made, tmpLast, last)
		if f != nil {
			f.Close()
		}
		return nil, nil, fail(rel, rule)
	}
	// The close of the last connection writes the WAL into the database file
	// and removes the -wal and -shm files. SQLite finds them by the file name.
	if db.Close() != nil {
		return drop(ruleOpen)
	}
	f, fi, err := safefile.Open(dir, tmpLast, fileRule)
	if err != nil {
		return drop(ruleChanged)
	}
	if !os.SameFile(made, fi) {
		return drop(ruleChanged)
	}
	if syncFile(f) != nil {
		return drop(ruleCreate)
	}
	if beforeRename != nil {
		beforeRename()
	}
	if _, err := dir.Lstat(last); err == nil {
		return drop(ruleChanged)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return drop(ruleExamine)
	}
	if dir.Rename(tmpLast, last) != nil {
		return drop(ruleCreate)
	}
	d, err := dir.Open(".")
	if err == nil {
		err = syncFile(d)
		d.Close()
	}
	if err != nil {
		return drop(ruleCreate)
	}
	return made, f, nil
}
