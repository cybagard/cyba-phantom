package store

import (
	"context"
	"database/sql/driver"
	"io/fs"
	"os"
	"sync/atomic"

	"modernc.org/sqlite"
)

// onConnect is a test hook. Production code leaves it nil. A test sets it to
// count the connections that the pool opens.
var onConnect func()

// beforeDriverOpen is a test hook. Production code leaves it nil. A test sets
// it to change the file system between the checks and the open of the driver.
var beforeDriverOpen func()

// fileID is the device and the inode of a file.
type fileID struct{ dev, ino uint64 }

// connector opens each connection of the pool. Each new connection is checked.
// The checks run before the driver opens it, except for the first connection,
// which Open has just checked. They run again on the new connection, with the
// database_list check, before the pool uses it. So they also run after the
// pool drops a connection, for example after a cancelled query.
type connector struct {
	driver.Connector
	root *os.Root
	rel  string
	want string   // the absolute path that database_list must give
	id   fileID   // the identity of the database file that Open checked
	held *os.File // the database file, open for the life of the pool

	// checked is true until the first Connect: Open has just run the checks.
	checked atomic.Bool
}

func newConnector(root *os.Root, rel, path, dsn string, held *os.File, id fileID) (*connector, error) {
	base, err := sqlite.NewConnector(dsn)
	if err != nil {
		return nil, fail(rel, ruleOpen)
	}
	c := &connector{Connector: base, root: root, rel: rel, want: path, id: id, held: held}
	c.checked.Store(true)
	return c, nil
}

// Close closes the held descriptor. database/sql calls it from DB.Close, after
// it has closed the connections. The descriptor is closed only here: SQLite
// holds POSIX record locks on the file, and the close of any descriptor of the
// file drops all locks of the process on it.
func (c *connector) Close() error { return c.held.Close() }

// identityOf returns the device and the inode of a file from an Lstat result.
func identityOf(rel string, fi fs.FileInfo, err error) (fileID, error) {
	if err != nil {
		return fileID{}, fail(rel, ruleExamine)
	}
	dev, ino, ok := fileIdentity(fi)
	if !ok {
		return fileID{}, fail(rel, ruleExamine) // fail closed
	}
	return fileID{dev, ino}, nil
}

// check runs the parent checks and the file checks. The database file must
// exist: if it is gone, the driver would make a new file, so this is a refusal.
// The file must be the one that Open holds open. The path that SQLite opens must
// lead to the same file as the path through the root.
func (c *connector) check() error {
	if err := checkParents(c.root, c.rel); err != nil {
		return err
	}
	fi, err := checkFiles(c.root, c.rel)
	if err != nil {
		return err
	}
	if fi == nil {
		return fail(c.rel, ruleChanged)
	}
	id, err := identityOf(c.rel, fi, nil)
	if err != nil {
		return err
	}
	if id != c.id {
		return fail(c.rel, ruleChanged)
	}
	fi, err = os.Lstat(c.want)
	if pid, err := identityOf(c.rel, fi, err); err != nil || pid != id {
		return fail(c.rel, ruleLocation)
	}
	return nil
}

// Connect opens one connection. A failed check closes it and gives a fixed
// error: no driver text and no connection string.
func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	if onConnect != nil {
		onConnect()
	}
	if !c.checked.Swap(false) {
		if err := c.check(); err != nil {
			return nil, err
		}
	}
	if beforeDriverOpen != nil {
		beforeDriverOpen()
	}
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, fail(c.rel, ruleOpen)
	}
	err = c.location(ctx, conn)
	if err == nil {
		err = c.check()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// location checks, on the new connection itself, that the file which SQLite
// opened for the main database is the checked path.
func (c *connector) location(ctx context.Context, conn driver.Conn) error {
	q, ok := conn.(driver.QueryerContext)
	if !ok {
		return fail(c.rel, ruleOpen)
	}
	rows, err := q.QueryContext(ctx, "PRAGMA database_list", nil)
	if err != nil {
		return fail(c.rel, ruleOpen)
	}
	defer rows.Close()
	dest := make([]driver.Value, len(rows.Columns()))
	for rows.Next(dest) == nil && len(dest) >= 3 {
		if name, _ := dest[1].(string); name == "main" {
			if file, _ := dest[2].(string); file != c.want {
				return fail(c.rel, ruleLocation)
			}
			return nil
		}
	}
	return fail(c.rel, ruleOpen)
}
