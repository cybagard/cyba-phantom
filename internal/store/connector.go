package store

import (
	"context"
	"database/sql/driver"
	"os"
	"sync/atomic"

	"modernc.org/sqlite"
)

// onConnect is a test hook. Production code leaves it nil. A test sets it to
// count the connections that the pool opens.
var onConnect func()

// connector opens each connection of the pool. It checks the parent directories
// and the files before the driver opens a connection, and it checks them again,
// with the database_list check, on the new connection before the pool uses it.
// So the checks run again for each connection that the pool makes after it drops
// one, for example after a cancelled query.
type connector struct {
	driver.Connector
	root *os.Root
	rel  string
	want string // the absolute path that database_list must give

	// checked is true until the first Connect: Open has just run the checks.
	checked atomic.Bool
}

func newConnector(root *os.Root, rel, path, dsn string) (*connector, error) {
	base, err := sqlite.NewConnector(dsn)
	if err != nil {
		return nil, fail(rel, ruleOpen)
	}
	c := &connector{Connector: base, root: root, rel: rel, want: path}
	c.checked.Store(true)
	return c, nil
}

// check runs the parent checks and the file checks. The database file must
// exist: if it is gone, the driver would make a new file, so this is a refusal.
func (c *connector) check() error {
	if err := checkParents(c.root, c.rel); err != nil {
		return err
	}
	absent, err := checkFiles(c.root, c.rel)
	if err == nil && absent {
		err = fail(c.rel, ruleChanged)
	}
	return err
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
