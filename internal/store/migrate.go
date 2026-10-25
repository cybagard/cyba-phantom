package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
)

// migrationFiles holds the migrations. The store reads no SQL from disk.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

// The fixed error classes of the migration step.
const (
	ruleVacuum  = "must use auto_vacuum incremental"
	ruleNames   = "migrations must have a four-digit number, in order from 0001 with no gap"
	ruleForeign = "has tables and no schema version"
	ruleNewer   = "has a schema version above the newest migration"
	ruleMigrate = "migration failed"
	ruleEvent   = "has no event table of this binary"
)

const (
	eventSQL     = "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'event'"
	schemaName   = "database schema"
	insertOrigin = "INSERT INTO meta (key, value) VALUES ('tlog_origin', ?)"
	setVersion   = "INSERT INTO meta (key, value) VALUES ('schema_version', ?) " +
		"ON CONFLICT (key) DO UPDATE SET value = excluded.value"
)

var migrationName = regexp.MustCompile(`^[0-9]{4}_[A-Za-z0-9_]+\.sql$`)

// Migrate brings the database that Open made to the newest embedded schema
// version. On a new database it also stores origin as meta.tlog_origin.
func Migrate(db *sql.DB, origin string) error {
	set, _ := fs.Sub(migrationFiles, "migrations") // fails only for an invalid name
	return migrate(db, set, origin)
}

// migrate does the work of Migrate for a set of migrations, in one transaction.
// A refused database is not changed. An error is an *Error with a fixed rule.
func migrate(db *sql.DB, set fs.FS, origin string) error {
	scripts, err := readScripts(set)
	if err != nil {
		return err
	}
	ctx := context.Background()
	var autoVacuum int
	if err := db.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&autoVacuum); err != nil {
		return fail(schemaName, ruleMigrate)
	}
	if autoVacuum != 2 {
		return fail(schemaName, ruleVacuum)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fail(schemaName, ruleMigrate)
	}
	defer tx.Rollback()
	have, fresh, rule := currentVersion(ctx, tx)
	switch {
	case rule != "":
		return fail(schemaName, rule)
	case have > len(scripts):
		return fail(schemaName, ruleNewer)
	case have == len(scripts):
		return checkEvent(ctx, tx, scripts)
	}
	for _, s := range scripts[have:] {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fail(schemaName, ruleMigrate)
		}
	}
	if fresh {
		if _, err := tx.ExecContext(ctx, insertOrigin, origin); err != nil {
			return fail(schemaName, ruleMigrate)
		}
	}
	if _, err := tx.ExecContext(ctx, setVersion, strconv.Itoa(len(scripts))); err != nil {
		return fail(schemaName, ruleMigrate)
	}
	if err := checkEvent(ctx, tx, scripts); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fail(schemaName, ruleMigrate)
	}
	return nil
}

// checkEvent compares the stored text of the event table with the text that
// the scripts store in a new database. It changes nothing in the database.
func checkEvent(ctx context.Context, tx *sql.Tx, scripts []string) error {
	want, err := newEventText(ctx, scripts)
	if err != nil {
		return fail(schemaName, ruleMigrate)
	}
	var got string
	switch err := tx.QueryRowContext(ctx, eventSQL).Scan(&got); {
	case err == sql.ErrNoRows:
		return fail(schemaName, ruleEvent)
	case err != nil:
		return fail(schemaName, ruleMigrate)
	}
	if got != want {
		return fail(schemaName, ruleEvent)
	}
	return nil
}

// newEventText applies the scripts to a new database in memory. It returns the
// text that this database stores for the event table, and closes the database.
func newEventText(ctx context.Context, scripts []string) (string, error) {
	mem, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return "", err
	}
	defer mem.Close()
	mem.SetMaxOpenConns(1)
	for _, s := range scripts {
		if _, err := mem.ExecContext(ctx, s); err != nil {
			return "", err
		}
	}
	var text string
	err = mem.QueryRowContext(ctx, eventSQL).Scan(&text)
	return text, err
}

// readScripts returns the SQL of the migrations. Name i (from 0) of the sorted
// list must be NNNN_name.sql with NNNN = i+1.
func readScripts(set fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(set, ".")
	if err != nil || len(entries) == 0 {
		return nil, fail(schemaName, ruleNames)
	}
	scripts := make([]string, len(entries))
	for i, e := range entries {
		name := e.Name()
		b, err := fs.ReadFile(set, name)
		if err != nil || e.IsDir() || !migrationName.MatchString(name) || name[:4] != fmt.Sprintf("%04d", i+1) {
			return nil, fail(schemaName, ruleNames)
		}
		scripts[i] = string(b)
	}
	return scripts, nil
}

// currentVersion reads the state of the database. If sqlite_master has no entry,
// the database is new (version 0). If it has entries but no meta table or no
// valid schema_version, the result is ruleForeign.
func currentVersion(ctx context.Context, tx *sql.Tx) (version int, fresh bool, rule string) {
	var entries, metas int
	err := tx.QueryRowContext(ctx, "SELECT count(*), count(CASE WHEN type = 'table' AND name = 'meta' THEN 1 END) FROM sqlite_master").
		Scan(&entries, &metas)
	switch {
	case err != nil:
		return 0, false, ruleMigrate
	case entries == 0:
		return 0, true, ""
	case metas == 0:
		return 0, false, ruleForeign
	}
	var v string
	switch err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = 'schema_version'").Scan(&v); {
	case err == sql.ErrNoRows:
		return 0, false, ruleForeign
	case err != nil:
		return 0, false, ruleMigrate
	}
	if version, err = strconv.Atoi(v); err != nil || version < 1 {
		return 0, false, ruleForeign
	}
	return version, false, ""
}
