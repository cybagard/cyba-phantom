package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/tlog"
	"github.com/cybagard/cyba-phantom/internal/verify"
)

// stateDir is the state directory. The config loader keeps each state path below it.
const stateDir = "/var/lib/phantom"

// vkeyName is the public key file that LoadOrCreateSigner keeps below the state directory.
const vkeyName = "keys/checkpoint.vkey"

// startParams holds the values of the store start. Each path is relative to Root, in slash form.
type startParams struct {
	Root, StorePath, TlogDir, Origin string
	Reserved                         []string
	Interval                         time.Duration
	BodyPrefix                       bool
}

// startDeps holds the parts that a test replaces to count the opens or to see the sink.
type startDeps struct {
	openLog         func(*os.Root, string) (*tlog.Log, error)
	openStore       func(*os.Root, string, store.Options) (*sql.DB, error)
	migrate         func(*sql.DB, string) error
	newCheckpointer func(*tlog.Log, note.Signer, note.Verifier, tlog.NoteSink, *os.Root, string, time.Duration, *slog.Logger) (*tlog.Checkpointer, error)
	runCheckpointer func(context.Context, *tlog.Checkpointer)
}

var realDeps = startDeps{tlog.OpenLog, store.Open, store.Migrate, tlog.NewCheckpointer,
	func(ctx context.Context, c *tlog.Checkpointer) { c.Run(ctx) }}

// paramsOf reads the values of the store start from the loaded config.
func paramsOf(cfg *config.Config) startParams {
	rel := func(abs string) string {
		r, err := filepath.Rel(stateDir, abs)
		if err != nil {
			return abs // The loader keeps the path below the state directory, so this is not reached.
		}
		return filepath.ToSlash(r)
	}
	str := func(k string) string { v, _ := cfg.Get(k); return v.Str }
	iv, _ := cfg.Get("tlog.checkpoint_interval")
	bp, _ := cfg.Get("privacy.store_body_prefix")
	return startParams{
		Root: stateDir, StorePath: rel(str("store.path")), TlogDir: rel(str("tlog.dir")), Origin: str("tlog.origin"),
		Reserved: []string{rel(str("tlog.dir")), rel(str("acme.cache_dir")), rel(filepath.Dir(str("bundle.path")))},
		Interval: iv.Dur, BodyPrefix: bp.Bool,
	}
}

// started is the store part of the process: the writer, or the drain when the store did not open, and the checkpointer.
type started struct {
	q      *event.Queue
	writer *store.Writer // nil when the store did not open
	drops  store.DropCount
	root   *os.Root
	log    *tlog.Log
	db     *sql.DB
	cancel context.CancelFunc // stops the checkpointer
	ckpt   sync.WaitGroup
	wg     sync.WaitGroup // the writer, or the drain
}

// Healthy tells if the store part works: false with no writer, else the health of the writer.
func (s *started) Healthy() bool { return s.writer != nil && s.writer.Healthy() }

// start opens the log and the store one time each and starts the writer or the drain, and the checkpointer.
// A part that does not open or start leaves the process running: it is logged, and the store part is not healthy.
// There is no reopen, retry or restart. q and c are the queue and its counters.
func start(p startParams, q *event.Queue, c *event.Counters, d startDeps, lg *slog.Logger) *started {
	s := &started{q: q, cancel: func() {}}
	var err error
	if s.root, err = os.OpenRoot(p.Root); err != nil {
		lg.Error("state directory does not open", "error", err)
	} else if s.log, err = d.openLog(s.root, p.TlogDir); err != nil {
		lg.Error("log does not open", "error", err)
		s.log = nil
	} else if s.db, err = s.openDB(p, d); err != nil {
		lg.Error("store does not open", "error", err)
	}
	if s.db != nil {
		s.writer = store.NewWriter(s.db, q, s.log, c, p.BodyPrefix, lg, store.Recovery{State: s.root, Origin: p.Origin, Log: s.log})
		s.wg.Go(func() { s.writer.Run(context.Background()) })
	} else {
		s.wg.Go(func() { store.Discard(context.Background(), q, &s.drops) })
	}
	if s.log != nil {
		if err := s.startCheckpointer(p, d, lg); err != nil {
			lg.Error("checkpointer does not start", "error", err)
		}
	}
	return s
}

// openDB opens the store and brings its schema to the newest version. A refusal closes the database.
func (s *started) openDB(p startParams, d startDeps) (*sql.DB, error) {
	db, err := d.openStore(s.root, p.StorePath, store.Options{Reserved: p.Reserved})
	if err != nil {
		return nil, err
	}
	if err := d.migrate(db, p.Origin); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// startCheckpointer gives the checkpointer the checkpoint row sink over the spool. The sink has the writer, or nil.
func (s *started) startCheckpointer(p startParams, d startDeps, lg *slog.Logger) error {
	_, exists, err := tlog.SignerState(s.root)
	if err != nil {
		return err
	}
	size, _ := s.log.Head()
	signer, err := tlog.LoadOrCreateSigner(s.root, lg, p.Origin, exists, uint64(size))
	if err != nil {
		return err
	}
	f, err := s.root.Open(vkeyName)
	if err != nil {
		return err
	}
	defer f.Close()
	v, err := verify.ReadKey(f)
	if err != nil {
		return err
	}
	spool, err := tlog.OpenSpool(s.root, lg, p.Origin, v, nil)
	if err != nil {
		return err
	}
	cp, err := d.newCheckpointer(s.log, signer, v, store.NewSink(s.writer, spool, p.Origin, v), s.root, p.Origin, p.Interval, lg)
	if err != nil {
		return err
	}
	var ctx context.Context
	ctx, s.cancel = context.WithCancel(context.Background())
	s.ckpt.Go(func() { d.runCheckpointer(ctx, cp) })
	return nil
}

// Stop ends the store part. It stops the checkpointer first: after the writer returns, a sink call would wait
// for a reply that does not come. Then it closes the queue, waits for the writer or the drain, and closes the files.
func (s *started) Stop() {
	s.cancel()
	s.ckpt.Wait()
	s.q.Close()
	s.wg.Wait()
	if s.db != nil {
		s.db.Close()
	}
	if s.log != nil {
		s.log.Close()
	}
	if s.root != nil {
		s.root.Close()
	}
}
