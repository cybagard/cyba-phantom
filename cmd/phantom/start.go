package main

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/tlog"
	"github.com/cybagard/cyba-phantom/internal/verify"
)

// stateDir is the state directory. The config loader keeps each state path below it.
const stateDir = config.DefaultStateRoot

// startParams holds the values of the store start. Each path is relative to Root, in slash form.
type startParams struct {
	Root, StorePath, TlogDir, Origin string
	CacheDir                         string // the certificate cache directory
	Reserved                         []string
	Interval                         time.Duration
	BodyPrefix                       bool
}

// startDeps holds the parts that a test replaces. A test counts the calls that
// open the log and the store, or looks at the sink.
type startDeps struct {
	openLog   func(*os.Root, string) (*tlog.Log, error)
	openStore func(*os.Root, string, store.Options) (*sql.DB, error)
	migrate   func(*sql.DB, string) error
	newWriter func(*sql.DB, *event.Queue, *tlog.Log, *event.Counters, bool,
		*slog.Logger, store.Recovery) *store.Writer
	newCheckpointer func(*tlog.Log, note.Signer, note.Verifier, tlog.NoteSink,
		*os.Root, string, time.Duration, *slog.Logger) (*tlog.Checkpointer, error)
	runCheckpointer func(context.Context, *tlog.Checkpointer)
}

var realDeps = startDeps{
	openLog:   tlog.OpenLog,
	openStore: store.Open,
	migrate:   store.Migrate,
	// newWriter wraps store.NewWriter because its parameter list is long.
	newWriter: func(db *sql.DB, q *event.Queue, l *tlog.Log, c *event.Counters,
		bp bool, lg *slog.Logger, r store.Recovery) *store.Writer {
		return store.NewWriter(db, q, l, c, bp, lg, r)
	},
	newCheckpointer: tlog.NewCheckpointer,
	runCheckpointer: func(ctx context.Context, c *tlog.Checkpointer) { c.Run(ctx) },
}

// paramsOf reads the values of the store start from the loaded config.
func paramsOf(cfg *config.Config) startParams {
	rel := func(abs string) string {
		// The loader checks the path below the state directory after symlinks.
		// A path that is not below it as text gives a ".." path. The open
		// through the root then refuses it.
		r, err := filepath.Rel(stateDir, abs)
		if err != nil {
			return abs
		}
		return filepath.ToSlash(r)
	}
	str := func(k string) string { v, _ := cfg.Get(k); return v.Str }
	iv, _ := cfg.Get("tlog.checkpoint_interval")
	bp, _ := cfg.Get("privacy.store_body_prefix")
	return startParams{
		Root: stateDir, StorePath: rel(str("store.path")), TlogDir: rel(str("tlog.dir")), Origin: str("tlog.origin"),
		CacheDir: rel(str("acme.cache_dir")),
		Reserved: []string{rel(str("tlog.dir")), rel(str("acme.cache_dir")), rel(filepath.Dir(str("bundle.path")))},
		Interval: iv.Dur, BodyPrefix: bp.Bool,
	}
}

// storePart is the store part of the process. It holds the checkpointer and
// the writer. When the store did not open, it holds the drain in place of the
// writer.
type storePart struct {
	q      *event.Queue
	writer *store.Writer // nil when the store did not open
	drops  store.DropCount
	root   *os.Root
	log    *tlog.Log
	db     *sql.DB
	sink   *store.Sink
	cp     *tlog.Checkpointer // nil when the checkpointer did not start
	cancel context.CancelFunc // stops the checkpointer
	ckpt   sync.WaitGroup
	wg     sync.WaitGroup // the writer, or the drain
}

// Healthy tells if the store part works: false with no writer, else the health of the writer.
func (s *storePart) Healthy() bool { return s.writer != nil && s.writer.Healthy() }

// TlogHealthy tells if the checkpointer started and is healthy. Healthy does not show the checkpointer.
func (s *storePart) TlogHealthy() bool { return s.cp != nil && s.cp.Healthy() }

// Drops returns the count of the events that the drain dropped. It stays zero when the store opened.
func (s *storePart) Drops() store.Drops { return s.drops.Load() }

// start opens the log and the store one time each. It starts the writer or
// the drain, and the checkpointer. If the state directory, the log or the
// store does not open, there is no writer. Then the store part is not healthy.
// start logs a checkpointer that does not start, and Healthy does not show it
// (see TlogHealthy). There is no reopen, retry or restart. q and c are the
// queue and its counters.
func start(p startParams, q *event.Queue, c *event.Counters, d startDeps, lg *slog.Logger) *storePart {
	s := &storePart{q: q, cancel: func() {}}
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
		s.writer = d.newWriter(s.db, q, s.log, c, p.BodyPrefix, lg, store.Recovery{State: s.root, Origin: p.Origin, Log: s.log})
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

// openDB opens the store and brings its schema to the newest version. openDB closes the database when Migrate refuses it.
func (s *storePart) openDB(p startParams, d startDeps) (*sql.DB, error) {
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

// hasSignedCheckpoint tells if the store has a checkpoint row or the spool has
// an entry. Then an earlier key signed a checkpoint, even when the key files,
// the signer state and the log are gone. The rows of a store that did not open
// are unknown. So an entry at storePath counts as a signed checkpoint. A
// storePath that cannot be examined gives an error. Without an entry at
// storePath, only the spool counts.
func (s *storePart) hasSignedCheckpoint(storePath string) (bool, error) {
	if s.db != nil {
		var found bool
		if err := s.db.QueryRow("SELECT EXISTS (SELECT 1 FROM checkpoint)").Scan(&found); err != nil || found {
			return found, err
		}
	} else if _, err := s.root.Lstat(storePath); err == nil {
		return true, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		// The text has no cause: the cause names the configured path.
		return false, errors.New("store path cannot be examined")
	}
	// The spool must be a real directory. A FIFO or a symlink there must not
	// block the start or lead out of the state directory.
	fi, err := s.root.Lstat(tlog.SpoolDirName)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, errors.New("checkpoints directory cannot be examined")
	} else if fi.Mode()&fs.ModeSymlink != 0 {
		return false, errors.New("checkpoints must be a real directory and not a symlink")
	} else if !fi.IsDir() {
		return false, errors.New("checkpoints is not a directory")
	}
	// O_DIRECTORY makes the open fail for an entry that replaced the directory
	// after the Lstat, a FIFO for example. The open does not block.
	dir, err := s.root.OpenFile(tlog.SpoolDirName, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	if _, err := dir.Readdirnames(1); err != nil {
		if err == io.EOF { // an empty directory
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// sameKey refuses a public key that is not the key of the signer. The key hash
// has 32 bits, so a different key can have the same name and hash. So sameKey
// also checks that the public key accepts a signature of the signer.
func sameKey(signer note.Signer, v note.Verifier) error {
	if v.Name() != signer.Name() || v.KeyHash() != signer.KeyHash() {
		return errors.New("public key file does not match the signer")
	}
	msg := []byte("phantom public key check\n")
	sig, err := signer.Sign(msg)
	if err != nil {
		return err
	}
	if !v.Verify(msg, sig) {
		return errors.New("public key file does not verify the signer")
	}
	return nil
}

// startCheckpointer gives the checkpointer the checkpoint row sink over the
// spool. The sink has the writer, or nil. startCheckpointer makes a new key
// only on a first start (SEC-16). A checkpoint row, a spool entry, or an error
// on a read of either gives no new key. A store that did not open but has an
// entry at its path also gives no new key.
func (s *storePart) startCheckpointer(p startParams, d startDeps, lg *slog.Logger) error {
	_, exists, err := tlog.SignerState(s.root)
	if err != nil {
		return err
	}
	signed, err := s.hasSignedCheckpoint(p.StorePath)
	if err != nil {
		return err
	}
	size, _ := s.log.Head()
	signer, err := tlog.LoadOrCreateSigner(s.root, lg, p.Origin, exists || signed, uint64(size))
	if err != nil {
		return err
	}
	f, err := s.root.Open(tlog.VKeyName)
	if err != nil {
		return err
	}
	defer f.Close()
	v, err := verify.ReadKey(f)
	if err != nil {
		return err
	}
	if err := sameKey(signer, v); err != nil {
		return err
	}
	spool, err := tlog.OpenSpool(s.root, lg, p.Origin, v, nil)
	if err != nil {
		return err
	}
	s.sink = store.NewSink(s.writer, spool, p.Origin, v)
	cp, err := d.newCheckpointer(s.log, signer, v, s.sink, s.root, p.Origin, p.Interval, lg)
	if err != nil {
		return err
	}
	s.cp = cp
	var ctx context.Context
	ctx, s.cancel = context.WithCancel(context.Background())
	s.ckpt.Go(func() { d.runCheckpointer(ctx, cp) })
	return nil
}

// Stop ends the store part. It stops the checkpointer first: after the writer returns, a sink call would wait
// for a reply that does not come. Then it closes the queue, waits for the writer or the drain, and closes the files.
func (s *storePart) Stop() {
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
