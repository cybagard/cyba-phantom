package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
)

// releaseTrust returns the trust set of the release build. It holds public keys
// only and no test key (ADR-027). It is empty until the reference public key
// is known. Each call returns a new list.
func releaseTrust() bundle.TrustSet { return bundle.TrustSet{} }

// The seams of the bundle start. A test replaces them.
var (
	bundleTrust = releaseTrust
	newLoader   = bundle.NewLoader
)

// bundlePart is the bundle part of the process. A nil loader means that no
// load ran.
type bundlePart struct {
	l  *bundle.Loader
	lg *slog.Logger
}

// Reload asks the loader for one load with the source src. It is the one
// reload entry: SIGHUP calls it with SourceSignal. The loader reports the
// result (an event and a log line), and a rejected bundle leaves the running
// bundle. With no loader, Reload writes one fixed line, loads nothing and
// gives no event.
func (b *bundlePart) Reload(src bundle.Source) {
	if b.l == nil {
		b.lg.Error("bundle does not reload: no bundle loader")
		return
	}
	_, _ = b.l.LoadFrom(src)
}

// notifyReload returns the channel of the SIGHUP handler. The buffer of 1
// keeps one signal that comes during a load. signal.Notify drops the others.
func notifyReload() chan os.Signal {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	return hup
}

// reloadOnSignal calls Reload with SourceSignal for each signal on hup, one
// load at a time, until ctx ends. A load that has begun runs to its end.
// A load in its wait for the swap gap has begun. It can run up to 30 s after
// ctx ended. After ctx ended, no new load begins.
func (b *bundlePart) reloadOnSignal(ctx context.Context, hup <-chan os.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		}
		if ctx.Err() != nil {
			return
		}
		b.Reload(bundle.SourceSignal)
	}
}

// Healthy is true only when the start accepted a bundle and the state of
// the loader is not a fault.
func (b *bundlePart) Healthy() bool {
	return b.l != nil && b.l.Current() != nil && b.l.Healthy()
}

// startBundle loads the bundle one time with the source start. It runs only
// when the store part has a writer. Then the store opened and checked the
// state directory and its parents. Each failure writes one fixed line. No
// failure ends the process, and the decoys serve with no bundle (C3).
func startBundle(p startParams, s *storePart, q *event.Queue, lg *slog.Logger) *bundlePart {
	if s.writer == nil {
		lg.Error("bundle does not load: store is not running")
		return &bundlePart{lg: lg}
	}
	trust := bundleTrust()
	if trust.Check(nil) != nil {
		lg.Error("bundle does not load: trust set is not valid")
		return &bundlePart{lg: lg}
	}
	// A key error ends the load also for a reference bundle (fail closed).
	install, err := bundle.LoadOrCreateInstallKey(s.root)
	if err != nil {
		lg.Error("bundle does not load: install key is not valid")
		return &bundlePart{lg: lg}
	}
	l := newLoader(s.root, p.BundlePath, trust, install)
	l.SetEvents(q, lg)
	_, _ = l.Load(true) // the loader reports the result; Healthy shows it
	return &bundlePart{l: l, lg: lg}
}
