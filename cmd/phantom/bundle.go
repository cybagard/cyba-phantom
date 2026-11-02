package main

import (
	"log/slog"

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
type bundlePart struct{ l *bundle.Loader }

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
		return &bundlePart{}
	}
	trust := bundleTrust()
	if trust.Check(nil) != nil {
		lg.Error("bundle does not load: trust set is not valid")
		return &bundlePart{}
	}
	// A key error ends the load also for a reference bundle (fail closed).
	install, err := bundle.LoadOrCreateInstallKey(s.root)
	if err != nil {
		lg.Error("bundle does not load: install key is not valid")
		return &bundlePart{}
	}
	l := newLoader(s.root, p.BundlePath, trust, install)
	l.SetEvents(q, lg)
	_, _ = l.Load(true) // the loader reports the result; Healthy shows it
	return &bundlePart{l}
}
