package bundle

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// Source is the place a load comes from.
type Source uint8

// The sources of a load. The zero value of Source is not a source.
const (
	SourceStart Source = iota + 1
	SourceSignal
	SourceReload
	SourceFetch
)

var sourceText = [...]string{
	SourceStart:  "start",
	SourceSignal: "signal",
	SourceReload: "reload",
	SourceFetch:  "fetch",
}

// String returns the text of the source, for example "fetch". A value that is
// not one of the four sources gives "unknown".
func (s Source) String() string {
	if s < SourceStart || int(s) >= len(sourceText) {
		return "unknown"
	}
	return sourceText[s]
}

// ErrSource is the error of LoadFrom for a value that is not a Source.
var ErrSource = errors.New("bundle: source")

// digest is the SHA-256 of the archive. ok is true when the loader read the
// bundle file and the signature file.
type digest struct {
	v  [32]byte
	ok bool
}

// hex returns the 64 lower-case hex digits of the digest.
func (d digest) hex() string { return hex.EncodeToString(d.v[:]) }

// member is one name and value of a load. The event detail and the log line
// of the load both hold these members.
type member struct{ name, value string }

// members gives the members of one load. The values come from the source, the
// digest, the rejection code, and the accepted bundle b. A nil b with a zero
// code gives the source and the digest only. No error text and no member of a
// rejected manifest is in the list.
func members(src Source, sum digest, b *Bundle, code Code) []member {
	ms := []member{{"source", src.String()}}
	if sum.ok {
		ms = append(ms, member{"sha256", sum.hex()})
	}
	switch {
	case b != nil:
		ms = append(ms, member{"version", b.manifest.Version}, member{"key_id", b.manifest.KeyID})
	case code != 0:
		ms = append(ms, member{"reason", code.String()})
	}
	return ms
}

// SetEvents sets the queue and the log of the loader. A nil q sends no event.
// A nil log writes no line. The log lines have fixed text and typed values
// only.
func (l *Loader) SetEvents(q *event.Queue, log *slog.Logger) {
	loadMu.Lock()
	defer loadMu.Unlock()
	l.events, l.log = q, log
}

// LoadFrom is Load for this source. Load(true) is LoadFrom(SourceStart).
// Load(false) is LoadFrom(SourceReload).
//
// When SetEvents gave a queue, LoadFrom sends one bundle_load event for an
// accept or one bundle_rejected event for a rejection. When SetEvents gave a
// log, it writes one log line. A state fault is no rejection code. It gives a
// log line and no event. A value that is not a Source reads nothing and gives
// ErrSource.
func (l *Loader) LoadFrom(src Source) (*Bundle, error) {
	if src < SourceStart || src > SourceFetch {
		return nil, ErrSource
	}
	loadMu.Lock()
	defer loadMu.Unlock()
	var sum digest
	b, err := l.load(src == SourceStart, &sum)
	l.report(src, sum, b, err)
	return b, err
}

// report sends the event and writes the log line of one load.
func (l *Loader) report(src Source, sum digest, b *Bundle, err error) {
	kind, code, msg, level := event.KindBundleLoad, Code(0), "bundle loaded", slog.LevelInfo
	if err != nil {
		c, ok := CodeOf(err)
		if !ok {
			l.logMembers(slog.LevelError, "bundle state fault", members(src, sum, nil, 0))
			return
		}
		kind, code, msg, level = event.KindBundleRejected, c, "bundle rejected", slog.LevelWarn
	}
	ms := members(src, sum, b, code)
	l.logMembers(level, msg, ms)
	if l.events == nil {
		return
	}
	d := make(event.Detail, len(ms))
	for _, m := range ms {
		d[m.name] = event.Str(m.value)
	}
	// NewEvent cannot fail here. The detail has at most four members. Each is
	// a bounded enum, 64 hex digits, or a checked version or key ID.
	e, _ := event.NewEvent(l.now, event.Input{Kind: kind, Detail: d})
	l.events.Enqueue(e)
}

// logMembers writes one log line with the members as attributes.
func (l *Loader) logMembers(level slog.Level, msg string, ms []member) {
	if l.log == nil {
		return
	}
	attrs := make([]slog.Attr, len(ms))
	for i, m := range ms {
		attrs[i] = slog.String(m.name, m.value)
	}
	l.log.LogAttrs(context.Background(), level, msg, attrs...)
}
