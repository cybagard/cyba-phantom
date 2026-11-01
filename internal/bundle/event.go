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

// newEvent makes the event of one load. It takes typed values only. These are
// the kind, the rejection code, the source and the digest. For an accept, they
// also include the version and key ID that the manifest check accepted. No
// error text and no member of a rejected manifest goes into the event. The
// event has no session.
func newEvent(now event.Clock, kind event.Kind, code Code, src Source, sum digest, version, keyID string) (*event.Event, error) {
	d := event.Detail{"source": event.Str(src.String())}
	if sum.ok {
		d["sha256"] = event.Str(sum.hex())
	}
	if kind == event.KindBundleRejected {
		d["reason"] = event.Str(code.String())
	} else {
		d["version"], d["key_id"] = event.Str(version), event.Str(keyID)
	}
	return event.NewEvent(now, event.Input{Kind: kind, Detail: d})
}

// SetEvents makes the loader send one event for each load to q. It also writes
// one log line for each load to log. A nil q sends no event. A nil log writes
// no line. The log lines have fixed text and typed values only.
func (l *Loader) SetEvents(q *event.Queue, log *slog.Logger) {
	loadMu.Lock()
	defer loadMu.Unlock()
	l.events, l.log = q, log
}

// LoadFrom is Load for this source. Load(true) is LoadFrom(SourceStart).
// Load(false) is LoadFrom(SourceReload). Then it sends one bundle_load event
// for an accept or one bundle_rejected event for a rejection. It also writes
// one log line. A state fault is no rejection code. It gives a log line and no
// event. A value that is not a Source reads nothing and gives ErrSource.
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
	attrs := []slog.Attr{slog.String("source", src.String())}
	if sum.ok {
		attrs = append(attrs, slog.String("sha256", sum.hex()))
	}
	kind, code, version, keyID := event.KindBundleLoad, Code(0), "", ""
	msg, level := "bundle loaded", slog.LevelInfo
	if err == nil {
		version, keyID = b.manifest.Version, b.manifest.KeyID
		attrs = append(attrs, slog.String("version", version), slog.String("key_id", keyID))
	} else if c, ok := CodeOf(err); ok {
		kind, code, msg, level = event.KindBundleRejected, c, "bundle rejected", slog.LevelWarn
		attrs = append(attrs, slog.String("reason", c.String()))
	} else {
		l.logAttrs(slog.LevelError, "bundle state fault", attrs)
		return
	}
	l.logAttrs(level, msg, attrs)
	if l.events == nil {
		return
	}
	e, eerr := newEvent(l.now, kind, code, src, sum, version, keyID)
	if eerr != nil {
		l.logAttrs(slog.LevelWarn, "bundle event not made", attrs)
		return
	}
	l.events.Enqueue(e)
}

func (l *Loader) logAttrs(level slog.Level, msg string, attrs []slog.Attr) {
	if l.log != nil {
		l.log.LogAttrs(context.Background(), level, msg, attrs...)
	}
}
