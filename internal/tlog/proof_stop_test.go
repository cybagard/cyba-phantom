package tlog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests below use a log of 600 leaves. OpenLog does not read the full
// tiles 0/000 and 0/001 at this size, so only a proof call reads them.
func TestTS13BadOlderTileStopsTheLog(t *testing.T) {
	withoutSync(t)
	for _, c := range []struct {
		name, tile string
		index      int64
		damage     func(file string, b []byte) error
	}{
		{"changed byte", "tile/8/0/000", 5, func(f string, b []byte) error { b[len(b)/2] ^= 1; return os.WriteFile(f, b, 0o600) }},
		{"changed byte in the second tile", "tile/8/0/001", 300, func(f string, b []byte) error { b[0] ^= 1; return os.WriteFile(f, b, 0o600) }},
		{"short file", "tile/8/0/000", 5, func(f string, b []byte) error { return os.WriteFile(f, b[:len(b)-1], 0o600) }},
		{"missing file", "tile/8/0/001", 300, func(f string, _ []byte) error { return os.Remove(f) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			state, dir := newLogState(t)
			l := openTestLog(t, state)
			appendTo(t, l, 0, 600)
			if _, err := l.ProveInclusion(c.index, 600); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "tlog", filepath.FromSlash(c.tile))
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.damage(file, b); err != nil {
				t.Fatal(err)
			}
			proof, first := l.ProveInclusion(c.index, 600)
			if proof != nil || first == nil {
				t.Fatalf("proof %v, error %v", proof, first)
			}
			var e *Error
			if !errors.As(first, &e) || !strings.Contains(e.Name, c.tile) || !tileNames.MatchString(e.Name) {
				t.Fatalf("error %q does not name the tile %s", first, c.tile)
			}
			if _, err := l.Append(testEvent(600)); err != first {
				t.Fatalf("append: error %v, want %v", err, first)
			}
			if _, err := l.RootAt(600); err != first {
				t.Fatalf("root: error %v, want %v", err, first)
			}
			for _, sizes := range [][2]int64{{0, 600}, {600, 600}, {100, 600}, {-1, 5}} {
				if p, err := l.ProveConsistency(sizes[0], sizes[1]); p != nil || err != first {
					t.Fatalf("consistency %v: proof %v, error %v", sizes, p, err)
				}
			}
			if p, err := l.ProveInclusion(-1, 5); p != nil || err != first {
				t.Fatalf("inclusion with a bad index: proof %v, error %v", p, err)
			}
			if n, _ := l.Head(); n != 600 {
				t.Fatalf("size %d after the stop", n)
			}
			// A new open is the way back. It must not panic.
			l.Close()
			if l2, err := OpenLog(state, "tlog"); err == nil {
				l2.Close()
			}
		})
	}
}

func TestTS13BadProofInputDoesNotStopTheLog(t *testing.T) {
	withoutSync(t)
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, 600)
	if _, err := l.ProveInclusion(600, 600); err == nil {
		t.Fatal("no error for a bad index")
	}
	if _, err := l.ProveConsistency(5, 601); err == nil {
		t.Fatal("no error for a bad size")
	}
	if i, err := l.Append(testEvent(600)); err != nil || i != 600 {
		t.Fatalf("append: index %d, error %v", i, err)
	}
}
