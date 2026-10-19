package tlog

import (
	"os"
	"strings"
	"testing"
)

// The tests below use a log of 600 leaves. OpenLog does not read the full
// tiles 0/000 and 0/001 at this size, so only a proof call reads them.
func TestTS13BadOlderTileStopsTheLog(t *testing.T) {
	withoutSync(t)
	for _, c := range []struct {
		name, tile, rule string
		index            int64
		damage           func(file string, b []byte) error
	}{
		{"changed byte", "tile/8/0/000", ruleProofRead, 5, func(f string, b []byte) error { b[len(b)/2] ^= 1; return os.WriteFile(f, b, 0o600) }},
		{"changed byte in the second tile", "tile/8/0/001", ruleProofRead, 300, func(f string, b []byte) error { b[0] ^= 1; return os.WriteFile(f, b, 0o600) }},
		{"short file", "tile/8/0/000", ruleLength, 5, func(f string, b []byte) error { return os.WriteFile(f, b[:len(b)-1], 0o600) }},
		{"missing file", "tile/8/0/001", ruleMissing, 300, func(f string, _ []byte) error { return os.Remove(f) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, file, state := tileLog(t, 600, c.tile)
			if _, err := l.ProveInclusion(c.index, 600); err != nil {
				t.Fatal(err)
			}
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
			if e := wantTileError(t, len(proof), first, c.rule); !strings.Contains(e.Name, c.tile) {
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
			// Open the log again. OpenLog must not panic. It returns no error, because
			// it does not read the bad tile. The new log appends, and a proof that
			// reads the bad tile gives the tile error again: the package does not
			// repair the tile.
			l.Close()
			l2 := openTestLog(t, state)
			if i, err := l2.Append(testEvent(600)); err != nil || i != 600 {
				t.Fatalf("append to the new log: index %d, error %v", i, err)
			}
			proof, err = l2.ProveInclusion(c.index, 600)
			if e := wantTileError(t, len(proof), err, c.rule); !strings.Contains(e.Name, c.tile) {
				t.Fatalf("error %q does not name the tile %s", err, c.tile)
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
