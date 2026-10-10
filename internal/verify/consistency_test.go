package verify

import (
	"slices"
	"testing"

	"golang.org/x/mod/sumdb/note"
	modtlog "golang.org/x/mod/sumdb/tlog"

	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// consProof returns the consistency proof file content from oldSize to newSize.
func consProof(t testing.TB, l *tlog.Log, oldSize, newSize int64) ConsistencyProof {
	t.Helper()
	hs, err := l.ProveConsistency(oldSize, newSize)
	if err != nil {
		t.Fatal(err)
	}
	return ConsistencyProof{OldSize: oldSize, NewSize: newSize, Hashes: hs}
}

// emptyCheckpoint signs the checkpoint of a tree with no leaf.
func emptyCheckpoint(t testing.TB, s note.Signer, root modtlog.Hash) []byte {
	t.Helper()
	msg, err := tlog.SignCheckpoint(s, 0, root)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// T-S-14: the consistency rule for a real log. A gap between the sizes is not a
// fault. A size of 0 needs no proof.
func TestTS14_Consistency(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	other, _ := newKey(t, origin) // same name, another key
	l, _ := realLog(t, 300)
	cp := func(size int64) []byte { return checkpointAt(t, l, s, size) }
	empty, _ := modtlog.TreeHash(0, nil)
	for name, tc := range map[string]struct {
		prior, latest []byte
		proofs        []ConsistencyProof
		want          error
	}{
		"latest larger":             {cp(5), cp(10), []ConsistencyProof{consProof(t, l, 5, 10)}, nil},
		"latest larger, many proof": {cp(5), cp(10), []ConsistencyProof{consProof(t, l, 1, 2), consProof(t, l, 5, 10)}, nil},
		"same size":                 {cp(10), cp(10), nil, nil},
		"latest smaller":            {cp(10), cp(5), []ConsistencyProof{consProof(t, l, 5, 10)}, nil},
		"prior is empty":            {emptyCheckpoint(t, s, empty), cp(10), nil, nil},
		"latest is empty":           {cp(10), emptyCheckpoint(t, s, empty), nil, nil},
		"both are empty":            {emptyCheckpoint(t, s, empty), emptyCheckpoint(t, s, empty), nil, nil},
		"sizes with a gap":          {cp(3), cp(300), []ConsistencyProof{consProof(t, l, 3, 300)}, nil},
		"sizes with a gap, reverse": {cp(300), cp(3), []ConsistencyProof{consProof(t, l, 3, 300)}, nil},
		"power of two sizes":        {cp(128), cp(256), []ConsistencyProof{consProof(t, l, 128, 256)}, nil},
		"proof with other sizes":    {cp(5), cp(10), []ConsistencyProof{consProof(t, l, 5, 11)}, ErrNoProof},
		"proof with reverse sizes":  {cp(5), cp(10), []ConsistencyProof{{OldSize: 10, NewSize: 5}}, ErrNoProof},
		"no proof":                  {cp(5), cp(10), nil, ErrNoProof},
		"prior of another key":      {checkpointAt(t, l, other, 5), cp(10), []ConsistencyProof{consProof(t, l, 5, 10)}, ErrSignature},
		"latest of another key":     {cp(5), checkpointAt(t, l, other, 10), []ConsistencyProof{consProof(t, l, 5, 10)}, ErrSignature},
		"prior is bad":              {cp(5)[:20], cp(10), nil, ErrSignature},
		"same size, other root":     {cp(10), emptyAt(t, s, 10, modtlog.Hash{9}), nil, ErrFork},
		"empty with another root":   {emptyCheckpoint(t, s, modtlog.Hash{9}), cp(10), nil, ErrFork},
		"empty, latest, bad root":   {cp(10), emptyCheckpoint(t, s, modtlog.Hash{9}), nil, ErrFork},
		"both empty, bad roots":     {emptyCheckpoint(t, s, modtlog.Hash{9}), emptyCheckpoint(t, s, modtlog.Hash{9}), nil, ErrFork},
	} {
		wantErr(t, name, Consistency(v, tc.prior, tc.latest, tc.proofs), tc.want)
	}
	// A proof with a hash that is changed.
	for _, i := range []int{0, 1} {
		p := consProof(t, l, 5, 10)
		p.Hashes = slices.Clone(p.Hashes)
		p.Hashes[i][0] ^= 1
		wantErr(t, "changed hash", Consistency(v, cp(5), cp(10), []ConsistencyProof{p}), ErrFork)
		wantErr(t, "changed hash, reverse", Consistency(v, cp(10), cp(5), []ConsistencyProof{p}), ErrFork)
	}
	short := consProof(t, l, 5, 10)
	short.Hashes = short.Hashes[1:]
	wantErr(t, "hash missing", Consistency(v, cp(5), cp(10), []ConsistencyProof{short}), ErrFork)
	empty5 := consProof(t, l, 5, 10)
	empty5.Hashes = nil
	wantErr(t, "no hash", Consistency(v, cp(5), cp(10), []ConsistencyProof{empty5}), ErrFork)
}

// emptyAt signs a checkpoint of the given size with a root that the caller gives.
func emptyAt(t testing.TB, s note.Signer, size uint64, root modtlog.Hash) []byte {
	t.Helper()
	msg, err := tlog.SignCheckpoint(s, size, root)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// T-S-14: two logs with one key and one different leaf have a fork. The proof
// of the second log does not link the first log to the second log.
func TestTS14_ConsistencyFork(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	a, _ := realLog(t, 20)
	b, _ := realLogOf(t, 20, `{"m":%d}`)
	for _, tc := range []struct{ old, new int64 }{{1, 20}, {5, 20}, {5, 10}, {16, 20}} {
		prior := checkpointAt(t, a, s, tc.old)
		latest := checkpointAt(t, b, s, tc.new)
		wantErr(t, "proof of the second log", Consistency(v, prior, latest, []ConsistencyProof{consProof(t, b, tc.old, tc.new)}), ErrFork)
		wantErr(t, "proof of the first log", Consistency(v, prior, latest, []ConsistencyProof{consProof(t, a, tc.old, tc.new)}), ErrFork)
		// The reverse order, with the smaller note from the second log.
		wantErr(t, "reverse", Consistency(v, latest, prior, []ConsistencyProof{consProof(t, b, tc.old, tc.new)}), ErrFork)
	}
	// The same size and another leaf gives another root.
	wantErr(t, "same size", Consistency(v, checkpointAt(t, a, s, 20), checkpointAt(t, b, s, 20), nil), ErrFork)
	// One log gives no fault at the same sizes.
	if err := Consistency(v, checkpointAt(t, a, s, 5), checkpointAt(t, a, s, 20), []ConsistencyProof{consProof(t, a, 5, 20)}); err != nil {
		t.Errorf("one log: %v", err)
	}
}

// T-S-14: the errors have fixed text that holds no input bytes.
func TestTS14_ConsistencyErrorText(t *testing.T) {
	if ErrFork.Error() != "verify: checkpoints are not consistent: the log has a fork" {
		t.Errorf("ErrFork text: %q", ErrFork)
	}
	if ErrFork == ErrNoProof {
		t.Error("ErrFork and ErrNoProof are one error")
	}
}
