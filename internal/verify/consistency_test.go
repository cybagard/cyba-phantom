package verify

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
	modtlog "golang.org/x/mod/sumdb/tlog"

	"github.com/cybagard/cyba-phantom/internal/tlog"
	"github.com/cybagard/cyba-phantom/internal/tlog/verifier"
)

// consProof returns the parsed consistency proof from oldSize to newSize.
func consProof(t testing.TB, l *tlog.Log, oldSize, newSize int64) ConsistencyProof {
	t.Helper()
	hs, err := l.ProveConsistency(oldSize, newSize)
	if err != nil {
		t.Fatal(err)
	}
	return ConsistencyProof{OldSize: oldSize, NewSize: newSize, Hashes: hs}
}

// checkpointOf reads a note with the key v, as the command does.
func checkpointOf(t testing.TB, v note.Verifier, b []byte) Checkpoint {
	t.Helper()
	c, err := ReadCheckpoint(bytes.NewReader(b), v)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// consistencyOf reads both notes with the key v, then calls Consistency. A note
// that does not read gives its error.
func consistencyOf(v note.Verifier, prior, latest []byte, proofs []ConsistencyProof) error {
	p, err := ReadCheckpoint(bytes.NewReader(prior), v)
	if err != nil {
		return err
	}
	l, err := ReadCheckpoint(bytes.NewReader(latest), v)
	if err != nil {
		return err
	}
	return Consistency(p, l, proofs)
}

// emptyCheckpoint signs the checkpoint of a tree with no leaf.
func emptyCheckpoint(t testing.TB, s note.Signer, root modtlog.Hash) []byte {
	t.Helper()
	return signedAt(t, s, 0, root)
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
		"latest larger":               {cp(5), cp(10), []ConsistencyProof{consProof(t, l, 5, 10)}, nil},
		"latest larger, many proofs":  {cp(5), cp(10), []ConsistencyProof{consProof(t, l, 1, 2), consProof(t, l, 5, 10)}, nil},
		"same size":                   {cp(10), cp(10), nil, nil},
		"latest smaller":              {cp(10), cp(5), []ConsistencyProof{consProof(t, l, 5, 10)}, nil},
		"prior is empty":              {emptyCheckpoint(t, s, empty), cp(10), nil, nil},
		"latest is empty":             {cp(10), emptyCheckpoint(t, s, empty), nil, nil},
		"both are empty":              {emptyCheckpoint(t, s, empty), emptyCheckpoint(t, s, empty), nil, nil},
		"sizes with a gap":            {cp(3), cp(300), []ConsistencyProof{consProof(t, l, 3, 300)}, nil},
		"sizes with a gap, reverse":   {cp(300), cp(3), []ConsistencyProof{consProof(t, l, 3, 300)}, nil},
		"power of two sizes":          {cp(128), cp(256), []ConsistencyProof{consProof(t, l, 128, 256)}, nil},
		"proof with other sizes":      {cp(5), cp(10), []ConsistencyProof{consProof(t, l, 5, 11)}, ErrNoProof},
		"proof with reverse sizes":    {cp(5), cp(10), []ConsistencyProof{{OldSize: 10, NewSize: 5}}, ErrNoProof},
		"no proof":                    {cp(5), cp(10), nil, ErrNoProof},
		"latest smaller, no proof":    {cp(10), cp(5), nil, ErrNoProof},
		"prior of another key":        {checkpointAt(t, l, other, 5), cp(10), []ConsistencyProof{consProof(t, l, 5, 10)}, ErrSignature},
		"latest of another key":       {cp(5), checkpointAt(t, l, other, 10), []ConsistencyProof{consProof(t, l, 5, 10)}, ErrSignature},
		"prior is bad":                {cp(5)[:20], cp(10), nil, ErrCheckpoint},
		"same size, other root":       {cp(10), signedAt(t, s, 10, modtlog.Hash{9}), nil, ErrFork},
		"empty with another root":     {emptyCheckpoint(t, s, modtlog.Hash{9}), cp(10), nil, ErrFork},
		"latest is empty, other root": {cp(10), emptyCheckpoint(t, s, modtlog.Hash{9}), nil, ErrFork},
		"both empty, bad roots":       {emptyCheckpoint(t, s, modtlog.Hash{9}), emptyCheckpoint(t, s, modtlog.Hash{9}), nil, ErrFork},
	} {
		wantErr(t, name, consistencyOf(v, tc.prior, tc.latest, tc.proofs), tc.want)
	}
	// A proof with a hash that is changed.
	for _, i := range []int{0, 1} {
		p := consProof(t, l, 5, 10)
		p.Hashes = slices.Clone(p.Hashes)
		p.Hashes[i][0] ^= 1
		wantErr(t, "changed hash", consistencyOf(v, cp(5), cp(10), []ConsistencyProof{p}), ErrFork)
		wantErr(t, "changed hash, reverse", consistencyOf(v, cp(10), cp(5), []ConsistencyProof{p}), ErrFork)
	}
	short := consProof(t, l, 5, 10)
	short.Hashes = short.Hashes[1:]
	wantErr(t, "hash missing", consistencyOf(v, cp(5), cp(10), []ConsistencyProof{short}), ErrFork)
	noHash := consProof(t, l, 5, 10)
	noHash.Hashes = nil
	wantErr(t, "no hash", consistencyOf(v, cp(5), cp(10), []ConsistencyProof{noHash}), ErrFork)
}

// signedAt signs a checkpoint of the given size with a root that the caller gives.
func signedAt(t testing.TB, s note.Signer, size uint64, root modtlog.Hash) []byte {
	t.Helper()
	msg, err := verifier.SignCheckpoint(s, size, root)
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
		wantErr(t, "proof of the second log", consistencyOf(v, prior, latest, []ConsistencyProof{consProof(t, b, tc.old, tc.new)}), ErrFork)
		wantErr(t, "proof of the first log", consistencyOf(v, prior, latest, []ConsistencyProof{consProof(t, a, tc.old, tc.new)}), ErrFork)
		// The reverse order, with the smaller note from the second log.
		wantErr(t, "reverse", consistencyOf(v, latest, prior, []ConsistencyProof{consProof(t, b, tc.old, tc.new)}), ErrFork)
	}
	// The same size and another leaf gives another root.
	wantErr(t, "same size", consistencyOf(v, checkpointAt(t, a, s, 20), checkpointAt(t, b, s, 20), nil), ErrFork)
	// One log gives no fault at the same sizes.
	if err := consistencyOf(v, checkpointAt(t, a, s, 5), checkpointAt(t, a, s, 20), []ConsistencyProof{consProof(t, a, 5, 20)}); err != nil {
		t.Errorf("one log: %v", err)
	}
}

// T-S-14: two checkpoints with different origins are not one log, also when the
// roots and the sizes are equal. A zero value is not consistent with itself or
// with a real checkpoint. A size above the cap gives ErrRange.
func TestTS14_ConsistencyOrigin(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	s2, text2 := newKey(t, origin+"-b")
	v2, _ := ParseKey([]byte(text2))
	l, _ := realLog(t, 10)
	a, b := checkpointOf(t, v, checkpointAt(t, l, s, 10)), checkpointOf(t, v2, checkpointAt(t, l, s2, 10))
	proofs := []ConsistencyProof{consProof(t, l, 5, 10)}
	a5, b5 := checkpointOf(t, v, checkpointAt(t, l, s, 5)), checkpointOf(t, v2, checkpointAt(t, l, s2, 5))
	wantErr(t, "same size and root", Consistency(a, b, nil), ErrFork)
	wantErr(t, "same size and root, reverse", Consistency(b, a, nil), ErrFork)
	wantErr(t, "with a proof", Consistency(a5, b, proofs), ErrFork)
	wantErr(t, "with a proof, reverse", Consistency(b, a5, proofs), ErrFork)
	wantErr(t, "same origin", Consistency(a5, a, proofs), nil)
	wantErr(t, "other origin, same origin", Consistency(b5, b, proofs), nil)

	var zero Checkpoint
	wantErr(t, "zero and zero", Consistency(zero, zero, nil), ErrFork)
	wantErr(t, "zero and real", Consistency(zero, a, nil), ErrFork)
	wantErr(t, "real and zero", Consistency(a, zero, nil), ErrFork)
	big := a
	big.size = maxSize + 1
	wantErr(t, "size above the cap", Consistency(a, big, nil), ErrRange)
	wantErr(t, "prior size above the cap", Consistency(big, a, nil), ErrRange)
}

// T-S-14: the errors have fixed text that holds no input bytes. The text of
// ErrFork does not say that the log has a fork, because a bad consistency proof
// gives the same error.
func TestTS14_ConsistencyErrorText(t *testing.T) {
	for _, tc := range []struct {
		err  error
		text string
	}{
		{ErrFork, "verify: checkpoints are not consistent"},
		{ErrNoProof, "verify: no consistency proof has the needed sizes"},
	} {
		if tc.err.Error() != tc.text {
			t.Errorf("error text: %q, want %q", tc.err, tc.text)
		}
	}
	if strings.Contains(ErrFork.Error(), "has a fork") {
		t.Errorf("ErrFork text says that the log has a fork: %q", ErrFork)
	}
	if ErrFork == ErrNoProof {
		t.Error("ErrFork and ErrNoProof are one error")
	}
}
