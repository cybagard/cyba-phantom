package verify

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/mod/sumdb/note"
	modtlog "golang.org/x/mod/sumdb/tlog"

	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// realLog opens a real log in a temporary state directory and appends n events.
// Event i is the canonical JSON {"n":i}. The function returns the log and the
// events in the order of their leaves.
func realLog(t *testing.T, n int) (*tlog.Log, []Event) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Close() })
	l, err := tlog.OpenLog(state, "tlog")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var events []Event
	for i := 0; i < n; i++ {
		e, err := ParseEvent([]byte(fmt.Sprintf(`{"n":%d}`, i)))
		if err != nil {
			t.Fatal(err)
		}
		if idx, err := l.Append(e.Hash); err != nil || idx != int64(i) {
			t.Fatalf("append %d: index %d, %v", i, idx, err)
		}
		events = append(events, e)
	}
	return l, events
}

// checkpointAt signs the checkpoint of the first size leaves of the log.
func checkpointAt(t *testing.T, l *tlog.Log, s note.Signer, size int64) []byte {
	t.Helper()
	root, err := l.RootAt(size)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tlog.SignCheckpoint(s, uint64(size), root)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// proofAt returns the proof file content for leaf index in the tree of size.
func proofAt(t *testing.T, l *tlog.Log, index, size int64) InclusionProof {
	t.Helper()
	hs, err := l.ProveInclusion(index, size)
	if err != nil {
		t.Fatal(err)
	}
	return InclusionProof{Index: index, TreeSize: size, Hashes: hs}
}

// T-S-14 and the T-U-12 class: a real log, real signed checkpoints, and a
// check of the first, the last, and the middle leaf at each size.
func TestTS14_InclusionRoundTrip(t *testing.T) {
	sizes := []int64{1, 2, 255, 256, 257}
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, events := realLog(t, 257)
	for _, size := range sizes {
		// The log holds 257 leaves. RootAt gives the root of each smaller tree,
		// which is the tree the log had when it had this size.
		msg := checkpointAt(t, l, s, size)
		root, _ := l.RootAt(size)
		for _, i := range slices.Compact([]int64{0, size / 2, size - 1}) {
			res, err := Inclusion(v, msg, events[i], proofAt(t, l, i, size))
			if err != nil {
				t.Fatalf("size %d, leaf %d: %v", size, i, err)
			}
			want := proofAt(t, l, i, size).Hashes
			if res.Origin != origin || res.Size != uint64(size) || res.Root != root ||
				res.EventHash != events[i].Hash || res.LeafIndex != i || !slices.Equal(res.Proof, want) {
				t.Errorf("size %d, leaf %d: result %+v", size, i, res)
			}
		}
	}
	// A tree of one leaf has an empty proof.
	msg := checkpointAt(t, l, s, 1)
	res, err := Inclusion(v, msg, events[0], proofAt(t, l, 0, 1))
	if err != nil || len(res.Proof) != 0 {
		t.Errorf("size 1: %+v, %v", res, err)
	}
	// The proof file path: the JSON of 04 §7 gives the same result.
	p := proofAt(t, l, 100, 257)
	var hashes string
	for i, h := range p.Hashes {
		if i > 0 {
			hashes += ","
		}
		hashes += `"` + base64.StdEncoding.EncodeToString(h[:]) + `"`
	}
	parsed, err := ParseInclusionProof([]byte(fmt.Sprintf(`{"index":100,"tree_size":257,"hashes":[%s]}`, hashes)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inclusion(v, checkpointAt(t, l, s, 257), events[100], parsed); err != nil {
		t.Errorf("proof from a file: %v", err)
	}
}

// T-S-14: a changed event, a forged checkpoint, and a proof that does not fit
// are refused, and no result comes back.
func TestTS14_InclusionRefused(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	other, _ := newKey(t, origin) // same name, another key
	l, events := realLog(t, 10)
	msg := checkpointAt(t, l, s, 10)
	good := proofAt(t, l, 3, 10)
	changed, err := ParseEvent([]byte(`{"n":4}`)) // the bytes of leaf 4, offered for leaf 3
	if err != nil {
		t.Fatal(err)
	}
	flipped, err := ParseEvent([]byte(`{"n":3,"x":0}`))
	if err != nil {
		t.Fatal(err)
	}
	badHash := proofAt(t, l, 3, 10)
	badHash.Hashes = slices.Clone(badHash.Hashes)
	badHash.Hashes[0][0] ^= 1
	short := proofAt(t, l, 3, 10)
	short.Hashes = short.Hashes[1:]
	root := modtlog.Hash{1}
	withRoot := proofAt(t, l, 3, 10)
	withRoot.Root, withRoot.Consistency = &root, []modtlog.Hash{}
	bridged := proofAt(t, l, 3, 5) // the tree of 5 leaves, with a root and a consistency proof
	r5, _ := l.RootAt(5)
	cons, err := l.ProveConsistency(5, 10)
	if err != nil {
		t.Fatal(err)
	}
	bridged.Root, bridged.Consistency = &r5, cons
	larger := InclusionProof{Index: 3, TreeSize: 11, Hashes: good.Hashes}
	otherRoot, _ := tlog.SignCheckpoint(s, 10, modtlog.Hash{9})
	empty := checkpointAt(t, l, s, 0)
	for name, tc := range map[string]struct {
		msg  []byte
		e    Event
		p    InclusionProof
		want error
	}{
		"changed event":                 {msg, changed, good, ErrNotVerified},
		"event with an added member":    {msg, flipped, good, ErrNotVerified},
		"wrong index":                   {msg, events[3], proofAt(t, l, 4, 10), ErrNotVerified},
		"index set to another leaf":     {msg, events[3], InclusionProof{Index: 4, TreeSize: 10, Hashes: good.Hashes}, ErrNotVerified},
		"proof hash changed":            {msg, events[3], badHash, ErrNotVerified},
		"proof hash missing":            {msg, events[3], short, ErrNotVerified},
		"checkpoint of another key":     {checkpointAt(t, l, other, 10), events[3], good, ErrCheckpoint},
		"checkpoint with another root":  {otherRoot, events[3], good, ErrNotVerified},
		"checkpoint of the empty tree":  {empty, events[3], good, ErrTreeSize},
		"proof size larger":             {msg, events[3], larger, ErrTreeSize},
		"proof size smaller, bridged":   {msg, events[3], bridged, ErrBridged},
		"proof size equal, with a root": {msg, events[3], withRoot, ErrBridged},
		"proof size smaller, no root":   {msg, events[3], proofAt(t, l, 3, 5), ErrBridged},
		"index past the size":           {msg, events[3], InclusionProof{Index: 10, TreeSize: 10, Hashes: good.Hashes}, ErrNotVerified},
		"checkpoint note is bad":        {msg[:len(msg)-3], events[3], good, ErrCheckpoint},
	} {
		res, err := Inclusion(v, tc.msg, tc.e, tc.p)
		wantErr(t, name, err, tc.want)
		if err != nil && (res.Root != [32]byte{} || res.Proof != nil || res.Origin != "") {
			t.Errorf("%s: result is not empty with an error: %+v", name, res)
		}
	}
	// The same inputs pass when nothing is changed.
	if _, err := Inclusion(v, msg, events[3], good); err != nil {
		t.Errorf("unchanged inputs: %v", err)
	}
	// A size-0 checkpoint has no leaf. Its proof size is 0.
	_, err = Inclusion(v, empty, events[0], InclusionProof{Hashes: []modtlog.Hash{}})
	wantErr(t, "empty tree, size 0 proof", err, ErrNotVerified)
}
