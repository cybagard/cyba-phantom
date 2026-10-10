package verify

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
	modtlog "golang.org/x/mod/sumdb/tlog"

	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// realLog opens a real log in a temporary state directory and appends n events.
// Event i is the canonical JSON {"n":i}. The function returns the log and the
// events in the order of their leaves.
func realLog(t testing.TB, n int) (*tlog.Log, []Event) {
	t.Helper()
	return realLogOf(t, n, `{"n":%d}`)
}

// realLogOf is realLog with another event form. The form takes the index.
func realLogOf(t testing.TB, n int, form string) (*tlog.Log, []Event) {
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
		e, err := ParseEvent([]byte(fmt.Sprintf(form, i)))
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
func checkpointAt(t testing.TB, l *tlog.Log, s note.Signer, size int64) []byte {
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
func proofAt(t testing.TB, l *tlog.Log, index, size int64) InclusionProof {
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
	withMember, err := ParseEvent([]byte(`{"n":3,"x":0}`))
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
		"event with an added member":    {msg, withMember, good, ErrNotVerified},
		"wrong index":                   {msg, events[3], proofAt(t, l, 4, 10), ErrNotVerified},
		"index set to another leaf":     {msg, events[3], InclusionProof{Index: 4, TreeSize: 10, Hashes: good.Hashes}, ErrNotVerified},
		"proof hash changed":            {msg, events[3], badHash, ErrNotVerified},
		"proof hash missing":            {msg, events[3], short, ErrNotVerified},
		"checkpoint of another key":     {checkpointAt(t, l, other, 10), events[3], good, ErrSignature},
		"checkpoint with another root":  {otherRoot, events[3], good, ErrNotVerified},
		"checkpoint of the empty tree":  {empty, events[3], good, ErrTreeSize},
		"proof size larger":             {msg, events[3], larger, ErrTreeSize},
		"proof size equal, with a root": {msg, events[3], withRoot, ErrProof},
		"proof size smaller, no root":   {msg, events[3], proofAt(t, l, 3, 5), ErrProof},
		"index past the size":           {msg, events[3], InclusionProof{Index: 10, TreeSize: 10, Hashes: good.Hashes}, ErrNotVerified},
		"checkpoint note is bad":        {msg[:len(msg)-3], events[3], good, ErrSignature},
	} {
		res, err := Inclusion(v, tc.msg, tc.e, tc.p)
		wantErr(t, name, err, tc.want)
		if err != nil && !reflect.DeepEqual(res, Result{}) {
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

// bridgedProof returns the proof file content for leaf index in the tree of
// size m, with the root at m and the consistency proof from m to n.
func bridgedProof(t testing.TB, l *tlog.Log, index, m, n int64) InclusionProof {
	t.Helper()
	p := proofAt(t, l, index, m)
	root, err := l.RootAt(m)
	if err != nil {
		t.Fatal(err)
	}
	cons, err := l.ProveConsistency(m, n)
	if err != nil {
		t.Fatal(err)
	}
	p.Root, p.Consistency = &root, cons
	return p
}

// T-S-14: a proof at a size below the checkpoint size needs the root at that
// size and a consistency proof. Both must verify.
func TestTS14_InclusionBridged(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, events := realLog(t, 300)
	msg := checkpointAt(t, l, s, 300)
	root300, _ := l.RootAt(300)
	good := bridgedProof(t, l, 3, 5, 300)
	res, err := Inclusion(v, msg, events[3], good)
	if err != nil || res.Size != 300 || res.Root != root300 || res.LeafIndex != 3 ||
		!slices.Equal(res.Proof, good.Hashes) || !slices.Equal(res.Consistency, good.Consistency) {
		t.Fatalf("bridged proof: %+v, %v", res, err)
	}
	// A proof file read from JSON gives the same result.
	parsed, err := ParseInclusionProof(proofJSON(good))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inclusion(v, msg, events[3], parsed); err != nil {
		t.Errorf("bridged proof from a file: %v", err)
	}
	if _, err := Inclusion(v, msg, events[298], bridgedProof(t, l, 298, 299, 300)); err != nil {
		t.Errorf("proof one leaf below the checkpoint: %v", err)
	}
	wrongRoot := bridgedProof(t, l, 3, 5, 300)
	wrongRoot.Root = &modtlog.Hash{1}
	badCons := bridgedProof(t, l, 3, 5, 300)
	badCons.Consistency = slices.Clone(badCons.Consistency)
	badCons.Consistency[0][0] ^= 1
	badIncl := bridgedProof(t, l, 3, 5, 300)
	badIncl.Hashes = slices.Clone(badIncl.Hashes)
	badIncl.Hashes[0][0] ^= 1
	noCons := bridgedProof(t, l, 3, 5, 300)
	noCons.Consistency = []modtlog.Hash{}
	atSize := proofAt(t, l, 3, 300)
	r := modtlog.Hash{1}
	atSize.Root, atSize.Consistency = &r, []modtlog.Hash{}
	atSizeRootOnly := proofAt(t, l, 3, 300)
	atSizeRootOnly.Root = &r
	zero := InclusionProof{TreeSize: 0, Hashes: []modtlog.Hash{}, Root: &modtlog.Hash{}, Consistency: []modtlog.Hash{}}
	for name, tc := range map[string]struct {
		p    InclusionProof
		want error
	}{
		"wrong root at m":             {wrongRoot, ErrNotVerified},
		"changed consistency hash":    {badCons, ErrFork},
		"changed inclusion hash":      {badIncl, ErrNotVerified},
		"empty consistency proof":     {noCons, ErrFork},
		"root at the checkpoint size": {atSize, ErrProof},
		"root alone at the size":      {atSizeRootOnly, ErrProof},
		"size 0 with a root":          {zero, ErrNotVerified},
		"no root below the size":      {proofAt(t, l, 3, 5), ErrProof},
		"consistency of another sizes": {func() InclusionProof {
			p := bridgedProof(t, l, 3, 5, 300)
			c := bridgedProof(t, l, 3, 6, 300)
			p.Consistency = c.Consistency
			return p
		}(), ErrFork},
		"size above the checkpoint size": {InclusionProof{Index: 3, TreeSize: 301, Hashes: good.Hashes}, ErrTreeSize},
	} {
		res, err := Inclusion(v, msg, events[3], tc.p)
		wantErr(t, name, err, tc.want)
		if err != nil && !reflect.DeepEqual(res, Result{}) {
			t.Errorf("%s: result is not empty with an error: %+v", name, res)
		}
	}
}

// proofJSON writes the proof file form of p (04 §7).
func proofJSON(p InclusionProof) []byte {
	list := func(hs []modtlog.Hash) string {
		items := make([]string, 0, len(hs))
		for _, h := range hs {
			items = append(items, `"`+base64.StdEncoding.EncodeToString(h[:])+`"`)
		}
		return "[" + strings.Join(items, ",") + "]"
	}
	s := fmt.Sprintf(`{"index":%d,"tree_size":%d,"hashes":%s`, p.Index, p.TreeSize, list(p.Hashes))
	if p.Root != nil {
		s += fmt.Sprintf(`,"root":"%s","consistency":%s`, base64.StdEncoding.EncodeToString(p.Root[:]), list(p.Consistency))
	}
	return []byte(s + "}")
}

// T-S-14: the check does not panic. The event bytes and the proof bytes must
// parse. If they do not, the target returns at once. For any checkpoint bytes,
// an error gives the zero Result. A success gives a Result that matches the
// inputs. The seeds hold verified cases and refused cases.
func FuzzTS14_Inclusion(f *testing.F) {
	s, text := newKey(f, origin)
	v, _ := ParseKey([]byte(text))
	l, events := realLog(f, 10)
	msg := checkpointAt(f, l, s, 10)
	good := proofAt(f, l, 3, 10)
	otherRoot, _ := tlog.SignCheckpoint(s, 10, modtlog.Hash{9})
	root := modtlog.Hash{1}
	withRoot := proofAt(f, l, 3, 10)
	withRoot.Root, withRoot.Consistency = &root, []modtlog.Hash{}
	bridged := bridgedProof(f, l, 3, 5, 10)
	for _, seed := range []struct{ cp, ev, pf []byte }{
		{msg, events[3].Raw, proofJSON(good)},                                                        // verified
		{msg, events[4].Raw, proofJSON(good)},                                                        // another event
		{msg, events[3].Raw, proofJSON(proofAt(f, l, 4, 10))},                                        // wrong index
		{msg, events[3].Raw, proofJSON(InclusionProof{Index: 3, TreeSize: 11, Hashes: good.Hashes})}, // larger tree
		{msg, events[3].Raw, proofJSON(proofAt(f, l, 3, 5))},                                         // smaller tree, no root
		{msg, events[3].Raw, proofJSON(bridged)},                                                     // bridged
		{msg, events[3].Raw, proofJSON(withRoot)},                                                    // root at the same size
		{otherRoot, events[3].Raw, proofJSON(good)},                                                  // another root
		{msg[:len(msg)-3], events[3].Raw, proofJSON(good)},                                           // bad note
		{msg, []byte(`{"n":3,"x":0}`), proofJSON(good)},                                              // event with an added member
		{checkpointAt(f, l, s, 0), events[0].Raw, []byte(`{"index":0,"tree_size":0,"hashes":[]}`)},   // empty tree
	} {
		f.Add(seed.cp, seed.ev, seed.pf)
	}
	f.Fuzz(func(t *testing.T, cp, evBytes, pfBytes []byte) {
		e, err := ParseEvent(evBytes)
		if err != nil {
			return
		}
		p, err := ParseInclusionProof(pfBytes)
		if err != nil {
			return
		}
		res, err := Inclusion(v, cp, e, p)
		if err != nil {
			if !reflect.DeepEqual(res, Result{}) {
				t.Errorf("result is not empty with an error: %+v", res)
			}
			return
		}
		c, err := ParseCheckpoint(cp, v)
		if err != nil {
			t.Fatalf("Inclusion accepted a checkpoint that ParseCheckpoint refuses: %v", err)
		}
		if res.Origin != c.Origin || res.Size != c.Size || res.Root != c.Root ||
			res.EventHash != e.Hash || res.LeafIndex != p.Index || !slices.Equal(res.Proof, p.Hashes) ||
			!slices.Equal(res.Consistency, p.Consistency) || (p.TreeSize == int64(c.Size)) != (p.Root == nil) ||
			p.TreeSize > int64(c.Size) {
			t.Errorf("result does not match the inputs: %+v", res)
		}
	})
}
