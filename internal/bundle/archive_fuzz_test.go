package bundle

import (
	"slices"
	"testing"
)

// T-S-19: no panic for any input. On success, the archive is within all caps.
func FuzzTS19ReadArchive(f *testing.F) {
	fail, pass := fixtures()
	for _, x := range append(fail, pass...) {
		f.Add(x.b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := ReadArchive(b)
		if err != nil {
			if a != nil || err != ErrArchiveInvalid {
				t.Fatalf("failure gave archive %v, len %d, error %v", a != nil, lenOf(a), err)
			}
			return
		}
		names := a.Names()
		if len(names) != a.Len() || a.Len() > MaxEntries {
			t.Fatalf("%d names, len %d", len(names), a.Len())
		}
		if !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
			t.Fatal("names are not sorted and unique")
		}
		total := 0
		for _, n := range names {
			data, ok := a.File(n)
			if !ok || len(data) > MaxEntryBytes {
				t.Fatalf("entry %q: found %v, size %d", n, ok, len(data))
			}
			total += len(data)
		}
		if total > MaxDecodedBytes {
			t.Fatalf("files hold %d bytes", total)
		}
	})
}
