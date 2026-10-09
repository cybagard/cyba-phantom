package event

import "testing"

var allKinds = []Kind{
	KindRequest, KindCallback, KindBeacon, KindScoreChange,
	KindBundleLoad, KindBundleRejected, KindAlertSent, KindRetention,
}

// T-S-12: the kind set is closed and the name match is exact.
func TestTS12_KindSet(t *testing.T) {
	names := []string{"request", "callback", "beacon", "score_change",
		"bundle_load", "bundle_rejected", "alert_sent", "retention"}
	for i, n := range names {
		k, err := ParseKind(n)
		if err != nil || k != allKinds[i] || k.String() != n {
			t.Errorf("ParseKind(%q) = %v, %v", n, k, err)
		}
	}
	for _, bad := range []string{"", "Callback", "CALLBACK", " callback", "callback ", "callback\x00", "scorechange", "evidence"} {
		if _, err := ParseKind(bad); err == nil {
			t.Errorf("ParseKind(%q) gave no error", bad)
		}
	}
	for _, k := range []Kind{0, 9, 255} {
		if _, err := k.MarshalText(); err == nil || k.String() != "unknown" {
			t.Errorf("Kind(%d) is accepted", k)
		}
	}
}

// T-S-12: only the 6 evidence kinds are evidence; a value that is not a kind
// is an error and never false.
func TestTS12_EvidencePredicate(t *testing.T) {
	want := map[Kind]bool{KindCallback: true, KindScoreChange: true, KindAlertSent: true,
		KindBundleLoad: true, KindBundleRejected: true, KindRetention: true}
	for _, k := range allKinds {
		got, err := k.IsEvidence()
		if err != nil || got != want[k] {
			t.Errorf("%v.IsEvidence() = %v, %v", k, got, err)
		}
	}
	for _, k := range []Kind{0, 9, 255} {
		if got, err := k.IsEvidence(); err == nil || got {
			t.Errorf("Kind(%d).IsEvidence() = %v, %v", k, got, err)
		}
	}
}

// T-S-12: request and beacon records cannot be hashed; an unknown kind is an
// error; the evidence kinds hash.
func TestTS12_HashEvidenceRefusal(t *testing.T) {
	for _, k := range append(allKinds, 0, 9) {
		r := Record{TS: 1, Kind: k}
		h, err := HashEvidence(r)
		b, berr := EvidenceBytes(r)
		ok, _ := k.IsEvidence()
		if ok != (err == nil) || ok != (berr == nil) {
			t.Errorf("kind %v: hash error %v, bytes error %v", k, err, berr)
		}
		if ok && h != Hash(b) {
			t.Errorf("kind %v: hash differs from Hash of the bytes", k)
		}
		if !ok && h != [32]byte{} {
			t.Errorf("kind %v: refused hash is not zero", k)
		}
	}
}
