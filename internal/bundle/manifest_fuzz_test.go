package bundle

import (
	"testing"
	"time"
)

// T-S-19: no panic for any input. A failure is ErrManifestInvalid. A success
// is a manifest that is within every rule of the format, and its two checks give
// a fixed error or none.
func FuzzTS19ParseManifest(f *testing.F) {
	for _, c := range append(refusedManifests(), validManifests()...) {
		f.Add([]byte(c.in))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseManifest(b)
		if err != nil {
			if m != nil || err != ErrManifestInvalid {
				t.Fatalf("failure gave manifest %v, error %v", m != nil, err)
			}
			return
		}
		if len(b) > MaxManifestBytes || !validVersion(m.Version) || !validKeyID(m.KeyID) {
			t.Fatalf("manifest %+v from %d bytes", m, len(b))
		}
		if !m.Created.Before(m.Expires) || m.Expires.Sub(m.Created) > maxValidity ||
			m.Created.Nanosecond() != 0 || m.Expires.Nanosecond() != 0 ||
			m.Created.Location() != time.UTC || m.Expires.Location() != time.UTC {
			t.Fatalf("times %v, %v", m.Created, m.Expires)
		}
		if m.Rotation != nil && !validKeyID(m.Rotation.From) {
			t.Fatalf("rotation %+v", m.Rotation)
		}
		if err := m.CheckEngine(); err != nil && err != ErrMinEngine {
			t.Fatalf("engine check: %v", err)
		}
		if err := m.CheckExpiry(testNow); err != nil && err != ErrExpired {
			t.Fatalf("expiry check: %v", err)
		}
	})
}
