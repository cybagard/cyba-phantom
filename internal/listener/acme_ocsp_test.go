package listener

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"
)

// TestTS16OCSPIsOffForACachedCertificateWithAnOCSPURL seeds a certificate whose
// leaf names an OCSP server and an issuer URL on another host. Start loads it,
// and a handshake and a second load use it. The recording guard sees no call.
// The control case turns stapling on. There the guard sees the other host, so
// the seeded certificate does start an OCSP request when stapling is on.
func TestTS16OCSPIsOffForACachedCertificateWithAnOCSPURL(t *testing.T) {
	for _, c := range []struct {
		name     string
		stapling bool
	}{
		{"stapling off", false},
		{"stapling on (control)", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var mu sync.Mutex
			var seen []string
			addr := closedAddr(t)
			a := newTestACME(t, func(p *ACMEParams) {
				p.CA = "https://" + addr
				p.OnEgress = func(h string) { mu.Lock(); seen = append(seen, h); mu.Unlock() }
			})
			// The "stapling off" case keeps the value that NewACME sets.
			if c.stapling {
				a.cfg.OCSP.DisableStapling = false
			}
			now := time.Now()
			seedCertFor(t, a, "decoy.test", now.Add(-time.Hour), now.Add(90*24*time.Hour), []string{"http://ocsp.other.test/"})
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			mustNil(t, a.Start(ctx))
			if _, err := handshake(a, "decoy.test"); err != nil {
				t.Fatal(err)
			}
			if _, err := a.cfg.CacheManagedCertificate(ctx, "decoy.test"); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			// The background work may call the guard for the closed CA port.
			other := slices.DeleteFunc(slices.Clone(seen), func(h string) bool { return h == addr })
			if c.stapling && len(other) == 0 {
				t.Error("control: the OCSP request did not reach the guard")
			}
			if !c.stapling && len(other) != 0 {
				t.Errorf("the guard saw %v", other)
			}
		})
	}
}
