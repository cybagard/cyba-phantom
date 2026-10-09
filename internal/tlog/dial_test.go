package tlog

import (
	"errors"
	"testing"
)

// T-S-13: the dial check refuses an unspecified, link-local unicast, or
// multicast address, also in the IPv4-mapped form. Loopback and public addresses
// are allowed.
func TestTS13_DialRefusesAddresses(t *testing.T) {
	refused := []string{
		"169.254.169.254:443", "0.0.0.0:443", "224.0.0.1:443", "239.1.2.3:443",
		"[fe80::1]:443", "[::]:443", "[ff02::1]:443", "[ff01::1]:443", "[ff05::1]:443",
		"[::ffff:169.254.169.254]:443", "[::ffff:0.0.0.0]:443", "[::ffff:224.0.0.1]:443",
		"not-an-address",
	}
	allowed := []string{"127.0.0.1:443", "[::1]:443", "93.184.216.34:443", "[2001:db8::1]:443", "10.0.0.1:443"}
	for _, a := range refused {
		if err := refuseAddress("tcp", a, nil); !errors.Is(err, errPublishAddress) {
			t.Errorf("%s: err = %v, want a refusal", a, err)
		}
	}
	for _, a := range allowed {
		if err := refuseAddress("tcp", a, nil); err != nil {
			t.Errorf("%s: err = %v, want none", a, err)
		}
	}
}
