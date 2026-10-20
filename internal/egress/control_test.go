package egress

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestTS21ControlRefusesBadInput(t *testing.T) {
	for _, addr := range []string{":443", "[::1", "1.2.3.4", "<nil>", ""} {
		err := control(context.Background(), "tcp4", addr, nil)
		if err != ErrRefused {
			t.Errorf("address %q: got %v", addr, err)
		}
	}
	for _, network := range []string{"ip4", "unix", "tcp", "udp", ""} {
		err := control(context.Background(), network, "8.8.8.8:443", nil)
		if err != ErrRefused {
			t.Errorf("network %q: got %v", network, err)
		}
	}
}

func TestTS21ControlAppliesTheRule(t *testing.T) {
	tests := []struct {
		network, global string
	}{
		{"tcp4", "8.8.8.8:443"},
		{"udp4", "8.8.8.8:53"},
		{"tcp6", "[2606:4700::1111]:443"},
		{"udp6", "[2606:4700::1111]:53"},
	}
	refused := []string{
		"169.254.169.254:80", "[fe80::1%eth0]:443", "[::ffff:10.0.0.1]:443",
	}
	for _, tc := range tests {
		err := control(context.Background(), tc.network, tc.global, nil)
		if err != nil {
			t.Errorf("%s %s: got %v", tc.network, tc.global, err)
		}
		for _, addr := range refused {
			err := control(context.Background(), tc.network, addr, nil)
			if err != ErrRefused {
				t.Errorf("%s %s: got %v", tc.network, addr, err)
			}
		}
	}
}

func TestTS21ErrRefusedText(t *testing.T) {
	text := ErrRefused.Error()
	if text == "" || strings.ContainsAny(text, "0123456789:") {
		t.Errorf("text %q has a digit or a colon", text)
	}
}

func TestTS21RefusalSurvivesOpError(t *testing.T) {
	err := control(context.Background(), "tcp4", "10.0.0.1:80", nil)
	wrapped := &net.OpError{Op: "dial", Net: "tcp", Err: err}
	if !errors.Is(wrapped, ErrRefused) {
		t.Errorf("errors.Is is false for %v", wrapped)
	}
}
