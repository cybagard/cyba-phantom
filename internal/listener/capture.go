package listener

import (
	"context"
	"crypto/tls"
	"sync/atomic"
)

// Caps of the lists in a Hello. A list over its cap keeps its first entries.
const (
	maxCipherSuites = 128
	maxExtensions   = 128
	maxSigSchemes   = 64
	maxGroups       = 64
	maxVersions     = 16
	maxALPN         = 255
)

// Hello is the copy of the first ClientHello of a connection. The lists are
// in wire order and keep GREASE values. All arrays have a fixed size, so the
// copy has a fixed size.
type Hello struct {
	ciphers    [maxCipherSuites]uint16
	extensions [maxExtensions]uint16
	sigSchemes [maxSigSchemes]uint16
	groups     [maxGroups]uint16
	versions   [maxVersions]uint16

	nCiphers, nExtensions, nSigSchemes, nGroups, nVersions uint8

	alpn    [maxALPN]byte
	alpnLen uint8

	serverName bool
	cut        bool
}

// CipherSuites returns the cipher suites in wire order. The caller must not
// change the returned slice.
func (h *Hello) CipherSuites() []uint16 { return h.ciphers[:h.nCiphers] }

// Extensions returns the extension IDs in wire order. The caller must not
// change the returned slice.
func (h *Hello) Extensions() []uint16 { return h.extensions[:h.nExtensions] }

// SignatureSchemes returns the signature schemes in wire order. The caller
// must not change the returned slice.
func (h *Hello) SignatureSchemes() []uint16 { return h.sigSchemes[:h.nSigSchemes] }

// SupportedGroups returns the supported groups in wire order. The caller must
// not change the returned slice.
func (h *Hello) SupportedGroups() []uint16 { return h.groups[:h.nGroups] }

// SupportedVersions returns the supported versions in wire order. When the
// client sends no supported_versions extension, crypto/tls extrapolates the
// list from the legacy version, and Extensions has no entry 43. The caller
// must not change the returned slice.
func (h *Hello) SupportedVersions() []uint16 { return h.versions[:h.nVersions] }

// ALPN returns the first ALPN value, or "" when the client sent none. The value
// is raw client bytes. Escape it before it goes to a log or an event (SEC-07).
func (h *Hello) ALPN() string { return string(h.alpn[:h.alpnLen]) }

// HasServerName tells if the client sent a server name. The name is not kept.
func (h *Hello) HasServerName() bool { return h.serverName }

// Cut tells if a list was longer than its cap.
func (h *Hello) Cut() bool { return h.cut }

type stateKey struct{}

// connState is the value of one connection in its context. The first
// ClientHello stays; a later one does not replace it.
type connState struct {
	hello atomic.Pointer[Hello]
}

func withConnState(ctx context.Context) context.Context {
	return context.WithValue(ctx, stateKey{}, new(connState))
}

// HelloFrom returns the ClientHello copy of the connection of a request, or
// nil when there is none.
func HelloFrom(ctx context.Context) *Hello {
	if s, ok := ctx.Value(stateKey{}).(*connState); ok {
		return s.hello.Load()
	}
	return nil
}

// captureHello is the GetConfigForClient callback. It does no I/O, takes no
// lock and always returns nil, nil.
func captureHello(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	if s, ok := chi.Context().Value(stateKey{}).(*connState); ok {
		s.capture(chi)
	}
	return nil, nil
}

func (s *connState) capture(chi *tls.ClientHelloInfo) {
	h := new(Hello)
	var c [5]bool
	h.nCiphers, c[0] = copyCapped(h.ciphers[:], chi.CipherSuites)
	h.nExtensions, c[1] = copyCapped(h.extensions[:], chi.Extensions)
	h.nSigSchemes, c[2] = copyCapped(h.sigSchemes[:], chi.SignatureSchemes)
	h.nGroups, c[3] = copyCapped(h.groups[:], chi.SupportedCurves)
	h.nVersions, c[4] = copyCapped(h.versions[:], chi.SupportedVersions)
	h.cut = c[0] || c[1] || c[2] || c[3] || c[4]
	if len(chi.SupportedProtos) > 0 {
		h.alpnLen = uint8(copy(h.alpn[:], chi.SupportedProtos[0]))
	}
	h.serverName = chi.ServerName != ""
	s.hello.CompareAndSwap(nil, h)
}

// copyCapped copies the first entries of src into dst. It returns their number
// and true when src has more entries than dst.
func copyCapped[T ~uint16](dst []uint16, src []T) (uint8, bool) {
	for i, v := range src {
		if i == len(dst) {
			return uint8(i), true
		}
		dst[i] = uint16(v)
	}
	return uint8(len(src)), false
}
