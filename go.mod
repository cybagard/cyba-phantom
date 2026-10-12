module github.com/cybagard/cyba-phantom

// The build pins the exact release via GOTOOLCHAIN=go1.27.2 (Makefile,
// CI env): every build runs the same Go, downloaded with Go's checksum
// verification when the local toolchain differs. This is what makes the
// two-build hash compare (T-P-07) meaningful. M-1 has four dependencies:
// the YAML parser go.yaml.in/yaml/v3 (SEC-11); golang.org/x/mod for
// the tlog tiles and proofs and the signed checkpoint notes (sumdb/tlog,
// sumdb/note; ADR-002, SEC-16); modernc.org/sqlite, a CGO-free SQLite
// for the event store (ADR-002, SEC-20; C1); and
// github.com/caddyserver/certmagic for the ACME certificates of the decoy
// listener (FR-01, SEC-21), with go.uber.org/zap for its logger setting.
// golang.org/x/net must stay at v0.60.0 or later (HTTP/2 fixes
// GO-2026-6603, -6610, -6611, -6612, -6617); certmagic v0.25.6 asks only
// for v0.59.0. A certmagic bump names the new acmez and x/net versions
// and its vulnerability check. github.com/letsencrypt/pebble/v2 and
// github.com/letsencrypt/challtestsrv (MPL-2.0) are test dependencies
// only: the ACME test server of T-I-01 runs in the test process; they are
// not in the release binaries. x/mod must stay at
// v0.40.0 or later: earlier versions do not check every tile against its
// parent in tlog.TileHashReader (GO-2026-6179). modernc.org/sqlite
// v1.60.1 embeds SQLite 3.53.4; a bump names the new embedded SQLite
// version and its sqlite.org CVE check. The second require block holds
// the indirect modules.
go 1.27.2

require (
	github.com/caddyserver/certmagic v0.25.6
	github.com/letsencrypt/challtestsrv v1.4.2
	github.com/letsencrypt/pebble/v2 v2.10.1
	go.uber.org/zap v1.28.0
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/mod v0.41.0
	modernc.org/sqlite v1.60.1
)

require (
	github.com/caddyserver/zerossl v0.1.6 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mholt/acmez/v3 v3.1.7 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
