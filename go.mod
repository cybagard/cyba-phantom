module github.com/cybagard/cyba-phantom

// The build pins the exact release via GOTOOLCHAIN=go1.27.2 (Makefile,
// CI env): every build runs the same Go, downloaded with Go's checksum
// verification when the local toolchain differs. This is what makes the
// two-build hash compare (T-P-07) meaningful. M-1 has three dependencies:
// the YAML parser go.yaml.in/yaml/v3 (SEC-11); golang.org/x/mod for
// the tlog tiles and proofs and the signed checkpoint notes (sumdb/tlog,
// sumdb/note; ADR-002, SEC-16); and modernc.org/sqlite, a CGO-free
// SQLite for the event store (ADR-002, SEC-20; C1). x/mod must stay at
// v0.40.0 or later: earlier versions do not check every tile against its
// parent in tlog.TileHashReader (GO-2026-6179). modernc.org/sqlite
// v1.60.1 embeds SQLite 3.53.4; a bump names the new embedded SQLite
// version and its sqlite.org CVE check. The second require block holds
// its indirect modules.
go 1.27.2

require (
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/mod v0.41.0
	modernc.org/sqlite v1.60.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.48.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
