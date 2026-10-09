module github.com/cybagard/cyba-phantom

// The build pins the exact release via GOTOOLCHAIN=go1.27.1 (Makefile,
// CI env): every build runs the same Go, downloaded with Go's checksum
// verification when the local toolchain differs. This is what makes the
// two-build hash compare (T-P-07) meaningful. M-1 has two dependencies:
// the YAML parser go.yaml.in/yaml/v3 (SEC-11), and golang.org/x/mod for
// the tlog tiles and proofs and the signed checkpoint notes (sumdb/tlog,
// sumdb/note; ADR-002, SEC-16). x/mod must stay at v0.40.0 or later:
// earlier versions do not check every tile against its parent in
// tlog.TileHashReader (GO-2026-6179).
go 1.27.1

require (
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/mod v0.41.0
)
