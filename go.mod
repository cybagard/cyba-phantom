module github.com/cybagard/cyba-phantom

// The build pins the exact release via GOTOOLCHAIN=go1.27.1 (Makefile,
// CI env): every build runs the same Go, downloaded with Go's checksum
// verification when the local toolchain differs. This is what makes the
// two-build hash compare (T-P-07) meaningful. M-1 has one dependency,
// the YAML parser go.yaml.in/yaml/v3 (SEC-11).
go 1.27.1

require go.yaml.in/yaml/v3 v3.0.5
