module github.com/cybagard/cyba-phantom

// The build pins the exact release via GOTOOLCHAIN=go1.27.1 (Makefile,
// CI env): every build runs the same Go, downloaded with Go's checksum
// verification when the local toolchain differs. This is what makes the
// two-build hash compare (T-P-07) meaningful. Zero dependencies in M-1.
go 1.27.1
