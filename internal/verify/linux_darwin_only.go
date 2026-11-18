//go:build !(linux || darwin)

package verify

// The verifier supports only Linux and macOS. On another system, the first
// build error is the name below. Other undefined names follow it.
var _ = the_verify_package_supports_linux_and_darwin_only
