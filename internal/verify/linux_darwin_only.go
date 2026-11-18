//go:build !(linux || darwin) || android || ios

package verify

// The verifier supports only Linux and macOS. Android and ios set the linux
// and darwin tags, so the constraint names them. On another unix system, on
// android and on ios, the first build error of the package is the name below.
// On a system that is not unix, the safefile guard stops the build first.
var _ = the_verify_package_supports_linux_and_darwin_only
