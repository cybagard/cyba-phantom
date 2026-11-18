//go:build !unix

package safefile

// The package uses unix file calls. On a system that is not unix, the build
// error is the name below.
var _ = the_safefile_package_supports_unix_only
