//go:build !unix

package safefile

// The package uses unix file calls. On another system, the build error
// is the name below.
var _ = the_safefile_package_supports_unix_only
