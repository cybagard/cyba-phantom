//go:build !unix

package config

// The package uses unix file calls. It imports internal/safefile, so on a
// system that is not unix, the safefile guard stops the build before this
// name shows.
var _ = the_config_package_supports_unix_only
