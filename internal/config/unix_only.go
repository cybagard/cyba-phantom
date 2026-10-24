//go:build !unix

package config

// The package uses unix file calls. On another system the build fails here
// with the name below, and not with a list of undefined symbols.
var _ = the_config_package_supports_unix_only
