//go:build !unix

package config

// The package uses unix file calls. On another system, the first build
// error is the name below. Other undefined names follow it.
var _ = the_config_package_supports_unix_only
