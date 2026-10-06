//go:build !unix

package config

import "io/fs"

// fileOwner cannot find the owner on this system, so the owner rule fails closed.
func fileOwner(fs.FileInfo) (uint32, bool) { return 0, false }
