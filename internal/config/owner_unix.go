//go:build unix

package config

import (
	"io/fs"
	"syscall"
)

// fileOwner returns the owner user of a file.
func fileOwner(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
