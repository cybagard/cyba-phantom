//go:build !unix

package store

import "os"

// diskSpace cannot find the free space on this system, so the check of the
// space fails closed. Open fails here too (see fileFacts).
var diskSpace = func(*os.Root, string) (size, fsSize, free uint64, ok bool) { return 0, 0, 0, false }
