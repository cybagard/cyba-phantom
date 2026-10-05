//go:build !unix

package main

import "os"

// openNoBlock opens path read-only. Non-Unix systems have no FIFO race.
func openNoBlock(path string) (*os.File, error) {
	return os.Open(path)
}
