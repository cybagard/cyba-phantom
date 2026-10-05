//go:build unix

package main

import (
	"os"
	"syscall"
)

// openNoBlock opens path read-only without blocking on a FIFO.
func openNoBlock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
