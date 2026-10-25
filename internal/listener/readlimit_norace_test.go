//go:build !race

package listener

// readAllocMax is the most that Load may allocate for a file that grows before
// the read, without the race detector. A read limit of 64 KiB + 1 byte
// allocates 144 KiB. A read limit of twice that allocates 304 KiB.
const readAllocMax = 224 << 10
