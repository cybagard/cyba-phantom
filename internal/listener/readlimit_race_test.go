//go:build race

package listener

// readAllocMax is the most that Load may allocate for a file that grows before
// the read, with the race detector. A read limit of 64 KiB + 1 byte allocates
// 286 KiB. A read limit of twice that allocates 606 KiB.
const readAllocMax = 448 << 10
