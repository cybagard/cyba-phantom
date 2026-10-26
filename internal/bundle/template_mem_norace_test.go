//go:build !race

package bundle

// ts25Race is false without the race detector. T-S-25 then checks the memory
// and time pass lines of each case.
const ts25Race = false
