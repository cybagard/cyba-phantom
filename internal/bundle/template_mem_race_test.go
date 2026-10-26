//go:build race

package bundle

// ts25Race is true with the race detector. T-S-25 then checks the memory and
// time pass lines of no case, because the detector adds memory and time.
const ts25Race = true
