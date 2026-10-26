//go:build race

package bundle

// ts25Race is true with the race detector. T-S-25 then checks no pass line for
// the memory and the time, because the detector adds memory and time.
const ts25Race = true
