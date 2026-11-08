package main

import (
	"runtime"
	"sync/atomic"

	"golang.org/x/sys/cpu"
)

// aesWarning is the one fixed line of the start for a CPU with no hardware
// AES. Without hardware AES, the token verify is not constant time (SEC-33).
const aesWarning = "phantom: warning: no hardware AES, token verify is not constant time"

// noHardwareAES is the health flag for a CPU with no hardware AES.
// The start sets it. It does not change the Healthy result of any part.
var noHardwareAES atomic.Bool

// cpuBits holds the CPU fields that the rule of aesAsm reads.
type cpuBits struct {
	x86AES, sse41, ssse3 bool
	arm64AES             bool
	s390xAES, s390xCBC   bool
}

// hasHardwareAES is the seam of serveWith. A test replaces it.
var hasHardwareAES = func() bool {
	return aesAsm(runtime.GOARCH, cpuBits{
		x86AES: cpu.X86.HasAES, sse41: cpu.X86.HasSSE41, ssse3: cpu.X86.HasSSSE3,
		arm64AES: cpu.ARM64.HasAES,
		s390xAES: cpu.S390X.HasAES, s390xCBC: cpu.S390X.HasAESCBC,
	})
}

// aesAsm reports whether crypto/aes uses its assembly path on goarch.
// It follows the selection in go1.27.3 of the standard library.
// Thus the warning shows exactly when crypto/aes uses the software path.
func aesAsm(goarch string, c cpuBits) bool {
	switch goarch {
	case "amd64":
		return c.x86AES && c.sse41 && c.ssse3
	case "arm64":
		return c.arm64AES
	case "ppc64", "ppc64le":
		return true // The assembly path runs on each POWER8 or newer CPU.
	case "s390x":
		return c.s390xAES && c.s390xCBC
	}
	return false // Each other architecture has no assembly path.
}
