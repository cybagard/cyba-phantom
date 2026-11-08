package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// realHasHardwareAES is the real CPU check. A package variable is set before
// init runs, so it holds the function that init replaces.
var realHasHardwareAES = hasHardwareAES

// Some other tests of the package compare exact output. Set the CPU check to
// hardware AES for them, so that they do not depend on the host CPU.
func init() {
	hasHardwareAES = func() bool { return true }
}

// startWithAES runs the start with an injected CPU check. It stops serve after
// the start line, and returns the finished run and the flag after the start.
func startWithAES(t *testing.T, hw bool) (r *running, flag bool) {
	t.Helper()
	old := hasHardwareAES
	t.Cleanup(func() { hasHardwareAES = old; noHardwareAES.Store(false) })
	hasHardwareAES = func() bool { return hw }
	https, plain, ca := openListeners(t)
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
	r = launchServe(t, cfg, tempState(t, cfg), realDeps)
	// The wait has a bound: a start line without the fixed text must fail.
	select {
	case <-r.out.started:
	case <-r.done:
		t.Fatalf("serve ended before the start line: exit %d; stderr %q", r.code, r.err.String())
	case <-time.After(netWait):
		t.Fatalf("no start line in %v; stdout %q", netWait, r.out.String())
	}
	flag = noHardwareAES.Load()
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(sigtermWait):
		t.Fatalf("serve did not return %v after the cancel", sigtermWait)
	}
	return r, flag
}

// stderrCount returns how many lines of text are equal to line.
func stderrCount(text, line string) int {
	n := 0
	for _, l := range strings.Split(text, "\n") {
		if l == line {
			n++
		}
	}
	return n
}

// TestTS29_NoHardwareAESWarns checks the start with no hardware AES. The
// fixed warning line comes one time on stderr. The start line comes on stdout.
// Serve runs until the stop and gives exit 0 (SEC-33).
func TestTS29_NoHardwareAESWarns(t *testing.T) {
	r, _ := startWithAES(t, false)
	const line = "phantom: warning: no hardware AES, token verify is not constant time"
	if n := stderrCount(r.err.String(), line); n != 1 {
		t.Errorf("warning line %d times, want 1; stderr %q", n, r.err.String())
	}
	if !strings.Contains(r.out.String(), "phantom: started") {
		t.Errorf("no start line; stdout %q", r.out.String())
	}
	if r.code != 0 {
		t.Errorf("exit %d, want 0", r.code)
	}
}

// TestTS29_NoHardwareAESFlagAndSuffix checks that the same start sets the
// health flag and adds the suffix to the start line. The suffix is the only
// change: no part of the store or the bundle reports it as not healthy.
func TestTS29_NoHardwareAESFlagAndSuffix(t *testing.T) {
	r, flag := startWithAES(t, false)
	if !flag {
		t.Error("the health flag is not set after the start")
	}
	base, _ := startWithAES(t, true)
	want := strings.TrimSuffix(base.out.String(), "\n") + " — no hardware AES\n"
	if got := r.out.String(); got != want {
		t.Errorf("start line %q, want %q", got, want)
	}
}

// TestTS29_HardwareAESIsQuiet checks that with hardware AES the start writes
// no warning, does not set the flag, and adds no suffix.
func TestTS29_HardwareAESIsQuiet(t *testing.T) {
	noHardwareAES.Store(true) // A stale flag: the start must clear it.
	r, flag := startWithAES(t, true)
	if flag {
		t.Error("the health flag is set with hardware AES")
	}
	if n := strings.Count(r.err.String(), "no hardware AES"); n != 0 {
		t.Errorf("warning text in stderr %q, want none", r.err.String())
	}
	if got := r.out.String(); strings.Contains(got, "AES") || !strings.HasPrefix(got, "phantom: started") {
		t.Errorf("start line %q, want the start line with no AES suffix", got)
	}
}

// aesHelperEnv makes TestTS29_RealCheckHelper run. If it is not set, the
// helper skips.
const aesHelperEnv = "PHANTOM_TEST_AES_HELPER"

// TestTS29_RealCheckOffGivesFalse runs the test binary again with
// GODEBUG=cpu.aes=off. Then x/sys/cpu reports no AES on each host, so the real
// CPU check must give false (SEC-33).
func TestTS29_RealCheckOffGivesFalse(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("the cpu.aes option exists on amd64 and arm64 only")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTS29_RealCheckHelper$")
	cmd.Env = append(os.Environ(), aesHelperEnv+"=1", "GODEBUG=cpu.aes=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v (context %v), output:\n%s", err, ctx.Err(), out)
	}
	// A skipped helper or a pattern with no test also exits 0.
	if !strings.Contains(string(out), "real check: false\n") {
		t.Errorf("child output has no result of false:\n%s", out)
	}
}

// TestTS29_RealCheckHelper is the child of TestTS29_RealCheckOffGivesFalse.
func TestTS29_RealCheckHelper(t *testing.T) {
	if os.Getenv(aesHelperEnv) == "" {
		t.Skip("child of TestTS29_RealCheckOffGivesFalse")
	}
	fmt.Printf("real check: %v\n", realHasHardwareAES())
}

// TestTS29_AESRule checks the rule for each architecture and each operand.
func TestTS29_AESRule(t *testing.T) {
	x86 := cpuBits{x86AES: true, sse41: true, ssse3: true}
	for _, c := range []struct {
		name, arch string
		bits       cpuBits
		want       bool
	}{
		{"amd64 all", "amd64", x86, true},
		{"amd64 no AES", "amd64", cpuBits{sse41: true, ssse3: true}, false},
		{"amd64 no SSE4.1", "amd64", cpuBits{x86AES: true, ssse3: true}, false},
		{"amd64 no SSSE3", "amd64", cpuBits{x86AES: true, sse41: true}, false},
		{"amd64 arm field only", "amd64", cpuBits{arm64AES: true}, false},
		{"arm64 AES", "arm64", cpuBits{arm64AES: true}, true},
		{"arm64 no AES", "arm64", x86, false},
		{"ppc64le", "ppc64le", cpuBits{}, true},
		{"ppc64", "ppc64", cpuBits{}, true},
		{"s390x both", "s390x", cpuBits{s390xAES: true, s390xCBC: true}, true},
		{"s390x no CBC", "s390x", cpuBits{s390xAES: true}, false},
		{"s390x no AES", "s390x", cpuBits{s390xCBC: true}, false},
		{"386", "386", cpuBits{x86AES: true, sse41: true, ssse3: true, arm64AES: true}, false},
		{"riscv64", "riscv64", cpuBits{arm64AES: true}, false},
	} {
		if got := aesAsm(c.arch, c.bits); got != c.want {
			t.Errorf("%s: aesAsm = %v, want %v", c.name, got, c.want)
		}
	}
}
