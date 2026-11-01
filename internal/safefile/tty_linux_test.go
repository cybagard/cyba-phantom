//go:build linux

package safefile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// ttyEnv names the variable that makes the test binary run as the child. Its
// value is the row. The variable with the suffix _NAME holds the /dev name.
const ttyEnv = "SAFEFILE_TTY_ROW"

// TestTS23_NoControllingTerminal checks that Open, OpenPath and OpenRoot do
// not make a terminal the controlling terminal. Open and OpenPath use
// O_NOCTTY. OpenRoot uses O_DIRECTORY, which refuses a terminal. A session
// leader with no controlling terminal gets one when it opens a terminal
// device without such a guard. Each row runs in its own child, because a
// process gets a controlling terminal only once.
func TestTS23_NoControllingTerminal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can make an entry in /dev")
	}
	if row := os.Getenv(ttyEnv); row != "" {
		ttyChild(t, row, os.Getenv(ttyEnv+"_NAME"))
		return
	}
	for _, row := range []string{"Open", "OpenPath", "OpenRoot"} {
		t.Run(row, func(t *testing.T) {
			name := fmt.Sprintf("safefile-tty-%d-%s", os.Getpid(), row)
			t.Cleanup(func() {
				os.Remove("/dev/" + name)
				os.Remove("/dev/q" + name)
				os.Remove("/dev/old" + name)
			})
			cmd := exec.Command(os.Args[0], "-test.v",
				"-test.run=^TestTS23_NoControllingTerminal$")
			cmd.Env = append(os.Environ(), ttyEnv+"="+row, ttyEnv+"_NAME="+name)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			out, err := cmd.CombinedOutput()
			pass := []byte("--- PASS: TestTS23_NoControllingTerminal")
			if err != nil || !bytes.Contains(out, pass) {
				t.Fatalf("child: %v\n%s", err, out)
			}
		})
	}
}

// ttyChild runs in a session with no controlling terminal. It swaps a link to
// a terminal device in after the check, and wants an error and no new
// controlling terminal. Open and OpenPath want ErrChanged. OpenRoot wants
// ErrType, because O_DIRECTORY makes the kernel refuse the terminal.
func ttyChild(t *testing.T, row, name string) {
	sid, _, e := syscall.RawSyscall(syscall.SYS_GETSID, 0, 0, 0)
	if e != 0 || int(sid) != os.Getpid() {
		t.Fatalf("session %d, %v, want a session leader (pid %d)",
			sid, e, os.Getpid())
	}
	if tty := ttyNr(t); tty != "0" {
		t.Fatalf("tty_nr = %s before the open, want 0", tty)
	}
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var unlock, n uint32
	ioctl(t, m, syscall.TIOCSPTLCK, &unlock)
	ioctl(t, m, syscall.TIOCGPTN, &n)
	pts := "pts/" + strconv.Itoa(int(n))
	switch row {
	case "Open":
		r, err := os.OpenRoot("/dev")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		// O_EXCL and O_NOFOLLOW: the open does not follow a link at the name.
		w, err := os.OpenFile("/dev/"+name,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		w.Close()
		t.Cleanup(func() { os.Remove("/dev/" + name) })
		swapAfterCheck(t, func(string) {
			if err := os.Symlink(pts, "/dev/q"+name); err != nil {
				t.Error(err)
			}
			if err := os.Rename("/dev/q"+name, "/dev/"+name); err != nil {
				t.Error(err)
			}
		})
		if err := open(t, r, name, base); !errors.Is(err, ErrChanged) {
			t.Errorf("Open: err = %v, want ErrChanged", err)
		}
	case "OpenPath":
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		swapAfterCheck(t, func(string) {
			if err := os.Symlink("/dev/"+pts, p+".q"); err != nil {
				t.Error(err)
			}
			if err := os.Rename(p+".q", p); err != nil {
				t.Error(err)
			}
		})
		rule := base
		rule.FollowEnd = true
		f, fi, err := OpenPath(p, rule)
		if err = verdict(t, f, fi, err); !errors.Is(err, ErrChanged) {
			t.Errorf("OpenPath: err = %v, want ErrChanged", err)
		}
	case "OpenRoot":
		r, err := os.OpenRoot("/dev")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if err := os.Mkdir("/dev/"+name, 0o700); err != nil {
			t.Fatal(err)
		}
		swapAfterCheck(t, func(string) {
			if err := os.Symlink(pts, "/dev/q"+name); err != nil {
				t.Error(err)
			}
			if err := os.Rename("/dev/"+name, "/dev/old"+name); err != nil {
				t.Error(err)
			}
			if err := os.Rename("/dev/q"+name, "/dev/"+name); err != nil {
				t.Error(err)
			}
		})
		rule := Rule{Type: Dir, Owner: OwnerSelf}
		if _, err := OpenRoot(r, name, rule); !errors.Is(err, ErrType) {
			t.Errorf("OpenRoot: err = %v, want ErrType", err)
		}
	default:
		t.Fatalf("unknown row %q", row)
	}
	if tty := ttyNr(t); tty != "0" {
		t.Errorf("tty_nr = %s, want 0", tty)
	}
}

// ioctl runs request on f with the pointer arg.
func ioctl(t *testing.T, f *os.File, request uintptr, arg *uint32) {
	t.Helper()
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), request,
		uintptr(unsafe.Pointer(arg)))
	if e != 0 {
		t.Fatalf("ioctl %#x: %v", request, e)
	}
}

// ttyNr gives field 7 of /proc/self/stat. The command name in field 2 can
// hold spaces and brackets, so the parse starts after the last ")".
func ttyNr(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	// After ")": state, ppid, pgrp, session, tty_nr.
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	if len(f) < 5 {
		t.Fatalf("short stat line %q", s)
	}
	return f[4]
}
