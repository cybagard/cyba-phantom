package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stall is the stalled time of one pressure file.
// ok is false when the file is missing or its text is not valid.
type stall struct {
	d  time.Duration
	ok bool
}

// pressure holds the io and the cpu stall of the cgroup and of the host.
type pressure struct{ ioCgroup, ioHost, cpuCgroup, cpuHost stall }

// parsePressure gives the "total=" value of the "some" line of a pressure file.
// The value is in microseconds.
func parsePressure(text string) (time.Duration, error) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "some" {
			continue
		}
		for _, kv := range f[1:] {
			if v, found := strings.CutPrefix(kv, "total="); found {
				us, err := strconv.ParseUint(v, 10, 63)
				return time.Duration(us) * time.Microsecond, err
			}
		}
		return 0, errors.New("the some line has no total")
	}
	return 0, errors.New("no some line")
}

// readStall reads the pressure file at path. A missing file or a text that
// does not parse gives a stall with ok false.
func readStall(path string) stall {
	b, err := os.ReadFile(path)
	if err != nil {
		return stall{}
	}
	d, err := parsePressure(string(b))
	return stall{d, err == nil}
}

// readPressure reads the io and cpu pressure files of the cgroup and the host.
func readPressure() pressure {
	return pressure{
		ioCgroup:  readStall("/sys/fs/cgroup/io.pressure"),
		ioHost:    readStall("/proc/pressure/io"),
		cpuCgroup: readStall("/sys/fs/cgroup/cpu.pressure"),
		cpuHost:   readStall("/proc/pressure/cpu"),
	}
}

// since gives the stall from begin to s, or "not readable".
func (s stall) since(begin stall) string {
	if !s.ok || !begin.ok {
		return "not readable"
	}
	return (s.d - begin.d).String()
}

// note gives the io and the cpu pressure from p to now. A process that waits
// for the disk or for a CPU has a low CPU time. The pressure counts any stalled
// task of the cgroup or the host. It shows the kind of wait that the kernel
// counted, not proof.
func (p pressure) note(now pressure) string {
	return fmt.Sprintf("; io pressure %s (cgroup), %s (host); cpu pressure %s (cgroup), %s (host) since begin",
		now.ioCgroup.since(p.ioCgroup), now.ioHost.since(p.ioHost),
		now.cpuCgroup.since(p.cpuCgroup), now.cpuHost.since(p.cpuHost))
}

// startNote gives the start line time, then extra, then the pressure note.
// The pressure is the one at begin. The note reads the pressure now.
func (p pressure) startNote(line time.Duration, extra string) string {
	return fmt.Sprintf("; start line %v after begin%s", line, extra) + p.note(readPressure())
}

// wantPressure checks that r has the host io pressure at begin when the host
// has the file. On a host without the file, it checks nothing.
func wantPressure(t *testing.T, r *running) {
	t.Helper()
	if readStall("/proc/pressure/io").ok && !r.pressure.ioHost.ok {
		t.Error("the host io pressure was readable, but r.pressure has none")
	}
}

// TestTI03_ParsePressure checks that the parse reads the total of the some
// line (NFR-05).
func TestTI03_ParsePressure(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       time.Duration
		fail       bool
	}{
		{"some and full", "some avg10=0.00 avg60=0.00 avg300=0.00 total=42\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=7\n", 42 * time.Microsecond, false},
		{"full first", "full avg10=0.00 total=7\nsome avg10=0.00 total=42\n", 42 * time.Microsecond, false},
		{"above 2^32", "some avg10=0.00 total=9999999999\n", 9999999999 * time.Microsecond, false},
		{"no some line", "full avg10=0.00 avg60=0.00 avg300=0.00 total=7\n", 0, true},
		{"no total", "some avg10=0.00 avg60=0.00 avg300=0.00\nfull avg10=0.00 total=7\n", 0, true},
		{"empty", "", 0, true},
	} {
		got, err := parsePressure(tc.text)
		if (err != nil) != tc.fail || got != tc.want {
			t.Errorf("%s: got %v, error %v; want %v, fail %t", tc.name, got, err, tc.want, tc.fail)
		}
	}
}

// TestTI03_ReadStall checks that readStall reads one file. A file with no
// total and a missing file give ok false (NFR-05).
func TestTI03_ReadStall(t *testing.T) {
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "good"), filepath.Join(dir, "bad")
	if err := os.WriteFile(good, []byte("some avg10=0.00 total=42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("some avg10=0.00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readStall(good); got != (stall{42 * time.Microsecond, true}) {
		t.Errorf("valid file: got %+v, want 42µs with ok", got)
	}
	if got := readStall(bad); got.ok {
		t.Errorf("file with no total: got %+v, want ok false", got)
	}
	if got := readStall(filepath.Join(dir, "missing")); got.ok {
		t.Errorf("missing file: got %+v, want ok false", got)
	}
}

// TestTI03_ReadPressure checks that each value of readPressure comes from its
// own file. A stall total never falls, so the value lies between two reads of
// that file. A file that this host does not have gives no check (NFR-05).
func TestTI03_ReadPressure(t *testing.T) {
	paths := [4]string{"/sys/fs/cgroup/io.pressure", "/proc/pressure/io", "/sys/fs/cgroup/cpu.pressure", "/proc/pressure/cpu"}
	var before [4]stall
	for i, path := range paths {
		before[i] = readStall(path)
	}
	got := readPressure()
	for i, path := range paths {
		after := readStall(path)
		v := [4]stall{got.ioCgroup, got.ioHost, got.cpuCgroup, got.cpuHost}[i]
		if before[i].ok && (!v.ok || v.d < before[i].d || v.d > after.d) {
			t.Errorf("%s: before %v, readPressure %+v, after %v", path, before[i].d, v, after.d)
		}
	}
}

// TestTI03_PressureNote checks the text with a distinct value in each place.
// It also checks "not readable" for a begin or a now with no value (NFR-05).
func TestTI03_PressureNote(t *testing.T) {
	ms := func(n time.Duration) stall { return stall{n * time.Millisecond, true} }
	begin := pressure{ms(1), ms(2), ms(3), ms(4)}
	now := pressure{ms(4), ms(8), ms(12), ms(16)}
	want := "; io pressure 3ms (cgroup), 6ms (host); cpu pressure 9ms (cgroup), 12ms (host) since begin"
	if got := begin.note(now); got != want {
		t.Errorf("note = %q, want %q", got, want)
	}
	want = "; io pressure not readable (cgroup), 6ms (host); cpu pressure 9ms (cgroup), 12ms (host) since begin"
	if got := (pressure{ioHost: ms(2), cpuCgroup: ms(3), cpuHost: ms(4)}).note(now); got != want {
		t.Errorf("begin not readable: note = %q, want %q", got, want)
	}
	want = "; io pressure 3ms (cgroup), not readable (host); cpu pressure 9ms (cgroup), 12ms (host) since begin"
	now.ioHost = stall{}
	if got := begin.note(now); got != want {
		t.Errorf("now not readable: note = %q, want %q", got, want)
	}
}

// TestTI03_SlowText checks the failure text of a slow start. It has the start
// line time, the CPU time, and the pressure, in this order. It reads the CPU
// time and the pressure at the time of the call (NFR-05).
func TestTI03_SlowText(t *testing.T) {
	hostIO := readStall("/proc/pressure/io").ok
	// A begin CPU time one hour ahead gives a negative CPU time since begin.
	r := &running{out: newStartWriter(), begin: time.Now(), cpu: cpuTime() + time.Hour, pressure: pressure{stall{0, true}, stall{0, true}, stall{0, true}, stall{0, true}}}
	r.out.at = r.begin.Add(time.Second)
	got := r.slow()
	for _, want := range []string{"; start line 1s after begin, process CPU time -", " since begin; io pressure ", " since begin"} {
		if !strings.Contains(got, want) {
			t.Errorf("slow text %q has no %q", got, want)
		}
	}
	if !hostIO {
		return
	}
	// The host io stall total since boot is above 0, and begin is 0.
	m := regexp.MustCompile(`io pressure [^,]*, (\S+) \(host\)`).FindStringSubmatch(got)
	if m == nil || m[1] == "not" || m[1] == "0s" || strings.HasPrefix(m[1], "-") {
		t.Errorf("slow text %q: want a host io pressure above 0", got)
	}
}
