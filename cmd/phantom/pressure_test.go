package main

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stall is the stalled time of one pressure file.
// ok is false when no file could be read.
type stall struct {
	d  time.Duration
	ok bool
}

// pressure holds the io and the cpu stall of the cgroup, or of the host.
type pressure struct{ io, cpu stall }

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

// readStall reads the pressure file of kind ("io" or "cpu").
// The cgroup file comes first, then the host file.
func readStall(kind string) stall {
	for _, path := range []string{"/sys/fs/cgroup/" + kind + ".pressure", "/proc/pressure/" + kind} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if d, err := parsePressure(string(b)); err == nil {
			return stall{d, true}
		}
	}
	return stall{}
}

func readPressure() pressure { return pressure{io: readStall("io"), cpu: readStall("cpu")} }

// since gives the stall from begin to now, or "not readable".
func (now stall) since(begin stall) string {
	if !now.ok || !begin.ok {
		return "not readable"
	}
	return (now.d - begin.d).String()
}

// note gives the io and the cpu pressure since begin. A process that waits
// for the disk or for a CPU has a low CPU time. The stall shows which one.
func (begin pressure) note() string {
	now := readPressure()
	return "; io pressure " + now.io.since(begin.io) + ", cpu pressure " + now.cpu.since(begin.cpu) + " since begin"
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

// TestTI03_PressureNote checks the stall text, with a value and with
// "not readable" (NFR-05).
func TestTI03_PressureNote(t *testing.T) {
	if got := (stall{3 * time.Millisecond, true}).since(stall{time.Millisecond, true}); got != "2ms" {
		t.Errorf("since = %q, want 2ms", got)
	}
	if got := (stall{}).since(stall{time.Millisecond, true}); got != "not readable" {
		t.Errorf("since = %q, want not readable", got)
	}
}

// TestTI03_SlowText checks the failure text of a slow start (NFR-05).
// It has the start line time, the CPU time, and the io and cpu pressure.
func TestTI03_SlowText(t *testing.T) {
	r := &running{out: newStartWriter(), begin: time.Now(), pressure: pressure{}}
	r.out.at = r.begin.Add(time.Second)
	got := r.slow()
	for _, want := range []string{"start line 1s after begin", "process CPU time ", "; io pressure ", ", cpu pressure ", " since begin"} {
		if !strings.Contains(got, want) {
			t.Errorf("slow text %q has no %q", got, want)
		}
	}
}
