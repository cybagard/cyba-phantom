package sensortime

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// boundMS is written out: math.MaxInt64 ns as ms, 2262-04-11T23:47:16.854Z.
const boundMS int64 = 9223372036854

const (
	goodID  = "01234567-89ab-4cde-8f01-23456789abcd"
	upperID = "01234567-89AB-4CDE-8F01-23456789ABCD"
)

// T-U-30: a Linux boot id that cannot be read gives the fixed error. So does
// a text that is not lower-case UUID form with one line feed.
func TestTU30_LinuxBootIDParse(t *testing.T) {
	cases := []struct {
		name string
		in   string
		err  error
		ok   bool
	}{
		{"valid", goodID + "\n", nil, true},
		{"read error", goodID + "\n", errors.New("denied"), false},
		{"no LF", goodID, nil, false},
		{"37 bytes, last is not LF", goodID + "x", nil, false},
		{"LF and extra byte", goodID + "\nx", nil, false},
		{"two LF", goodID + "\n\n", nil, false},
		{"upper case", upperID + "\n", nil, false},
		{"one upper letter", "E" + goodID[1:] + "\n", nil, false},
		{"wrong dash place", goodID[:9] + "-" + goodID[10:] + "\n", nil, false},
		{"no dash", strings.ReplaceAll(goodID, "-", "0") + "\n", nil, false},
		{"non hex", "g" + goodID[1:] + "\n", nil, false},
		{"colon in a hex place", ":" + goodID[1:] + "\n", nil, false},
		{"semicolon in a hex place", ";" + goodID[1:] + "\n", nil, false},
		{"35 bytes", goodID[:34] + "\n", nil, false},
		{"38 bytes", goodID + "00\n", nil, false},
		{"empty", "", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseLinuxBootID([]byte(c.in), c.err)
			if c.ok {
				if err != nil || got != goodID {
					t.Fatalf("got %q, %v", got, err)
				}
				return
			}
			if !errors.Is(err, ErrBootID) || got != "" {
				t.Fatalf("got %q, %v; want ErrBootID", got, err)
			}
		})
	}
}

func TestTU30_DarwinBootIDForm(t *testing.T) {
	cases := []struct {
		name, in string
		err      error
		want     string
	}{
		{"upper case as the host gives it", upperID, nil, goodID},
		{"lower case", goodID, nil, goodID},
		{"mixed case", upperID[:24] + goodID[24:], nil, goodID},
		{"sysctl error", upperID, errors.New("x"), ""},
		{"empty", "", nil, ""},
		{"LF at end", upperID + "\n", nil, ""},
		{"wrong dash place", upperID[:9] + "-" + upperID[10:], nil, ""},
		{"non hex", "G" + upperID[1:], nil, ""},
		{"colon in a hex place", ":" + upperID[1:], nil, ""},
		{"semicolon in a hex place", ";" + upperID[1:], nil, ""},
		{"37 characters, first 36 valid", upperID + "0", nil, ""},
	}
	for _, c := range cases {
		got, err := normalizeDarwinBootID(c.in, c.err)
		if got != c.want || (c.want == "") != errors.Is(err, ErrBootID) {
			t.Errorf("%s: got %q, %v", c.name, got, err)
		}
	}
}

// The default source of the running GOOS gives the documented form.
func TestTU30_DefaultSource(t *testing.T) {
	src := DefaultSource()
	if src.Wall == nil || src.BootClock == nil || src.BootID == nil {
		t.Fatal("source has a nil function")
	}
	before := time.Now()
	wall := src.Wall()
	after := time.Now()
	if wall.Before(before.Add(-time.Second)) || wall.After(after.Add(time.Second)) {
		t.Fatalf("wall %v is not the time now, between %v and %v",
			wall, before, after)
	}
	up1 := linuxUptime(t)
	a, err := src.BootClock()
	if err != nil {
		t.Fatal(err)
	}
	up2 := linuxUptime(t)
	b, err := src.BootClock()
	if err != nil || a < 0 || b < a {
		t.Fatalf("boot clock %v then %v, %v", a, b, err)
	}
	id, err := src.BootID()
	if err != nil {
		t.Fatal(err)
	}
	again, err := src.BootID()
	if err != nil || again != id {
		t.Fatalf("boot id %q then %q, %v", id, again, err)
	}
	switch runtime.GOOS {
	case "linux", "darwin":
		if !validUUID(id, false) {
			t.Fatalf("boot id %q is not lower-case UUID form", id)
		}
		if runtime.GOOS == "linux" && a < time.Millisecond {
			t.Fatalf("boot clock %v is too small", a)
		}
		// The boot clock is the time since the host boot, not the wall time.
		// The reads of the uptime come before and after the boot clock read.
		if runtime.GOOS == "linux" &&
			(a < up1-time.Second || a > up2+time.Second) {
			t.Fatalf("boot clock %v is not between uptime %v and %v", a, up1, up2)
		}
	default:
		if id != "" {
			t.Fatalf("boot id %q on a GOOS with none", id)
		}
	}
}

// linuxUptime gives the first field of /proc/uptime. It gives 0 on another
// GOOS.
func linuxUptime(t *testing.T) time.Duration {
	t.Helper()
	if runtime.GOOS != "linux" {
		return 0
	}
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		t.Fatalf("uptime text %q has no field", b)
	}
	s, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		t.Fatal(err)
	}
	return time.Duration(s * float64(time.Second))
}

// T-U-30: a GOOS with no boot id gives an empty boot id and no error. The
// Go monotonic clock gives an elapsed time that grows at each read.
func TestTU30_MonotonicSource(t *testing.T) {
	src := monotonicSource()
	if src.Wall == nil {
		t.Fatal("wall clock is nil")
	}
	id, err := src.BootID()
	if id != "" || err != nil {
		t.Fatalf("boot id %q, %v; want empty and nil", id, err)
	}
	prev := time.Duration(0)
	for i := 0; i < 3; i++ {
		d, err := src.BootClock()
		if err != nil || d < prev || (i > 0 && d == prev) {
			t.Fatalf("elapsed %v after %v, %v", d, prev, err)
		}
		prev = d
		time.Sleep(time.Millisecond)
	}
	if prev <= 0 {
		t.Fatalf("elapsed time %v did not grow", prev)
	}
}

func typical() State {
	return State{
		S: 1794000000000, BootID: goodID, BootClock: 36 * time.Hour,
		FirstEvent: 120, FirstSession: 40, CatchUp: 600000,
		Jump: Jump{ID: 3, Size: 7200000, At: 1793990000000,
			FirstEvent: 100, FirstSession: 30},
		NextEvent: 5000, NextSession: 900,
	}
}

// Each case sets one field to a low or high value that is in range.
var fieldCases = []struct {
	name string
	set  func(*State)
}{
	{"S min", func(s *State) { s.S = 0 }},
	{"S max", func(s *State) { s.S = boundMS }},
	{"no boot id", func(s *State) { s.BootID = "" }},
	{"boot clock min", func(s *State) { s.BootClock = 0 }},
	{"boot clock max", func(s *State) { s.BootClock = 1<<63 - 1 }},
	{"first event min", func(s *State) { s.FirstEvent = 0 }},
	{"first event max", func(s *State) { s.FirstEvent = 1<<63 - 1 }},
	{"first session min", func(s *State) { s.FirstSession = 0 }},
	{"first session max", func(s *State) { s.FirstSession = 1<<63 - 1 }},
	{"catch-up min", func(s *State) { s.CatchUp = 0 }},
	{"catch-up max", func(s *State) { s.CatchUp = boundMS }},
	{"no jump", func(s *State) { s.Jump = Jump{} }},
	{"jump id min", func(s *State) { s.Jump.ID = 1 }},
	{"jump id max", func(s *State) { s.Jump.ID = 1<<63 - 1 }},
	{"jump size min", func(s *State) { s.Jump.Size = 1 }},
	{"jump size max", func(s *State) { s.Jump.Size = boundMS }},
	{"jump at min", func(s *State) { s.Jump.At = 0 }},
	{"jump at max", func(s *State) { s.Jump.At = boundMS }},
	{"jump first event min", func(s *State) { s.Jump.FirstEvent = 0 }},
	{"jump first event max", func(s *State) { s.Jump.FirstEvent = 1<<63 - 1 }},
	{"jump first session min", func(s *State) { s.Jump.FirstSession = 0 }},
	{"jump first session max", func(s *State) { s.Jump.FirstSession = 1<<63 - 1 }},
	{"next event min", func(s *State) { s.NextEvent = 0 }},
	{"next event max", func(s *State) { s.NextEvent = 1<<63 - 1 }},
	{"next session min", func(s *State) { s.NextSession = 0 }},
	{"next session max", func(s *State) { s.NextSession = 1<<63 - 1 }},
}

func TestTU30_StateRoundTrip(t *testing.T) {
	for _, c := range append(fieldCases, struct {
		name string
		set  func(*State)
	}{"typical", func(*State) {}}) {
		s := typical()
		c.set(&s)
		v, err := s.Encode()
		if err != nil {
			t.Fatalf("%s: encode: %v", c.name, err)
		}
		got, err := Decode(v)
		if err != nil || got != s {
			t.Fatalf("%s: got %+v, %v; want %+v", c.name, got, err, s)
		}
		if again, _ := got.Encode(); again != v {
			t.Fatalf("%s: second encode %q, first %q", c.name, again, v)
		}
	}
}

// Each field has its own place: a change of one field changes the string,
// and no two fields swap.
func TestTU30_StateFieldPlaces(t *testing.T) {
	base, _ := typical().Encode()
	if base != "1;1794000000000;"+goodID+";129600000000000;120;40;600000;"+
		"3;7200000;1793990000000;100;30;5000;900" {
		t.Fatalf("form changed: %q", base)
	}
}

func TestTU30_StateBadValue(t *testing.T) {
	good, _ := typical().Encode()
	parts := strings.Split(good, ";")
	bad := map[string]string{
		"empty": "", "only version": "1", "junk": "x",
		"extra field": good + ";0", "extra empty field": good + ";",
		"version 2": "2" + good[1:], "no version": good[2:],
		"plus sign":     strings.Replace(good, "1794000000000", "+1794000000000", 1),
		"leading zero":  strings.Replace(good, ";120;", ";0120;", 1),
		"minus zero":    strings.Replace(good, ";600000;", ";-0;", 1),
		"upper boot id": strings.Replace(good, goodID, upperID, 1),
		"short boot id": strings.Replace(good, goodID, goodID[1:], 1),
		"long boot id":  strings.Replace(good, goodID, goodID+"0", 1),
		"space":         strings.Replace(good, ";40;", "; 40;", 1),
		"overflow":      strings.Replace(good, ";120;", ";9223372036854775808;", 1),
		"decimal":       strings.Replace(good, ";120;", ";1.5;", 1),
	}
	for i := 0; i < len(parts); i++ {
		bad["truncated before field "+string(rune('a'+i))] =
			strings.Join(parts[:i], ";")
	}
	bad["truncated in last field"] = good[:len(good)-1] + ";"
	for i := 1; i < len(parts); i++ {
		if i == 2 {
			continue
		}
		p := append([]string(nil), parts...)
		p[i] = "x"
		bad["non-numeric field "+string(rune('a'+i))] = strings.Join(p, ";")
	}
	for name, v := range bad {
		if _, err := Decode(v); err != ErrState {
			t.Errorf("%s: err = %v, want ErrState", name, err)
		}
	}
}

// Each case breaks one range rule of validate.
func TestTU30_StateRangeRules(t *testing.T) {
	rules := []struct {
		name string
		set  func(*State)
	}{
		{"S before 1970", func(s *State) { s.S = -1 }},
		{"S after 2262", func(s *State) { s.S = boundMS + 1 }},
		{"boot id upper case", func(s *State) { s.BootID = upperID }},
		{"boot id junk", func(s *State) { s.BootID = "a;b" }},
		{"negative boot clock", func(s *State) { s.BootClock = -1 }},
		{"negative first event", func(s *State) { s.FirstEvent = -1 }},
		{"negative first session", func(s *State) { s.FirstSession = -1 }},
		{"negative next event", func(s *State) { s.NextEvent = -1 }},
		{"negative next session", func(s *State) { s.NextSession = -1 }},
		{"negative catch-up", func(s *State) { s.CatchUp = -1 }},
		{"catch-up too large", func(s *State) { s.CatchUp = boundMS + 1 }},
		{"negative jump id", func(s *State) { s.Jump.ID = -1 }},
		{"jump size zero", func(s *State) { s.Jump.Size = 0 }},
		{"jump size negative", func(s *State) { s.Jump.Size = -1 }},
		{"jump size too large", func(s *State) { s.Jump.Size = boundMS + 1 }},
		{"jump at negative", func(s *State) { s.Jump.At = -1 }},
		{"jump at too large", func(s *State) { s.Jump.At = boundMS + 1 }},
		{"negative jump first event", func(s *State) { s.Jump.FirstEvent = -1 }},
		{"negative jump first session", func(s *State) { s.Jump.FirstSession = -1 }},
		{"no jump but size", func(s *State) { s.Jump = Jump{Size: 1} }},
		{"no jump but rowid", func(s *State) { s.Jump = Jump{FirstEvent: 1} }},
		{"no jump but at", func(s *State) { s.Jump = Jump{At: 1} }},
	}
	for _, r := range rules {
		s := typical()
		r.set(&s)
		if v, err := s.Encode(); err != ErrState || v != "" {
			t.Errorf("%s: encode gave %q, %v", r.name, v, err)
		}
		if _, err := Decode(s.format()); err != ErrState {
			t.Errorf("%s: decode err = %v, want ErrState", r.name, err)
		}
	}
}

func TestTU30_ErrorTextFixed(t *testing.T) {
	const secret = "SECRET-VALUE-9"
	s := typical()
	s.BootID = secret
	_, e1 := s.Encode()
	_, e2 := Decode(strings.Replace(typical().format(), goodID, secret, 1))
	_, e3 := parseLinuxBootID([]byte(secret), nil)
	_, e4 := normalizeDarwinBootID(secret, nil)
	for _, e := range []error{e1, e2, e3, e4} {
		if e == nil || strings.Contains(e.Error(), secret) {
			t.Errorf("error %v is nil or has the value", e)
		}
	}
	if e2 != ErrState || e3 != ErrBootID || e4 != ErrBootID {
		t.Error("errors are not the fixed values")
	}
}
