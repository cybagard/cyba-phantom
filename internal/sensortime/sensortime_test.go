package sensortime

import (
	"errors"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
		FirstEvent: 120, FirstSession: 40, CatchUp: 600000, GraceSum: 1800000,
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
	{"S min", func(s *State) { s.S, s.Jump = 0, Jump{} }},
	{"S max", func(s *State) { s.S = boundMS }},
	{"no boot id", func(s *State) { s.BootID = "" }},
	{"boot clock min", func(s *State) { s.BootClock = 0 }},
	{"boot clock max", func(s *State) { s.BootClock = 1<<63 - 1 }},
	{"first event min", func(s *State) { s.FirstEvent = 0 }},
	{"first event max", func(s *State) {
		s.FirstEvent, s.NextEvent = 1<<63-1, 1<<63-1
	}},
	{"first session min", func(s *State) { s.FirstSession = 0 }},
	{"first session max", func(s *State) {
		s.FirstSession, s.NextSession = 1<<63-1, 1<<63-1
	}},
	{"catch-up min", func(s *State) { s.CatchUp = 0 }},
	{"catch-up max", func(s *State) { s.CatchUp = 86400000 }},
	{"grace sum min", func(s *State) { s.GraceSum = 0 }},
	{"grace sum max", func(s *State) { s.GraceSum = 3600000 }},
	{"no jump", func(s *State) { s.Jump = Jump{} }},
	{"jump id min", func(s *State) { s.Jump.ID = 1 }},
	{"jump id max", func(s *State) { s.Jump.ID = boundMS }},
	{"jump size min", func(s *State) { s.Jump.Size = 1 }},
	{"jump size max", func(s *State) {
		s.S, s.Jump.At, s.Jump.Size = boundMS, boundMS, boundMS
	}},
	{"jump at min", func(s *State) { s.Jump.At, s.Jump.Size = 1, 1 }},
	{"jump at max", func(s *State) { s.S, s.Jump.At = boundMS, boundMS }},
	{"jump first event min", func(s *State) { s.Jump.FirstEvent = 0 }},
	{"jump first event max", func(s *State) {
		s.Jump.FirstEvent, s.NextEvent = 1<<63-1, 1<<63-1
	}},
	{"jump first session min", func(s *State) { s.Jump.FirstSession = 0 }},
	{"jump first session max", func(s *State) {
		s.Jump.FirstSession, s.NextSession = 1<<63-1, 1<<63-1
	}},
	{"next event min", func(s *State) {
		s.NextEvent, s.FirstEvent, s.Jump.FirstEvent = 0, 0, 0
	}},
	{"next event max", func(s *State) { s.NextEvent = 1<<63 - 1 }},
	{"next session min", func(s *State) {
		s.NextSession, s.FirstSession, s.Jump.FirstSession = 0, 0, 0
	}},
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
		"1800000;3;7200000;1793990000000;100;30;5000;900" {
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
		{"catch-up too large", func(s *State) { s.CatchUp = 86400001 }},
		{"negative grace sum", func(s *State) { s.GraceSum = -1 }},
		{"grace sum over 1 h", func(s *State) { s.GraceSum = 3600001 }},
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

// Each rule has a state that passes at its edge and one that fails one above.
func TestTU30_StateCrossRules(t *testing.T) {
	rules := []struct {
		name    string
		ok, bad func(*State)
	}{
		{"jump at and S",
			func(s *State) { s.Jump.At = s.S },
			func(s *State) { s.Jump.At = s.S + 1 }},
		{"jump size and at",
			func(s *State) { s.Jump.Size = s.Jump.At },
			func(s *State) { s.Jump.Size = s.Jump.At + 1 }},
		{"catch-up",
			func(s *State) { s.CatchUp = 86400000 },
			func(s *State) { s.CatchUp = 86400001 }},
		{"grace sum",
			func(s *State) { s.GraceSum = 3600000 },
			func(s *State) { s.GraceSum = 3600001 }},
		{"first event",
			func(s *State) { s.FirstEvent = s.NextEvent },
			func(s *State) { s.FirstEvent = s.NextEvent + 1 }},
		{"first session",
			func(s *State) { s.FirstSession = s.NextSession },
			func(s *State) { s.FirstSession = s.NextSession + 1 }},
		{"jump first event",
			func(s *State) { s.Jump.FirstEvent = s.NextEvent },
			func(s *State) { s.Jump.FirstEvent = s.NextEvent + 1 }},
		{"jump first session",
			func(s *State) { s.Jump.FirstSession = s.NextSession },
			func(s *State) { s.Jump.FirstSession = s.NextSession + 1 }},
		{"jump id",
			func(s *State) { s.Jump.ID = boundMS },
			func(s *State) { s.Jump.ID = boundMS + 1 }},
	}
	for _, r := range rules {
		s := typical()
		r.ok(&s)
		v, err := s.Encode()
		if got, derr := Decode(v); err != nil || derr != nil || got != s {
			t.Errorf("%s: edge value: %v, %v", r.name, err, derr)
		}
		s = typical()
		r.bad(&s)
		if v, err := s.Encode(); err != ErrState || v != "" {
			t.Errorf("%s: encode gave %q, %v", r.name, v, err)
		}
		if _, err := Decode(s.format()); err != ErrState {
			t.Errorf("%s: decode err = %v, want ErrState", r.name, err)
		}
	}
}

// The epoch of this package is the token epoch, 2026-01-01 UTC.
func TestTU30_EpochConstant(t *testing.T) {
	want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	if epochMS != want {
		t.Fatalf("epochMS = %d, want %d", epochMS, want)
	}
}

const (
	hourMS  = int64(3600000)
	dayMS   = 24 * hourMS
	s0      = epochMS + 100*dayMS // a stored S after the epoch
	otherID = "fedcba98-7654-4321-8fed-cba987654321"
)

// fake is a source with clocks that a test sets. It is safe for many
// goroutines. Its boot clock goes down only when a test lowers it.
type fake struct {
	wall, boot atomic.Int64 // wall in unix ms, boot in ns
	id         string
	idErr      error
	bootErr    error // set by a test before the goroutines run
	wallCalls  atomic.Int32
}

func newFake(wall int64, boot time.Duration, id string) *fake {
	f := &fake{id: id}
	f.wall.Store(wall)
	f.boot.Store(int64(boot))
	return f
}

func (f *fake) source() Source {
	return Source{
		Wall: func() time.Time {
			f.wallCalls.Add(1)
			return time.UnixMilli(f.wall.Load())
		},
		BootClock: func() (time.Duration, error) {
			return time.Duration(f.boot.Load()), f.bootErr
		},
		BootID: func() (string, error) { return f.id, f.idErr },
	}
}

// stored gives a valid stored state of S s at the boot clock boot.
func stored(s int64, id string, boot time.Duration) *State {
	return &State{
		S: s, BootID: id, BootClock: boot, FirstEvent: 120, FirstSession: 40,
		CatchUp: 600000,
		Jump: Jump{ID: 3, Size: 7200000, At: s, FirstEvent: 100,
			FirstSession: 30},
		NextEvent: 5000, NextSession: 900,
	}
}

func mustStart(t *testing.T, f *fake, in StartInput) (*Clock, Result) {
	t.Helper()
	c, r, err := Start(f.source(), in)
	if err != nil {
		t.Fatal(err)
	}
	return c, r
}

func mustNow(t *testing.T, c *Clock) int64 {
	t.Helper()
	s, err := c.Now()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTU30_SameBootAddsElapsed(t *testing.T) {
	for _, off := range []int64{40 * dayMS, -40 * dayMS} {
		for _, el := range []time.Duration{0, 90 * time.Minute, 40 * time.Hour} {
			f := newFake(s0+off, 10*time.Hour+el, goodID)
			st := stored(s0, goodID, 10*time.Hour)
			in := StartInput{Stored: st, NextEvent: 7000, NextSession: 100}
			c, r := mustStart(t, f, in)
			want := s0 + el.Milliseconds()
			if r.State.S != want || mustNow(t, c) != want || r.Jump != nil {
				t.Fatalf("wall %+d, el %v: S %d, jump %v; want %d",
					off, el, r.State.S, r.Jump, want)
			}
			w := *st
			w.S, w.BootClock, w.NextEvent = want, 10*time.Hour+el, 7000
			if r.State != w {
				t.Fatalf("state %+v, want %+v", r.State, w)
			}
			if f.wallCalls.Load() != 0 {
				t.Fatal("start or Now called Wall")
			}
		}
	}
}

func TestTU30_RebootTakesLargerOfStoredAndWall(t *testing.T) {
	cases := []struct {
		name  string
		st    *State
		id    string
		boot  time.Duration
		off   int64 // wall minus stored S
		wantS int64 // offset from s0
		jump  int64 // 0: none
	}{
		{"lower boot clock", stored(s0, goodID, 10*time.Hour), goodID,
			10*time.Hour - 1, 2 * hourMS, 2 * hourMS, 2 * hourMS},
		{"other boot id", stored(s0, goodID, 10*time.Hour), otherID,
			20 * time.Hour, 2 * hourMS, 2 * hourMS, 2 * hourMS},
		{"no boot id now", stored(s0, goodID, 10*time.Hour), "",
			20 * time.Hour, 2 * hourMS, 2 * hourMS, 2 * hourMS},
		{"no boot id stored", stored(s0, "", 10*time.Hour), goodID,
			20 * time.Hour, 2 * hourMS, 2 * hourMS, 2 * hourMS},
		{"no boot id on both", stored(s0, "", 10*time.Hour), "",
			20 * time.Hour, 2 * hourMS, 2 * hourMS, 2 * hourMS},
		{"wall behind", stored(s0, goodID, 10*time.Hour), otherID,
			20 * time.Hour, -5 * hourMS, 0, 0},
		{"exactly 1 h", stored(s0, goodID, 10*time.Hour), otherID,
			20 * time.Hour, hourMS, hourMS, 0},
		{"1 h and 1 ms", stored(s0, goodID, 10*time.Hour), otherID,
			20 * time.Hour, hourMS + 1, hourMS + 1, hourMS + 1},
	}
	for _, c := range cases {
		f := newFake(s0+c.off, c.boot, c.id)
		in := StartInput{Stored: c.st, NextEvent: 7000, NextSession: 100}
		_, r := mustStart(t, f, in)
		st := r.State
		if st.S != s0+c.wantS || st.FirstEvent != 7000 ||
			st.FirstSession != 900 || st.CatchUp != 0 ||
			st.NextEvent != 7000 || st.NextSession != 900 {
			t.Errorf("%s: state %+v", c.name, st)
		}
		if c.jump == 0 {
			if r.Jump != nil || st.Jump != c.st.Jump {
				t.Errorf("%s: jump %v, state jump %+v", c.name, r.Jump, st.Jump)
			}
			continue
		}
		want := Jump{ID: 4, Size: c.jump, At: st.S, FirstEvent: 7000,
			FirstSession: 900}
		if r.Jump == nil || *r.Jump != (JumpResult{4, c.jump, KindStart}) ||
			st.Jump != want {
			t.Errorf("%s: jump %v, state jump %+v", c.name, r.Jump, st.Jump)
		}
	}
}

func TestTU30_NoStoredState(t *testing.T) {
	f := newFake(s0+400*dayMS, time.Minute, goodID)
	_, r := mustStart(t, f, StartInput{NextEvent: 7, NextSession: 3})
	want := State{S: s0 + 400*dayMS, BootID: goodID, BootClock: time.Minute,
		FirstEvent: 7, FirstSession: 3, NextEvent: 7, NextSession: 3}
	if r.State != want || r.Jump != nil {
		t.Fatalf("state %+v, jump %v", r.State, r.Jump)
	}
}

func TestTU30_StartClampsS(t *testing.T) {
	far := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	cases := []struct {
		name string
		st   *State
		wall int64
		boot time.Duration
		want int64
	}{
		{"wall at max", nil, boundMS, 0, boundMS},
		{"wall above max", nil, boundMS + 1, 0, boundMS},
		{"wall far above max", nil, far, 0, boundMS},
		{"wall at 0", nil, 0, 0, 0},
		{"wall below 0", nil, -1, 0, 0},
		{"stored at max, wall behind", stored(boundMS, otherID, 0), 5, 0,
			boundMS},
		{"sum at max", stored(boundMS-1000, goodID, 0), 0, time.Second,
			boundMS},
		{"sum above max", stored(boundMS-1000, goodID, 0), 0,
			time.Second + time.Millisecond, boundMS},
		{"sum below max", stored(boundMS-1000, goodID, 0), 0,
			time.Second - time.Millisecond, boundMS - 1},
		{"huge boot clock", stored(boundMS, goodID, 0), 0, 1<<63 - 1,
			boundMS},
	}
	for _, c := range cases {
		f := newFake(c.wall, c.boot, goodID)
		_, r := mustStart(t, f, StartInput{Stored: c.st})
		if r.State.S != c.want {
			t.Errorf("%s: S %d, want %d", c.name, r.State.S, c.want)
		}
	}
}

func TestTU30_StartRefusals(t *testing.T) {
	f := newFake(s0, time.Hour, goodID)
	f.idErr = ErrBootID
	if c, _, err := Start(f.source(), StartInput{}); err != ErrBootID || c != nil {
		t.Errorf("boot id error: %v", err)
	}
	f = newFake(s0, time.Hour, goodID)
	f.bootErr = errors.New("clock")
	if _, _, err := Start(f.source(), StartInput{}); err != f.bootErr {
		t.Errorf("boot clock error: %v", err)
	}
	f = newFake(s0, time.Hour, goodID)
	bad := stored(s0, goodID, 0)
	bad.CatchUp = 86400001
	if _, _, err := Start(f.source(), StartInput{Stored: bad}); err != ErrState {
		t.Errorf("bad stored state: %v", err)
	}
	// Only the check of the stored state refuses these. A start would
	// otherwise clamp S or use the wall clock, and give a valid state.
	negBoot := stored(s0, goodID, 0)
	negBoot.BootClock = -time.Second
	aboveBound := stored(maxMS+1, goodID, 0)
	belowZero := stored(-5, goodID, 0)
	aboveBound.Jump, belowZero.Jump = Jump{}, Jump{}
	for name, st := range map[string]*State{
		"negative boot clock": negBoot,
		"S above the bound":   aboveBound,
		"S below 0":           belowZero,
	} {
		f := newFake(s0, time.Hour, goodID)
		if c, _, err := Start(f.source(), StartInput{Stored: st}); c != nil ||
			!errors.Is(err, ErrState) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A source boot id that is not in lower-case UUID form gives ErrBootID. A
// negative boot clock gives ErrState. A known jump id out of range gives
// ErrState.
func TestTU30_StartSourceChecks(t *testing.T) {
	for _, id := range []string{"NOT-A-UUID", upperID} {
		f := newFake(s0, time.Hour, id)
		if c, _, err := Start(f.source(), StartInput{}); c != nil ||
			!errors.Is(err, ErrBootID) {
			t.Errorf("boot id %q: %v", id, err)
		}
	}
	f := newFake(s0, -time.Second, goodID)
	if c, _, err := Start(f.source(), StartInput{}); c != nil ||
		!errors.Is(err, ErrState) {
		t.Errorf("boot clock -1 s: %v", err)
	}
	for _, known := range []int64{-1, boundMS + 1} {
		f := newFake(s0, time.Hour, goodID)
		if c, _, err := Start(f.source(), StartInput{KnownJumpID: known}); c != nil ||
			!errors.Is(err, ErrState) {
			t.Errorf("known jump id %d: %v", known, err)
		}
	}
	f = newFake(s0, time.Hour, goodID)
	if _, _, err := Start(f.source(), StartInput{KnownJumpID: boundMS}); err != nil {
		t.Errorf("known jump id at the bound: %v", err)
	}
}

// The values of the kinds are the kind label values of ADR-043.
func TestTU30_JumpKindValues(t *testing.T) {
	if KindStart != "start" || KindGrace != "grace" {
		t.Errorf("kinds %q and %q", KindStart, KindGrace)
	}
}

func TestTU30_JumpIDAboveKnownIDs(t *testing.T) {
	cases := []struct {
		known, stored, want int64
	}{{0, 0, 1}, {9, 3, 10}, {2, 3, 4}, {3, 3, 4}, {0, 8, 9}}
	for _, c := range cases {
		st := stored(s0, goodID, time.Hour)
		st.Jump.ID = c.stored
		if c.stored == 0 {
			st.Jump = Jump{}
		}
		f := newFake(s0+2*hourMS, time.Hour, otherID)
		clk, r := mustStart(t, f, StartInput{Stored: st, KnownJumpID: c.known})
		if r.Jump == nil || r.Jump.ID != c.want || r.State.Jump.ID != c.want {
			t.Fatalf("known %d, stored %d: jump %v", c.known, c.stored, r.Jump)
		}
		// The next jump of this clock goes above the one it gave.
		f.wall.Store(s0 + 10*hourMS)
		r2, err := clk.Check()
		if err != nil || r2.Jump == nil || r2.Jump.ID != c.want+1 {
			t.Fatalf("grace jump after id %d: %v, %v", c.want, r2.Jump, err)
		}
	}
}

// graceClock starts a clock at S s on the same host boot at boot clock boot.
func graceClock(t *testing.T, s int64, boot time.Duration) (*fake, *Clock) {
	f := newFake(s, boot, goodID)
	c, _ := mustStart(t, f, StartInput{Stored: stored(s, goodID, boot),
		NextEvent: 8000, NextSession: 950})
	return f, c
}

func TestTU30_GraceFollowsWallForward(t *testing.T) {
	cases := []struct {
		name string
		s    int64
		boot time.Duration
		off  int64 // wall minus S
		move bool
		jump bool
	}{
		{"boot clock 6 h - 1 ns, jump", s0, 6*time.Hour - 1, 2 * hourMS, true, true},
		{"boot clock 6 h", s0, 6 * time.Hour, 2 * hourMS, false, false},
		{"boot clock 0", s0, 0, 2 * hourMS, true, true},
		{"1 h, no jump", s0, time.Hour, hourMS, true, false},
		{"1 h and 1 ms, jump", s0, time.Hour, hourMS + 1, true, true},
		{"1 ms, no jump", s0, time.Hour, 1, true, false},
		{"wall equal", s0, time.Hour, 0, false, false},
		{"wall behind", s0, time.Hour, -3 * hourMS, false, false},
		{"epoch - 1 ms, jump", epochMS - 1, 10 * time.Hour, 2 * hourMS, true, true},
		{"epoch - 1 ms, no jump", epochMS - 1, 10 * time.Hour, 1, true, false},
		{"epoch", epochMS, 10 * time.Hour, 2 * hourMS, false, false},
		{"before epoch, wall behind", 5 * dayMS, 10 * time.Hour, -hourMS,
			false, false},
	}
	for _, c := range cases {
		f, clk := graceClock(t, c.s, c.boot)
		f.wall.Store(c.s + c.off)
		r, err := clk.Check()
		if r.Write {
			clk.Committed()
		}
		want := c.s
		if c.move {
			want += c.off
		}
		if err != nil || r.State.S != want || mustNow(t, clk) != want ||
			(r.Jump != nil) != c.jump {
			t.Errorf("%s: S %d (want %d), jump %v, %v",
				c.name, r.State.S, want, r.Jump, err)
			continue
		}
		if !c.jump {
			if r.State.Jump != stored(c.s, goodID, 0).Jump {
				t.Errorf("%s: jump record changed: %+v", c.name, r.State.Jump)
			}
			continue
		}
		// The jump starts at the first rowids of the host boot (120, 40).
		wantJ := Jump{ID: 4, Size: c.off, At: want, FirstEvent: 120,
			FirstSession: 40}
		if *r.Jump != (JumpResult{4, c.off, KindGrace}) || r.State.Jump != wantJ {
			t.Errorf("%s: jump %v, record %+v", c.name, r.Jump, r.State.Jump)
		}
		if r.State.CatchUp != 600000 || r.State.NextEvent != 8000 {
			t.Errorf("%s: state %+v", c.name, r.State)
		}
	}
}

func TestTU30_GraceClampsS(t *testing.T) {
	f, c := graceClock(t, s0, time.Hour)
	f.wall.Store(boundMS + 5*dayMS)
	r, err := c.Check()
	if err != nil || r.State.S != boundMS || r.Jump == nil ||
		r.State.Jump.At != boundMS {
		t.Fatalf("%+v, %v", r, err)
	}
	if _, err := r.State.Encode(); err != nil {
		t.Fatal(err)
	}
}

// S follows only the boot clock of the source. The test moves the boot clock
// 3 h. The wall clock stays at the first S, so it is behind S after the move.
func TestTU30_HostSuspendCountsInS(t *testing.T) {
	for _, boot := range []time.Duration{10 * time.Hour, time.Hour} {
		f, c := graceClock(t, s0, boot)
		before := mustNow(t, c)
		f.boot.Add(int64(3 * time.Hour))
		after := mustNow(t, c)
		if after-before != 3*hourMS {
			t.Fatalf("boot %v: S %d then %d", boot, before, after)
		}
		r, err := c.Check()
		if err != nil || r.Jump != nil || r.State.S != after ||
			mustNow(t, c) != after {
			t.Fatalf("boot %v: check %+v, %v", boot, r, err)
		}
	}
}

func TestTU30_ReaderErrorAndBackwardBootClock(t *testing.T) {
	f, c := graceClock(t, s0, 10*time.Hour)
	f.boot.Add(int64(time.Minute))
	want := mustNow(t, c)
	f.bootErr = errors.New("clock")
	if s, err := c.Now(); err == nil || s != 0 {
		t.Errorf("Now gave %d, %v", s, err)
	}
	if _, err := c.Snapshot(); err == nil {
		t.Error("Snapshot gave no error")
	}
	if _, err := c.Check(); err == nil {
		t.Error("Check gave no error")
	}
	f.bootErr = nil
	f.boot.Store(int64(time.Hour)) // a boot clock that went down
	if got := mustNow(t, c); got != s0 {
		t.Errorf("S %d with a lower boot clock, want the base %d", got, s0)
	}
	f.boot.Store(int64(10*time.Hour + time.Minute))
	if got := mustNow(t, c); got != want {
		t.Errorf("S %d, want %d", got, want)
	}
}

// A check with the wall clock equal to S makes no new base. A new base would
// drop the part of a millisecond of the boot clock. Then S goes down 1 ms.
func TestTU30_CheckWithWallEqualToSKeepsBase(t *testing.T) {
	f, c := graceClock(t, s0, time.Hour)
	f.boot.Store(int64(time.Hour + 1600*time.Microsecond))
	f.wall.Store(s0 + 1)
	if r, err := c.Check(); err != nil || r.State.S != s0+1 {
		t.Fatalf("check: %+v, %v", r, err)
	}
	f.boot.Store(int64(time.Hour + 2500*time.Microsecond))
	if got := mustNow(t, c); got != s0+2 {
		t.Fatalf("S %d after the check, want %d", got, s0+2)
	}
}

// A grace move makes its base at the boot clock of the check, not of the
// start. At boot clock 2 h the wall is S + 10 h. At 3 h, S is S + 11 h.
func TestTU30_GraceBaseAtCheckBootClock(t *testing.T) {
	f, c := graceClock(t, s0, time.Hour)
	f.boot.Store(int64(2 * time.Hour))
	f.wall.Store(s0 + 10*hourMS)
	r, err := c.Check()
	if err != nil || r.Jump == nil || r.Jump.Size != 9*hourMS || !r.Write {
		t.Fatalf("check: %+v, %v", r, err)
	}
	c.Committed()
	f.boot.Store(int64(3 * time.Hour))
	if got := mustNow(t, c); got != s0+11*hourMS {
		t.Fatalf("S %d, want %d", got, s0+11*hourMS)
	}
	// The boot clock is 30 min past the base, so S moves 30 min. The wall is
	// at 40 min. That is a move of 10 min, so no jump.
	f, c = graceClock(t, s0, time.Hour)
	f.boot.Store(int64(time.Hour + 30*time.Minute))
	f.wall.Store(s0 + 40*60000)
	r, err = c.Check()
	if err != nil || r.Jump != nil || r.State.S != s0+40*60000 {
		t.Fatalf("small move: %+v, %v", r, err)
	}
	// The boot clock is 1 h past the base, so S is S0 + 1 h at the check. The
	// wall is at 90 min. That is a move of 30 min, so no jump. A threshold on
	// the wall minus the base would see 90 min and give a jump.
	f, c = graceClock(t, s0, time.Hour)
	f.boot.Store(int64(2 * time.Hour))
	f.wall.Store(s0 + 90*60000)
	r, err = c.Check()
	if err != nil || r.Jump != nil || r.State.S != s0+90*60000 ||
		r.State.GraceSum != 30*60000 {
		t.Fatalf("move after 1 h of boot clock: %+v, %v", r, err)
	}
}

// The state of a check is at its own boot clock, with or without a move.
// The boot clock is after the base.
func TestTU30_CheckStateAtItsBootClock(t *testing.T) {
	f, c := graceClock(t, s0, 10*time.Hour)
	f.boot.Store(int64(11*time.Hour + 30*time.Minute))
	r, err := c.Check()
	if err != nil || r.Jump != nil || r.State.S != s0+90*60000 ||
		r.State.BootClock != 11*time.Hour+30*time.Minute {
		t.Fatalf("no move: %+v, %v", r, err)
	}
	f, c = graceClock(t, s0, time.Hour)
	f.boot.Store(int64(2 * time.Hour))
	f.wall.Store(s0 + 10*hourMS)
	r, err = c.Check()
	if err != nil || r.Jump == nil || r.State.S != s0+10*hourMS ||
		r.State.BootClock != 2*time.Hour {
		t.Fatalf("move: %+v, %v", r, err)
	}
}

func TestTU30_SnapshotAtCurrentBootClock(t *testing.T) {
	f, c := graceClock(t, s0, 10*time.Hour)
	f.boot.Add(int64(90 * time.Minute))
	st, err := c.Snapshot()
	if err != nil || st.S != s0+90*60000 || st.BootClock != 11*time.Hour+30*time.Minute ||
		st.BootID != goodID || st.FirstEvent != 120 || st.NextEvent != 8000 {
		t.Fatalf("%+v, %v", st, err)
	}
	v, err := st.Encode()
	if got, derr := Decode(v); err != nil || derr != nil || got != st {
		t.Fatalf("encode %v, decode %v", err, derr)
	}
}

// 8 readers see a non-decreasing S while one goroutine makes grace jumps.
// Each reader reads once and signals before the first check. The checks go
// on until each reader has read 100 times while they run. A reader counts a
// read only when the flag checking is set before and after the read. A bound
// on the checks ends the loop, so a reader that cannot count fails the test.
func TestTU30_ReadersNeverSeeSGoDown(t *testing.T) {
	const readers, minReads, minChecks, maxChecks = 8, 100, 2000, 1000000
	f, c := graceClock(t, s0, time.Minute)
	var stop, checking atomic.Bool
	var wg sync.WaitGroup
	var reads [readers]atomic.Int64
	ready := make(chan struct{}, readers)
	errc := make(chan string, readers)
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			last, err := c.Now()
			if err != nil {
				errc <- "reader error"
				ready <- struct{}{}
				return
			}
			ready <- struct{}{}
			for !stop.Load() {
				before := checking.Load()
				s, err := c.Now()
				if err != nil || s < last {
					errc <- "reader saw S go down or an error"
					return
				}
				last = s
				if before && checking.Load() {
					reads[i].Add(1)
				}
				runtime.Gosched()
			}
		}()
	}
	for i := 0; i < readers; i++ {
		<-ready
	}
	enough := func() bool {
		for i := range reads {
			if reads[i].Load() < minReads {
				return false
			}
		}
		return true
	}
	jumps, checks := 0, 0
	checking.Store(true)
	for i := 1; i <= maxChecks && (i <= minChecks || !enough()); i++ {
		f.boot.Add(int64(time.Millisecond))
		f.wall.Store(s0 + int64(i)*2*hourMS)
		r, err := c.Check()
		if err != nil {
			t.Fatal(err)
		}
		c.Committed()
		checks++
		if r.Jump != nil {
			jumps++
		}
		runtime.Gosched()
	}
	checking.Store(false)
	var got [readers]int64
	for i := range reads {
		got[i] = reads[i].Load()
	}
	stop.Store(true)
	wg.Wait()
	close(errc)
	for e := range errc {
		t.Error(e)
	}
	for i, n := range got {
		if n < minReads {
			t.Errorf("reader %d made %d reads in the check phase", i, n)
		}
	}
	if jumps != checks {
		t.Fatalf("%d grace jumps in %d checks, want one in each", jumps, checks)
	}
}

// A reader reads its boot clock before a grace move and loads the base after
// it. It must get S of the new base. The boot clock does not move between the
// two reads. The first reader stops after its boot clock read. A check moves
// S 40 d. Then a second reader calls Now.
func TestTU30_LaterNowNeverLowerThanEarlierReturn(t *testing.T) {
	f := newFake(s0, time.Hour, goodID)
	src := f.source()
	reached, release := make(chan struct{}), make(chan struct{})
	var hold atomic.Bool
	inner := src.BootClock
	src.BootClock = func() (time.Duration, error) {
		bc, err := inner()
		if hold.CompareAndSwap(true, false) {
			reached <- struct{}{}
			<-release
		}
		return bc, err
	}
	c, _, err := Start(src, StartInput{Stored: stored(s0, goodID, time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	hold.Store(true)
	a := make(chan int64, 1)
	go func() {
		s, err := c.Now()
		if err != nil {
			s = -1
		}
		a <- s
	}()
	<-reached
	f.wall.Store(s0 + 40*dayMS)
	if r, err := c.Check(); err != nil || r.Jump == nil || !r.Write {
		t.Fatalf("check: %+v, %v", r, err)
	}
	c.Committed()
	sb := mustNow(t, c)
	close(release)
	if sa := <-a; sa < sb || sb < s0+40*dayMS {
		t.Fatalf("first reader S %d, second reader S %d", sa, sb)
	}
}

// A boot clock below 0, after a valid start, gives ErrState with no S and no
// change of state.
func TestTU30_NegativeBootClockAfterStart(t *testing.T) {
	f, c := graceClock(t, s0, time.Hour)
	f.wall.Store(s0 + 10*hourMS)
	f.boot.Store(int64(-time.Nanosecond))
	if s, err := c.Now(); s != 0 || !errors.Is(err, ErrState) {
		t.Errorf("Now: %d, %v", s, err)
	}
	if st, err := c.Snapshot(); st != (State{}) || !errors.Is(err, ErrState) {
		t.Errorf("Snapshot: %+v, %v", st, err)
	}
	if r, err := c.Check(); r.Jump != nil || r.State != (State{}) ||
		!errors.Is(err, ErrState) {
		t.Errorf("Check: %+v, %v", r, err)
	}
	f.boot.Store(int64(time.Hour))
	if got := mustNow(t, c); got != s0 {
		t.Errorf("S %d after the refused calls, want %d", got, s0)
	}
	f.boot.Store(int64(math.MinInt64))
	if s, err := c.Now(); s != 0 || !errors.Is(err, ErrState) {
		t.Errorf("Now at the minimum: %d, %v", s, err)
	}
}
