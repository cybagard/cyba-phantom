// Package sensortime holds the clocks and the stored state of the sensor time
// (ADR-043). It has the boot clock, the boot id and the value of the meta key
// sensor_time. It also has the start rules, the grace and the atomic S. It
// has no caller yet.
package sensortime

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// Fixed errors. No text of a stored value or of a file is in them.
var (
	// ErrBootID means that the host boot id cannot be read, or is not in the
	// form of its platform. On Linux no start may take "no boot id" for it.
	ErrBootID = errors.New("sensortime: boot id missing or malformed")
	// ErrState means that a stored value does not decode, or has a field
	// out of range.
	ErrState = errors.New("sensortime: stored state malformed or out of range")
)

// maxMS is the largest S: math.MaxInt64 ns as ms, 2262-04-11T23:47:16.854Z.
const maxMS int64 = 9223372036854

// Source gives the three inputs of the sensor time. A test sets each of them.
// BootID returns an empty string only on a GOOS that has no boot id.
type Source struct {
	Wall      func() time.Time
	BootClock func() (time.Duration, error)
	BootID    func() (string, error)
}

// newSource makes the default source: the wall clock and the two functions
// of the GOOS file.
func newSource(
	bootClock func() (time.Duration, error), bootID func() (string, error),
) Source {
	return Source{Wall: time.Now, BootClock: bootClock, BootID: bootID}
}

// Jump is the last forward jump. The zero value means that there is none.
type Jump struct {
	ID           int64 // 0 means no jump
	Size         int64 // J in ms
	At           int64 // S in ms at the jump
	FirstEvent   int64 // first event rowid that the jump moves
	FirstSession int64 // first session rowid that the jump moves
}

// State is the value of the meta key sensor_time.
type State struct {
	S            int64         // sensor time, unix ms
	BootID       string        // empty on a GOOS with no boot id
	BootClock    time.Duration // boot clock at the write
	FirstEvent   int64         // first event rowid of this host boot
	FirstSession int64         // first session rowid of this host boot
	CatchUp      int64         // ms of catch-up used on this host boot
	Jump         Jump
	NextEvent    int64 // rowid floor of event
	NextSession  int64 // rowid floor of session
}

const (
	stateVersion = "1"
	stateFields  = 14
)

// Encode gives the one canonical string of a state. It refuses a state that
// Decode would refuse, so Decode(Encode(x)) is x.
func (s State) Encode() (string, error) {
	if err := s.validate(); err != nil {
		return "", err
	}
	return s.format(), nil
}

func (s State) format() string {
	n := func(v int64) string { return strconv.FormatInt(v, 10) }
	return strings.Join([]string{
		stateVersion, n(s.S), s.BootID, n(int64(s.BootClock)),
		n(s.FirstEvent), n(s.FirstSession), n(s.CatchUp),
		n(s.Jump.ID), n(s.Jump.Size), n(s.Jump.At),
		n(s.Jump.FirstEvent), n(s.Jump.FirstSession),
		n(s.NextEvent), n(s.NextSession),
	}, ";")
}

// validate checks these rules. Each failure gives ErrState.
//   - S is from 0 to 9223372036854 ms (1970 to 2262).
//   - The boot id is empty or in lower-case UUID form.
//   - The boot clock is not negative.
//   - The four rowids of the state are not negative.
//   - The catch-up used is from 0 to 86400000 ms (24 h).
//   - The first event rowid is not more than the next event rowid. The same
//     holds for the session rowids.
//   - With no jump (ID 0), every jump field is 0. The ID is not negative.
//   - With a jump, Size is from 1 to 9223372036854 ms.
//   - With a jump, At is from 0 to 9223372036854 ms, and not after S.
//   - With a jump, Size is not more than At.
//   - With a jump, its two rowids are not negative. They are not more than
//     the next event rowid and the next session rowid.
func (s State) validate() error {
	j := s.Jump
	inMS := func(v int64) bool { return v >= 0 && v <= maxMS }
	ok := inMS(s.S) && (s.BootID == "" || validUUID(s.BootID, false)) &&
		s.BootClock >= 0 &&
		s.FirstEvent >= 0 && s.FirstSession >= 0 &&
		s.NextEvent >= 0 && s.NextSession >= 0 &&
		s.CatchUp >= 0 && s.CatchUp <= catchUpMaxMS &&
		s.FirstEvent <= s.NextEvent && s.FirstSession <= s.NextSession &&
		j.ID >= 0 && j.FirstEvent >= 0 && j.FirstSession >= 0
	if j.ID == 0 {
		ok = ok && j == Jump{}
	} else {
		ok = ok && j.Size >= 1 && j.Size <= maxMS && inMS(j.At) &&
			j.At <= s.S && j.Size <= j.At &&
			j.FirstEvent <= s.NextEvent && j.FirstSession <= s.NextSession
	}
	if !ok {
		return ErrState
	}
	return nil
}

// Decode reads a string of Encode. A value that does not decode, or has a
// field out of range (see validate), gives ErrState. It accepts one spelling
// only: Encode(Decode(v)) is v.
func Decode(v string) (State, error) {
	f := strings.Split(v, ";")
	if len(f) != stateFields || f[0] != stateVersion {
		return State{}, ErrState
	}
	var n [stateFields]int64
	for i, t := range f {
		if i == 0 || i == 2 {
			continue
		}
		x, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return State{}, ErrState
		}
		n[i] = x
	}
	s := State{
		S: n[1], BootID: f[2], BootClock: time.Duration(n[3]),
		FirstEvent: n[4], FirstSession: n[5], CatchUp: n[6],
		Jump: Jump{
			ID: n[7], Size: n[8], At: n[9], FirstEvent: n[10],
			FirstSession: n[11],
		},
		NextEvent: n[12], NextSession: n[13],
	}
	if s.validate() != nil || s.format() != v {
		return State{}, ErrState
	}
	return s, nil
}

// start holds the Go monotonic clock reading of the process start.
var start = time.Now()

// monotonicSource is the source of a GOOS with no boot id. The Go monotonic
// clock gives the elapsed time since the start of the process. The caller
// takes the reboot rule at each start.
func monotonicSource() Source {
	return newSource(
		func() (time.Duration, error) { return time.Since(start), nil },
		func() (string, error) { return "", nil },
	)
}

// validUUID tells if s is 36 characters in the form 8-4-4-4-12 of hex digits.
// With upper false, a letter must be lower case.
func validUUID(s string, upper bool) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		case upper && c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// parseLinuxBootID reads the file /proc/sys/kernel/random/boot_id. The text
// is exactly 36 characters in lower-case UUID form and one line feed. A read
// error or any other text gives ErrBootID. It never gives an empty boot id.
func parseLinuxBootID(b []byte, readErr error) (string, error) {
	if readErr != nil || len(b) != 37 || b[36] != '\n' {
		return "", ErrBootID
	}
	id := string(b[:36])
	if !validUUID(id, false) {
		return "", ErrBootID
	}
	return id, nil
}

// normalizeDarwinBootID reads the sysctl kern.bootsessionuuid. The system
// gives upper-case UUID form with no line feed. The sensor stores lower case,
// so one host boot has one spelling. Other text, or an error, gives
// ErrBootID. It never gives an empty boot id.
func normalizeDarwinBootID(s string, sysErr error) (string, error) {
	if sysErr != nil || !validUUID(s, true) {
		return "", ErrBootID
	}
	return strings.ToLower(s), nil
}
