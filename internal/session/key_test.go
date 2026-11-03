package session

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func keyBytes(k Key) [32]byte { return k.st().key }

// T-U-24: a new holder has a new key. The key has 32 bytes, not all zero.
func TestTU24NewHolderHasNewKey(t *testing.T) {
	when := at("2026-03-01T10:00:00Z")
	a, b := keyBytes(NewDayKey().At(when)), keyBytes(NewDayKey().At(when))
	if a == b {
		t.Fatal("two holders gave one key for one date")
	}
	for _, k := range [][32]byte{a, b} {
		if k == [32]byte{} {
			t.Fatal("the key is all zero")
		}
	}
}

// T-U-24: the key follows the UTC date, in either direction. A snapshot keeps
// its key after a date change.
func TestTU24KeyFollowsTheUTCDate(t *testing.T) {
	d := NewDayKey()
	k1 := d.At(at("2026-03-01T00:00:00Z"))
	if again := d.At(at("2026-03-01T23:59:59Z")); keyBytes(again) != keyBytes(k1) {
		t.Error("the key changed inside one date")
	}
	k2 := d.At(at("2026-03-02T00:00:00Z"))
	if keyBytes(k2) == keyBytes(k1) {
		t.Error("the key did not change at the next date")
	}
	k3 := d.At(at("2026-03-01T12:00:00Z"))
	if keyBytes(k3) == keyBytes(k1) || keyBytes(k3) == keyBytes(k2) {
		t.Error("a clock step back gave an old key")
	}
	if d.At(at("2026-03-01T01:00:00Z")).st() != k3.st() {
		t.Error("the key changed inside one date after a step back")
	}
	if keyBytes(k1) == [32]byte{} || k1.st().date != "2026-03-01" {
		t.Errorf("the snapshot changed: date %q", k1.st().date)
	}
	const ip = "198.51.100.23"
	if *k1.SessionID(ip, "") == *k2.SessionID(ip, "") {
		t.Error("the ids of two dates are equal")
	}
}

// T-U-24: the date is the UTC date of the time, not the local date, and not
// the month.
func TestTU24DateIsUTC(t *testing.T) {
	d := NewDayKey()
	local := time.FixedZone("west", -5*3600)
	// 23:30 at UTC-5 on 03-01 is 04:30 UTC on 03-02.
	k := d.At(time.Date(2026, 3, 1, 23, 30, 0, 0, local))
	if k.st().date != "2026-03-02" {
		t.Fatalf("date %q, want 2026-03-02", k.st().date)
	}
	if d.At(at("2026-03-02T05:00:00Z")).st() != k.st() {
		t.Error("one UTC date gave two keys")
	}
	if d.At(at("2026-03-01T10:00:00Z")).st() == k.st() {
		t.Error("two UTC dates gave one key")
	}
}

func atAll(d *DayKey, times []time.Time) []Key {
	keys := make([]Key, len(times))
	ids := make([]*string, len(times))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range times {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			keys[i] = d.At(times[i])
			ids[i] = keys[i].SessionID("198.51.100.23", "")
			_ = keys[i].IPHMAC(netip.MustParseAddr("198.51.100.23"))
		}()
	}
	close(start)
	wg.Wait()
	for i, k := range keys {
		if *ids[i] != *k.SessionID("198.51.100.23", "") {
			panic("a snapshot changed")
		}
	}
	return keys
}

// T-U-24: 8 goroutines over a date change. Run it with -race. After they end,
// one new date has one key. Goroutines that see one new date share one key.
func TestTU24ConcurrentDateChange(t *testing.T) {
	d := NewDayKey()
	before, after := at("2026-03-01T10:00:00Z"), at("2026-03-02T10:00:00Z")
	d.At(before)
	mixed := make([]time.Time, 8)
	for i := range mixed {
		mixed[i] = before
		if i%2 == 1 {
			mixed[i] = after
		}
	}
	atAll(d, mixed)
	final := d.At(after)
	for _, k := range []Key{d.At(after), d.At(after.Add(time.Hour))} {
		if k.st() != final.st() {
			t.Fatal("the uses of the new date gave two keys")
		}
	}
	// All goroutines see the date change together: they get one key.
	next := at("2026-03-03T10:00:00Z")
	same := make([]time.Time, 8)
	for i := range same {
		same[i] = next
	}
	keys := atAll(d, same)
	for _, k := range keys {
		if k.st() != keys[0].st() {
			t.Fatal("goroutines of one new date have different keys")
		}
	}
	if keys[0].st() == final.st() {
		t.Error("the key did not change at the next date")
	}
}

// T-U-24: the zero Key never computes an HMAC under an all-zero key.
func TestTU24ZeroKeyComputesNothing(t *testing.T) {
	var k Key
	if got := k.IPHMAC(netip.MustParseAddr("198.51.100.23")); got != "" {
		t.Errorf("IPHMAC of the zero Key %q", got)
	}
	if got := k.SessionID("198.51.100.23", ""); got != nil {
		t.Errorf("SessionID of the zero Key %q", *got)
	}
}

// T-U-24: a goroutine that loses the swap uses the winner's state when the date
// is equal. It swaps again when the date is not equal. The hook makes the swap
// fail on every run.
func TestTU24LoserOfTheSwap(t *testing.T) {
	t.Cleanup(func() { beforeSwap = nil })
	const date = "2026-03-01"
	when := at("2026-03-01T10:00:00Z")

	for _, c := range []struct {
		name, winnerDate string
		sameDate         bool
	}{
		{"equal date", date, true},
		{"other date", "2026-03-05", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := NewDayKey()
			winner := newState(c.winnerDate)
			calls := 0
			beforeSwap = func(cur *atomic.Pointer[state]) {
				calls++
				if calls == 1 {
					cur.Store(winner)
				}
			}
			got := d.At(when).st()
			if got.date != date {
				t.Fatalf("date %q, want %q", got.date, date)
			}
			if c.sameDate {
				if got != winner || calls != 1 {
					t.Errorf("loser did not use the winner: %d swaps", calls)
				}
				return
			}
			if got == winner || calls != 2 {
				t.Errorf("loser did not swap again: %d swaps", calls)
			}
			if d.cur().Load() != got {
				t.Error("the second swap did not publish the new state")
			}
		})
	}
}

type box struct {
	d  *DayKey
	dv DayKey
	k  Key
	kp *Key
}

// T-U-24: no fmt verb, slog handler or JSON encoder gives a byte of the key.
func TestTU24KeyIsNotPrinted(t *testing.T) {
	d := NewDayKey()
	k := d.At(at("2026-03-01T10:00:00Z"))
	for i := range k.st().key {
		k.st().key[i] = 0xb0 + byte(i)
	}
	m := k.st().key
	needles := []string{
		string(m[:8]), hex.EncodeToString(m[:8]),
		strings.ToUpper(hex.EncodeToString(m[:8])),
		"176 177 178 179", `\xb0\xb1`, "0xb0, 0xb1", "b0b1b2b3",
		"176,177,178,179", base64.StdEncoding.EncodeToString(m[:6]),
	}
	holds := func(s string) bool {
		for _, n := range needles {
			if strings.Contains(s, n) {
				return true
			}
		}
		return false
	}
	values := map[string]any{
		"*DayKey": d, "DayKey": *d, "Key": k, "*Key": &k,
		"box": box{d, *d, k, &k}, "*box": &box{d, *d, k, &k},
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d", "%q"} {
		if !holds(fmt.Sprintf(verb, m)) {
			t.Fatalf("%s: the check does not see the bytes of a bare key", verb)
		}
		for name, v := range values {
			if out := fmt.Sprintf(verb, v); holds(out) {
				t.Errorf("%s of a %s holds the key: %.200q", verb, name, out)
			}
		}
	}
	var text, js bytes.Buffer
	logs := []*slog.Logger{
		slog.New(slog.NewTextHandler(&text, nil)),
		slog.New(slog.NewJSONHandler(&js, nil)),
	}
	for name, v := range values {
		for _, l := range logs {
			l.Info("x", slog.Any("v", v), "w", v, slog.Group("g", "v", v))
		}
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if holds(string(out)) {
			t.Errorf("json of a %s holds the key: %.200q", name, out)
		}
	}
	if !holds(string(m[:])) || !holds(fmt.Sprint(m)) {
		t.Fatal("the check does not see the bytes of a bare key")
	}
	for _, v := range []any{m, m[:]} {
		out, err := json.Marshal(v)
		if err != nil || !holds(string(out)) {
			t.Fatalf("the check does not see the json of a bare key: %.60q", out)
		}
	}
	var ctlText, ctlJS bytes.Buffer
	slog.New(slog.NewTextHandler(&ctlText, nil)).Info("x", "v", m)
	slog.New(slog.NewJSONHandler(&ctlJS, nil)).Info("x", "v", m)
	if !holds(ctlText.String()) || !holds(ctlJS.String()) {
		t.Fatal("the check does not see the bare key in a log")
	}
	if holds(text.String()) || holds(js.String()) {
		t.Errorf("a log holds the key: %.200q %.200q", text.String(), js.String())
	}
	if text.Len() == 0 || js.Len() == 0 {
		t.Error("the loggers wrote nothing")
	}
}
