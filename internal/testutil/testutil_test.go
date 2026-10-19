package testutil

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// fakeT records a failure and ends the goroutine, as t.Fatalf does.
type fakeT struct {
	testing.TB
	msg atomic.Value
}

func (f *fakeT) Helper() {}

func (f *fakeT) Fatalf(format string, args ...any) {
	f.msg.Store(fmt.Sprintf(format, args...))
	runtime.Goexit()
}

// runFake runs fn with a fakeT in its own goroutine and returns the fault text.
func runFake(fn func(t testing.TB)) string {
	f := &fakeT{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(f)
	}()
	<-done
	s, _ := f.msg.Load().(string)
	return s
}

func TestWaitForReturnsWhenTrue(t *testing.T) {
	var n atomic.Int32
	WaitFor(t, func() bool { return n.Add(1) >= 5 }, 10*time.Second)
	if n.Load() < 5 {
		t.Errorf("cond ran %d times, want at least 5", n.Load())
	}
}

func TestWaitForFailsAtLimit(t *testing.T) {
	msg := runFake(func(f testing.TB) { WaitFor(f, func() bool { return false }, 20*time.Millisecond) })
	if msg == "" {
		t.Error("WaitFor did not fail the test at the limit")
	}
}

// A value that a subtest sets is back to the old value when the subtest ends.
func TestSetRestoresAfterSubtest(t *testing.T) {
	v := 1
	t.Run("sub", func(t *testing.T) {
		Set(t, &v, 2)
		if v != 2 {
			t.Errorf("v = %d in the subtest, want 2", v)
		}
	})
	if v != 1 {
		t.Errorf("v = %d after the subtest, want 1", v)
	}
}

func TestSetNestedRestoresInOrder(t *testing.T) {
	f := func() string { return "old" }
	t.Run("sub", func(t *testing.T) {
		Set(t, &f, func() string { return "a" })
		Set(t, &f, func() string { return "b" })
		if got := f(); got != "b" {
			t.Errorf("f() = %q, want b", got)
		}
	})
	if got := f(); got != "old" {
		t.Errorf("f() = %q after the subtest, want old", got)
	}
}
