// Command notest calls egresstest in a binary that is not a test binary. Each
// call must fail the testing.TB that it gets.
package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress/egresstest"
)

// fakeTB records a fatal call. Fatalf stops the goroutine as testing.T does.
type fakeTB struct {
	testing.TB
	failed bool
}

func (f *fakeTB) Helper()               {}
func (f *fakeTB) Cleanup(func())        {}
func (f *fakeTB) Fatalf(string, ...any) { f.failed = true; panic(f) }

// failed tells if call fails the testing.TB that it gets.
func failed(call func(testing.TB)) (failed bool) {
	f := &fakeTB{}
	defer func() {
		if r := recover(); r != nil && r != any(f) {
			panic(r)
		}
		failed = f.failed
	}()
	call(f)
	return false
}

func main() {
	fmt.Printf("testing.Testing=%t\n", testing.Testing())
	fmt.Printf("Dialer failed=%t\n", failed(func(t testing.TB) {
		egresstest.Dialer(t, time.Second)
	}))
	fmt.Printf("NewNames failed=%t\n", failed(func(t testing.TB) {
		egresstest.NewNames(t)
	}))
}
