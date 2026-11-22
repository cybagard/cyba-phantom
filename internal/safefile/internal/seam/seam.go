// Package seam holds the test hooks of package safefile. Only code below
// internal/safefile can import it. A hook runs any test code. No hook
// result can make a refused file pass.
package seam

import (
	"errors"
	"sync/atomic"
)

// FileID is the device and inode of a file.
type FileID struct{ Dev, Ino uint64 }

// Crash is the result of a Step hook that stops the write at once, as a
// crash does. No later step and no cleanup runs.
var Crash = errors.New("seam: simulated crash")

// Hooks is one set of test hooks. A nil field is a hook that is off.
type Hooks struct {
	BeforeCheck func(name string)    // before the Lstat of a name
	AfterCheck  func(name string)    // between the Lstat and the open
	AfterOpen   func(name string)    // between the open and the fstat
	OtherOwner  func(id FileID) bool // true: refuse as another owner

	// Step runs before each step of a write. The step names are "create",
	// "write", "sync", "close", "check", "rename", "link", "remove" and
	// "dirsync". An error that is not Crash makes the step fail with that
	// error. Crash stops the write. The name is the file or directory.
	Step func(step, name string) error
}

var current atomic.Pointer[Hooks]

// Current gives the active set, or nil on the production path.
func Current() *Hooks { return current.Load() }

// Install makes h the active set. It returns false when a set is active.
func Install(h *Hooks) bool { return current.CompareAndSwap(nil, h) }

// Remove ends the set h when it is the active set.
func Remove(h *Hooks) { current.CompareAndSwap(h, nil) }
