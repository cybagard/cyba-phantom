// Package seam holds the test hooks of package safefile. Only code below
// internal/safefile can import it. A hook can refuse a file or wait. No hook
// can give an owner, a mode or a size.
package seam

import "sync/atomic"

// FileID is the device and inode of a file.
type FileID struct{ Dev, Ino uint64 }

// Hooks is one set of test hooks. A nil field is a hook that is off.
type Hooks struct {
	BeforeCheck func(name string)    // before the Lstat of a name
	AfterCheck  func(name string)    // between the Lstat and the open
	AfterOpen   func(name string)    // between the open and the fstat
	OtherOwner  func(id FileID) bool // true: refuse as another owner
}

var current atomic.Pointer[Hooks]

// Current gives the active set, or nil on the production path.
func Current() *Hooks { return current.Load() }

// Install makes h the active set. It returns false when a set is active.
func Install(h *Hooks) bool { return current.CompareAndSwap(nil, h) }

// Remove ends the set h when it is the active set.
func Remove(h *Hooks) { current.CompareAndSwap(h, nil) }
