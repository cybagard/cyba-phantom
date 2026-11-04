// Package token mints and verifies canary tokens (FR-03, SEC-33, ADR-036).
//
// A token is one AES-128 block. The plaintext holds the trap index, the time
// unit and a counter. The last 56 bits are zero. Verify gives the fields back
// from the token and the key set alone. It uses no store and no session.
package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// The layout of the plaintext block (ADR-036 decision 1). The block is
// big-endian: index, unit and counter, then 56 zero check bits. The first
// 64 bits hold the index, the unit and the high bits of the counter. Byte 8
// holds the low 8 bits of the counter. Bytes 9 to 15 are the check bits.
const (
	// Size is the length of a token in bytes.
	Size = aes.BlockSize

	indexBits       = 10
	unitBits        = 20
	counterBits     = 42
	indexShift      = 64 - indexBits
	unitShift       = indexShift - unitBits
	counterLowBits  = 8
	counterHighBits = counterBits - counterLowBits
	fieldBytes      = 9
	maxTraps        = 1 << indexBits
	unitMask        = 1<<unitBits - 1
	counterMask     = 1<<counterBits - 1
	counterHighMask = 1<<counterHighBits - 1
)

// The time unit (ADR-036 decision 2): 10 minutes since the epoch, modulo
// 2^20. The epoch is 2026-01-01T00:00:00Z.
const (
	epochUnix   = 1767225600
	unitSeconds = 600
)

// The position of a key set in the ring that Verify gets. A ring can hold
// any number of key sets. Result.Set is the position of the matching key set.
// First and Second name the first two positions.
const (
	First  = 0
	Second = 1
)

// Errors of the package. No error holds key bytes or token bytes.
var (
	ErrNoKeySet = errors.New("token: no key set")
	ErrIndex    = errors.New("token: trap index out of range")
	ErrTraps    = errors.New("token: trap list must hold 1 to 1024 ids")
	ErrKey      = errors.New("token: key is not valid")
	ErrSeed     = errors.New("token: seed is empty")
	// ErrRange is the error of MintRange for a list or an out slice of a bad
	// length.
	ErrRange = errors.New("token: range must hold 1 to 68 indexes and match out")
)

// MaxRange is the largest number of tokens in one MintRange call. It is 64
// trap ids of a template (SEC-32) and 4 header slots of a route (ADR-038).
const MaxRange = 68

// keyInfo is the HKDF info of the AES key (ADR-036 decision 4). A zero byte
// comes after the label. keyBytes is the length of the AES-128 key.
const (
	keyInfo  = "phantom-token-v1\x00aes-128"
	keyBytes = 16
)

// deriveKey derives the AES key from the seed. The seed is the secret and the
// bundle SHA-256 is the salt. A test replaces it to see the key slice.
var deriveKey = func(seed []byte, sum [32]byte) ([]byte, error) {
	return hkdf.Key(sha256.New, seed, sum[:], keyInfo, keyBytes)
}

// zeroCheck is the value that the 56 check bits must have.
var zeroCheck [Size - fieldBytes]byte

// scratch holds the buffers for one cipher call. A local array that goes to
// cipher.Block as a slice moves to the heap. The pool avoids that. A call of
// Verify or Check uses one buffer.
var scratch = sync.Pool{New: func() any { return new([2 * Size]byte) }}

// KeySet mints and verifies the tokens of one key. It holds the cipher, a
// copy of the trap ids and the mint counter. It has no exported field. A
// KeySet is safe for concurrent use. Do not copy it. The fields are behind one
// pointer. A struct with a *KeySet in an unexported field prints an address
// under %s and %q. It prints no trap id.
type KeySet struct{ *keySetState }

type keySetState struct {
	block   cipher.Block
	traps   []string
	counter atomic.Uint64
	// ref is 1 for a key set of a reference bundle, else 0. Verify selects on
	// it with crypto/subtle, so it is an int.
	ref int
	// setID is the first 8 bytes of the bundle SHA-256, big-endian. A key set
	// from newKeySet or newKeySetBlock has a zero set id. Verify selects it
	// with a mask.
	setID uint64
}

// redacted is the text that Format writes for every verb.
const redacted = "token.KeySet"

// Format writes one fixed text for each verb that fmt gives it. The text
// holds no field, no pointer and no counter. Only a *KeySet uses Format.
// fmt can print the fields of a KeySet copy, and of a *KeySet in an unexported
// field.
func (k *KeySet) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(redacted))
}

// NewKeySet makes a key set from the token seed of a bundle. The key is
// HKDF-SHA-256 of the seed, with the bundle SHA-256 as salt. The index of a
// trap is its position in traps. reference is true for a bundle of the
// reference class. An empty seed gives ErrSeed. A bad trap count gives
// ErrTraps, before any derivation. A failed derivation gives ErrKey. The
// function clears the derived key bytes before it returns. The cipher keeps
// the key in its key schedule, and crypto/aes has no call that clears it. No
// error holds a byte of the seed.
func NewKeySet(seed []byte, sum [32]byte, traps []string, reference bool) (*KeySet, error) {
	if len(seed) == 0 {
		return nil, ErrSeed
	}
	if len(traps) == 0 || len(traps) > maxTraps {
		return nil, ErrTraps
	}
	key, err := deriveKey(seed, sum)
	defer clear(key)
	if err != nil {
		return nil, ErrKey
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKey
	}
	k, err := newKeySetBlock(b, traps)
	if err != nil {
		return nil, err
	}
	if reference {
		k.ref = 1
	}
	k.setID = binary.BigEndian.Uint64(sum[:8])
	return k, nil
}

// newKeySet makes a key set from an AES-128 key and the trap ids. The index
// of a trap is its position in the list.
func newKeySet(key []byte, traps []string) (*KeySet, error) {
	if len(key) != 16 {
		return nil, ErrKey
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKey
	}
	return newKeySetBlock(b, traps)
}

// newKeySetBlock makes a key set from a cipher. The counter starts at a
// random 42-bit value (ADR-036 decision 3).
func newKeySetBlock(b cipher.Block, traps []string) (*KeySet, error) {
	if len(traps) == 0 || len(traps) > maxTraps {
		return nil, ErrTraps
	}
	var s [8]byte
	_, _ = rand.Read(s[:]) // rand.Read never gives an error.
	k := &KeySet{&keySetState{block: b, traps: slices.Clone(traps)}}
	k.counter.Store(binary.BigEndian.Uint64(s[:]) & counterMask)
	return k, nil
}

// unitOf gives the time unit of t. A time before the epoch gives a unit near
// the top of the range, with no error.
func unitOf(t time.Time) uint64 {
	s := t.Unix() - epochUnix
	u := s / unitSeconds
	if s%unitSeconds < 0 {
		u--
	}
	return uint64(u) & unitMask
}

// pack writes the plaintext block to b. The fields must be in range.
func pack(b []byte, index, unit, counter uint64) {
	hi := index<<indexShift | unit<<unitShift | counter>>counterLowBits
	binary.BigEndian.PutUint64(b, hi)
	b[8] = byte(counter)
	clear(b[fieldBytes:Size])
}

// unpack reads the fields of the plaintext block b.
func unpack(b []byte) (index, unit, counter uint64) {
	hi := binary.BigEndian.Uint64(b)
	index = hi >> indexShift
	unit = hi >> unitShift & unitMask
	counter = (hi&counterHighMask)<<counterLowBits | uint64(b[8])
	return index, unit, counter
}

// Mint makes a token for the trap at index, with the time unit of at. Each
// call uses a new counter value (ADR-036 decision 3). It does not allocate
// in steady state. After a GC, or under the race detector, the buffer pool
// can allocate a small, bounded amount of memory.
func (k *KeySet) Mint(index int, at time.Time) ([Size]byte, error) {
	var out [Size]byte
	if k == nil || k.keySetState == nil || k.block == nil {
		return out, ErrNoKeySet
	}
	if index < 0 || index >= len(k.traps) {
		return out, ErrIndex
	}
	n := k.counter.Add(1) & counterMask
	buf := scratch.Get().(*[2 * Size]byte)
	pack(buf[:Size], uint64(index), unitOf(at), n)
	k.block.Encrypt(buf[Size:], buf[:Size])
	copy(out[:], buf[Size:])
	// Without this, the pool keeps the plaintext fields and the token bytes.
	// The buffer holds no key.
	clear(buf[:])
	scratch.Put(buf)
	return out, nil
}

// MintRange makes one token for each trap in indexes, with the time unit of
// at. It reserves all counters with one atomic add, so the ranges of parallel
// calls do not overlap. Token i is for the trap at indexes[i]. It uses the
// counter first+i, masked to 42 bits, and writes the token to out[i]. It
// gives ErrRange for an empty list, for more than MaxRange indexes, and for
// an out slice of another length. It gives ErrIndex for an index that is not
// a trap. A refused call moves no counter and writes nothing to out.
// The caller must not change indexes during the call. The counter can pass
// 2^42-1 inside a range and wrap to 0. The caller sees this from first and
// the length. It does not allocate in steady state. After a GC, or under the
// race detector, the buffer pool can allocate a small, bounded amount of
// memory.
func (k *KeySet) MintRange(indexes []int, at time.Time, out [][Size]byte) (first uint64, err error) {
	if k == nil || k.keySetState == nil || k.block == nil {
		return 0, ErrNoKeySet
	}
	n := uint64(len(indexes))
	if n == 0 || n > MaxRange || uint64(len(out)) != n {
		return 0, ErrRange
	}
	for _, index := range indexes {
		if index < 0 || index >= len(k.traps) {
			return 0, ErrIndex
		}
	}
	first = (k.counter.Add(n) - n + 1) & counterMask
	unit := unitOf(at)
	buf := scratch.Get().(*[2 * Size]byte)
	for i, index := range indexes {
		pack(buf[:Size], uint64(index), unit, (first+uint64(i))&counterMask)
		k.block.Encrypt(buf[Size:], buf[:Size])
		copy(out[i][:], buf[Size:])
	}
	// Without this, the pool keeps the plaintext fields and the token bytes.
	// The buffer holds no key.
	clear(buf[:])
	scratch.Put(buf)
	return first, nil
}

// Result is the outcome of Verify, Ring.Verify and Ring.Check. When OK is
// false, the other fields are zero.
type Result struct {
	OK   bool
	Trap string // the trap id
	Unit uint32 // the time unit of the mint
	Set  int    // the position of the matching key set in the ring
	// Counter is the 42-bit counter of the token.
	Counter uint64
	// Reference is true when the matching key set is of a reference bundle.
	Reference bool
	// SetID is the first 8 bytes of the bundle SHA-256 of the matching key
	// set. A key set from newKeySet or newKeySetBlock has a zero set id.
	SetID [8]byte
	// Stale and Future give the window class of the token. Only Ring.Verify
	// and Ring.Check set them. A future token is also stale. They never change
	// OK.
	Stale, Future bool
}

// Verify checks a token against the key sets of the ring. It decrypts the
// token under each key set, also after a match. It checks the 56 bits and
// the index with crypto/subtle, and it selects the result with no early
// return. A nil key set in the ring does not match. It does not allocate
// in steady state. After a GC, or under the race detector, the buffer pool
// can allocate a small, bounded amount of memory. The ring can have any
// length.
func Verify(ring []*KeySet, tok [Size]byte) Result {
	buf := scratch.Get().(*[2 * Size]byte)
	res := verifyIn(buf, ring, tok)
	// Without this, the pool keeps the plaintext fields and the token bytes.
	// The buffer holds no key.
	clear(buf[:])
	scratch.Put(buf)
	return res
}

// verifyIn is Verify with the buffer of the caller. The caller clears it.
func verifyIn(buf *[2 * Size]byte, ring []*KeySet, tok [Size]byte) Result {
	in, out := buf[:Size], buf[Size:]
	var matched, set, index, unit, reference int
	var counter, setID uint64
	for i, k := range ring {
		if k == nil || k.keySetState == nil || k.block == nil {
			continue
		}
		copy(in, tok[:])
		k.block.Decrypt(out, in)
		idx, un, c := unpack(out)
		zero := subtle.ConstantTimeCompare(out[fieldBytes:], zeroCheck[:])
		below := subtle.ConstantTimeLessOrEq(int(idx), len(k.traps)-1)
		ok := zero & below
		matched |= ok
		set = subtle.ConstantTimeSelect(ok, i, set)
		index = subtle.ConstantTimeSelect(ok, int(idx), index)
		unit = subtle.ConstantTimeSelect(ok, int(un), unit)
		reference = subtle.ConstantTimeSelect(ok, k.ref, reference)
		// ConstantTimeSelect takes an int, which has 32 bits on some platforms.
		m := -uint64(ok)
		counter = counter&^m | c&m
		setID = setID&^m | k.setID&m
	}
	if matched == 0 {
		return Result{}
	}
	res := Result{OK: true, Trap: ring[set].traps[index], Unit: uint32(unit), Set: set, Counter: counter, Reference: reference == 1}
	binary.BigEndian.PutUint64(res.SetID[:], setID)
	return res
}
