// Package token mints and verifies canary tokens (FR-03, SEC-33, ADR-036).
//
// A token is one AES-128 block. The plaintext holds the trap index, the time
// unit and a counter. The last 56 bits are zero. Verify gives the fields back
// from the token and the key set alone. It uses no store and no session.
package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
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

// The position of a key set in the ring that Verify gets.
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
)

// zeroCheck is the value that the 56 check bits must have.
var zeroCheck [Size - fieldBytes]byte

// scratch holds the buffers for one cipher call. A local array that goes to
// cipher.Block as a slice moves to the heap. The pool avoids that.
var scratch = sync.Pool{New: func() any { return new([2 * Size]byte) }}

// KeySet mints and verifies the tokens of one key. It holds the cipher, a
// copy of the trap ids and the mint counter. It has no exported field. A
// KeySet is safe for concurrent use. Do not copy it.
type KeySet struct {
	block   cipher.Block
	traps   []string
	counter atomic.Uint64
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
	k := &KeySet{block: b, traps: slices.Clone(traps)}
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
// call uses a new counter value (ADR-036 decision 3). It does not allocate.
func (k *KeySet) Mint(index int, at time.Time) ([Size]byte, error) {
	var out [Size]byte
	if k == nil || k.block == nil {
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
	clear(buf[:])
	scratch.Put(buf)
	return out, nil
}

// Result is the outcome of Verify. When OK is false, the other fields are
// zero.
type Result struct {
	OK   bool
	Trap string // the trap id
	Unit uint32 // the time unit of the mint
	Set  int    // the position of the matching key set: First or Second
}

// Verify checks a token against the key sets of the ring. It decrypts the
// token under each key set, also after a match. It checks the 56 bits and
// the index with crypto/subtle, and it selects the result with no early
// return. A nil key set in the ring does not match. It does not allocate.
func Verify(ring []*KeySet, tok [Size]byte) Result {
	buf := scratch.Get().(*[2 * Size]byte)
	in, out := buf[:Size], buf[Size:]
	var matched, set, index, unit int
	for i, k := range ring {
		if k == nil || k.block == nil {
			continue
		}
		copy(in, tok[:])
		k.block.Decrypt(out, in)
		idx, un, _ := unpack(out)
		zero := subtle.ConstantTimeCompare(out[fieldBytes:], zeroCheck[:])
		below := subtle.ConstantTimeLessOrEq(int(idx), len(k.traps)-1)
		ok := zero & below
		matched |= ok
		set = subtle.ConstantTimeSelect(ok, i, set)
		index = subtle.ConstantTimeSelect(ok, int(idx), index)
		unit = subtle.ConstantTimeSelect(ok, int(un), unit)
	}
	clear(buf[:])
	scratch.Put(buf)
	if matched == 0 {
		return Result{}
	}
	return Result{OK: true, Trap: ring[set].traps[index], Unit: uint32(unit), Set: set}
}
