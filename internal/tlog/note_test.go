package tlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/tlog/verifier"
	"golang.org/x/mod/sumdb/note"
)

// noteKeys makes a signer and a verifier from a fixed seed. The keys are made
// only for the tests. The tests of the note format are in internal/tlog/verifier.
func noteKeys(t *testing.T, name string, seedByte byte) (note.Signer, note.Verifier) {
	t.Helper()
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	sum := sha256.Sum256(append(append([]byte(name+"\n"), 1), pub...))
	hash := binary.BigEndian.Uint32(sum[:4])
	enc := base64.StdEncoding.EncodeToString
	signer, err := note.NewSigner(fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, hash, enc(append([]byte{1}, seed...))))
	must(t, err)
	verifier, err := note.NewVerifier(fmt.Sprintf("%s+%08x+%s", name, hash, enc(append([]byte{1}, pub...))))
	must(t, err)
	return signer, verifier
}

func checkpointBody(c Checkpoint) string { return verifier.CheckpointBody(c) }

func testRoot() (r [32]byte) {
	for i := range r {
		r[i] = byte(i)
	}
	return r
}
