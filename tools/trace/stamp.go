// Stamp: the spec sync stamp. manifest.json records the date (YYYY-MM-DD)
// of the last internal sync plus a SHA-256 hash of every other file in
// spec/. Verify mode re-hashes the directory and reports drift (a changed
// file without a new sync, or a file that is not stamped). --write
// rotates the stamp; it never reports drift.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// manifest is spec/manifest.json. File names are keys so json.Marshal
// sorts them.
type manifest struct {
	Synced string            `json:"synced"`
	Files  map[string]string `json:"files"`
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// hashDir maps every regular file in specDir (except manifest.json) to
// its SHA-256. Subdirectories are findings: spec/ must be flat. A
// non-nil error means the directory itself is unreadable.
func hashDir(specDir string) (map[string]string, []string, error) {
	hashes := map[string]string{}
	var findings []string
	entries, err := os.ReadDir(specDir)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read spec dir %s: %v", specDir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			findings = append(findings, fmt.Sprintf("spec: unexpected subdirectory %s (spec/ must be flat)", e.Name()))
			continue
		}
		if e.Name() == "manifest.json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(specDir, e.Name()))
		if err != nil {
			findings = append(findings, fmt.Sprintf("spec: cannot read %s: %v", e.Name(), err))
			continue
		}
		hashes[e.Name()] = sha256Hex(data)
	}
	return hashes, findings, nil
}

// runStamp verifies (or, with write, rotates) the sync stamp. It returns
// findings and a fatal error only for an unreadable spec directory.
func runStamp(specDir string, write bool) ([]string, error) {
	hashes, findings, err := hashDir(specDir)
	if err != nil {
		return nil, err
	}
	if write {
		m := manifest{
			Synced: time.Now().UTC().Format("2006-01-02"),
			Files:  hashes,
		}
		out, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return findings, fmt.Errorf("stamp: %v", err)
		}
		if err := os.WriteFile(filepath.Join(specDir, "manifest.json"), append(out, '\n'), 0o644); err != nil {
			return findings, fmt.Errorf("stamp: cannot write manifest.json: %v", err)
		}
		return nil, nil
	}

	data, err := os.ReadFile(filepath.Join(specDir, "manifest.json"))
	if err != nil {
		return append(findings, fmt.Sprintf("spec: manifest.json missing or unreadable: %v", err)), nil
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return append(findings, fmt.Sprintf("spec: manifest.json malformed: %v", err)), nil
	}
	for name, want := range m.Files {
		got, ok := hashes[name]
		if !ok {
			findings = append(findings, fmt.Sprintf("spec: %s is stamped but missing from spec/", name))
			continue
		}
		if got != want {
			findings = append(findings, fmt.Sprintf("spec: %s changed since the sync stamp (%s)", name, m.Synced))
		}
	}
	for name := range hashes {
		if _, ok := m.Files[name]; !ok {
			findings = append(findings, fmt.Sprintf("spec: %s is not stamped (add it or re-sync)", name))
		}
	}
	return findings, nil
}
