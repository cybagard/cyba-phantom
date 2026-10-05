// Stamp: the spec sync stamp. manifest.json records the date (YYYY-MM-DD)
// of the last sync from the canonical spec plus a SHA-256 hash of every
// other file in spec/. Verify mode re-hashes the directory and reports drift (a changed
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
	"regexp"
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
	if err := checkSpecDir(specDir); err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(specDir)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read spec dir %q: %v", specDir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			findings = append(findings, fmt.Sprintf("spec: unexpected subdirectory %s (spec/ must be flat)", printableName(e.Name())))
			continue
		}
		if e.Name() == "manifest.json" {
			continue
		}
		// Names and errors are PR-controlled: a finding carries an
		// allow-listed name only, never raw error text.
		name := printableName(e.Name())
		data, err := readCapped(filepath.Join(specDir, e.Name()))
		if f := readFinding("spec: "+name, err); f != "" {
			findings = append(findings, f)
			continue
		}
		if err != nil {
			findings = append(findings, fmt.Sprintf("spec: cannot read %s", name))
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
		// Never write through a symlink: an existing manifest.json must be
		// a regular file. Write a temp file and rename it into place, so a
		// symlink swapped in after the check is replaced, not followed.
		target := filepath.Join(specDir, "manifest.json")
		if fi, err := os.Lstat(target); err == nil && !fi.Mode().IsRegular() {
			return findings, fmt.Errorf("stamp: manifest.json is not a regular file")
		}
		if err := writeReplace(target, append(out, '\n')); err != nil {
			return findings, fmt.Errorf("stamp: cannot write manifest.json: %v", err)
		}
		return findings, nil
	}

	data, err := readCapped(filepath.Join(specDir, "manifest.json"))
	if err != nil {
		return append(findings, "spec: manifest.json is missing, not a regular file, unreadable, or over the size cap"), nil
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		// The decoder error quotes manifest content raw: never print it.
		return append(findings, "spec: manifest.json is not valid JSON in the stamp format"), nil
	}
	// Manifest keys and the sync date are PR-controlled: print only
	// allow-listed names, and never print the date.
	if !syncDateRE.MatchString(m.Synced) {
		findings = append(findings, "spec: manifest.json sync date is not in YYYY-MM-DD form")
	}
	for name, want := range m.Files {
		got, ok := hashes[name]
		if !ok {
			findings = append(findings, fmt.Sprintf("spec: %s is stamped but missing from spec/", printableName(name)))
			continue
		}
		if got != want {
			findings = append(findings, fmt.Sprintf("spec: %s changed since the sync stamp", printableName(name)))
		}
	}
	for name := range hashes {
		if _, ok := m.Files[name]; !ok {
			findings = append(findings, fmt.Sprintf("spec: %s is not stamped (add it or re-sync)", printableName(name)))
		}
	}
	return findings, nil
}

// syncDateRE is the only accepted form of the manifest sync date.
var syncDateRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// writeReplace writes data to a temp file in the target's directory, then
// renames it over target. Rename replaces a symlink; it never follows one.
func writeReplace(target string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".manifest-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), target)
}
