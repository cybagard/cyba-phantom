package reference

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The tests of the README and of the expiry of the reference bundle (SEC-42,
// T-U-29).

const (
	readmeFile   = "README.md"
	manifestFile = "src/manifest.json"
	// noFetchSentence is the fixed sentence of the README about the fetch URL.
	noFetchSentence = "The project serves no fetch URL (`bundle.fetch_url`) for the reference bundle."
	// watchDays is the number of days before expires that the watch needs.
	watchDays = 45
	// resignText is the fixed error text of the expiry watch.
	resignText = "reference bundle expires in fewer than 45 days: the key holder signs the bundle again, with a new manifest version"
)

// manifestFields holds the two members of the manifest that the tests read.
type manifestFields struct {
	KeyID   string `json:"key_id"`
	Expires string `json:"expires"`
}

func readManifest(b []byte) (manifestFields, error) {
	var m manifestFields
	if err := json.Unmarshal(b, &m, parseOpts...); err != nil {
		return m, fmt.Errorf("manifest: %w", err)
	}
	return m, nil
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checkReadmeFacts reports a README that does not hold the key_id and the
// expires of the manifest, as written there.
func checkReadmeFacts(readme, manifest []byte) error {
	m, err := readManifest(manifest)
	if err != nil {
		return err
	}
	if m.KeyID == "" || m.Expires == "" {
		return errors.New("manifest has no key_id or no expires")
	}
	for name, v := range map[string]string{"key_id": m.KeyID, "expires": m.Expires} {
		if !bytes.Contains(readme, []byte(v)) {
			return fmt.Errorf("README does not hold the %s %q", name, v)
		}
	}
	return nil
}

// checkNoFetch reports a README without the fixed no-fetch-URL sentence.
func checkNoFetch(readme []byte, sentence string) error {
	if !bytes.Contains(readme, []byte(sentence)) {
		return fmt.Errorf("README does not hold the sentence %q", sentence)
	}
	return nil
}

// expiryWatch fails when fewer than watchDays days remain before expires.
func expiryWatch(manifest []byte, now time.Time) error {
	m, err := readManifest(manifest)
	if err != nil {
		return err
	}
	exp, err := time.Parse(time.RFC3339, m.Expires)
	if err != nil {
		return fmt.Errorf("manifest expires: %w", err)
	}
	if exp.Sub(now) < watchDays*24*time.Hour {
		return errors.New(resignText)
	}
	return nil
}

func TestTU29_ReadmeHoldsKeyIDAndExpires(t *testing.T) {
	readme, manifest := mustRead(t, readmeFile), mustRead(t, manifestFile)
	if err := checkReadmeFacts(readme, manifest); err != nil {
		t.Fatal(err)
	}
	m, _ := readManifest(manifest)
	badReadme := bytes.ReplaceAll(readme, []byte(m.Expires), []byte("2027-11-17T00:00:00Z"))
	if bytes.Equal(badReadme, readme) {
		t.Fatal("test copy of the README is not changed")
	}
	if checkReadmeFacts(badReadme, manifest) == nil {
		t.Error("README with another expires date passes")
	}
	badManifest := bytes.ReplaceAll(manifest, []byte(`"`+m.KeyID+`"`), []byte(`"ref9"`))
	if bytes.Equal(badManifest, manifest) {
		t.Fatal("test copy of the manifest is not changed")
	}
	if checkReadmeFacts(readme, badManifest) == nil {
		t.Error("manifest with another key_id passes")
	}
}

func TestTU29_ReadmeHoldsNoFetchSentence(t *testing.T) {
	readme := mustRead(t, readmeFile)
	if err := checkNoFetch(readme, noFetchSentence); err != nil {
		t.Fatal(err)
	}
	bad := strings.ReplaceAll(string(readme), noFetchSentence, "")
	if checkNoFetch([]byte(bad), noFetchSentence) == nil {
		t.Error("README without the sentence passes")
	}
}

func TestTU29_ExpiryWatchRows(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) []byte {
		return fmt.Appendf(nil, `{"key_id":"ref1","expires":%q}`, now.Add(d).Format(time.RFC3339))
	}
	const day = 24 * time.Hour
	// The wanted text is written out here, apart from resignText.
	const want = "reference bundle expires in fewer than 45 days: the key holder signs the bundle again, with a new manifest version"
	rows := []struct {
		name     string
		manifest []byte
		fixed    bool // The row fails with the fixed text.
		pass     bool
	}{
		{"44 days", at(44 * day), true, false},
		{"46 days", at(46 * day), false, true},
		{"exactly 45 days", at(45 * day), false, true},
		{"past", at(-day), true, false},
		{"no expires", []byte(`{"key_id":"ref1"}`), false, false},
		{"bad expires", []byte(`{"key_id":"ref1","expires":"soon"}`), false, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			err := expiryWatch(r.manifest, now)
			switch {
			case r.pass && err != nil:
				t.Errorf("fails: %v", err)
			case !r.pass && err == nil:
				t.Error("passes")
			case r.fixed && err.Error() != want:
				t.Errorf("error text %q, want %q", err, want)
			case !r.pass && !r.fixed && err.Error() == want:
				t.Error("a bad manifest gives the text of an expiry")
			}
		})
	}
	if !strings.Contains(want, "signs the bundle again") || !strings.Contains(want, "new manifest version") {
		t.Error("the fixed text does not name the re-sign step")
	}
}

// TestTU29_ExpiryWatch is the watch on the committed manifest. It fails when
// fewer than 45 days remain before expires.
func TestTU29_ExpiryWatch(t *testing.T) {
	manifest := mustRead(t, manifestFile)
	// The README holds the expires of the committed file, so a copy of the
	// manifest with another date fails here.
	if err := checkReadmeFacts(mustRead(t, readmeFile), manifest); err != nil {
		t.Fatal(err)
	}
	if err := expiryWatch(manifest, time.Now()); err != nil {
		t.Fatal(err)
	}
}
