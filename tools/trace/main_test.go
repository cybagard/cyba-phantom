package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// mirrorScript is the absolute path of tools/mirror-diff.sh. Other tests
// change the working directory, so TestMain sets the path before any test
// runs.
var mirrorScript string

func TestMain(m *testing.M) {
	var err error
	if mirrorScript, err = filepath.Abs("../mirror-diff.sh"); err != nil {
		fmt.Fprintln(os.Stderr, "mirror-diff script path:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
