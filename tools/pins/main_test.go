package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var (
	digestA = strings.Repeat("a", 64)
	digestB = strings.Repeat("b", 64)
)

// files maps a path below the repository root to its text.
type files map[string]string

// baseFiles returns copies of the four files that agree. Line numbers in
// the expected messages below come from these texts.
func baseFiles() files {
	return files{
		goModFile: "module example.com/x\n\ngo 1.27.3\n",
		makeFile: "# GOTOOLCHAIN := go1.0.0\n" +
			"GOTOOLCHAIN := go1.27.3\n" +
			"export GOTOOLCHAIN\n",
		ciFile: "# GOTOOLCHAIN: go1.0.0\n" +
			"  # image: golang:0.0.0\n" +
			"env:\n" +
			"  GOTOOLCHAIN: go1.27.3\n" +
			"jobs:\n" +
			"  oracle:\n" +
			"    container:\n" +
			"      image: golang:1.27.3@sha256:" + digestA + "\n",
		dockerFile: "# FROM golang:0.0.0\n" +
			"FROM golang:1.27.3@sha256:" + digestA + "\n",
	}
}

// edit replaces the first old text in a file. It fails the test when the
// text is not there, so a test never passes because an edit did nothing.
func (f files) edit(t *testing.T, name, old, repl string) {
	t.Helper()
	if !strings.Contains(f[name], old) {
		t.Fatalf("%s has no text %q", name, old)
	}
	f[name] = strings.Replace(f[name], old, repl, 1)
}

// write puts the files in a new temporary directory and returns it.
func (f files) write(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range f {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func skew(file string, line int, got, want, goLine string) string {
	return fmt.Sprintf("%s:%d: version %q is not version %q of %s", file, line, got, want, goLine)
}

func badForm(file string, line int, what, text, want string) string {
	return fmt.Sprintf("%s:%d: %s line %q is not of the form %q", file, line, what, text, want)
}

func TestRepoFilesAgree(t *testing.T) {
	if fails := check(filepath.Join("..", "..")); len(fails) > 0 {
		t.Fatalf("the files of the repository disagree:\n%s", strings.Join(fails, "\n"))
	}
}

func TestBaseFilesAgree(t *testing.T) {
	if fails := check(baseFiles().write(t)); len(fails) > 0 {
		t.Fatalf("got failures: %q", fails)
	}
}

func TestAgreeingVariants(t *testing.T) {
	cases := map[string]func(t *testing.T, f files){
		"toolchain line of the same version": func(t *testing.T, f files) {
			f.edit(t, goModFile, "go 1.27.3\n", "go 1.27.3\n\ntoolchain go1.27.3\n")
		},
		"version with two digits in a part": func(t *testing.T, f files) {
			for _, name := range []string{goModFile, makeFile, ciFile, dockerFile} {
				f[name] = strings.ReplaceAll(f[name], "1.27.3", "10.27.30")
			}
		},
		"export line is not an assignment": func(t *testing.T, f files) {
			f.edit(t, makeFile, "export GOTOOLCHAIN\n", "export GOTOOLCHAIN\nexport GOTOOLCHAIN\n")
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			f := baseFiles()
			mod(t, f)
			if fails := check(f.write(t)); len(fails) > 0 {
				t.Fatalf("got failures: %q", fails)
			}
		})
	}
}

func TestDisagreement(t *testing.T) {
	image := func(digest string) string { return "golang:1.27.3@sha256:" + digest }
	cases := []struct {
		name string
		mod  func(t *testing.T, f files)
		want []string
	}{
		{
			name: "go line at an older version",
			mod:  func(t *testing.T, f files) { f.edit(t, goModFile, "go 1.27.3", "go 1.27.2") },
			want: []string{
				skew(makeFile, 2, "1.27.3", "1.27.2", "go.mod:3"),
				skew(ciFile, 4, "1.27.3", "1.27.2", "go.mod:3"),
				skew(dockerFile, 2, "1.27.3", "1.27.2", "go.mod:3"),
			},
		},
		{
			name: "Makefile GOTOOLCHAIN at another version",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "\nGOTOOLCHAIN := go1.27.3", "\nGOTOOLCHAIN := go1.27.2")
			},
			want: []string{skew(makeFile, 2, "1.27.2", "1.27.3", "go.mod:3")},
		},
		{
			name: "ci.yml GOTOOLCHAIN at another version",
			mod:  func(t *testing.T, f files) { f.edit(t, ciFile, "GOTOOLCHAIN: go1.27.3", "GOTOOLCHAIN: go1.28.0") },
			want: []string{skew(ciFile, 4, "1.28.0", "1.27.3", "go.mod:3")},
		},
		{
			name: "second GOTOOLCHAIN key in a job env",
			mod: func(t *testing.T, f files) {
				f.edit(t, ciFile, "    container:\n", "    env:\n      GOTOOLCHAIN: go1.27.3\n    container:\n")
			},
			want: []string{"ci.yml:8: 2 GOTOOLCHAIN lines (lines [4 8]), one needed"},
		},
		{
			name: "ci.yml image digest differs from the Dockerfile digest",
			mod: func(t *testing.T, f files) {
				f.edit(t, ciFile, "sha256:"+digestA, "sha256:"+digestB)
			},
			want: []string{fmt.Sprintf("%s:8: image %q is not the image %q of %s:2",
				ciFile, image(digestB), image(digestA), dockerFile)},
		},
		{
			name: "Dockerfile digest differs from the ci.yml digest",
			mod: func(t *testing.T, f files) {
				f.edit(t, dockerFile, "sha256:"+digestA, "sha256:"+digestB)
			},
			want: []string{fmt.Sprintf("%s:8: image %q is not the image %q of %s:2",
				ciFile, image(digestA), image(digestB), dockerFile)},
		},
		{
			name: "Dockerfile tag at another version with the same digest in both files",
			mod: func(t *testing.T, f files) {
				f.edit(t, dockerFile, "golang:1.27.3@", "golang:1.27.2@")
				f.edit(t, ciFile, "golang:1.27.3@", "golang:1.27.2@")
			},
			want: []string{skew(dockerFile, 2, "1.27.2", "1.27.3", "go.mod:3")},
		},
		{
			name: "toolchain line that differs",
			mod: func(t *testing.T, f files) {
				f.edit(t, goModFile, "go 1.27.3\n", "go 1.27.3\n\ntoolchain go1.27.2\n")
			},
			want: []string{skew(goModFile, 5, "1.27.2", "1.27.3", "go.mod:3")},
		},
		{
			name: "toolchain line without the go prefix",
			mod: func(t *testing.T, f files) {
				f.edit(t, goModFile, "go 1.27.3\n", "go 1.27.3\n\ntoolchain 1.27.3\n")
			},
			want: []string{badForm(goModFile, 5, "toolchain", "toolchain 1.27.3", "toolchain go<x>.<y>.<z>")},
		},
		{
			name: "second toolchain line",
			mod: func(t *testing.T, f files) {
				f.edit(t, goModFile, "go 1.27.3\n", "go 1.27.3\n\ntoolchain go1.27.3\n\ntoolchain go1.27.3\n")
			},
			want: []string{"go.mod:7: 2 toolchain lines (lines [5 7]), one needed"},
		},
		{
			name: "second go line",
			mod:  func(t *testing.T, f files) { f.edit(t, goModFile, "go 1.27.3\n", "go 1.27.3\ngo 1.27.3\n") },
			want: []string{"go.mod:4: 2 go lines (lines [3 4]), one needed"},
		},
		{
			name: "second Makefile assignment with =",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "export", "GOTOOLCHAIN = go1.27.3\nexport")
			},
			want: []string{"Makefile:3: 2 GOTOOLCHAIN assignment lines (lines [2 3]), one needed"},
		},
		{
			name: "second Makefile assignment with ?=",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "export", "GOTOOLCHAIN ?= go1.27.3\nexport")
			},
			want: []string{"Makefile:3: 2 GOTOOLCHAIN assignment lines (lines [2 3]), one needed"},
		},
		{
			name: "second Makefile assignment with +=",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "export", "GOTOOLCHAIN += go1.27.3\nexport")
			},
			want: []string{"Makefile:3: 2 GOTOOLCHAIN assignment lines (lines [2 3]), one needed"},
		},
		{
			name: "second Makefile assignment with :=",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "export", "GOTOOLCHAIN := go1.27.3\nexport")
			},
			want: []string{"Makefile:3: 2 GOTOOLCHAIN assignment lines (lines [2 3]), one needed"},
		},
		{
			name: "export with an assignment is a second assignment",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "export GOTOOLCHAIN\n", "export GOTOOLCHAIN := go1.27.3\n")
			},
			want: []string{"Makefile:3: 2 GOTOOLCHAIN assignment lines (lines [2 3]), one needed"},
		},
		{
			name: "second image line",
			mod: func(t *testing.T, f files) {
				f.edit(t, ciFile, "    container:\n", "    services:\n      image: golang:1.27.3\n    container:\n")
			},
			want: []string{"ci.yml:10: 2 image lines (lines [8 10]), one needed"},
		},
		{
			name: "second FROM line",
			mod: func(t *testing.T, f files) {
				f[dockerFile] += "FROM golang:1.27.3@sha256:" + digestA + "\n"
			},
			want: []string{".devcontainer/Dockerfile:3: 2 FROM lines (lines [2 3]), one needed"},
		},
		{
			name: "second FROM line in lower case",
			mod:  func(t *testing.T, f files) { f[dockerFile] += "from scratch\n" },
			want: []string{".devcontainer/Dockerfile:3: 2 FROM lines (lines [2 3]), one needed"},
		},
		{
			name: "go line with a part missing",
			mod:  func(t *testing.T, f files) { f.edit(t, goModFile, "go 1.27.3", "go 1.27") },
			want: []string{badForm(goModFile, 3, "go", "go 1.27", "go <x>.<y>.<z>")},
		},
		{
			name: "go line with a suffix",
			mod:  func(t *testing.T, f files) { f.edit(t, goModFile, "go 1.27.3", "go 1.27.3-rc1") },
			want: []string{badForm(goModFile, 3, "go", "go 1.27.3-rc1", "go <x>.<y>.<z>")},
		},
		{
			name: "go line with a comment",
			mod:  func(t *testing.T, f files) { f.edit(t, goModFile, "go 1.27.3", "go 1.27.3 // pin") },
			want: []string{badForm(goModFile, 3, "go", "go 1.27.3 // pin", "go <x>.<y>.<z>")},
		},
		{
			name: "go line with a prefix part",
			mod:  func(t *testing.T, f files) { f.edit(t, goModFile, "go 1.27.3", "go 1.1.27.3") },
			want: []string{badForm(goModFile, 3, "go", "go 1.1.27.3", "go <x>.<y>.<z>")},
		},
		{
			name: "go line with no version",
			mod:  func(t *testing.T, f files) { f.edit(t, goModFile, "go 1.27.3", "go") },
			want: []string{badForm(goModFile, 3, "go", "go", "go <x>.<y>.<z>")},
		},
		{
			name: "Makefile assignment with =",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "GOTOOLCHAIN := go1.27.3", "GOTOOLCHAIN = go1.27.3")
			},
			want: []string{badForm(makeFile, 2, "GOTOOLCHAIN assignment", "GOTOOLCHAIN = go1.27.3", "GOTOOLCHAIN := go<x>.<y>.<z>")},
		},
		{
			name: "Makefile assignment without the go prefix",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "GOTOOLCHAIN := go1.27.3", "GOTOOLCHAIN := 1.27.3")
			},
			want: []string{badForm(makeFile, 2, "GOTOOLCHAIN assignment", "GOTOOLCHAIN := 1.27.3", "GOTOOLCHAIN := go<x>.<y>.<z>")},
		},
		{
			name: "Makefile assignment with override",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "GOTOOLCHAIN := go1.27.3", "override GOTOOLCHAIN := go1.27.3")
			},
			want: []string{badForm(makeFile, 2, "GOTOOLCHAIN assignment", "override GOTOOLCHAIN := go1.27.3", "GOTOOLCHAIN := go<x>.<y>.<z>")},
		},
		{
			name: "ci.yml GOTOOLCHAIN with a local value",
			mod:  func(t *testing.T, f files) { f.edit(t, ciFile, "GOTOOLCHAIN: go1.27.3", "GOTOOLCHAIN: local") },
			want: []string{badForm(ciFile, 4, "GOTOOLCHAIN", "  GOTOOLCHAIN: local", "GOTOOLCHAIN: go<x>.<y>.<z>")},
		},
		{
			name: "ci.yml GOTOOLCHAIN with a trailing comment",
			mod: func(t *testing.T, f files) {
				f.edit(t, ciFile, "GOTOOLCHAIN: go1.27.3", "GOTOOLCHAIN: go1.27.3 # pin")
			},
			want: []string{badForm(ciFile, 4, "GOTOOLCHAIN", "  GOTOOLCHAIN: go1.27.3 # pin", "GOTOOLCHAIN: go<x>.<y>.<z>")},
		},
		{
			name: "ci.yml image with two words",
			mod:  func(t *testing.T, f files) { f.edit(t, ciFile, "      image: golang", "      image: x golang") },
			want: []string{badForm(ciFile, 8, "image", "      image: x golang:1.27.3@sha256:"+digestA, "image: <image>")},
		},
		{
			name: "Dockerfile FROM without a digest",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, "@sha256:"+digestA, "") },
			want: []string{badForm(dockerFile, 2, "FROM", "FROM golang:1.27.3", "FROM golang:<x>.<y>.<z>@sha256:<64 hex digits>")},
		},
		{
			name: "Dockerfile FROM with 63 hex digits",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, digestA, digestA[1:]) },
			want: []string{badForm(dockerFile, 2, "FROM", "FROM golang:1.27.3@sha256:"+digestA[1:], "FROM golang:<x>.<y>.<z>@sha256:<64 hex digits>")},
		},
		{
			name: "Dockerfile FROM with 65 hex digits",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, digestA, digestA+"a") },
			want: []string{badForm(dockerFile, 2, "FROM", "FROM golang:1.27.3@sha256:"+digestA+"a", "FROM golang:<x>.<y>.<z>@sha256:<64 hex digits>")},
		},
		{
			name: "Dockerfile FROM with an upper-case digit",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, "sha256:a", "sha256:A") },
			want: []string{badForm(dockerFile, 2, "FROM", "FROM golang:1.27.3@sha256:A"+digestA[1:], "FROM golang:<x>.<y>.<z>@sha256:<64 hex digits>")},
		},
		{
			name: "Dockerfile FROM with a non-hex digit",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, "sha256:a", "sha256:g") },
			want: []string{badForm(dockerFile, 2, "FROM", "FROM golang:1.27.3@sha256:g"+digestA[1:], "FROM golang:<x>.<y>.<z>@sha256:<64 hex digits>")},
		},
		{
			name: "Dockerfile FROM with another algorithm",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, "sha256:", "sha512:") },
			want: []string{badForm(dockerFile, 2, "FROM", "FROM golang:1.27.3@sha512:"+digestA, "FROM golang:<x>.<y>.<z>@sha256:<64 hex digits>")},
		},
		{
			name: "Dockerfile FROM with a stage name",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, digestA+"\n", digestA+" AS dev\n") },
			want: []string{badForm(dockerFile, 2, "FROM", "FROM golang:1.27.3@sha256:"+digestA+" AS dev", "FROM golang:<x>.<y>.<z>@sha256:<64 hex digits>")},
		},
		{
			name: "Dockerfile FROM in lower case",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, "\nFROM", "\nfrom") },
			want: []string{badForm(dockerFile, 2, "FROM", "from golang:1.27.3@sha256:"+digestA, "FROM golang:<x>.<y>.<z>@sha256:<64 hex digits>")},
		},
		{
			name: "no go line",
			mod:  func(t *testing.T, f files) { f.edit(t, goModFile, "go 1.27.3\n", "") },
			want: []string{"go.mod: no go line"},
		},
		{
			name: "no GOTOOLCHAIN assignment in the Makefile",
			mod:  func(t *testing.T, f files) { f.edit(t, makeFile, "GOTOOLCHAIN := go1.27.3\n", "") },
			want: []string{"Makefile: no GOTOOLCHAIN assignment line"},
		},
		{
			name: "no GOTOOLCHAIN key in ci.yml",
			mod:  func(t *testing.T, f files) { f.edit(t, ciFile, "  GOTOOLCHAIN: go1.27.3\n", "") },
			want: []string{"ci.yml: no GOTOOLCHAIN line"},
		},
		{
			name: "no image key in ci.yml",
			mod: func(t *testing.T, f files) {
				f.edit(t, ciFile, "      image: golang:1.27.3@sha256:"+digestA+"\n", "")
			},
			want: []string{"ci.yml: no image line"},
		},
		{
			name: "no FROM line",
			mod: func(t *testing.T, f files) {
				f.edit(t, dockerFile, "FROM golang:1.27.3@sha256:"+digestA+"\n", "")
			},
			want: []string{".devcontainer/Dockerfile: no FROM line"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := baseFiles()
			c.mod(t, f)
			got := check(f.write(t))
			// A message names ci.yml by its path. The cases use the short name.
			for i := range got {
				got[i] = strings.ReplaceAll(got[i], ciFile, "ci.yml")
			}
			want := slices.Clone(c.want)
			for i := range want {
				want[i] = strings.ReplaceAll(want[i], ciFile, "ci.yml")
			}
			if !slices.Equal(got, want) {
				t.Fatalf("got failures:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

func TestMissingFileFails(t *testing.T) {
	for _, name := range []string{goModFile, makeFile, ciFile, dockerFile} {
		t.Run(name, func(t *testing.T) {
			f := baseFiles()
			delete(f, name)
			got := check(f.write(t))
			if len(got) != 1 || !strings.HasPrefix(got[0], name+": cannot read the file: ") {
				t.Fatalf("got failures: %q", got)
			}
		})
	}
}

func TestUnreadableFileFails(t *testing.T) {
	dir := baseFiles().write(t)
	path := filepath.Join(dir, makeFile)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	got := check(dir)
	if len(got) != 1 || !strings.HasPrefix(got[0], "Makefile: cannot read the file: ") {
		t.Fatalf("got failures: %q", got)
	}
}

func TestLargeFileFails(t *testing.T) {
	f := baseFiles()
	f[makeFile] += strings.Repeat("#\n", maxFileBytes/2)
	got := check(f.write(t))
	if len(got) != 1 || !strings.Contains(got[0], "the file is larger than") {
		t.Fatalf("got failures: %q", got)
	}
	// A file of exactly the limit is not too large.
	f = baseFiles()
	f[makeFile] += strings.Repeat("#", maxFileBytes-len(f[makeFile]))
	if got := check(f.write(t)); len(got) != 0 {
		t.Fatalf("a file of the limit size must pass, got %q", got)
	}
}

func TestRunPrintsOneLineForEachFailure(t *testing.T) {
	f := baseFiles()
	f.edit(t, goModFile, "go 1.27.3", "go 1.27.2")
	var stdout, stderr bytes.Buffer
	if rc := run(f.write(t), &stdout, &stderr); rc != 1 {
		t.Fatalf("exit status %d, want 1", rc)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout %q, want empty", stdout.String())
	}
	if n := strings.Count(stderr.String(), "\n"); n != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", n, stderr.String())
	}
}

func TestRunPassesWithExitZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if rc := run(baseFiles().write(t), &stdout, &stderr); rc != 0 {
		t.Fatalf("exit status %d, stderr %q", rc, stderr.String())
	}
	if stderr.Len() != 0 || !strings.Contains(stdout.String(), "agree") {
		t.Fatalf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
}
