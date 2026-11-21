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
// the expected messages below come from these texts. The comment lines name
// the key words on purpose: a comment line must never count.
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

// secondJob returns a second job of ci.yml that runs in the given image. It
// comes after the job of baseFiles, so its image line is line 11.
func secondJob(image string) string {
	return "  other:\n    container:\n      image: " + image + "\n"
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

func notAllowed(file string, line int, text string) string {
	return fmt.Sprintf("%s:%d: line %q is not an allowed line", file, line, text)
}

// shortNames gives the failures of check with ci.yml by its short name, as
// the cases below write it.
func shortNames(fails []string) []string {
	out := slices.Clone(fails)
	for i := range out {
		out[i] = strings.ReplaceAll(out[i], ciFile, "ci.yml")
	}
	return out
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
		"comment lines that name the key words": func(t *testing.T, f files) {
			f[goModFile] += "// go 1.0.0\n\t// toolchain go1.0.0\n"
			f[makeFile] += "# GOTOOLCHAIN := go1.0.0\n\t# export GOTOOLCHAIN\n  # unexport GOTOOLCHAIN\n"
			f[ciFile] += "  # image: x\n\t# container: golang:1.0.0\n    # uses: docker://x\n    # GOTOOLCHAIN: go1.0.0\n"
			f[dockerFile] += "# ENV GOTOOLCHAIN=go1.0.0\n  # FROM scratch\n"
		},
		"second job with the same image": func(t *testing.T, f files) {
			f[ciFile] += secondJob("golang:1.27.3@sha256:" + digestA)
		},
		"backslash line before a line without a key word": func(t *testing.T, f files) {
			f[makeFile] += "FOO := bar \\\nBAZ := 1\n"
			f[dockerFile] += "RUN true \\\n  && true\n"
		},
		"Dockerfile comment that ends in a backslash before FROM": func(t *testing.T, f files) {
			f.edit(t, dockerFile, "FROM golang:1.27.3", "# note \\\nFROM golang:1.27.3")
		},
		"lines without a key word": func(t *testing.T, f files) {
			f[goModFile] += "\nrequire (\n\tgo.uber.org/x v1.0.0\n)\n"
			f[makeFile] += "all:\n\tgo test ./...\n"
			f[ciFile] += "    runs-on: ubuntu-latest\n"
			f[dockerFile] += "RUN go version\n"
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
			want: []string{notAllowed("ci.yml", 8, "      GOTOOLCHAIN: go1.27.3")},
		},
		{
			name: "second GOTOOLCHAIN key at the indent of the first",
			mod: func(t *testing.T, f files) {
				f.edit(t, ciFile, "jobs:\n", "  GOTOOLCHAIN: go1.27.3\njobs:\n")
			},
			want: []string{"ci.yml:5: 2 GOTOOLCHAIN lines (lines [4 5]), one allowed"},
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
			want: []string{notAllowed(goModFile, 5, "toolchain 1.27.3")},
		},
		{
			name: "second toolchain line",
			mod: func(t *testing.T, f files) {
				f.edit(t, goModFile, "go 1.27.3\n", "go 1.27.3\n\ntoolchain go1.27.3\n\ntoolchain go1.27.3\n")
			},
			want: []string{"go.mod:7: 2 toolchain lines (lines [5 7]), one allowed"},
		},
		{
			name: "second go line",
			mod:  func(t *testing.T, f files) { f.edit(t, goModFile, "go 1.27.3\n", "go 1.27.3\ngo 1.27.3\n") },
			want: []string{"go.mod:4: 2 go lines (lines [3 4]), one allowed"},
		},
		{
			name: "second Makefile assignment with :=",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "export", "GOTOOLCHAIN := go1.27.3\nexport")
			},
			want: []string{"Makefile:3: 2 GOTOOLCHAIN assignment lines (lines [2 3]), one allowed"},
		},
		{
			name: "second export line",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "export GOTOOLCHAIN\n", "export GOTOOLCHAIN\nexport GOTOOLCHAIN\n")
			},
			want: []string{"Makefile:4: 2 export GOTOOLCHAIN lines (lines [3 4]), one allowed"},
		},
		{
			name: "second container line",
			mod: func(t *testing.T, f files) {
				f.edit(t, ciFile, "    container:\n", "    container:\n    container:\n")
			},
			want: []string{"ci.yml: 2 container lines and 1 image lines, the numbers must be equal"},
		},
		{
			name: "second image line at a deeper indent",
			mod: func(t *testing.T, f files) {
				f.edit(t, ciFile, "    container:\n", "    services:\n          image: golang:1.27.3\n    container:\n")
			},
			want: []string{
				"ci.yml: 1 container lines and 2 image lines, the numbers must be equal",
				fmt.Sprintf("%s:8: image %q is not the image %q of %s:2",
					ciFile, "golang:1.27.3", image(digestA), dockerFile),
			},
		},
		{
			name: "second job with an image of another digest",
			mod: func(t *testing.T, f files) {
				f[ciFile] += secondJob("golang:1.27.3@sha256:" + digestB)
			},
			want: []string{fmt.Sprintf("%s:11: image %q is not the image %q of %s:2",
				ciFile, image(digestB), image(digestA), dockerFile)},
		},
		{
			name: "second job with an image of another tag",
			mod: func(t *testing.T, f files) {
				f[ciFile] += secondJob("golang:1.27.2@sha256:" + digestA)
			},
			want: []string{fmt.Sprintf("%s:11: image %q is not the image %q of %s:2",
				ciFile, "golang:1.27.2@sha256:"+digestA, image(digestA), dockerFile)},
		},
		{
			name: "second job with a container line and no image line",
			mod: func(t *testing.T, f files) {
				f[ciFile] += "  other:\n    container:\n"
			},
			want: []string{"ci.yml: 2 container lines and 1 image lines, the numbers must be equal"},
		},
		{
			name: "second FROM line",
			mod: func(t *testing.T, f files) {
				f[dockerFile] += "FROM golang:1.27.3@sha256:" + digestA + "\n"
			},
			want: []string{".devcontainer/Dockerfile:3: 2 FROM lines (lines [2 3]), one allowed"},
		},
		{
			name: "comment line that ends in a backslash",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "# GOTOOLCHAIN := go1.0.0", "# note \\")
			},
			want: []string{`Makefile:1: comment line "# note \\" ends in a backslash`},
		},
		{
			name: "Makefile assignment after a line that ends in a backslash",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "GOTOOLCHAIN := go1.27.3", "FOO := bar \\\nGOTOOLCHAIN := go1.27.3")
			},
			want: []string{`Makefile:3: line "GOTOOLCHAIN := go1.27.3" is joined to the line before it`},
		},
		{
			name: "Makefile export after a line that ends in a backslash",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "export GOTOOLCHAIN", "FOO := bar \\\nexport GOTOOLCHAIN")
			},
			want: []string{`Makefile:4: line "export GOTOOLCHAIN" is joined to the line before it`},
		},
		{
			name: "Dockerfile FROM after a line that ends in a backslash",
			mod: func(t *testing.T, f files) {
				f.edit(t, dockerFile, "FROM golang:1.27.3", "RUN true \\\nFROM golang:1.27.3")
			},
			want: []string{`.devcontainer/Dockerfile:3: line "FROM golang:1.27.3@sha256:` + digestA +
				`" is joined to the line before it`},
		},
		{
			name: "indented comment line that ends in a backslash",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "export", "\t# note \\\nexport")
			},
			want: []string{`Makefile:3: comment line "\t# note \\" ends in a backslash`},
		},
		{
			name: "Makefile assignment with =",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "GOTOOLCHAIN := go1.27.3", "GOTOOLCHAIN = go1.27.3")
			},
			want: []string{notAllowed(makeFile, 2, "GOTOOLCHAIN = go1.27.3")},
		},
		{
			name: "Makefile assignment without the go prefix",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "GOTOOLCHAIN := go1.27.3", "GOTOOLCHAIN := 1.27.3")
			},
			want: []string{notAllowed(makeFile, 2, "GOTOOLCHAIN := 1.27.3")},
		},
		{
			name: "Makefile assignment with override",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "GOTOOLCHAIN := go1.27.3", "override GOTOOLCHAIN := go1.27.3")
			},
			want: []string{notAllowed(makeFile, 2, "override GOTOOLCHAIN := go1.27.3")},
		},
		{
			name: "export with an assignment",
			mod: func(t *testing.T, f files) {
				f.edit(t, makeFile, "export GOTOOLCHAIN\n", "export GOTOOLCHAIN := go1.27.3\n")
			},
			want: []string{notAllowed(makeFile, 3, "export GOTOOLCHAIN := go1.27.3")},
		},
		{
			name: "ci.yml GOTOOLCHAIN with a local value",
			mod:  func(t *testing.T, f files) { f.edit(t, ciFile, "GOTOOLCHAIN: go1.27.3", "GOTOOLCHAIN: local") },
			want: []string{notAllowed("ci.yml", 4, "  GOTOOLCHAIN: local")},
		},
		{
			name: "ci.yml GOTOOLCHAIN with a trailing comment",
			mod: func(t *testing.T, f files) {
				f.edit(t, ciFile, "GOTOOLCHAIN: go1.27.3", "GOTOOLCHAIN: go1.27.3 # pin")
			},
			want: []string{notAllowed("ci.yml", 4, "  GOTOOLCHAIN: go1.27.3 # pin")},
		},
		{
			name: "ci.yml image with two words",
			mod:  func(t *testing.T, f files) { f.edit(t, ciFile, "      image: golang", "      image: x golang") },
			want: []string{notAllowed("ci.yml", 8, "      image: x golang:1.27.3@sha256:"+digestA)},
		},
		{
			name: "ci.yml container with a trailing comment",
			mod:  func(t *testing.T, f files) { f.edit(t, ciFile, "    container:\n", "    container: # c\n") },
			want: []string{notAllowed("ci.yml", 7, "    container: # c")},
		},
		{
			name: "Dockerfile FROM without a digest",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, "@sha256:"+digestA, "") },
			want: []string{notAllowed(dockerFile, 2, "FROM golang:1.27.3")},
		},
		{
			name: "Dockerfile FROM with 63 hex digits",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, digestA, digestA[1:]) },
			want: []string{notAllowed(dockerFile, 2, "FROM golang:1.27.3@sha256:"+digestA[1:])},
		},
		{
			name: "Dockerfile FROM with 65 hex digits",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, digestA, digestA+"a") },
			want: []string{notAllowed(dockerFile, 2, "FROM golang:1.27.3@sha256:"+digestA+"a")},
		},
		{
			name: "Dockerfile FROM with an upper-case digit",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, "sha256:a", "sha256:A") },
			want: []string{notAllowed(dockerFile, 2, "FROM golang:1.27.3@sha256:A"+digestA[1:])},
		},
		{
			name: "Dockerfile FROM with a non-hex digit",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, "sha256:a", "sha256:g") },
			want: []string{notAllowed(dockerFile, 2, "FROM golang:1.27.3@sha256:g"+digestA[1:])},
		},
		{
			name: "Dockerfile FROM with another algorithm",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, "sha256:", "sha512:") },
			want: []string{notAllowed(dockerFile, 2, "FROM golang:1.27.3@sha512:"+digestA)},
		},
		{
			name: "Dockerfile FROM with a stage name",
			mod:  func(t *testing.T, f files) { f.edit(t, dockerFile, digestA+"\n", digestA+" AS dev\n") },
			want: []string{notAllowed(dockerFile, 2, "FROM golang:1.27.3@sha256:"+digestA+" AS dev")},
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
			name: "no export line in the Makefile",
			mod:  func(t *testing.T, f files) { f.edit(t, makeFile, "export GOTOOLCHAIN\n", "") },
			want: []string{"Makefile: no export GOTOOLCHAIN line"},
		},
		{
			name: "no GOTOOLCHAIN key in ci.yml",
			mod:  func(t *testing.T, f files) { f.edit(t, ciFile, "  GOTOOLCHAIN: go1.27.3\n", "") },
			want: []string{"ci.yml: no GOTOOLCHAIN line"},
		},
		{
			name: "no container key in ci.yml",
			mod:  func(t *testing.T, f files) { f.edit(t, ciFile, "    container:\n", "") },
			want: []string{"ci.yml: no container line"},
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
			got := shortNames(check(f.write(t)))
			want := shortNames(c.want)
			if !slices.Equal(got, want) {
				t.Fatalf("got failures:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

// TestRejectedForms tests each other form of a line with a key word. The
// form is added as a new line, or it replaces the line named by old. The
// only failure is that the new line is not an allowed line.
func TestRejectedForms(t *testing.T) {
	cases := []struct {
		name string
		file string
		old  string // the line that the form replaces; empty to add the form
		text string // the form, one line
	}{
		// go.mod
		{"go.mod indented toolchain line", goModFile, "", " toolchain go1.28.0"},
		{"go.mod toolchain line after a tab", goModFile, "", "\ttoolchain go1.28.0"},
		{"go.mod go line after a tab, added", goModFile, "", "\tgo 1.27.3"},
		{"go.mod go line after a tab, replaced", goModFile, "go 1.27.3", "\tgo 1.27.3"},
		{"go.mod go line with a tab as the separator", goModFile, "go 1.27.3", "go\t1.27.3"},
		{"go.mod toolchain line with a comment", goModFile, "", "toolchain go1.27.3 // pin"},
		// Makefile
		{"Makefile tab before :=", makeFile, "", "GOTOOLCHAIN\t:= go1.2.3"},
		{"Makefile tab before :=, replaced", makeFile, "GOTOOLCHAIN := go1.27.3", "GOTOOLCHAIN\t:= go1.27.3"},
		{"Makefile export with a tab", makeFile, "", "export\tGOTOOLCHAIN := go1.2.3"},
		{"Makefile export with a tab and no value", makeFile, "export GOTOOLCHAIN", "export\tGOTOOLCHAIN"},
		{"Makefile leading tab", makeFile, "", "\tGOTOOLCHAIN := go1.2.3"},
		{"Makefile leading tab, replaced", makeFile, "GOTOOLCHAIN := go1.27.3", "\tGOTOOLCHAIN := go1.27.3"},
		{"Makefile leading space on export", makeFile, "export GOTOOLCHAIN", " export GOTOOLCHAIN"},
		{"Makefile assignment with a comment", makeFile, "GOTOOLCHAIN := go1.27.3", "GOTOOLCHAIN := go1.27.3 # pin"},
		{"Makefile export with a comment", makeFile, "export GOTOOLCHAIN", "export GOTOOLCHAIN # pin"},
		{"Makefile target-specific assignment", makeFile, "", "lint: GOTOOLCHAIN := go1.2.3"},
		{"Makefile define", makeFile, "", "define GOTOOLCHAIN\ngo1.2.3\nendef"},
		{"Makefile unexport", makeFile, "", "unexport GOTOOLCHAIN"},
		{"Makefile undefine", makeFile, "", "undefine GOTOOLCHAIN"},
		{"Makefile recipe line", makeFile, "", "\tGOTOOLCHAIN=go1.2.3 go vet ./..."},
		{"Makefile go command with the variable", makeFile, "", "GO := GOTOOLCHAIN=go1.27.2 go"},
		{"Makefile eval", makeFile, "", "$(eval GOTOOLCHAIN := go1.2.3)"},
		// ci.yml
		{"ci.yml double-quoted key", ciFile, "", "    \"GOTOOLCHAIN\": go1.2.3"},
		{"ci.yml single-quoted key", ciFile, "", "    'GOTOOLCHAIN': go1.2.3"},
		{"ci.yml flow mapping", ciFile, "", "    env: {GOTOOLCHAIN: go1.2.3}"},
		{"ci.yml make argument", ciFile, "", "    run: make perf GOTOOLCHAIN=go1.2.3"},
		{"ci.yml GITHUB_ENV", ciFile, "", "    run: echo GOTOOLCHAIN=go1.2.3 >> $GITHUB_ENV"},
		{"ci.yml only key moved into a job env", ciFile, "  GOTOOLCHAIN: go1.27.3", "    GOTOOLCHAIN: go1.27.3"},
		{"ci.yml key after a prefix", ciFile, "  GOTOOLCHAIN: go1.27.3", "x  GOTOOLCHAIN: go1.27.3"},
		{"ci.yml container with a string", ciFile, "", "    container: golang:1.2.3"},
		{"ci.yml container with a string, replaced", ciFile, "    container:", "    container: golang:1.27.3"},
		{"ci.yml container after a dash", ciFile, "    container:", "    - container:"},
		{"ci.yml container in a flow mapping", ciFile, "", "    container: {image: golang:1.2.3}"},
		{"ci.yml quoted image key", ciFile, "", "      \"image\": golang:1.2.3"},
		{"ci.yml image key in upper case", ciFile, "", "      IMAGE: golang:1.2.3"},
		{"ci.yml image after a dash", ciFile, "      image: golang", "      - image: golang"},
		{"ci.yml image without indent", ciFile, "      image: golang", "image: golang"},
		{"ci.yml docker image in uses", ciFile, "", "      - uses: docker://golang:1.2.3"},
		// Dockerfile
		{"Dockerfile FROM after a tab, added", dockerFile, "", "\tFROM golang:1.2.3"},
		{"Dockerfile FROM after a tab, replaced", dockerFile, "FROM golang:1.27.3", "\tFROM golang:1.27.3"},
		{"Dockerfile FROM after a space", dockerFile, "", " FROM golang:1.2.3"},
		{"Dockerfile FROM in lower case, added", dockerFile, "", "from scratch"},
		{"Dockerfile FROM in lower case, replaced", dockerFile, "FROM golang:1.27.3", "from golang:1.27.3"},
		{"Dockerfile FROM in mixed case", dockerFile, "", "From scratch"},
		{"Dockerfile ENV GOTOOLCHAIN", dockerFile, "", "ENV GOTOOLCHAIN=go1.27.3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := baseFiles()
			var line int
			if c.old == "" {
				line = strings.Count(f[c.file], "\n") + 1
				f[c.file] += c.text + "\n"
			} else {
				line = strings.Count(f[c.file][:strings.Index(f[c.file], c.old)], "\n") + 1
				f.edit(t, c.file, c.old, c.text)
			}
			text := strings.Split(f[c.file], "\n")[line-1]
			got := check(f.write(t))
			want := []string{notAllowed(c.file, line, text)}
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
