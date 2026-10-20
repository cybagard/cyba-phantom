// Command trace checks the C10 traceability matrix and the spec sync stamp.
//
// Usage:
//
//	trace [matrix|stamp|all] [spec-dir] [--write]
//
// Modes:
//
//	matrix  (default) — verify spec/08-traceability.md against the
//	requirement IDs declared in 01-prd.md and the Covers columns of
//	07-test-plan.md, and require a byte-exact canonical re-emit.
//
//	stamp   — re-hash every file in the spec directory against
//	manifest.json; --write rotates the stamp instead of verifying.
//
//	all     — matrix and stamp.
//
//	tests   — trace tests [spec-dir] --milestone M-n: check the exit
//	criteria table of 07-test-plan.md. Each test ID is in one row. Each
//	ID of the rows up to M-n has a Go test or a Makefile marker. The
//	tree is the working directory. See tests.go.
//
// The spec directory defaults to "spec".
//
// Exit codes: 0 in sync, 1 findings, 2 usage or unreadable input.
package main

import (
	"fmt"
	"os"
	"strings"
)

// maxPrintedFindings caps the findings printed to the log.
const maxPrintedFindings = 25

func main() {
	os.Exit(run(os.Args[1:]))
}

func isMode(s string) bool {
	return s == "matrix" || s == "stamp" || s == "all" || s == "tests"
}

func run(args []string) int {
	mode, dir := "matrix", "spec"
	write := false
	milestone := ""
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--write":
			write = true
		case a == "--milestone":
			if i+1 == len(args) {
				fmt.Fprintln(os.Stderr, "trace: --milestone needs a value")
				return 2
			}
			i++
			milestone = args[i]
		case strings.HasPrefix(a, "--milestone="):
			milestone = strings.TrimPrefix(a, "--milestone=")
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "trace: unknown flag %q\n", a)
			return 2
		default:
			positional = append(positional, a)
		}
	}
	switch len(positional) {
	case 0:
		// defaults
	case 1:
		if isMode(positional[0]) {
			mode = positional[0]
		} else {
			dir = positional[0]
		}
	case 2:
		mode, dir = positional[0], positional[1]
		if !isMode(mode) {
			fmt.Fprintf(os.Stderr, "trace: unknown mode %q (want matrix, stamp, all, or tests)\n", mode)
			return 2
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: trace [matrix|stamp|all] [spec-dir] [--write]")
		fmt.Fprintln(os.Stderr, "       trace tests [spec-dir] --milestone M-n")
		return 2
	}
	if write && mode != "stamp" {
		fmt.Fprintln(os.Stderr, "trace: --write is only valid in stamp mode")
		return 2
	}
	if mode == "tests" && milestone == "" {
		fmt.Fprintln(os.Stderr, "trace: tests mode needs --milestone M-n")
		return 2
	}
	if mode != "tests" && milestone != "" {
		fmt.Fprintln(os.Stderr, "trace: --milestone is only valid in tests mode")
		return 2
	}

	var findings []string
	if mode == "matrix" || mode == "all" {
		f, err := runMatrix(dir)
		findings = append(findings, f...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trace: %v\n", err)
			return 2
		}
	}
	if mode == "stamp" || mode == "all" {
		f, err := runStamp(dir, write)
		findings = append(findings, f...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trace: %v\n", err)
			return 2
		}
		if write {
			fmt.Printf("trace: stamp rotated in %s\n", dir)
			if len(findings) == 0 {
				return 0
			}
		}
	}

	if mode == "tests" {
		f, err := runTests(dir, ".", milestone)
		findings = append(findings, f...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trace: %v\n", err)
			return 2
		}
	}

	if len(findings) > 0 {
		// Cap the printed findings: a hostile spec/ can produce many.
		for i, f := range findings {
			if i == maxPrintedFindings {
				fmt.Printf("trace: … %d more finding(s) not shown\n", len(findings)-i)
				break
			}
			fmt.Println("trace:", f)
		}
		fmt.Printf("trace FAIL: %d finding(s)\n", len(findings))
		return 1
	}
	switch mode {
	case "matrix":
		fmt.Println("trace: 08-traceability.md agrees with 01-prd.md and 07-test-plan.md (byte-exact)")
	case "stamp":
		fmt.Printf("trace: spec stamp in sync (%s)\n", dir)
	case "tests":
		fmt.Printf("trace: each test ID up to %s has a Go test or a marker\n", milestone)
	default:
		fmt.Println("trace: matrix and stamp in sync")
	}
	return 0
}
