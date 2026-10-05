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
//	all     — both.
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
	return s == "matrix" || s == "stamp" || s == "all"
}

func run(args []string) int {
	mode, dir := "matrix", "spec"
	write := false
	var positional []string
	for _, a := range args {
		switch {
		case a == "--write":
			write = true
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
			fmt.Fprintf(os.Stderr, "trace: unknown mode %q (want matrix, stamp, or all)\n", mode)
			return 2
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: trace [matrix|stamp|all] [spec-dir] [--write]")
		return 2
	}
	if write && mode != "stamp" {
		fmt.Fprintln(os.Stderr, "trace: --write is only valid in stamp mode")
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
	default:
		fmt.Println("trace: matrix and stamp in sync")
	}
	return 0
}
