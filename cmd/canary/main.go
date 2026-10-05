// Command canary is the Agent Canary sensor entry point.
//
// M-1 task 1.1 ships the skeleton only: config, wiring, and the run loop
// land in the later 1.x tasks (09). This binary reads no input, writes no
// files, and opens no connections; it exists to anchor the module, the
// Makefile, and the reproducible-build check (T-P-07).
package main

import "fmt"

func main() {
	fmt.Println("canary: M-1 skeleton — no listeners yet")
}
