// Command canary is the Agent Canary sensor entry point.
//
// M-1 task 1.1 ships the skeleton only: config, wiring, and the run loop
// land in the later 1.x tasks (09). This binary reads no input, writes no
// files, and opens no connections; it exists to anchor the module, the
// Makefile, and the reproducible-build check (T-P-07).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cybagard/cyba-phantom/internal/config"
)

func main() {
	var configPath string
	var check bool

	flag.StringVar(&configPath, "config", "/etc/agent-canary/config.yaml", "path to configuration file")
	flag.BoolVar(&check, "check", false, "validate configuration and exit")
	flag.Parse()

	opts := config.Options{
		Check: check,
	}

	cfg, err := config.Load(configPath, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\\n", err)
		os.Exit(1)
	}

	if check {
		os.Exit(0)
	}

	_ = cfg // Use config in later slices

	fmt.Println("canary: started successfully")
}
