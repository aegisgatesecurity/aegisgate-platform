// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Setup CLI Subcommand
// =========================================================================
//
// Implements `aegisgate setup` — an interactive or non-interactive wizard
// that detects the environment, recommends a deploy profile, generates a
// config file, validates it, and prints next steps.
//
// This subcommand does NOT start any servers. It only generates a config
// file and prints instructions.
//
// Usage:
//   aegisgate setup                           # interactive (prompts)
//   aegisgate setup --non-interactive         # auto-detect, no prompts
//   aegisgate setup --profile quickstart      # skip profile selection
//   aegisgate setup --output my-config.yaml   # custom output path
//   aegisgate setup --force                   # overwrite existing config
//
// =========================================================================

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/setup"
)

// isSetupSubcommand reports whether the first non-flag argument is "setup".
func isSetupSubcommand() bool {
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg == "setup"
	}
	return false
}

func init() {
	if isSetupSubcommand() {
		args := stripSubcommand(os.Args[1:], "setup")
		exit := runSetupSubcommand(args)
		os.Exit(exit)
	}
}

// runSetupSubcommand handles the "aegisgate setup" subcommand.
func runSetupSubcommand(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	nonInteractive := fs.Bool("non-interactive", false, "Run without prompts (auto-detect everything)")
	profile := fs.String("profile", "", "Use a specific deploy profile (skip selection)")
	output := fs.String("output", "aegisgate-platform.yaml", "Output config file path")
	force := fs.Bool("force", false, "Overwrite existing config file without prompting")
	help := fs.Bool("help", false, "Show help")

	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: aegisgate setup [options]")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "Run the setup wizard to generate a configuration file.")
		fmt.Fprintln(fs.Output(), "The wizard detects your environment and recommends a deploy profile.")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "Options:")
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "Examples:")
		fmt.Fprintln(fs.Output(), "  aegisgate setup                              # Interactive wizard")
		fmt.Fprintln(fs.Output(), "  aegisgate setup --non-interactive            # Auto-detect everything")
		fmt.Fprintln(fs.Output(), "  aegisgate setup --profile production         # Use production profile")
		fmt.Fprintln(fs.Output(), "  aegisgate setup -o /etc/aegisgate/config.yaml --force")
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *help {
		fs.Usage()
		return 0
	}

	opts := &setup.WizardOptions{
		NonInteractive: *nonInteractive,
		Profile:        *profile,
		OutputPath:     *output,
		Force:          *force,
	}

	configPath, err := setup.Run(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Setup failed: %v\n", err)
		return 1
	}
	if configPath == "" {
		// User cancelled (e.g. chose not to overwrite)
		return 0
	}

	return 0
}
