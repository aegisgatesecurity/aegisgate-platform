// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Config CLI Subcommand
// =========================================================================
//
// Implements `aegisgate config <validate|show|profiles>` — a CLI utility
// for validating config files, dumping the effective config, and listing
// deploy profiles.
//
// This subcommand does NOT start the proxy, MCP, or dashboard servers.
// It only loads config and performs validation/display, making it safe
// to run from CI gates, init containers, or pre-flight checks.
//
// Usage:
//   aegisgate config validate [config-file]  — validate a config file
//   aegisgate config show [config-file]      — dump effective config as YAML
//   aegisgate config profiles                — list deploy profiles
//
// If no config file is specified, the default "aegisgate-platform.yaml" is used.
//
// =========================================================================

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/platformconfig"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/profiles"
	"gopkg.in/yaml.v3"
)

// isConfigSubcommand reports whether the first non-flag argument is "config".
func isConfigSubcommand() bool {
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg == "config"
	}
	return false
}

func init() {
	if isConfigSubcommand() {
		args := stripSubcommand(os.Args[1:], "config")
		exit := runConfigSubcommand(args)
		os.Exit(exit)
	}
}

// runConfigSubcommand handles the "aegisgate config" subcommand.
func runConfigSubcommand(args []string) int {
	if len(args) == 0 {
		printConfigHelp()
		return 0
	}

	verb := args[0]
	rest := args[1:]

	switch verb {
	case "validate":
		return runConfigValidate(rest)
	case "show":
		return runConfigShow(rest)
	case "profiles":
		return runConfigProfiles(rest)
	case "help", "--help", "-h":
		printConfigHelp()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unknown config verb %q\n", verb)
		printConfigHelp()
		return 1
	}
}

// runConfigValidate handles `aegisgate config validate [file]`.
func runConfigValidate(args []string) int {
	fs := flag.NewFlagSet("config validate", flag.ExitOnError)
	help := fs.Bool("help", false, "Show help")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: aegisgate config validate [config-file]")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "Validate a config file for errors and warnings.")
		fmt.Fprintln(fs.Output(), "If no file is specified, uses aegisgate-platform.yaml.")
		fmt.Fprintln(fs.Output(), "")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *help {
		fs.Usage()
		return 0
	}

	configPath := "aegisgate-platform.yaml"
	if fs.NArg() > 0 {
		configPath = fs.Arg(0)
	}

	// Check if file exists
	if _, err := os.Stat(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Config file not found: %s\n", configPath)
		fmt.Fprintf(os.Stderr, "   Create one with: aegisgate setup --profile <name> --output %s\n", configPath)
		return 1
	}

	result, err := platformconfig.ValidateFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to load config: %v\n", err)
		return 1
	}

	fmt.Printf("Validating: %s\n\n", configPath)
	fmt.Print(result.Summary())

	if result.HasErrors() {
		return 1
	}
	return 0
}

// runConfigShow handles `aegisgate config show [file] [--format json|yaml]`.
func runConfigShow(args []string) int {
	fs := flag.NewFlagSet("config show", flag.ExitOnError)
	format := fs.String("format", "yaml", "Output format: yaml or json")
	help := fs.Bool("help", false, "Show help")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: aegisgate config show [config-file] [--format yaml|json]")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "Dump the effective config (after defaults + env overrides) as YAML or JSON.")
		fmt.Fprintln(fs.Output(), "If no file is specified, uses aegisgate-platform.yaml.")
		fmt.Fprintln(fs.Output(), "")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *help {
		fs.Usage()
		return 0
	}

	configPath := "aegisgate-platform.yaml"
	if fs.NArg() > 0 {
		configPath = fs.Arg(0)
	}

	cfg, err := platformconfig.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to load config: %v\n", err)
		return 1
	}

	switch *format {
	case "yaml":
		data, err := yaml.Marshal(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to marshal config: %v\n", err)
			return 1
		}
		fmt.Print(string(data))
	case "json":
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to marshal config: %v\n", err)
			return 1
		}
		fmt.Print(string(data))
	default:
		fmt.Fprintf(os.Stderr, "❌ Unknown format %q — use \"yaml\" or \"json\"\n", *format)
		return 1
	}

	return 0
}

// runConfigProfiles handles `aegisgate config profiles`.
func runConfigProfiles(args []string) int {
	fs := flag.NewFlagSet("config profiles", flag.ExitOnError)
	help := fs.Bool("help", false, "Show help")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: aegisgate config profiles")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "List all available deploy profiles with key settings.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *help {
		fs.Usage()
		return 0
	}

	fmt.Println("Available deploy profiles:")
	fmt.Println()

	for _, p := range profiles.List() {
		fmt.Printf("  ── %s (%s) ──\n", p.Name, p.ID)
		fmt.Printf("  Tier: %s\n", p.Tier)
		fmt.Printf("  %s\n\n", p.Description)

		summary, err := profiles.Summary(string(p.ID))
		if err != nil {
			log.Printf("Error generating summary for %s: %v", p.ID, err)
			continue
		}
		// Indent the summary for readability
		for _, line := range strings.Split(summary, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Printf("  %s\n", line)
			}
		}
		fmt.Println()
	}

	return 0
}

// printConfigHelp prints the help text for the config subcommand.
func printConfigHelp() {
	fmt.Println(`aegisgate config — Config management utility

Usage:
  aegisgate config validate [config-file]   Validate a config file
  aegisgate config show [config-file]       Dump effective config (YAML or JSON)
  aegisgate config profiles                 List deploy profiles with key settings

Options:
  --format <yaml|json>   Output format for "show" (default: yaml)

Examples:
  aegisgate config validate                      # Validate default config
  aegisgate config validate my-config.yaml       # Validate specific file
  aegisgate config show --format json            # Show effective config as JSON
  aegisgate config profiles                      # List deploy profiles`)
}
