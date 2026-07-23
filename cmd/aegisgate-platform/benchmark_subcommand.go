// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Benchmark CLI subcommand
//
// benchmark_subcommand.go wires the SXC benchmark suite into the
// CLI binary as `aegisgate benchmark run`. The run verb executes
// the SXC corpus against the Platform's ResponseGuard scanner
// and produces a precision/recall report.
//
// CLI surface:
//
//	aegisgate benchmark run [--facet=secrets|xss|compliance] [--category=...] [--json] [--out=FILE]
//	aegisgate benchmark list-records
//
// The subcommand is detected from os.Args[1] == "benchmark".
// It uses the same init() pattern as the evaluator subcommand.

package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/evaluator"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// runBenchmarkSubcommand implements the "aegisgate benchmark"
// CLI subcommand. The verbs are: run, list-records.
func runBenchmarkSubcommand(args []string) {
	if len(args) == 0 {
		benchmarkUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	exitCode := 0
	switch verb {
	case "run":
		exitCode = runBenchmarkRun(rest)
	case "list-records":
		runBenchmarkListRecords(rest)
	case "-help", "--help", "help":
		benchmarkUsage()
	default:
		fmt.Fprintf(os.Stderr, "benchmark: unknown verb %q\n", verb)
		benchmarkUsage()
		os.Exit(2)
	}
	os.Exit(exitCode)
}

// benchmarkUsage prints the help text for the benchmark subcommand.
func benchmarkUsage() {
	fmt.Fprintf(os.Stderr, `aegisgate benchmark — Adversarial Benchmark Suite (v3.8)

Usage:
  aegisgate benchmark run [flags]
  aegisgate benchmark list-records [--facet=FACET] [--category=CAT]

Flags (run):
  --facet          filter to a single facet (secrets, xss, compliance)
  --category       filter to a single category (e.g., secret_aws_key)
  --json           emit JSON only (default: human-readable)
  --out            write the result to this file (default: stdout)
  --key-ring       path to the keyring file (default: ephemeral)

Flags (list-records):
  --facet          filter to a single facet (secrets, xss, compliance)
  --category       filter to a single category

Examples:
  # Run full SXC benchmark against ResponseGuard
  aegisgate benchmark run

  # Run only the secrets facet
  aegisgate benchmark run --facet=secrets

  # Run a specific category and write JSON to a file
  aegisgate benchmark run --category=secret_aws_key --json --out=aws-results.json

  # List all SXC records
  aegisgate benchmark list-records

  # List only XSS records
  aegisgate benchmark list-records --facet=xss
`)
}

// runBenchmarkRun is the implementation of "aegisgate benchmark run".
// Returns the exit code: 0 on success, 1 on error, 2 on usage error.
func runBenchmarkRun(args []string) int {
	// Parse flags manually (keep it simple — no flag package needed).
	var facet string
	var category string
	var jsonOut bool
	var outFile string
	var keyRingPath string

	rest := args
	filtered := make([]string, 0, len(rest))
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		if strings.HasPrefix(arg, "--facet=") {
			facet = strings.TrimPrefix(arg, "--facet=")
		} else if strings.HasPrefix(arg, "--category=") {
			category = strings.TrimPrefix(arg, "--category=")
		} else if arg == "--json" {
			jsonOut = true
		} else if strings.HasPrefix(arg, "--out=") {
			outFile = strings.TrimPrefix(arg, "--out=")
		} else if strings.HasPrefix(arg, "--key-ring=") {
			keyRingPath = strings.TrimPrefix(arg, "--key-ring=")
		} else if arg == "--facet" && i+1 < len(rest) {
			i++
			facet = rest[i]
		} else if arg == "--category" && i+1 < len(rest) {
			i++
			category = rest[i]
		} else if arg == "--out" && i+1 < len(rest) {
			i++
			outFile = rest[i]
		} else if arg == "--key-ring" && i+1 < len(rest) {
			i++
			keyRingPath = rest[i]
		} else {
			filtered = append(filtered, arg)
		}
	}
	_ = filtered // unused for now

	// 1. Build the scanner (ResponseGuard with default config).
	scanner := evaluator.NewResponseGuardScanner(response.NewResponseGuard())

	// 2. Build (or load) the keyring.
	kr, keyRingCleanup, err := loadOrEphemeralKeyRing(keyRingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark run: keyring: %v\n", err)
		return 1
	}
	if keyRingCleanup != nil {
		defer keyRingCleanup()
	}

	// 3. Build the benchmark runner.
	runner, err := evaluator.NewBenchmarkRunner(scanner, kr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark run: %v\n", err)
		return 1
	}

	// 4. Build options.
	var opts []evaluator.BenchmarkOption
	if facet != "" {
		opts = append(opts, evaluator.WithFacet(evaluator.SXCFacet(facet)))
	}
	if category != "" {
		opts = append(opts, evaluator.WithCategory(evaluator.SXCCategory(category)))
	}

	// 5. Run the benchmark.
	result, err := runner.RunBenchmark(context.Background(), opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark run: %v\n", err)
		return 1
	}

	// 6. Output.
	if outFile != "" {
		// Write to file.
		var data []byte
		if jsonOut {
			data, err = evaluator.BenchmarkReportJSON(result)
		} else {
			data = []byte(evaluator.BenchmarkReportText(result))
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "benchmark run: report: %v\n", err)
			return 1
		}
		if err := os.WriteFile(outFile, data, 0o600); err != nil { //nosec G703 -- outFile is a CLI flag, not user input from HTTP
			fmt.Fprintf(os.Stderr, "benchmark run: write %s: %v\n", outFile, err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "Wrote benchmark report to %s\n", outFile)
	} else if jsonOut {
		data, err := evaluator.BenchmarkReportJSON(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "benchmark run: report: %v\n", err)
			return 1
		}
		fmt.Println(string(data))
	} else {
		fmt.Println(evaluator.BenchmarkReportText(result))
	}

	// Exit code: 0 on success, 3 on critical findings (FN > 50%).
	if result.FalseNegatives > result.TruePositives {
		return 3
	}
	return 0
}

// runBenchmarkListRecords lists the SXC corpus records.
func runBenchmarkListRecords(args []string) {
	var facet string
	var category string

	for _, arg := range args {
		if strings.HasPrefix(arg, "--facet=") {
			facet = strings.TrimPrefix(arg, "--facet=")
		} else if strings.HasPrefix(arg, "--category=") {
			category = strings.TrimPrefix(arg, "--category=")
		}
	}

	var records []evaluator.SXCRecord
	if facet != "" {
		records = evaluator.SXCByFacet(evaluator.SXCFacet(facet))
	} else if category != "" {
		records = evaluator.SXCByCategory(evaluator.SXCCategory(category))
	} else {
		records = evaluator.SXCCorpus()
	}

	fmt.Printf("SXC Corpus: %s @ %s\n", evaluator.SXCCorpusID, evaluator.SXCCorpusVersion)
	fmt.Printf("Records: %d\n\n", len(records))
	fmt.Printf("%-45s %-10s %-30s %-8s %s\n", "ID", "FACET", "CATEGORY", "LABEL", "TEXT")
	// Sort for deterministic output.
	sort.Slice(records, func(i, j int) bool {
		return records[i].ID < records[j].ID
	})
	for _, r := range records {
		text := r.Text
		if len(text) > 60 {
			text = text[:57] + "..."
		}
		fmt.Printf("%-45s %-10s %-30s %-8d %s\n", r.ID, r.Facet, r.Category, r.ExpectedLabel, text)
	}
}

// isBenchmarkSubcommand returns true if args look like the
// "aegisgate benchmark" subcommand.
func isBenchmarkSubcommand(args []string) bool {
	return len(args) > 0 && args[0] == "benchmark"
}

// stripBenchmarkSubcommand removes the "benchmark" prefix from args.
func stripBenchmarkSubcommand(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	return args[1:]
}

func init() {
	if isBenchmarkSubcommand(os.Args[1:]) {
		args := stripBenchmarkSubcommand(os.Args[1:])
		runBenchmarkSubcommand(args)
		// Unreachable: runBenchmarkSubcommand calls os.Exit.
		return
	}
}
