// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Build Tool Entry Point
// =========================================================================
//
// main.go is the CLI entry point. It parses arguments, then
// runs the build pipeline in order:
//
//   parseArgs -> validateInputs -> validateSchema -> lint
//     -> bundle -> generateIcons -> package -> emitInventory
//
// Each stage is a separate function. Failures short-circuit
// the pipeline and return a non-zero exit code.
//
// v0.1.0+ Lens Phase 1 (plain-JS pivot, 2026-06-19).
// =========================================================================

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Exit codes. See doc.go for the full list.
const (
	exitOK             = 0
	exitBadArgs        = 1
	exitSourceNotFound = 2
	exitSchemaFailed   = 3
	exitLintFailed     = 4
	exitBundleFailed   = 5
	exitPackageFailed  = 6
	exitIconsFailed    = 7
)

// Config is the parsed CLI configuration.
type Config struct {
	// Src is the path to the Lens source directory (the
	// `src/` directory in the Lens repo).
	Src string

	// Dist is the path to the output directory.
	Dist string

	// Version is the Lens semantic version (e.g., "0.1.0").
	Version string

	// Commit is the git commit SHA this build is from.
	Commit string

	// BuildTime is when the build was run. Set to time.Now()
	// in main(); passed through for testability.
	BuildTime time.Time

	// Strict makes the build fail on any lint warning.
	// Default true; use --no-strict for soft-fail mode (CI
	// generally wants strict).
	Strict bool
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintf(os.Stderr, "usage: build-lens-extension --src <dir> --dist <dir> --version <v> --commit <sha>\n")
		os.Exit(exitBadArgs)
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(errToExit(err))
	}
}

// run is the testable entry point. It is called from main() and
// from the unit tests. It returns an error tagged with the stage
// that failed.
func run(cfg *Config) error {
	if err := validateInputs(cfg); err != nil {
		return &stageError{stage: "validate-inputs", err: err}
	}
	if err := validateSchema(cfg); err != nil {
		return &stageError{stage: "validate-schema", err: err}
	}
	if err := lint(cfg); err != nil {
		return &stageError{stage: "lint", err: err}
	}
	if err := bundle(cfg); err != nil {
		return &stageError{stage: "bundle", err: err}
	}
	if err := generateIcons(cfg.Dist); err != nil {
		return &stageError{stage: "icons", err: err}
	}
	if err := package_(cfg); err != nil {
		return &stageError{stage: "package", err: err}
	}
	if err := emitInventory(cfg); err != nil {
		return &stageError{stage: "inventory", err: err}
	}
	return nil
}

// parseArgs parses the CLI flags. Returns *Config or error.
func parseArgs(args []string) (*Config, error) {
	fs := flag.NewFlagSet("build-lens-extension", flag.ContinueOnError)
	src := fs.String("src", "", "path to the Lens src/ directory (required)")
	dist := fs.String("dist", "./dist", "path to the output directory")
	version := fs.String("version", "dev", "Lens semantic version (e.g., 0.1.0)")
	commit := fs.String("commit", "unknown", "git commit SHA")
	strict := fs.Bool("strict", true, "fail on any lint warning")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *src == "" {
		return nil, fmt.Errorf("--src is required")
	}
	abs, err := filepath.Abs(*src)
	if err != nil {
		return nil, fmt.Errorf("--src: %w", err)
	}
	return &Config{
		Src:       abs,
		Dist:      *dist,
		Version:   *version,
		Commit:    *commit,
		BuildTime: time.Now().UTC(),
		Strict:    *strict,
	}, nil
}

// validateInputs checks that the source directory exists and
// contains the expected files.
func validateInputs(cfg *Config) error {
	// The source directory must exist.
	info, err := os.Stat(cfg.Src) // #nosec G703 -- cfg.Src is a developer-supplied CLI arg
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("source directory does not exist: %s", cfg.Src)
		}
		return fmt.Errorf("stat source: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source is not a directory: %s", cfg.Src)
	}
	// Required files in the source directory.
	// All source files are plain JavaScript (no TypeScript).
	// Subdirectories are preserved by the bundle stage.
	required := []string{
		"manifest.json",
		"content.js",
		"service-worker.js",
		"popup.html",
		"popup.js",
		"welcome.html",
		"welcome.js",
		"privacy/schema.js",
		"privacy/domain_hash.js",
		"detectors/regex.js",
		"detectors/luhn.js",
		"detectors/index.js",
		"detectors/from_platform.js",
		"api/client.js",
		"storage.js",
		"util/logger.js",
	}
	for _, f := range required {
		path := filepath.Join(cfg.Src, f)        // #nosec G703 -- `f` is a hardcoded list of required source files; cfg.Src is a developer-supplied CLI arg
		if _, err := os.Stat(path); err != nil { // #nosec G703 -- see above
			if os.IsNotExist(err) {
				return fmt.Errorf("required source file missing: %s", f)
			}
			return fmt.Errorf("stat %s: %w", f, err)
		}
	}
	return nil
}

// stageError wraps an error with the build stage that produced it.
type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string {
	return fmt.Sprintf("%s: %v", e.stage, e.err)
}

func (e *stageError) Unwrap() error { return e.err }

// errToExit maps a stageError to the appropriate exit code.
func errToExit(err error) int {
	if se, ok := err.(*stageError); ok {
		switch se.stage {
		case "validate-inputs":
			return exitSourceNotFound
		case "validate-schema":
			return exitSchemaFailed
		case "lint":
			return exitLintFailed
		case "bundle":
			return exitBundleFailed
		case "icons":
			return exitIconsFailed
		case "package", "inventory":
			return exitPackageFailed
		}
	}
	return exitBadArgs
}
