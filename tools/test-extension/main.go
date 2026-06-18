// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Test Harness: CLI Entry Point
// =========================================================================
//
// main.go is the test harness's CLI entry point. It parses
// arguments and orchestrates the test run:
//
//   parseArgs -> spawnChromium -> connectCDP -> loadExtension
//     -> runTests -> emitReport
//
// Each stage is a separate function. Failures short-circuit
// the pipeline and return a non-zero exit code.
//
// v3.5.0+ Lens Phase 2.
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
	exitTestFailed     = 1
	exitChromiumFailed = 2
	exitCDPFailed      = 3
	exitTestsMissing   = 4
	exitBadArgs        = 5
)

// Config is the parsed CLI configuration.
type Config struct {
	// Dist is the path to the Lens extension's dist/ directory
	// (produced by tools/build-lens-extension). The harness
	// loads the extension from this directory.
	Dist string

	// Tests is the path to the Lens repo's test/ directory
	// (contains the JSON test cases).
	Tests string

	// Provider is the AI provider to mock (chatgpt, claude,
	// gemini, copilot). Determines which testdata/<provider>.html
	// is used.
	Provider string

	// ChromiumPath is the path to the headless Chromium
	// binary. Defaults to "chromium" or "google-chrome" in
	// $PATH.
	ChromiumPath string

	// Port is the debugging port for the Chromium process.
	// Defaults to 9222.
	Port int

	// Timeout is the maximum time the harness will wait for
	// any single CDP operation. Defaults to 30 seconds.
	Timeout time.Duration

	// Output is the path to the JSON test report. Defaults to
	// "./test-report.json".
	Output string

	// TestdataDir is the path to the directory containing
	// the mock AI provider HTML pages. Defaults to
	// "./testdata" relative to the test-extension binary.
	TestdataDir string

	// Verbose enables verbose logging.
	Verbose bool
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintf(os.Stderr, "usage: test-extension --dist <dir> --tests <dir> --provider <name>\n")
		os.Exit(exitBadArgs)
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "test harness failed: %v\n", err)
		os.Exit(errToExit(err))
	}
}

// run is the testable entry point. It is called from main() and
// from the unit tests. It returns an error tagged with the stage
// that failed.
func run(cfg *Config) error {
	// 1. Validate inputs.
	if err := validateInputs(cfg); err != nil {
		return &stageError{stage: "validate-inputs", err: err}
	}

	// 2. Load the test cases.
	cases, err := loadCases(cfg.Tests, cfg.Provider)
	if err != nil {
		return &stageError{stage: "load-cases", err: err}
	}

	// 3. Spawn headless Chromium.
	proc, err := spawnChromium(cfg)
	if err != nil {
		return &stageError{stage: "spawn-chromium", err: err}
	}
	defer proc.Close()

	// 4. Connect via CDP.
	cdp, err := connectCDP(cfg)
	if err != nil {
		return &stageError{stage: "connect-cdp", err: err}
	}
	defer cdp.Close()

	// 5. Load the extension into Chromium.
	if err := loadExtension(cdp, cfg); err != nil {
		return &stageError{stage: "load-extension", err: err}
	}

	// 6. Run the tests.
	report, err := runTests(cdp, cfg, cases)
	if err != nil {
		return &stageError{stage: "run-tests", err: err}
	}

	// 7. Emit the report.
	if err := emitReport(cfg, report); err != nil {
		return &stageError{stage: "emit-report", err: err}
	}

	// Exit code based on report.
	if report.Failed > 0 {
		return &stageError{stage: "tests", err: fmt.Errorf("%d/%d tests failed", report.Failed, report.Total)}
	}
	return nil
}

// parseArgs parses the CLI flags.
func parseArgs(args []string) (*Config, error) {
	fs := flag.NewFlagSet("test-extension", flag.ContinueOnError)
	dist := fs.String("dist", "", "path to the Lens dist/ directory (required)")
	tests := fs.String("tests", "", "path to the Lens test/ directory (required)")
	provider := fs.String("provider", "chatgpt", "AI provider to mock (chatgpt, claude, gemini, copilot)")
	chromium := fs.String("chromium", "", "path to the chromium binary (default: chromium in $PATH)")
	// Port 0 means "OS-assigned". This is the safest default
	// (no port conflict with an existing chromium instance)
	// but requires the test harness to read the assigned
	// port from chromium's stderr or /json/version response.
	// For now, we use a fixed default of 9222 (the standard
	// Chromium DevTools port); users can override with --port.
	port := fs.Int("port", 9222, "CDP debugging port")
	timeout := fs.Duration("timeout", 30*time.Second, "per-operation timeout")
	output := fs.String("output", "./test-report.json", "path to the JSON test report")
	testdataDir := fs.String("testdata", "./testdata", "path to the testdata/ directory containing mock HTML pages")
	verbose := fs.Bool("verbose", false, "enable verbose logging")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *dist == "" {
		return nil, fmt.Errorf("--dist is required")
	}
	if *tests == "" {
		return nil, fmt.Errorf("--tests is required")
	}
	distAbs, err := filepath.Abs(*dist)
	if err != nil {
		return nil, fmt.Errorf("--dist: %w", err)
	}
	testsAbs, err := filepath.Abs(*tests)
	if err != nil {
		return nil, fmt.Errorf("--tests: %w", err)
	}
	return &Config{
		Dist:         distAbs,
		Tests:        testsAbs,
		Provider:     *provider,
		ChromiumPath: *chromium,
		Port:         *port,
		Timeout:      *timeout,
		Output:       *output,
		TestdataDir:  *testdataDir,
		Verbose:      *verbose,
	}, nil
}

// validateInputs checks that the required inputs exist.
func validateInputs(cfg *Config) error {
	// The dist directory must exist.
	info, err := os.Stat(cfg.Dist) // #nosec G703 -- cfg.Dist is a developer CLI arg
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("dist directory does not exist: %s", cfg.Dist)
		}
		return fmt.Errorf("stat dist: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("dist is not a directory: %s", cfg.Dist)
	}
	// Required files in the dist directory.
	required := []string{
		"manifest.json",
		"content.js",
		"service-worker.js",
		"popup/popup.html",
		"popup/popup.js",
		"welcome.html",
		"welcome.js",
	}
	for _, f := range required {
		path := filepath.Join(cfg.Dist, f)       // #nosec G703 -- `f` is a hardcoded list; cfg.Dist is a developer CLI arg
		if _, err := os.Stat(path); err != nil { // #nosec G304 G703 -- dist is a developer CLI arg; required file list is hardcoded
			if os.IsNotExist(err) {
				return fmt.Errorf("required dist file missing: %s", f)
			}
			return fmt.Errorf("stat %s: %w", f, err)
		}
	}
	// The tests directory must exist.
	testsInfo, err := os.Stat(cfg.Tests) // #nosec G703 -- cfg.Tests is a developer CLI arg
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("tests directory does not exist: %s", cfg.Tests)
		}
		return fmt.Errorf("stat tests: %w", err)
	}
	if !testsInfo.IsDir() {
		return fmt.Errorf("tests is not a directory: %s", cfg.Tests)
	}
	// The testdata HTML for the provider must exist.
	htmlPath := filepath.Join(cfg.TestdataDir, cfg.Provider+".html") // #nosec G703 -- testdataDir is a developer CLI arg
	if _, err := os.Stat(htmlPath); err != nil {                     // #nosec G304 G703 -- testdataDir is a developer CLI arg
		if os.IsNotExist(err) {
			return fmt.Errorf("testdata HTML missing for provider %q: %s", cfg.Provider, htmlPath)
		}
		return fmt.Errorf("stat testdata: %w", err)
	}
	return nil
}

// stageError wraps an error with the test stage that produced it.
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
		case "validate-inputs", "load-cases":
			return exitTestsMissing
		case "spawn-chromium":
			return exitChromiumFailed
		case "connect-cdp", "load-extension":
			return exitCDPFailed
		case "run-tests", "tests":
			return exitTestFailed
		}
	}
	return exitBadArgs
}
