// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Posture Check CLI subcommand + HTTP routes
// (v3.3.0 Phase 6.5)
// =========================================================================
//
// posture_subcommand.go wires pkg/posture into both the CLI binary
// (aegisgate status / aegisgate posture) and the dashboard HTTP API
// (/api/v1/posture, /api/v1/posture/verbose).
//
// The CLI subcommand is the most Padlock-DNA deliverable in v3.3.0:
// it answers "is your AegisGate doing what you think it is doing?"
// in plain language, readable by a non-technical operator per the
// original Padlock spec constraint 17.
//
// v3.3.0 Phase 6.5.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/posture"
)

// runStatusSubcommand implements the "aegisgate status" (or
// "aegisgate posture") CLI subcommand. It intentionally does NOT
// start the proxy, MCP, or dashboard servers - it only initializes
// the license manager and prints the posture report. This makes the
// subcommand usable from a system service file or a CI gate where
// the full platform is not (yet) running.
//
// Returns the process exit code: 0 for healthy/degraded, 1 for
// unhealthy, 2 for posture-check failure.
func runStatusSubcommand(licenseMgr *license.Manager, mode string, args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	verbose := fs.Bool("verbose", false, "Show detailed subsystem output (matches /api/v1/posture/verbose)")
	jsonOut := fs.Bool("json", false, "Emit JSON instead of plain text")
	help := fs.Bool("help", false, "Show this help message")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "aegisgate status: %v\n", err)
		return 2
	}
	if *help {
		fmt.Fprintf(os.Stderr, "aegisgate status - print AegisGate platform posture summary\n\n")
		fmt.Fprintf(os.Stderr, "Usage: aegisgate status [--verbose] [--json]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		return 0
	}

	checker := posture.NewChecker(posture.Deps{
		License:   licenseMgr,
		StartTime: startTime,
		Version:   version,
		Commit:    commit,
		Mode:      mode,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	report, err := checker.Check(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisgate status: posture check failed: %v\n", err)
		return 2
	}

	// Output routing.
	switch {
	case *jsonOut:
		data, err := posture.FormatJSON(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aegisgate status: JSON encoding failed: %v\n", err)
			return 2
		}
		fmt.Println(string(data))
	default:
		if *verbose {
			fmt.Print(posture.FormatVerboseText(report))
		} else {
			fmt.Print(posture.FormatText(report))
		}
	}

	// Exit code policy (locked in V3.3.0-ROADMAP §6.5):
	//   - healthy: 0 (operator can proceed)
	//   - degraded: 0 (still operating; just needs attention)
	//   - unhealthy: 1 (operator should investigate)
	//   - unknown: 0 (no signal; we don't fail on "we don't know")
	switch report.Overall {
	case posture.StatusUnhealthy:
		return 1
	default:
		return 0
	}
}

// handlePostureAPI serves GET /api/v1/posture. Currently the routes
// are registered inline in main.go (see cmd/aegisgate-platform/main.go
// dashMux.HandleFunc calls); this handler is reserved for a v0.2
// refactor that unifies all posture routes in one place.
//
//nolint:unused // reserved for v0.2
func handlePostureAPI(licenseMgr *license.Manager, mode string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		report, err := runPostureCheck(licenseMgr, mode)
		if err != nil {
			http.Error(w, "posture check failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, err := posture.FormatJSON(report)
		if err != nil {
			http.Error(w, "json encoding failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeBytes(w, data)
	})
}

// runPostureCheck is a shared helper used by both the API handler
// and the CLI subcommand. Centralizing it here keeps the timeout
// and dependency wiring consistent across both surfaces. The
// current main.go calls Checker.Check directly; this helper is
// reserved for a v0.2 refactor that unifies the two entry points.
//
//nolint:unused // reserved for v0.2
func runPostureCheck(licenseMgr *license.Manager, mode string) (*posture.Report, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	checker := posture.NewChecker(posture.Deps{
		License:   licenseMgr,
		StartTime: startTime,
		Version:   version,
		Commit:    commit,
		Mode:      mode,
	})
	return checker.Check(ctx)
}

// isStatusSubcommand reports whether the first non-flag argument is
// "status" or "posture". The detection happens BEFORE flag.Parse()
// runs so that we can short-circuit the normal platform startup
// when a posture subcommand is requested. This is the stdlib-flag
// idiom for subcommand parsing in a single-binary CLI.
//
// Why not cobra/urfave/cli? The AegisGate binary intentionally has
// zero runtime dependencies beyond the standard library (see the
// 13.3MB-binary goal in V3.2.0-ROADMAP). Adding a CLI framework
// would be a regression.
func isStatusSubcommand() bool {
	for _, arg := range os.Args[1:] {
		// Skip flags and their values.
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// The first positional argument is the subcommand.
		return arg == "status" || arg == "posture"
	}
	return false
}

// init wires the subcommand detection hook. We use init() rather than
// modifying main() directly because the subcommand needs to run
// BEFORE flag.Parse() consumes its own arguments. init() runs at
// package load time, which is the earliest possible hook in a
// single-file main package.
func init() {
	if isStatusSubcommand() {
		// The posture subcommand only needs the license manager.
		// We deliberately do NOT start the proxy/MCP/dashboard
		// servers - that would be wasteful and would make the
		// subcommand unusable from a CI gate.
		licenseMgr, err := initLicenseManagerForPosture()
		if err != nil {
			log.Fatalf("aegisgate status: failed to initialize license manager: %v", err)
		}
		// Strip the subcommand word from os.Args so the inner
		// flag parser (in runStatusSubcommand) only sees the flags
		// that belong to this subcommand.
		args := stripSubcommand(os.Args[1:], "status", "posture")
		// We don't have access to the mode flag at this point
		// (flag.Parse hasn't run). Default to "production" for the
		// subcommand - the mode only affects display, not behavior.
		exit := runStatusSubcommand(licenseMgr, "production", args)
		os.Exit(exit)
	}
}

// initLicenseManagerForPosture is a copy of the license init logic
// from main(). It exists because init() runs before main() and
// cannot call main()'s helpers. We intentionally duplicate only
// the minimal logic needed to validate the license - the full
// platform init (proxy, MCP, dashboard) is skipped.
//
// This duplication is locked in V3.3.0-ROADMAP §6.5 as an
// acceptable tradeoff: a subcommand should be self-contained and
// not depend on the rest of the platform's initialization.
func initLicenseManagerForPosture() (*license.Manager, error) {
	if *licensePubKey != "" {
		keyData, err := os.ReadFile(*licensePubKey)
		if err != nil {
			return nil, fmt.Errorf("read license public key %s: %w", *licensePubKey, err)
		}
		return license.NewManagerWithKey(string(keyData))
	}
	return license.NewManager()
}

// stripSubcommand removes the first occurrence of any of the named
// subcommand words from the args slice and returns the remainder.
// We need this because the subcommand word "status" / "posture" is
// passed as the first positional argument, but the inner flag
// parser only wants the flags.
func stripSubcommand(args []string, subcommands ...string) []string {
	subSet := make(map[string]bool, len(subcommands))
	for _, s := range subcommands {
		subSet[s] = true
	}
	out := make([]string, 0, len(args))
	skipped := false
	for _, a := range args {
		if !skipped && subSet[a] {
			skipped = true
			continue
		}
		out = append(out, a)
	}
	return out
}
