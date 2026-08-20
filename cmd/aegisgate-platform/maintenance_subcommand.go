// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Maintenance CLI Subcommand
// =========================================================================
//
// Implements `aegisgate maintenance <enable|disable|status|schedule>` —
// a CLI utility for controlling maintenance mode on a running platform.
//
// This subcommand makes HTTP calls to the /api/v1/maintenance API endpoint
// on the running platform. It does NOT start the platform itself.
//
// Usage:
//   aegisgate maintenance status                     # Check maintenance status
//   aegisgate maintenance enable [--message "msg"]   # Enable maintenance mode
//   aegisgate maintenance disable                     # Disable maintenance mode
//   aegisgate maintenance schedule --start --end --reason  # Schedule window
//
// =========================================================================

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// isMaintenanceSubcommand reports whether the first non-flag arg is "maintenance".
func isMaintenanceSubcommand() bool {
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg == "maintenance"
	}
	return false
}

func init() {
	if isMaintenanceSubcommand() {
		args := stripSubcommand(os.Args[1:], "maintenance")
		exit := runMaintenanceSubcommand(args)
		os.Exit(exit)
	}
}

func runMaintenanceSubcommand(args []string) int {
	if len(args) == 0 {
		printMaintenanceHelp()
		return 0
	}

	verb := args[0]
	rest := args[1:]

	switch verb {
	case "enable":
		return runMaintenanceEnable(rest)
	case "disable":
		return runMaintenanceDisable(rest)
	case "status":
		return runMaintenanceStatus(rest)
	case "schedule":
		return runMaintenanceSchedule(rest)
	case "help", "--help", "-h":
		printMaintenanceHelp()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unknown maintenance verb %q\n", verb)
		printMaintenanceHelp()
		return 1
	}
}

func runMaintenanceEnable(args []string) int {
	fs := flag.NewFlagSet("maintenance enable", flag.ExitOnError)
	message := fs.String("message", "", "Maintenance message shown to clients")
	retryAfter := fs.Int64("retry-after", 60, "Retry-After header value in seconds")
	host := fs.String("host", "localhost", "Platform host")
	port := fs.Int("port", 8443, "Dashboard/API port")
	help := fs.Bool("help", false, "Show help")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: aegisgate maintenance enable [options]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *help {
		fs.Usage()
		return 0
	}

	body := fmt.Sprintf(`{"message":%q,"retry_after_seconds":%d}`, *message, *retryAfter)
	return maintenanceAPI(*host, *port, "POST", body)
}

func runMaintenanceDisable(args []string) int {
	fs := flag.NewFlagSet("maintenance disable", flag.ExitOnError)
	host := fs.String("host", "localhost", "Platform host")
	port := fs.Int("port", 8443, "Dashboard/API port")
	help := fs.Bool("help", false, "Show help")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: aegisgate maintenance disable [options]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *help {
		fs.Usage()
		return 0
	}

	return maintenanceAPI(*host, *port, "DELETE", "")
}

func runMaintenanceStatus(args []string) int {
	fs := flag.NewFlagSet("maintenance status", flag.ExitOnError)
	host := fs.String("host", "localhost", "Platform host")
	port := fs.Int("port", 8443, "Dashboard/API port")
	help := fs.Bool("help", false, "Show help")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: aegisgate maintenance status [options]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *help {
		fs.Usage()
		return 0
	}

	return maintenanceAPI(*host, *port, "GET", "")
}

func runMaintenanceSchedule(args []string) int {
	fs := flag.NewFlagSet("maintenance schedule", flag.ExitOnError)
	startStr := fs.String("start", "", "Start time (RFC3339, e.g. 2026-01-01T02:00:00Z)")
	endStr := fs.String("end", "", "End time (RFC3339, e.g. 2026-01-01T04:00:00Z)")
	reason := fs.String("reason", "", "Reason for maintenance window")
	host := fs.String("host", "localhost", "Platform host")
	port := fs.Int("port", 8443, "Dashboard/API port")
	help := fs.Bool("help", false, "Show help")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: aegisgate maintenance schedule [options]")
		fmt.Fprintln(fs.Output(), "  --start and --end must be RFC3339 timestamps")
		fmt.Fprintln(fs.Output(), "  Use --start now to start immediately")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *help {
		fs.Usage()
		return 0
	}

	if *startStr == "" || *endStr == "" {
		fmt.Fprintln(os.Stderr, "❌ --start and --end are required")
		fs.Usage()
		return 1
	}

	// Allow "now" as a shortcut for start
	startTime := *startStr
	if strings.ToLower(startTime) == "now" {
		startTime = time.Now().UTC().Format(time.RFC3339)
	}

	body := fmt.Sprintf(`{"start_time":%q,"end_time":%q,"reason":%q}`, startTime, *endStr, *reason)
	return maintenanceAPI(*host, *port, "PUT", body)
}

// maintenanceAPI makes an HTTP call to the maintenance API endpoint.
func maintenanceAPI(host string, port int, method, body string) int {
	url := fmt.Sprintf("http://%s:%d/api/v1/maintenance", host, port)

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to create request: %v\n", err)
		return 1
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to connect to platform at %s:%d: %v\n", host, port, err)
		fmt.Fprintf(os.Stderr, "   Is the platform running? Start it with: aegisgate --embedded-mcp\n")
		return 1
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Pretty-print the JSON response
	var pretty map[string]interface{}
	if err := json.Unmarshal(respBody, &pretty); err == nil {
		prettyBytes, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Printf("%s\n", string(prettyBytes))
	} else {
		fmt.Printf("%s\n", string(respBody))
	}

	if resp.StatusCode >= 400 {
		return 1
	}
	return 0
}

func printMaintenanceHelp() {
	fmt.Println(`aegisgate maintenance — Maintenance window control

Usage:
  aegisgate maintenance status                       Check maintenance status
  aegisgate maintenance enable [--message "msg"]     Enable maintenance mode now
  aegisgate maintenance disable                       Disable maintenance mode
  aegisgate maintenance schedule --start --end --reason  Schedule a window

Options:
  --host <hostname>    Platform host (default: localhost)
  --port <port>        Dashboard/API port (default: 8443)
  --message <msg>      Message shown in 503 response (enable)
  --retry-after <sec>   Retry-After header value (default: 60)
  --start <time>        Start time in RFC3339 format (schedule)
  --end <time>          End time in RFC3339 format (schedule)
  --reason <text>       Reason for scheduled maintenance

Examples:
  aegisgate maintenance status
  aegisgate maintenance enable --message "Scheduled upgrade"
  aegisgate maintenance disable
  aegisgate maintenance schedule --start now --end 2026-08-21T04:00:00Z --reason "Security patch"`)
}
