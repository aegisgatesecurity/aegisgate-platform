// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - SOC Timeline CLI subcommand (TODO-502)
//
// soc_subcommand.go wires pkg/soc into the CLI
// binary as:
//   - aegisgate soc timeline --incident=<session-id>
//
// Tier gating: SOC timeline is FREE (no gate). It
// is a read-only data view, not a tier-gated feature.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/soc"
)

// runSOCSubcommand implements the "aegisgate soc"
// CLI subcommand.
func runSOCSubcommand(args []string) {
	if len(args) == 0 {
		socUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	exitCode := 0
	switch verb {
	case "timeline":
		exitCode = runSOCTimeline(rest)
	case "-help", "--help", "help":
		socUsage()
	default:
		fmt.Fprintf(os.Stderr, "soc: unknown verb %q\n", verb)
		socUsage()
		os.Exit(2)
	}
	os.Exit(exitCode)
}

// socUsage prints the help text.
func socUsage() {
	fmt.Fprintf(os.Stderr, `aegisgate soc — SOC Incident Timeline (TODO-502)

Usage:
  aegisgate soc timeline --incident=SESSION_ID

Flags (timeline):
  --incident       the session ID to query (REQUIRED)
  --seed           add sample events to the in-memory store
                   (for testing/demo; v0.1 only)
  --json           emit JSON only

Examples:
  # Get the timeline for a session
  aegisgate soc timeline --incident=session-123

  # Seed sample events then get the timeline
  aegisgate soc timeline --incident=session-123 --seed

  # Emit JSON only
  aegisgate soc timeline --incident=session-123 --json
`)
}

// runSOCTimeline is the implementation of
// "aegisgate soc timeline".
func runSOCTimeline(args []string) int {
	fs := flag.NewFlagSet("soc timeline", flag.ExitOnError)
	incident := fs.String("incident", "", "the session ID to query (REQUIRED)")
	seed := fs.Bool("seed", false, "add sample events to the in-memory store (for testing/demo)")
	jsonOut := fs.Bool("json", false, "emit JSON only")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *incident == "" {
		fmt.Fprintf(os.Stderr, "soc timeline: --incident is required\n")
		return 2
	}
	// Create the correlation engine.
	engine := correlation.NewEngine()
	if *seed {
		seedSampleEvents(engine, *incident)
	}
	// Wrap and query.
	wrapped := soc.WrapEngine(engine)
	result, err := soc.GetTimeline(context.Background(), wrapped, *incident)
	if err != nil {
		fmt.Fprintf(os.Stderr, "soc timeline: %v\n", err)
		return 1
	}
	if *jsonOut {
		js, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(js))
	} else {
		printSOCTimelineHuman(result)
	}
	return 0
}

// seedSampleEvents adds 5 sample events to the
// in-memory store. This is a v0.1 demo helper; the
// real data source is the platform's 5 protocol
// pillars calling RecordEvent.
func seedSampleEvents(engine *correlation.Engine, sessionID string) {
	now := time.Now().UTC()
	events := []*correlation.Event{
		{
			Protocol:  "http",
			AgentID:   "agent-1",
			SessionID: sessionID,
			EventType: "request",
			Severity:  "low",
			Decision:  "allow",
			Timestamp: now.Add(-30 * time.Second),
		},
		{
			Protocol:  "http",
			AgentID:   "agent-1",
			SessionID: sessionID,
			EventType: "response",
			Severity:  "low",
			Timestamp: now.Add(-25 * time.Second),
		},
		{
			Protocol:  "mcp",
			AgentID:   "agent-1",
			SessionID: sessionID,
			EventType: "tool_call",
			Severity:  "medium",
			Decision:  "allow",
			Timestamp: now.Add(-20 * time.Second),
		},
		{
			Protocol:  "mcp",
			AgentID:   "agent-1",
			SessionID: sessionID,
			EventType: "error",
			Severity:  "high",
			Decision:  "block",
			Timestamp: now.Add(-15 * time.Second),
		},
		{
			Protocol:  "a2a",
			AgentID:   "agent-1",
			SessionID: sessionID,
			EventType: "message",
			Severity:  "critical",
			Decision:  "alert",
			Timestamp: now.Add(-10 * time.Second),
		},
	}
	for _, evt := range events {
		_ = engine.RecordEvent(context.Background(), evt)
	}
}

// printSOCTimelineHuman prints the timeline in
// human-readable form.
func printSOCTimelineHuman(result *soc.TimelineResult) {
	fmt.Printf("Session: %s\n", result.SessionID)
	if result.AgentID != "" {
		fmt.Printf("Agent:   %s\n", result.AgentID)
	}
	fmt.Printf("Events:  %d", result.TotalCount)
	if result.TotalCount > 0 {
		fmt.Printf("  (%s to %s, %.1fs span)",
			result.StartTime.Format(time.RFC3339),
			result.EndTime.Format(time.RFC3339),
			result.EndTime.Sub(result.StartTime).Seconds(),
		)
	}
	fmt.Println()
	if result.HasCriticalEvents {
		fmt.Println("  ! contains critical events")
	}
	if len(result.ProtocolCounts) > 0 {
		fmt.Println("  Protocols:")
		for proto, count := range result.ProtocolCounts {
			fmt.Printf("    %s: %d\n", proto, count)
		}
	}
	if len(result.SeverityCounts) > 0 {
		fmt.Println("  Severities:")
		for sev, count := range result.SeverityCounts {
			fmt.Printf("    %s: %d\n", sev, count)
		}
	}
	for i, evt := range result.Events {
		fmt.Printf("  [%d] %s %s/%s sev=%s dec=%s\n",
			i+1,
			evt.Timestamp.Format(time.RFC3339),
			evt.Protocol,
			evt.EventType,
			evt.Severity,
			evt.Decision,
		)
	}
}

// isSOCSubcommand returns true if args look like the
// "aegisgate soc" subcommand.
func isSOCSubcommand(args []string) bool {
	return len(args) >= 1 && args[0] == "soc"
}

// stripSOCSubcommand removes the "soc" prefix from
// args.
func stripSOCSubcommand(args []string) []string {
	if len(args) < 1 {
		return nil
	}
	return args[1:]
}

// init wires the soc subcommand detection hook.
func init() {
	if isSOCSubcommand(os.Args[1:]) {
		args := stripSOCSubcommand(os.Args[1:])
		runSOCSubcommand(args)
		// Unreachable: runSOCSubcommand calls os.Exit.
	}
}
