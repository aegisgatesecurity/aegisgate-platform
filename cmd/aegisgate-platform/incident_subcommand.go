// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Incident Response CLI Subcommand (v3.8)
//
// incident_subcommand.go wires pkg/incident into the CLI
// binary as:
//   - aegisgate incident list [--status=...] [--severity=...]
//   - aegisgate incident get <id>
//   - aegisgate incident create --title=... --severity=...
//   - aegisgate incident triage <id> --severity=... --assignee=...
//   - aegisgate incident resolve <id> [--resolution=...]
//   - aegisgate incident rules
//   - aegisgate incident playbooks
//
// Tier gating: Incident response is available on all tiers.
// PostgreSQL persistence is Professional+ (FeaturePostgreSQL).

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/incident"
)

// runIncidentSubcommand implements the "aegisgate incident"
// CLI subcommand.
func runIncidentSubcommand(args []string) {
	if len(args) == 0 {
		incidentUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	exitCode := 0
	switch verb {
	case "list":
		exitCode = runIncidentList(rest)
	case "get":
		exitCode = runIncidentGet(rest)
	case "create":
		exitCode = runIncidentCreate(rest)
	case "triage":
		exitCode = runIncidentTriage(rest)
	case "resolve":
		exitCode = runIncidentResolve(rest)
	case "rules":
		exitCode = runIncidentRules(rest)
	case "playbooks":
		exitCode = runIncidentPlaybooks(rest)
	case "-help", "--help", "help":
		incidentUsage()
	default:
		fmt.Fprintf(os.Stderr, "incident: unknown verb %q\n", verb)
		incidentUsage()
		os.Exit(2)
	}
	os.Exit(exitCode)
}

// incidentUsage prints the help text.
func incidentUsage() {
	fmt.Fprintf(os.Stderr, `aegisgate incident — Incident Response Automation (v3.8)

Usage:
  aegisgate incident list [--status=...] [--severity=...] [--json]
  aegisgate incident get <id> [--json]
  aegisgate incident create --title=... --severity=low|medium|high|critical [--description=...] [--agent=...] [--session=...] [--json]
  aegisgate incident triage <id> --severity=low|medium|high|critical --assignee=... [--json]
  aegisgate incident resolve <id> [--resolution=...] [--json]
  aegisgate incident rules [--json]
  aegisgate incident playbooks [--json]

Verbs:
  list       List incidents (optional filters)
  get        Get a single incident by ID
  create     Create a new incident manually
  triage     Triage an incident (set severity + assignee)
  resolve    Resolve an incident
  rules      List built-in detection rules
  playbooks  List built-in playbooks

Examples:
  # List all open incidents
  aegisgate incident list --status=new,triaged

  # Create a manual incident
  aegisgate incident create --title="Suspicious activity" --severity=high

  # Triage an incident
  aegisgate incident triage inc_123 --severity=critical --assignee=analyst-1

  # Resolve an incident
  aegisgate incident resolve inc_123 --resolution="False alarm"
`)
}

// runIncidentList lists incidents with optional filters.
func runIncidentList(args []string) int {
	fs := flag.NewFlagSet("incident list", flag.ExitOnError)
	statusFilter := fs.String("status", "", "comma-separated status filter (new,triaged,investigating,contained,resolved,closed,false_positive)")
	severityFilter := fs.String("severity", "", "comma-separated severity filter (low,medium,high,critical)")
	jsonOut := fs.Bool("json", false, "emit JSON only")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", fs.Name(), err)
		fs.Usage()
		return 1
	}

	// Create engine with in-memory stores (CLI uses ephemeral state).
	engine := newIncidentEngine()
	query := &incident.IncidentQuery{}
	if *statusFilter != "" {
		query.Status = parseStatusFilter(*statusFilter)
	}
	if *severityFilter != "" {
		query.Severity = parseSeverityFilter(*severityFilter)
	}

	results, err := engine.ListIncidents(context.Background(), query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "incident list: %v\n", err)
		return 1
	}

	if *jsonOut {
		js, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(js))
	} else {
		if len(results) == 0 {
			fmt.Println("No incidents found.")
		} else {
			fmt.Printf("%-24s %-12s %-10s %-12s %-10s %s\n", "ID", "STATUS", "SEVERITY", "SOURCE", "AGENT", "TITLE")
			for _, inc := range results {
				fmt.Printf("%-24s %-12s %-10s %-12s %-10s %s\n",
					inc.ID, inc.Status, inc.Severity, inc.Source, inc.AgentID, inc.Title)
			}
		}
	}
	return 0
}

// runIncidentGet gets a single incident by ID.
func runIncidentGet(args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "incident get: ID is required\n")
		return 2
	}
	id := args[0]
	jsonOut := false
	if len(args) > 1 && args[1] == "--json" {
		jsonOut = true
	}

	engine := newIncidentEngine()
	inc, err := engine.GetIncident(context.Background(), id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "incident get: %v\n", err)
		return 1
	}
	if inc == nil {
		fmt.Fprintf(os.Stderr, "incident get: incident %s not found\n", id)
		return 1
	}

	if jsonOut {
		js, _ := json.MarshalIndent(inc, "", "  ")
		fmt.Println(string(js))
	} else {
		printIncidentHuman(inc)
	}
	return 0
}

// runIncidentCreate creates a new incident manually.
func runIncidentCreate(args []string) int {
	fs := flag.NewFlagSet("incident create", flag.ExitOnError)
	title := fs.String("title", "", "incident title (REQUIRED)")
	severity := fs.String("severity", "low", "severity: low, medium, high, critical")
	description := fs.String("description", "", "incident description")
	agentID := fs.String("agent", "", "agent ID")
	sessionID := fs.String("session", "", "session ID")
	jsonOut := fs.Bool("json", false, "emit JSON only")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", fs.Name(), err)
		fs.Usage()
		return 1
	}

	if *title == "" {
		fmt.Fprintf(os.Stderr, "incident create: --title is required\n")
		return 2
	}

	engine := newIncidentEngine()
	inc := incident.NewIncident(*title, *description, incident.IncidentSeverity(*severity), incident.SourceSOC)
	inc.AgentID = *agentID
	inc.SessionID = *sessionID

	created, err := engine.CreateIncident(context.Background(), inc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "incident create: %v\n", err)
		return 1
	}

	if *jsonOut {
		js, _ := json.MarshalIndent(created, "", "  ")
		fmt.Println(string(js))
	} else {
		fmt.Printf("Created incident: %s\n", created.ID)
		printIncidentHuman(created)
	}
	return 0
}

// runIncidentTriage triages an incident.
func runIncidentTriage(args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "incident triage: ID is required\n")
		return 2
	}
	id := args[0]

	fs := flag.NewFlagSet("incident triage", flag.ExitOnError)
	severity := fs.String("severity", "high", "severity: low, medium, high, critical")
	assignee := fs.String("assignee", "", "assignee (REQUIRED)")
	jsonOut := fs.Bool("json", false, "emit JSON only")
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", fs.Name(), err)
		fs.Usage()
		return 1
	}

	if *assignee == "" {
		fmt.Fprintf(os.Stderr, "incident triage: --assignee is required\n")
		return 2
	}

	engine := newIncidentEngine()
	triaged, err := engine.TriageIncident(context.Background(), id, incident.IncidentSeverity(*severity), *assignee)
	if err != nil {
		fmt.Fprintf(os.Stderr, "incident triage: %v\n", err)
		return 1
	}

	if *jsonOut {
		js, _ := json.MarshalIndent(triaged, "", "  ")
		fmt.Println(string(js))
	} else {
		fmt.Printf("Triaged incident: %s\n", triaged.ID)
		printIncidentHuman(triaged)
	}
	return 0
}

// runIncidentResolve resolves an incident.
func runIncidentResolve(args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "incident resolve: ID is required\n")
		return 2
	}
	id := args[0]

	fs := flag.NewFlagSet("incident resolve", flag.ExitOnError)
	resolution := fs.String("resolution", "", "resolution description")
	jsonOut := fs.Bool("json", false, "emit JSON only")
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", fs.Name(), err)
		fs.Usage()
		return 1
	}

	engine := newIncidentEngine()
	resolved, err := engine.ResolveIncident(context.Background(), id, *resolution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "incident resolve: %v\n", err)
		return 1
	}

	if *jsonOut {
		js, _ := json.MarshalIndent(resolved, "", "  ")
		fmt.Println(string(js))
	} else {
		fmt.Printf("Resolved incident: %s\n", resolved.ID)
		printIncidentHuman(resolved)
	}
	return 0
}

// runIncidentRules lists built-in detection rules.
func runIncidentRules(args []string) int {
	jsonOut := false
	if len(args) > 0 && args[0] == "--json" {
		jsonOut = true
	}

	rules := incident.DefaultDetectionRules()
	if jsonOut {
		js, _ := json.MarshalIndent(rules, "", "  ")
		fmt.Println(string(js))
	} else {
		if len(rules) == 0 {
			fmt.Println("No detection rules defined.")
		} else {
			fmt.Printf("%-30s %-12s %-10s %-10s %s\n", "ID", "SEVERITY", "AUTO-CREATE", "AUTO-EXEC", "NAME")
			for _, r := range rules {
				fmt.Printf("%-30s %-12s %-10v %-10v %s\n",
					r.ID, r.Severity, r.AutoCreate, r.AutoExecute, r.Name)
			}
		}
	}
	return 0
}

// runIncidentPlaybooks lists built-in playbooks.
func runIncidentPlaybooks(args []string) int {
	jsonOut := false
	if len(args) > 0 && args[0] == "--json" {
		jsonOut = true
	}

	playbooks := incident.DefaultPlaybooks()
	if jsonOut {
		js, _ := json.MarshalIndent(playbooks, "", "  ")
		fmt.Println(string(js))
	} else {
		if len(playbooks) == 0 {
			fmt.Println("No playbooks defined.")
		} else {
			fmt.Printf("%-24s %-12s %-10s %-6s %s\n", "ID", "SEVERITY", "SOURCE", "STEPS", "NAME")
			for _, pb := range playbooks {
				fmt.Printf("%-24s %-12s %-10s %-6d %s\n",
					pb.ID, pb.Severity, pb.Source, len(pb.Steps), pb.Name)
			}
		}
	}
	return 0
}

// printIncidentHuman prints an incident in human-readable form.
func printIncidentHuman(inc *incident.Incident) {
	fmt.Printf("ID:          %s\n", inc.ID)
	fmt.Printf("Title:       %s\n", inc.Title)
	fmt.Printf("Severity:    %s\n", inc.Severity)
	fmt.Printf("Status:      %s\n", inc.Status)
	fmt.Printf("Source:      %s\n", inc.Source)
	if inc.AgentID != "" {
		fmt.Printf("Agent:       %s\n", inc.AgentID)
	}
	if inc.SessionID != "" {
		fmt.Printf("Session:     %s\n", inc.SessionID)
	}
	if inc.Assignee != "" {
		fmt.Printf("Assignee:    %s\n", inc.Assignee)
	}
	fmt.Printf("Created:     %s\n", inc.CreatedAt.Format(time.RFC3339))
	if !inc.UpdatedAt.IsZero() {
		fmt.Printf("Updated:     %s\n", inc.UpdatedAt.Format(time.RFC3339))
	}
	if !inc.ResolvedAt.IsZero() {
		fmt.Printf("Resolved:   %s\n", inc.ResolvedAt.Format(time.RFC3339))
	}
	if len(inc.ComplianceMappings) > 0 {
		fmt.Println("Compliance:")
		for _, m := range inc.ComplianceMappings {
			fmt.Printf("  %s %s (%s): %s\n", m.Framework, m.ControlID, m.ControlName, m.Relevance)
		}
	}
	if len(inc.PlaybookRuns) > 0 {
		fmt.Printf("Playbook Runs: %d\n", len(inc.PlaybookRuns))
		for _, run := range inc.PlaybookRuns {
			fmt.Printf("  %s: %s (%d steps)\n", run.ID, run.Status, len(run.StepResults))
		}
	}
}

// newIncidentEngine creates an incident engine with in-memory
// stores and default detection rules + playbooks loaded.
func newIncidentEngine() *incident.Engine {
	is := incident.NewInMemoryIncidentStore()
	ps := incident.NewInMemoryPlaybookStore()
	rs := incident.NewInMemoryDetectionRuleStore()

	ctx := context.Background()

	// Load default playbooks.
	for _, pb := range incident.DefaultPlaybooks() {
		_ = ps.CreatePlaybook(ctx, pb)
	}

	// Load default detection rules.
	for _, rule := range incident.DefaultDetectionRules() {
		_ = rs.CreateRule(ctx, rule)
	}

	return incident.NewEngine(is, ps, rs)
}

// parseStatusFilter parses a comma-separated status filter.
func parseStatusFilter(filter string) []incident.IncidentStatus {
	if filter == "" {
		return nil
	}
	statuses := []incident.IncidentStatus{}
	for _, s := range splitCSV(filter) {
		statuses = append(statuses, incident.IncidentStatus(s))
	}
	return statuses
}

// parseSeverityFilter parses a comma-separated severity filter.
func parseSeverityFilter(filter string) []incident.IncidentSeverity {
	if filter == "" {
		return nil
	}
	severities := []incident.IncidentSeverity{}
	for _, s := range splitCSV(filter) {
		severities = append(severities, incident.IncidentSeverity(s))
	}
	return severities
}

// splitCSV splits a comma-separated string, trimming whitespace.
func splitCSV(s string) []string {
	result := []string{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := s[start:i]
			if len(part) > 0 {
				result = append(result, part)
			}
			start = i + 1
		}
	}
	return result
}

// isIncidentSubcommand returns true if args look like the
// "aegisgate incident" subcommand.
func isIncidentSubcommand(args []string) bool {
	return len(args) >= 1 && args[0] == "incident"
}

// stripIncidentSubcommand removes the "incident" prefix from args.
func stripIncidentSubcommand(args []string) []string {
	if len(args) < 1 {
		return nil
	}
	return args[1:]
}

// init wires the incident subcommand detection hook.
func init() {
	// Only register if os.Args has enough length.
	if len(os.Args) > 1 && isIncidentSubcommand(os.Args[1:]) {
		args := stripIncidentSubcommand(os.Args[1:])
		runIncidentSubcommand(args)
		// Unreachable: runIncidentSubcommand calls os.Exit.
	}
}
