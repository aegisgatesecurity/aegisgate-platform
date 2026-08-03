// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SOC 2 Audit Automation CLI (v3.8)
// =========================================================================
//
// CLI subcommand for SOC 2 audit automation. Generates evidence,
// workpapers, and signed audit reports from the command line.
//
// Usage:
//
//	aegisgate audit-soc2 generate [--org ORG] [--auditor AUDITOR] \
//	    [--type type1|type2] [--start START] [--end END] \
//	    [--categories security,availability,...] [--json] [--out FILE]
//	aegisgate audit-soc2 evidence [--org ORG] [--start START] [--end END] \
//	    [--categories security,availability,...] [--json]
//	aegisgate audit-soc2 workpapers [--org ORG] [--auditor AUDITOR] \
//	    [--start START] [--end END] [--json]
//	aegisgate audit-soc2 policies [--category security|availability|...] [--json]
//
// The subcommand wires into the main binary's init() hook, so it
// is discovered via "aegisgate --help" (the subcommandHelp list).
//
// =========================================================================

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/audit/soc2"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// runAuditSOC2Subcommand is the entry point for the "aegisgate audit-soc2"
// subcommand. It dispatches to the appropriate verb based on args.
func runAuditSOC2Subcommand(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: aegisgate audit-soc2 <generate|evidence|workpapers|policies> [flags]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Verbs:")
		fmt.Fprintln(os.Stderr, "  generate   Generate a full SOC 2 audit report")
		fmt.Fprintln(os.Stderr, "  evidence   Collect SOC 2 control evidence")
		fmt.Fprintln(os.Stderr, "  workpapers Generate SOC 2 workpapers")
		fmt.Fprintln(os.Stderr, "  policies   List SOC 2 policy templates")
		os.Exit(1)
	}

	verb := args[0]
	verbArgs := args[1:]

	switch verb {
	case "generate":
		runAuditSOC2Generate(verbArgs)
	case "evidence":
		runAuditSOC2Evidence(verbArgs)
	case "workpapers":
		runAuditSOC2Workpapers(verbArgs)
	case "policies":
		runAuditSOC2Policies(verbArgs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown verb: %q (expected generate|evidence|workpapers|policies)\n", verb)
		os.Exit(1)
	}
}

// parseCategories parses a comma-separated list of TSC categories.
func parseCategories(s string) []soc2.TrustServiceCategory {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	cats := make([]soc2.TrustServiceCategory, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		switch p {
		case "security":
			cats = append(cats, soc2.TSCSecurity)
		case "availability":
			cats = append(cats, soc2.TSCAvailability)
		case "processing_integrity", "processing-integrity", "pi":
			cats = append(cats, soc2.TSCProcessingIntegrity)
		case "confidentiality":
			cats = append(cats, soc2.TSCConfidentiality)
		case "privacy":
			cats = append(cats, soc2.TSCPrivacy)
		default:
			fmt.Fprintf(os.Stderr, "Warning: unknown TSC category %q, skipping\n", p)
		}
	}
	return cats
}

// parseTime parses a time string in RFC3339 or YYYY-MM-DD format.
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time format: %q (expected RFC3339 or YYYY-MM-DD)", s)
}

// runAuditSOC2Generate generates a full SOC 2 audit report.
func runAuditSOC2Generate(args []string) {
	fs := flag.NewFlagSet("audit-soc2 generate", flag.ExitOnError)
	org := fs.String("org", "AegisGate", "Organization name")
	auditor := fs.String("auditor", "AegisGate Audit", "Auditor name")
	auditType := fs.String("type", "type2", "Audit type: type1 or type2")
	startStr := fs.String("start", "", "Period start (RFC3339 or YYYY-MM-DD)")
	endStr := fs.String("end", "", "Period end (RFC3339 or YYYY-MM-DD)")
	categoriesStr := fs.String("categories", "", "Comma-separated TSC categories (security,availability,processing_integrity,confidentiality,privacy)")
	jsonOut := fs.Bool("json", false, "Output as JSON")
	outFile := fs.String("out", "", "Write output to file (default: stdout)")
	sign := fs.Bool("sign", false, "Sign the report with attestation envelope")
	keyRingPath := fs.String("key-ring", "", "Path to keyring file for signing")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", fs.Name(), err)
		fs.Usage()
		return
	}

	// Parse period.
	var periodStart, periodEnd time.Time
	var err error
	if *startStr != "" {
		periodStart, err = parseTime(*startStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing --start: %v\n", err)
			os.Exit(1)
		}
	} else {
		periodStart = time.Now().Add(-90 * 24 * time.Hour)
	}
	if *endStr != "" {
		periodEnd, err = parseTime(*endStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing --end: %v\n", err)
			os.Exit(1)
		}
	} else {
		periodEnd = time.Now()
	}

	// Parse audit type.
	var at soc2.AuditType
	switch *auditType {
	case "type1":
		at = soc2.AuditType1
	case "type2":
		at = soc2.AuditType2
	default:
		fmt.Fprintf(os.Stderr, "Unknown audit type: %q (expected type1 or type2)\n", *auditType)
		os.Exit(1)
	}

	// Build and collect.
	config := soc2.EvidenceCollectorConfig{
		Organization: *org,
		Auditor:      *auditor,
		Categories:   parseCategories(*categoriesStr),
	}
	collector := soc2.NewEvidenceCollector(config, nil) // nil scanner for CLI-only mode
	builder := soc2.NewReportBuilder(soc2.ReportConfig{
		Organization: *org,
		Auditor:      *auditor,
		PeriodStart:  periodStart,
		PeriodEnd:    periodEnd,
		Type:         at,
		Categories:   parseCategories(*categoriesStr),
	}, collector)

	report, err := builder.Build(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building report: %v\n", err)
		os.Exit(1)
	}

	// Optionally sign.
	if *sign {
		if *keyRingPath == "" {
			fmt.Fprintln(os.Stderr, "Error: --sign requires --key-ring")
			os.Exit(1)
		}
		kr, err := ioc.LoadKeyRing(*keyRingPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading keyring: %v\n", err)
			os.Exit(1)
		}
		env, err := soc2.SignReport(report, kr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error signing report: %v\n", err)
			os.Exit(1)
		}
		report.Attestation = env
	}

	// Output.
	var output []byte
	if *jsonOut {
		output, err = soc2.ReportToJSON(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		output = []byte(soc2.ReportToText(report))
	}

	writeOutput(output, *outFile)
}

// runAuditSOC2Evidence collects and displays SOC 2 control evidence.
func runAuditSOC2Evidence(args []string) {
	fs := flag.NewFlagSet("audit-soc2 evidence", flag.ExitOnError)
	org := fs.String("org", "AegisGate", "Organization name")
	startStr := fs.String("start", "", "Period start (RFC3339 or YYYY-MM-DD)")
	endStr := fs.String("end", "", "Period end (RFC3339 or YYYY-MM-DD)")
	categoriesStr := fs.String("categories", "", "Comma-separated TSC categories")
	jsonOut := fs.Bool("json", false, "Output as JSON")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", fs.Name(), err)
		fs.Usage()
		return
	}

	periodStart, periodEnd := parsePeriodDefaults(*startStr, *endStr)

	config := soc2.EvidenceCollectorConfig{
		Organization: *org,
		Categories:   parseCategories(*categoriesStr),
	}
	collector := soc2.NewEvidenceCollector(config, nil)

	evidence, err := collector.Collect(context.Background(), periodStart, periodEnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error collecting evidence: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		data, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else {
		fmt.Printf("SOC 2 Control Evidence (%s - %s)\n", periodStart.Format("2006-01-02"), periodEnd.Format("2006-01-02"))
		fmt.Printf("%-15s %-40s %-20s %-15s\n", "Control ID", "Name", "Category", "Status")
		fmt.Println(strings.Repeat("-", 90))
		for _, ce := range evidence {
			fmt.Printf("%-15s %-40s %-20s %-15s\n", ce.ControlID, ce.ControlName, ce.Category, ce.Status)
		}
	}
}

// runAuditSOC2Workpapers generates SOC 2 workpapers.
func runAuditSOC2Workpapers(args []string) {
	fs := flag.NewFlagSet("audit-soc2 workpapers", flag.ExitOnError)
	org := fs.String("org", "AegisGate", "Organization name")
	auditor := fs.String("auditor", "AegisGate Audit", "Auditor name")
	startStr := fs.String("start", "", "Period start (RFC3339 or YYYY-MM-DD)")
	endStr := fs.String("end", "", "Period end (RFC3339 or YYYY-MM-DD)")
	jsonOut := fs.Bool("json", false, "Output as JSON")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", fs.Name(), err)
		fs.Usage()
		return
	}

	periodStart, periodEnd := parsePeriodDefaults(*startStr, *endStr)

	config := soc2.EvidenceCollectorConfig{
		Organization: *org,
		Auditor:      *auditor,
	}
	collector := soc2.NewEvidenceCollector(config, nil)

	evidence, err := collector.Collect(context.Background(), periodStart, periodEnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error collecting evidence: %v\n", err)
		os.Exit(1)
	}

	workpapers, err := soc2.GenerateWorkpapers(evidence, periodStart, periodEnd, *org, *auditor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating workpapers: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		for i, wp := range workpapers {
			data, err := soc2.WorkpaperToJSON(&wp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling workpaper %d: %v\n", i, err)
				os.Exit(1)
			}
			fmt.Println(string(data))
		}
	} else {
		for _, wp := range workpapers {
			fmt.Println(soc2.WorkpaperToText(&wp))
			fmt.Println(strings.Repeat("=", 80))
		}
	}
}

// runAuditSOC2Policies lists SOC 2 policy templates.
func runAuditSOC2Policies(args []string) {
	fs := flag.NewFlagSet("audit-soc2 policies", flag.ExitOnError)
	categoryStr := fs.String("category", "", "Filter by TSC category")
	jsonOut := fs.Bool("json", false, "Output as JSON")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", fs.Name(), err)
		fs.Usage()
		return
	}

	policies := soc2.PolicyTemplates()

	if *categoryStr != "" {
		cats := parseCategories(*categoryStr)
		if len(cats) > 0 {
			filtered, err := soc2.PolicyForCategory(cats[0])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error filtering policies: %v\n", err)
				os.Exit(1)
			}
			policies = filtered
		}
	}

	if *jsonOut {
		data, err := json.MarshalIndent(policies, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else {
		fmt.Printf("%-15s %-45s %-20s %s\n", "ID", "Title", "Category", "Controls")
		fmt.Println(strings.Repeat("-", 100))
		for _, p := range policies {
			fmt.Printf("%-15s %-45s %-20s %s\n", p.ID, p.Title, p.Category, strings.Join(p.Controls, ", "))
		}
	}
}

// parsePeriodDefaults returns start/end times, defaulting to last 90 days.
func parsePeriodDefaults(startStr, endStr string) (time.Time, time.Time) {
	periodStart, err := parseTime(startStr)
	if err != nil || periodStart.IsZero() {
		periodStart = time.Now().Add(-90 * 24 * time.Hour)
	}
	periodEnd, err2 := parseTime(endStr)
	if err2 != nil || periodEnd.IsZero() {
		periodEnd = time.Now()
	}
	return periodStart, periodEnd
}

// writeOutput writes data to a file or stdout.
func writeOutput(data []byte, path string) {
	if path == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			// Stdout write failure is non-critical for a CLI audit tool.
			// The process will exit regardless after this call returns.
			fmt.Fprintf(os.Stderr, "Error writing to stdout: %v\n", err) // #nosec G706 -- CLI tool, stdout failure is non-critical
		}
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to %s: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Written to %s\n", path)
}

// isAuditSOC2Subcommand returns true if args look like the
// "aegisgate audit-soc2" subcommand.
func isAuditSOC2Subcommand(args []string) bool {
	return len(args) > 1 && args[0] == "audit-soc2"
}

// stripAuditSOC2Subcommand removes the "audit-soc2" prefix from args.
func stripAuditSOC2Subcommand(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	return args[1:]
}

func init() {
	if isAuditSOC2Subcommand(os.Args[1:]) {
		args := stripAuditSOC2Subcommand(os.Args[1:])
		runAuditSOC2Subcommand(args)
		// Unreachable: runAuditSOC2Subcommand calls os.Exit.
		return
	}
}

// Suppress unused-import warnings for packages only used by subcommand verbs.
var (
	_ *compliance.Scanner
	_ = ioc.LoadKeyRing
)
