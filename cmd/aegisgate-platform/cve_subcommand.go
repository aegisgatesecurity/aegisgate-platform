// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CVE Entry CLI subcommand (TODO-305)
//
// cve_subcommand.go wires pkg/cve into the CLI binary as
//   - aegisgate cve publish
//   - aegisgate cve verify
//   - aegisgate cve list
//
// The publish verb is the operator workflow for adding
// a new CVE entry to the feed. The verify verb is the
// consumer's (or auditor's) primary interface for
// verifying a signed entry offline. The list verb
// lists entries in a feed file.
//
// CLI surface:
//
//	aegisgate cve publish --id=... --title=... --description=... [flags]
//	aegisgate cve verify <envelope.json>
//	aegisgate cve list <feed.json>
//
// Tier gating: the publish side is Enterprise only
// (per the user's confirmation; mirrors the c3
// manifest gating pattern). The verify side is free
// (verifying a CVE entry is a public action). The
// tier check is at the HTTP layer (TODO-305 HTTP
// handler); the CLI is operator-only, so we don't
// enforce tier at the CLI layer.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/cve"
)

// runCVESubcommand implements the "aegisgate cve"
// CLI subcommand. The verbs are: publish, verify, list.
func runCVESubcommand(args []string) {
	if len(args) == 0 {
		cveUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	exitCode := 0
	switch verb {
	case "publish":
		exitCode = runCVEPublish(rest)
	case "verify":
		exitCode = runCVEVerify(rest)
	case "list":
		exitCode = runCVEList(rest)
	case "-help", "--help", "help":
		cveUsage()
	default:
		fmt.Fprintf(os.Stderr, "cve: unknown verb %q\n", verb)
		cveUsage()
		os.Exit(2)
	}
	os.Exit(exitCode)
}

// cveUsage prints the help text.
func cveUsage() {
	fmt.Fprintf(os.Stderr, `aegisgate cve — CVE Entry Publisher (TODO-305)

Usage:
  aegisgate cve publish [flags]
  aegisgate cve verify <envelope.json>
  aegisgate cve list <feed.json>

Flags (publish):
  --id             CVE-ID in AEGIS-YYYY-NNNN format (REQUIRED)
  --title          one-line title (REQUIRED)
  --description    multi-paragraph description (REQUIRED)
  --affected       comma-separated list of "<provider>/<model>@<version-range>"
                   (OPTIONAL, can be specified multiple times)
  --fixed          comma-separated list of "<provider>/<model>@<version>"
                   (OPTIONAL)
  --score          CVSS 3.1 base score, 0.0-10.0 (OPTIONAL)
  --vector         CVSS 3.1 vector string (REQUIRED if --score is set)
  --reference      URL (OPTIONAL, can be specified multiple times)
  --mitigation     mitigation text (OPTIONAL, can be specified multiple times)
  --discovered-by  name of the discoverer (REQUIRED)
  --disclosed-at   RFC3339 timestamp (OPTIONAL; defaults to now)
  --withdraw-at    RFC3339 timestamp (OPTIONAL; if set, this is a withdrawal)
  --ttl            envelope validity in seconds (0 = no expiration, DEFAULT)
  --out            write the signed envelope to this file (default: stdout)
  --feed           append to this feed file (in addition to --out)
  --key-ring       path to the keyring file (default: ephemeral)
  --json           emit JSON only

Flags (verify):
  --json           emit JSON only
  --key-id         expected key ID (refuse if mismatch)

Examples:
  # Publish a new CVE entry
  aegisgate cve publish \
      --id=AEGIS-2026-0001 \
      --title="[EXAMPLE] Prompt injection via Markdown alt-text" \
      --description="EXAMPLE entry. An attacker can..." \
      --affected="anthropic/claude-3-5-sonnet@<20241022" \
      --fixed="anthropic/claude-3-5-sonnet@20241022" \
      --score=7.5 \
      --vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" \
      --discovered-by="AegisGate Research" \
      --disclosed-at=2026-06-01T00:00:00Z

  # Verify a signed CVE entry
  aegisgate cve verify envelope.json

  # List entries in a feed
  aegisgate cve list feed.json
`)
}

// runCVEPublish is the implementation of
// "aegisgate cve publish". Returns 0 on success, 1 on
// error, 2 on usage error.
func runCVEPublish(args []string) int {
	fs := flag.NewFlagSet("cve publish", flag.ExitOnError)
	id := fs.String("id", "", "CVE-ID in AEGIS-YYYY-NNNN format (REQUIRED)")
	title := fs.String("title", "", "one-line title (REQUIRED)")
	description := fs.String("description", "", "multi-paragraph description (REQUIRED)")
	discoveredBy := fs.String("discovered-by", "", "name of the discoverer (REQUIRED)")
	disclosedAt := fs.String("disclosed-at", "", "RFC3339 timestamp (OPTIONAL; defaults to now)")
	withdrawAt := fs.String("withdraw-at", "", "RFC3339 timestamp (OPTIONAL; if set, this is a withdrawal)")
	score := fs.Float64("score", 0, "CVSS 3.1 base score, 0.0-10.0 (OPTIONAL)")
	vector := fs.String("vector", "", "CVSS 3.1 vector string (REQUIRED if --score is set)")
	outFile := fs.String("out", "", "write the signed envelope to this file (default: stdout)")
	feedFile := fs.String("feed", "", "append to this feed file (in addition to --out)")
	keyRingPath := fs.String("key-ring", "", "path to the keyring file (default: ephemeral)")
	ttl := fs.Int("ttl", 0, "envelope validity in seconds (0 = no expiration, DEFAULT)")
	jsonOut := fs.Bool("json", false, "emit JSON only")

	// Multi-value flags via custom flag.Var.
	var affected multiStringFlag
	fs.Var(&affected, "affected", "affected <provider>/<model>@<version-range> (repeatable)")
	var fixed multiStringFlag
	fs.Var(&fixed, "fixed", "fixed <provider>/<model>@<version> (repeatable)")
	var references multiStringFlag
	fs.Var(&references, "reference", "reference URL (repeatable)")
	var mitigations multiStringFlag
	fs.Var(&mitigations, "mitigation", "mitigation text (repeatable)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Required flags.
	if *id == "" {
		fmt.Fprintf(os.Stderr, "cve publish: --id is required\n")
		return 2
	}
	if *title == "" {
		fmt.Fprintf(os.Stderr, "cve publish: --title is required\n")
		return 2
	}
	if *description == "" {
		fmt.Fprintf(os.Stderr, "cve publish: --description is required\n")
		return 2
	}
	if *discoveredBy == "" {
		fmt.Fprintf(os.Stderr, "cve publish: --discovered-by is required\n")
		return 2
	}
	if *score > 0 && *vector == "" {
		fmt.Fprintf(os.Stderr, "cve publish: --vector is required when --score is set\n")
		return 2
	}

	// Parse disclosed_at.
	var disclosedTime time.Time
	if *disclosedAt != "" {
		t, err := time.Parse(time.RFC3339, *disclosedAt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cve publish: --disclosed-at: %v\n", err)
			return 2
		}
		disclosedTime = t
	} else {
		disclosedTime = time.Now().UTC()
	}

	// Parse withdraw_at.
	var withdrawTime time.Time
	if *withdrawAt != "" {
		t, err := time.Parse(time.RFC3339, *withdrawAt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cve publish: --withdraw-at: %v\n", err)
			return 2
		}
		withdrawTime = t
	}

	// Load the keyring.
	kr, keyRingCleanup, err := loadOrEphemeralKeyRing(*keyRingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cve publish: keyring: %v\n", err)
		return 1
	}
	if keyRingCleanup != nil {
		defer keyRingCleanup()
	}

	// Build the entry.
	entry := &cve.CVEEntry{
		ID:           *id,
		Title:        *title,
		Description:  *description,
		Affected:     []string(affected),
		Fixed:        []string(fixed),
		Score:        *score,
		Vector:       *vector,
		References:   []string(references),
		Mitigations:  []string(mitigations),
		DiscoveredBy: *discoveredBy,
		DisclosedAt:  disclosedTime,
		WithdrawnAt:  withdrawTime,
	}

	// Publish. TTL is 0 by default (CVE entries are
	// immutable).
	env, err := cve.Publish(entry, kr, time.Duration(*ttl)*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cve publish: Publish: %v\n", err)
		return 1
	}

	// Output.
	envelopeBytes, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cve publish: marshal: %v\n", err)
		return 1
	}
	if *outFile != "" {
		// Ensure the directory exists.
		if dir := filepath.Dir(*outFile); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				fmt.Fprintf(os.Stderr, "cve publish: mkdir %s: %v\n", dir, err)
				return 1
			}
		}
		if err := os.WriteFile(*outFile, envelopeBytes, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "cve publish: write %s: %v\n", *outFile, err)
			return 1
		}
		if !*jsonOut {
			fmt.Printf("Wrote signed CVE entry to %s\n", *outFile)
			fmt.Println(cveHumanSummary(env))
		}
	} else if !*jsonOut {
		fmt.Println(string(envelopeBytes))
		fmt.Println()
		fmt.Println(cveHumanSummary(env))
	} else {
		fmt.Println(string(envelopeBytes))
	}

	// Optionally append to a feed file.
	if *feedFile != "" {
		if err := appendToFeedFile(*feedFile, env); err != nil {
			fmt.Fprintf(os.Stderr, "cve publish: feed: %v\n", err)
			return 1
		}
		if !*jsonOut {
			fmt.Printf("Appended to feed %s\n", *feedFile)
		}
	}

	return 0
}

// runCVEVerify is the implementation of
// "aegisgate cve verify". Returns 0 on valid, 1 on
// invalid, 2 on usage error.
func runCVEVerify(args []string) int {
	fs := flag.NewFlagSet("cve verify", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON only")
	expectedKeyID := fs.String("key-id", "", "expected key ID (refuse if mismatch)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	positional := fs.Args()
	if len(positional) != 1 {
		fmt.Fprintf(os.Stderr, "cve verify: expected exactly one envelope file argument, got %d\n", len(positional))
		cveUsage()
		return 2
	}
	path := positional[0]
	cleanPath, err := safeFilePath(path)
	if err != nil {
		return 1
	}
	path = cleanPath
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cve verify: read %s: %v\n", path, err)
		return 1
	}
	vr, err := cve.VerifyJSON(context.Background(), data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cve verify: parse %s: %v\n", path, err)
		return 1
	}
	// Optional key-id check (M3 from TODO-303).
	if vr.Valid && *expectedKeyID != "" && vr.Envelope.Signature.KeyID != *expectedKeyID {
		vr.Valid = false
		vr.Reason = fmt.Sprintf("key ID mismatch: have %q, want %q",
			vr.Envelope.Signature.KeyID, *expectedKeyID)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(cveVerifyResultJSON(vr), "", "  ")
		fmt.Println(string(out))
	} else {
		printCVEVerifyHuman(vr)
	}
	if !vr.Valid {
		return 1
	}
	return 0
}

// runCVEList is the implementation of
// "aegisgate cve list". Lists all entries in a feed
// file. Returns 0 on success, 1 on error, 2 on usage
// error.
func runCVEList(args []string) int {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "cve list: expected exactly one feed file argument, got %d\n", len(args))
		cveUsage()
		return 2
	}
	path := args[0]
	f, err := cve.ReadJSONFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cve list: read %s: %v\n", path, err)
		return 1
	}
	if f.Len() == 0 {
		fmt.Println("(feed is empty)")
		return 0
	}
	fmt.Printf("Feed version %d, generated %s, %d entries:\n",
		f.Version, f.GeneratedAt.Format(time.RFC3339), f.Len())
	for i, env := range f.Entries {
		entry, err := cve.ParseEntry([]byte(env.RawPayload))
		if err != nil {
			fmt.Printf("  [%d] <unparseable: %v>\n", i+1, err)
			continue
		}
		marker := " "
		if entry.IsWithdrawal() {
			marker = "W"
		}
		fmt.Printf("  %s %s  %s  (%.1f %s)\n",
			marker, entry.ID, truncate(entry.Title, 60), entry.Score, entry.Band)
	}
	return 0
}

// cveHumanSummary returns a multi-line human-readable
// summary of a signed CVE entry envelope.
func cveHumanSummary(env interface{}) string {
	type summary struct {
		Type    string
		Subject string
		Issuer  string
		KeyID   string
	}
	js, _ := json.Marshal(env)
	var m map[string]interface{}
	_ = json.Unmarshal(js, &m)
	sig, _ := m["signature"].(map[string]interface{})
	keyID := ""
	if sig != nil {
		if k, ok := sig["key_id"].(string); ok {
			keyID = k
		}
	}
	return fmt.Sprintf(
		"CVE Entry Envelope:\n"+
			"  Type:    %v\n"+
			"  Subject: %v\n"+
			"  Issuer:  %v\n"+
			"  KeyID:   %s\n",
		m["type"], m["subject"], m["issuer"], keyID,
	)
}

// cveVerifyResultJSON is the flat JSON-friendly shape of
// VerifyResult, used by the CLI's --json output.
type cveVerifyResultJSONShape struct {
	Valid        bool   `json:"valid"`
	Reason       string `json:"reason,omitempty"`
	Type         string `json:"type,omitempty"`
	Subject      string `json:"subject,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
	ID           string `json:"id,omitempty"`
	Title        string `json:"title,omitempty"`
	Score        string `json:"score,omitempty"`
	Band         string `json:"band,omitempty"`
	DiscoveredBy string `json:"discovered_by,omitempty"`
	IsWithdrawal bool   `json:"is_withdrawal,omitempty"`
}

// cveVerifyResultJSON converts a VerifyResult to its
// flat JSON shape.
func cveVerifyResultJSON(vr *cve.VerifyResult) cveVerifyResultJSONShape {
	out := cveVerifyResultJSONShape{
		Valid:  vr.Valid,
		Reason: vr.Reason,
	}
	if vr.Envelope != nil {
		out.Type = string(vr.Envelope.Type)
		out.Subject = vr.Envelope.Subject
		out.Issuer = vr.Envelope.Issuer
		out.KeyID = vr.Envelope.Signature.KeyID
	}
	if vr.Entry != nil {
		out.ID = vr.Entry.ID
		out.Title = vr.Entry.Title
		out.DiscoveredBy = vr.Entry.DiscoveredBy
		if vr.Entry.Score > 0 {
			out.Score = fmt.Sprintf("%.1f", vr.Entry.Score)
			out.Band = vr.Entry.Band
		}
	}
	out.IsWithdrawal = vr.IsWithdrawal
	return out
}

// printCVEVerifyHuman prints the verify result in
// human-readable form.
func printCVEVerifyHuman(vr *cve.VerifyResult) {
	if !vr.Valid {
		fmt.Printf("INVALID: %s\n", vr.Reason)
		if vr.Envelope != nil {
			fmt.Printf("  Type:    %s\n", vr.Envelope.Type)
			fmt.Printf("  Subject: %s\n", vr.Envelope.Subject)
		}
		return
	}
	out := cveVerifyResultJSON(vr)
	fmt.Println("VALID")
	fmt.Printf("  Type:          %s\n", out.Type)
	fmt.Printf("  Subject:       %s\n", out.Subject)
	fmt.Printf("  Issuer:        %s\n", out.Issuer)
	fmt.Printf("  KeyID:         %s\n", out.KeyID)
	fmt.Printf("  CVE-ID:        %s\n", out.ID)
	fmt.Printf("  Title:         %s\n", out.Title)
	if out.Score != "" {
		fmt.Printf("  Score:         %s (%s)\n", out.Score, out.Band)
	}
	fmt.Printf("  DiscoveredBy:  %s\n", out.DiscoveredBy)
	if out.IsWithdrawal {
		fmt.Println("  STATUS:        WITHDRAWN")
	}
}

// appendToFeedFile reads a feed file (if it exists),
// appends the envelope, and writes it back. The env
// parameter is *attestation.Envelope (returned by
// cve.Publish); we accept it as a typed parameter
// rather than going through a JSON round-trip shim.
func appendToFeedFile(path string, env *attestation.Envelope) error {
	var feed *cve.Feed
	if _, err := os.Stat(path); err == nil {
		feed, err = cve.ReadJSONFile(path)
		if err != nil {
			return fmt.Errorf("read existing feed: %w", err)
		}
	} else {
		feed = cve.NewFeed()
	}
	if err := feed.AppendEntry(env); err != nil {
		return fmt.Errorf("append: %w", err)
	}
	return feed.WriteJSONFile(path)
}

// truncate truncates s to max chars with "..." suffix.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// multiStringFlag is a flag.Value that collects
// multiple occurrences into a slice. Used for
// repeatable --affected, --fixed, --reference,
// --mitigation.
type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join([]string(*m), ",")
}

func (m *multiStringFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// isCVESubcommand returns true if args look like the
// "aegisgate cve" subcommand.
func isCVESubcommand(args []string) bool {
	return len(args) >= 1 && args[0] == "cve"
}

// stripCVESubcommand removes the "cve" prefix from args.
func stripCVESubcommand(args []string) []string {
	if len(args) < 1 {
		return nil
	}
	return args[1:]
}

// init wires the cve subcommand detection hook.
func init() {
	if isCVESubcommand(os.Args[1:]) {
		args := stripCVESubcommand(os.Args[1:])
		runCVESubcommand(args)
		// Unreachable: runCVESubcommand calls os.Exit.
	}
}
