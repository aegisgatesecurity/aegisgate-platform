// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — IOC Baseline Seeder
//
// Generates IOC fingerprints from AegisGate's REAL scanner patterns.
// Iterates over scanner.DefaultPatterns() (all 223 patterns) and
// computes fingerprints using the exact same Detection fields that
// the proxy uses at runtime: Type="proxy_response", Severity, Pattern.
//
// This ensures fingerprint interoperability: a baseline IOC will match
// a live production detection because both sides compute the SHA-256
// over the same canonical JSON.
//
// CRITICAL: The proxy's iocFingerprintFromFinding() hardcodes
// Type="proxy_response" and does NOT set ThreatType. The seeder must
// match this exactly. Any deviation produces a different hash and the
// IOCs become cryptographically orphaned — structurally valid but
// functionally inert.
//
// Usage:
//   go run ./cmd/aegisgate-ioc-seed -o baseline-iocs.json [-keyring keyring.json]
//
// Without a keyring, the bundle is unsigned (for review/import only).
// With a keyring, each attestation is ECDSA-signed and the bundle
// envelope is signed — ready for gossip distribution.
//
// Apache 2.0. Copyright (c) AegisGate Security, LLC.
// =========================================================================

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
)

func main() {
	outputFile := flag.String("o", "baseline-iocs.json", "output bundle file")
	keyringFile := flag.String("keyring", "", "keyring JSON file for signing (optional)")
	verbose := flag.Bool("v", false, "verbose output (list every IOC)")
	flag.Parse()

	now := time.Now().UTC()
	instanceID := "aegisgate-baseline-seed"

	// ── Load all real scanner patterns ────────────────────────────
	// This is the critical fix: instead of hand-maintained lists of
	// pattern names, we iterate over scanner.DefaultPatterns() — the
	// exact same patterns the scanner uses at runtime. This guarantees
	// that Pattern.Name and Pattern.Severity match what the proxy
	// sees when it computes iocFingerprintFromFinding().
	patterns := scanner.DefaultPatterns()

	seen := make(map[string]bool) // dedup by fingerprint
	var attestations []ioc.IOCAttestation

	for _, p := range patterns {
		// Build the Detection EXACTLY as the proxy does:
		//   iocFingerprintFromFinding() in proxy.go constructs:
		//     {Pattern: f.Pattern.Name, Severity: severityStr, Type: "proxy_response"}
		//   It does NOT set ThreatType, ThreatLevel, ComplianceFramework,
		//   or ComplianceControl. Since those fields have `omitempty`,
		//   they are absent from the canonical JSON.
		//
		// We replicate this exactly. If we add any extra field, the
		// SHA-256 will differ and the IOC will never match a live
		// detection.
		detection := ioc.Detection{
			Type:     "proxy_response",
			Severity: ioc.Severity(scannerSeverityToIOC(p.Severity)),
			Pattern:  p.Name,
			// ThreatType, ThreatLevel, ComplianceFramework,
			// ComplianceControl: intentionally NOT set — matches proxy.
		}
		fp := ioc.Fingerprint(detection)
		if fp == "" {
			continue
		}
		if seen[fp] {
			continue
		}
		seen[fp] = true

		att := ioc.IOCAttestation{
			Fingerprint: fp,
			InstanceID:  instanceID,
			IOCType:     categoryToIOCType(p.Category),
			Severity:    ioc.Severity(scannerSeverityToIOC(p.Severity)),
			FirstSeen:   now,
			LastSeen:    now,
			Count:       1,
		}
		attestations = append(attestations, att)
	}

	// ── Build bundle ──────────────────────────────────────────────

	bundle := ioc.NewBundle(instanceID)

	// Sign if keyring provided
	signed := false
	var kr *ioc.KeyRing
	if *keyringFile != "" {
		var err error
		kr, err = ioc.LoadKeyRing(*keyringFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading keyring: %v\n", err)
			os.Exit(1)
		}
	}

	// Add attestations to bundle. If keyring is available, sign
	// each attestation individually before adding.
	for i := range attestations {
		if kr != nil {
			if err := ioc.SignAttestationWithKeyRing(&attestations[i], kr); err != nil {
				fmt.Fprintf(os.Stderr, "error: signing attestation %d: %v\n", i, err)
				os.Exit(1)
			}
		}
		bundle.Add(attestations[i])
	}

	// Sign the bundle envelope if keyring is available.
	if kr != nil {
		if err := bundle.SignWithKeyRing(kr); err != nil {
			fmt.Fprintf(os.Stderr, "error: signing bundle: %v\n", err)
			os.Exit(1)
		}
		signed = true
	}

	// Write output
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshaling bundle: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outputFile, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", *outputFile, err)
		os.Exit(1)
	}

	// ── Summary ───────────────────────────────────────────────────

	fmt.Printf("AegisGate IOC Baseline Seeder\n")
	fmt.Printf("═══════════════════════════════════════════════════════════\n")
	fmt.Printf("Source: scanner.DefaultPatterns() — %d total patterns\n", len(patterns))
	fmt.Printf("Unique IOCs (after fingerprint dedup): %d\n", len(attestations))
	fmt.Printf("Signed: %v\n", signed)
	fmt.Printf("Output: %s\n", *outputFile)
	fmt.Println()

	// Severity breakdown
	critical, high, medium, low := 0, 0, 0, 0
	for _, a := range attestations {
		switch a.Severity {
		case ioc.SeverityCritical:
			critical++
		case ioc.SeverityHigh:
			high++
		case ioc.SeverityMedium:
			medium++
		case ioc.SeverityLow:
			low++
		}
	}
	fmt.Printf("Severity breakdown:\n")
	fmt.Printf("  Critical: %d\n", critical)
	fmt.Printf("  High:     %d\n", high)
	fmt.Printf("  Medium:   %d\n", medium)
	fmt.Printf("  Low:      %d\n", low)
	fmt.Println()

	// Type breakdown
	typeCounts := make(map[ioc.IOCType]int)
	for _, a := range attestations {
		typeCounts[a.IOCType]++
	}
	// Sort types for stable output
	var types []string
	for t := range typeCounts {
		types = append(types, string(t))
	}
	sort.Strings(types)
	fmt.Printf("IOC type breakdown:\n")
	for _, t := range types {
		fmt.Printf("  %-25s %d\n", t, typeCounts[ioc.IOCType(t)])
	}

	// Category breakdown
	categoryCounts := make(map[string]int)
	for _, p := range patterns {
		categoryCounts[string(p.Category)]++
	}
	fmt.Println()
	fmt.Printf("Scanner category breakdown:\n")
	var cats []string
	for c := range categoryCounts {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		fmt.Printf("  %-25s %d patterns\n", c, categoryCounts[c])
	}

	if *verbose {
		fmt.Println()
		fmt.Printf("%-40s  %-10s  %-10s  %-20s  %s\n",
			"Pattern Name", "Severity", "Category", "IOC Type", "Fingerprint")
		fmt.Printf("%s\n", "─────────────────────────────────────────────────────────────────────────────────────────────────────")
		for _, p := range patterns {
			detection := ioc.Detection{
				Type:     "proxy_response",
				Severity: ioc.Severity(scannerSeverityToIOC(p.Severity)),
				Pattern:  p.Name,
			}
			fp := ioc.Fingerprint(detection)
			fmt.Printf("%-40s  %-10s  %-10s  %-20s  %s…\n",
				p.Name,
				scannerSeverityToIOC(p.Severity),
				p.Category,
				categoryToIOCType(p.Category),
				fp[:16])
		}
	}
}

// ── Mapping helpers ──────────────────────────────────────────────

// scannerSeverityToIOC maps scanner.Severity (int iota) to the IOC
// library's severity string. The proxy does the same mapping in
// iocFingerprintFromFinding() when it converts scanner.Severity to
// a severity string for the fingerprint.
func scannerSeverityToIOC(s scanner.Severity) string {
	switch s {
	case scanner.Critical:
		return "critical"
	case scanner.High:
		return "high"
	case scanner.Medium:
		return "medium"
	case scanner.Low:
		return "low"
	case scanner.Info:
		return "info"
	default:
		return "medium"
	}
}

// categoryToIOCType maps a scanner.Category to the appropriate IOCType.
// This is used for the IOCType field on IOCAttestation — it's metadata
// that helps peers categorize the IOC, but it does NOT participate in
// the fingerprint (the fingerprint is only over Type+Severity+Pattern).
func categoryToIOCType(c scanner.Category) ioc.IOCType {
	switch c {
	case scanner.CategoryPrompt:
		return ioc.IOCTypePromptInjection
	case scanner.CategoryXSS:
		return ioc.IOCTypeXSSDetected
	case scanner.CategoryCredential:
		return ioc.IOCTypeSecretLeak
	case scanner.CategoryPII:
		return ioc.IOCTypePIIDetected
	case scanner.CategoryFinancial:
		return ioc.IOCTypePIIDetected
	case scanner.CategoryCryptographic:
		return ioc.IOCTypeSecretLeak
	case scanner.CategoryNetwork:
		return ioc.IOCTypeProxyResponse
	case scanner.CategoryCompliance:
		return ioc.IOCTypeComplianceViolation
	default:
		return ioc.IOCTypeProxyResponse
	}
}
