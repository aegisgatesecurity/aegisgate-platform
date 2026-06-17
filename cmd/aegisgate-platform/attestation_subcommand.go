// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Attestation Envelope CLI subcommand (v3.5.0+ Tier 5 prep)
//
// attestation_subcommand.go wires pkg/attestation into the CLI
// binary as `aegisgate attestation verify <envelope.json>`.
// This is the auditor's primary interface for offline
// verification: they receive an envelope JSON, run the CLI,
// and get a structured pass/fail result.
//
// The CLI uses VerifyWithKey (the embedded public key); no
// network is required. The auditor can run this on a plane.
//
// v3.5.0+ Tier 5 prep. See plans/ENVELOPE-DESIGN-v1.1-FROZEN.md §5.4.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
)

// runAttestationSubcommand implements the "aegisgate attestation"
// CLI subcommand. The verb is one of: verify.
//
// init wires the subcommand detection hook. The subcommand is
// detected from os.Args[1] == "attestation".
func runAttestationSubcommand(args []string) {
	if len(args) == 0 {
		attestationUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	switch verb {
	case "verify":
		runAttestationVerify(rest)
	case "-help", "--help", "help":
		attestationUsage()
	default:
		fmt.Fprintf(os.Stderr, "attestation: unknown verb %q\n", verb)
		attestationUsage()
		os.Exit(2)
	}
}

// attestationUsage prints the help text for the attestation
// subcommand. The output is terse by design (CLI idiom).
func attestationUsage() {
	fmt.Fprintf(os.Stderr, `aegisgate attestation — verify AegisGate signed attestation envelopes

Usage:
  aegisgate attestation verify <envelope.json> [flags]

Flags:
  --json        emit JSON only (default: human-readable)
  --key-id      expected key ID (refuse if mismatch)

The envelope is verified using the embedded public key. No
network is required. For online verification (fetch the key
from /.well-known/), use the HTTP endpoint at
POST /api/v1/attestation/verify.

Examples:
  # Verify an envelope from a file
  aegisgate attestation verify envelope.json

  # Verify with a specific expected key ID
  aegisgate attestation verify --key-id=key-abc123 envelope.json
`)
}

// runAttestationVerify is the implementation of
// "aegisgate attestation verify <envelope.json>".
//
// Reads the envelope from the file, calls attestation.Verify
// (offline, embedded public key), and prints a structured
// result.
func runAttestationVerify(args []string) {
	fs := flag.NewFlagSet("attestation verify", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON only")
	expectedKeyID := fs.String("key-id", "", "expected key ID (refuse if mismatch)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	positional := fs.Args()
	if len(positional) != 1 {
		fmt.Fprintf(os.Stderr, "attestation verify: expected exactly one envelope file argument, got %d\n", len(positional))
		attestationUsage()
		os.Exit(2)
	}
	path := positional[0]
	cleanPath, err := safeFilePath(path)
	if err != nil {
		os.Exit(1)
	}
	path = cleanPath
	// Read the envelope from the file.
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attestation verify: read %s: %v\n", path, err)
		os.Exit(1)
	}
	// Parse the envelope.
	var env attestation.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		fmt.Fprintf(os.Stderr, "attestation verify: parse %s: %v\n", path, err)
		os.Exit(1)
	}
	// Verify the envelope.
	var verifyErr error
	if *expectedKeyID != "" {
		// Use VerifyWithKey with the embedded public key.
		// (We use the embedded public key because the
		// auditor scenario is offline; if the auditor has
		// a separate known key, they can use the HTTP
		// endpoint with the key id.)
		// For now, fall through to Verify and report the
		// key ID mismatch in the output.
		verifyErr = attestation.Verify(&env)
		if verifyErr == nil && env.Signature.KeyID != *expectedKeyID {
			verifyErr = fmt.Errorf("key ID mismatch: have %q, want %q", env.Signature.KeyID, *expectedKeyID)
		}
	} else {
		verifyErr = attestation.Verify(&env)
	}
	// Build the result.
	if *jsonOut {
		result := buildVerifyResultJSON(&env, verifyErr)
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		printVerifyResultHuman(&env, verifyErr)
	}
	// Exit code: 0 on success, 1 on failure.
	if verifyErr != nil {
		os.Exit(1)
	}
}

// verifyResult is the JSON output shape for `attestation verify
// --json`. It mirrors the design doc's "JSON verification
// result" section.
type verifyResult struct {
	Valid      bool   `json:"valid"`
	Type       string `json:"type"`
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	IssuedAt   string `json:"issued_at"`
	ValidUntil string `json:"valid_until,omitempty"`
	KeyID      string `json:"key_id"`
	Reason     string `json:"reason,omitempty"`
}

// buildVerifyResultJSON builds the JSON-serializable result
// from the envelope and (optional) verification error.
func buildVerifyResultJSON(env *attestation.Envelope, verifyErr error) verifyResult {
	r := verifyResult{
		Valid:      verifyErr == nil,
		Type:       string(env.Type),
		Subject:    env.Subject,
		Issuer:     env.Issuer,
		IssuedAt:   env.IssuedAt.Format("2006-01-02T15:04:05Z07:00"),
		ValidUntil: formatTime(env.ValidUntil),
		KeyID:      env.Signature.KeyID,
	}
	if verifyErr != nil {
		r.Reason = verifyErr.Error()
	}
	return r
}

// printVerifyResultHuman prints the result in human-readable form.
func printVerifyResultHuman(env *attestation.Envelope, verifyErr error) {
	if verifyErr != nil {
		fmt.Printf("INVALID: %s\n", verifyErr.Error())
		fmt.Printf("  Type:    %s\n", env.Type)
		fmt.Printf("  Subject: %s\n", env.Subject)
		fmt.Printf("  Issuer:  %s\n", env.Issuer)
		fmt.Printf("  KeyID:   %s\n", env.Signature.KeyID)
		return
	}
	fmt.Println("VALID")
	fmt.Printf("  Type:       %s\n", env.Type)
	fmt.Printf("  Subject:    %s\n", env.Subject)
	fmt.Printf("  Issuer:     %s\n", env.Issuer)
	fmt.Printf("  IssuedAt:   %s\n", env.IssuedAt.Format("2006-01-02T15:04:05Z07:00"))
	if !env.ValidUntil.IsZero() {
		fmt.Printf("  ValidUntil: %s\n", env.ValidUntil.Format("2006-01-02T15:04:05Z07:00"))
	}
	fmt.Printf("  KeyID:      %s\n", env.Signature.KeyID)
}

// formatTime formats a time.Time as RFC 3339, or empty string
// for the zero value.
func formatTime(t interface{ IsZero() bool }) string {
	if t.IsZero() {
		return ""
	}
	// We need to extract the actual time. Cast via type
	// assertion (the parameter type is interface{ IsZero() bool }
	// to avoid an import of time; we know it's time.Time at
	// the call site).
	type stringer interface{ Format(string) string }
	if s, ok := t.(stringer); ok {
		return s.Format("2006-01-02T15:04:05Z07:00")
	}
	return ""
}

// isAttestationSubcommand returns true if args look like the
// "aegisgate attestation" subcommand. The first arg must be
// exactly "attestation" (not a flag).
func isAttestationSubcommand(args []string) bool {
	return len(args) > 0 && args[0] == "attestation"
}

// stripAttestationSubcommand removes the "attestation" prefix
// from args. Returns the rest (the verb and its flags).
func stripAttestationSubcommand(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	return args[1:]
}

// init wires the attestation subcommand detection hook. Runs
// BEFORE main() and BEFORE flag.Parse() consumes the args.
// The subcommand only needs the attestation package (no
// platform subsystems required).
//
// This mirrors the pattern in evidence_subcommand.go.
func init() {
	if isAttestationSubcommand(os.Args[1:]) {
		args := stripAttestationSubcommand(os.Args[1:])
		runAttestationSubcommand(args)
		// Unreachable: runAttestationSubcommand calls os.Exit.
		// The early return is a safety net.
		return
	}
	// Detect silently if not our subcommand. Suppress the
	// unused import warning for strings.
	_ = strings.HasPrefix
}
