// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM CLI subcommand (TODO-302)
//
// aibom_subcommand.go wires pkg/aibom into the CLI binary as
//   - aegisgate aibom generate
//   - aegisgate aibom verify
//
// The generate verb is the operator's primary interface for
// producing a signed AIBOM. The verify verb is the auditor's
// primary interface for verifying a signed AIBOM offline.
//
// CLI surface:
//
//	aegisgate aibom generate --output=aibom.json
//	aegisgate aibom verify <envelope.json>
//	aegisgate aibom help
//
// The subcommand is detected from os.Args[1] == "aibom".
// It uses the same init() pattern as the evaluator and
// attestation subcommands.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/aibom"
	"os"
	"path/filepath"
)

// runAIBOMSubcommand implements the "aegisgate aibom"
// CLI subcommand. The verbs are: generate, verify.
//
// init wires the subcommand detection hook. The subcommand
// is detected from os.Args[1] == "aibom". On success the
// dispatcher calls os.Exit(0) explicitly (see the
// evaluator subcommand for the rationale).
func runAIBOMSubcommand(args []string) {
	if len(args) == 0 {
		aibomUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	exitCode := 0
	switch verb {
	case "generate":
		exitCode = runAIBOMGenerate(rest)
	case "verify":
		exitCode = runAIBOMVerify(rest)
	case "-help", "--help", "help":
		aibomUsage()
	default:
		fmt.Fprintf(os.Stderr, "aibom: unknown verb %q\n", verb)
		aibomUsage()
		os.Exit(2)
	}
	os.Exit(exitCode)
}

// aibomUsage prints the help text for the aibom subcommand.
func aibomUsage() {
	fmt.Fprintf(os.Stderr, `aegisgate aibom — AI Bill of Materials (CycloneDX 1.6 extension)

Usage:
  aegisgate aibom generate [flags]
  aegisgate aibom verify <envelope.json> [flags]

Flags (generate):
  --output           write the signed envelope to this file (default: stdout)
  --key-ring         path to the keyring file (default: ephemeral)
  --tier             platform tier (default: "unknown")
  --platform-version platform version (default: "unknown")
  --instance-id      operator instance id (default: empty)
  --notes            free-form note from the operator
  --json             emit JSON only (default: human-readable)

Flags (verify):
  --json             emit JSON only
  --key-id           expected key ID (refuse if mismatch)

Examples:
  # Generate an AIBOM for the current deployment
  aegisgate aibom generate --tier=professional --platform-version=3.4.0-beta.1

  # Generate with explicit output file
  aegisgate aibom generate --output=aibom.json --tier=professional

  # Verify a signed AIBOM
  aegisgate aibom verify aibom.json
`)
}

// runAIBOMGenerate is the implementation of
// "aegisgate aibom generate". Returns the exit code:
//
//	0 = success
//	1 = error
//	2 = usage error
func runAIBOMGenerate(args []string) int {
	fs := flag.NewFlagSet("aibom generate", flag.ExitOnError)
	outFile := fs.String("output", "", "write the signed envelope to this file (default: stdout)")
	keyRingPath := fs.String("key-ring", "", "path to the keyring file (default: ephemeral)")
	tier := fs.String("tier", "unknown", "platform tier (e.g., community, professional, enterprise)")
	platformVer := fs.String("platform-version", "unknown", "platform version (e.g., 3.4.0-beta.1)")
	instanceID := fs.String("instance-id", "", "operator instance id")
	notes := fs.String("notes", "", "free-form note from the operator")
	jsonOut := fs.Bool("json", false, "emit JSON only (default: human-readable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// 1. Load or build the keyring.
	kr, keyRingCleanup, err := loadOrEphemeralKeyRing(*keyRingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aibom generate: keyring: %v\n", err)
		return 1
	}
	if keyRingCleanup != nil {
		defer keyRingCleanup()
	}

	// 2. Generate the BOM. v0.1: the per-pillar data is
	// left as zero values (the BOM still emits the 5
	// pillars, but with Enabled=false). v0.2 will read
	// the live platform config and populate them.
	aibomOpts := aibom.AIBOMOptions{
		Tier:            *tier,
		PlatformVersion: *platformVer,
		InstanceID:      *instanceID,
		GeneratorNotes:  *notes,
	}
	a := aibom.BuildAIBOMFromOptions(aibomOpts)
	bom, err := aibom.GenerateFromAIBOM(a)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aibom generate: GenerateFromAIBOM: %v\n", err)
		return 1
	}

	// 3. Sign.
	env, err := aibom.Sign(bom, kr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aibom generate: Sign: %v\n", err)
		return 1
	}

	// 4. Output.
	envelopeBytes, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "aibom generate: marshal envelope: %v\n", err)
		return 1
	}
	if *outFile != "" {
		if err := os.WriteFile(*outFile, envelopeBytes, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "aibom generate: write %s: %v\n", *outFile, err)
			return 1
		}
		if !*jsonOut {
			fmt.Printf("Wrote signed AIBOM to %s\n", *outFile)
			fmt.Println(aibomHumanSummary(env))
		}
	} else {
		if *jsonOut {
			fmt.Println(string(envelopeBytes))
		} else {
			fmt.Println(string(envelopeBytes))
			fmt.Println()
			fmt.Println(aibomHumanSummary(env))
		}
	}
	return 0
}

// runAIBOMVerify is the implementation of
// "aegisgate aibom verify <envelope.json>". Returns 0 on
// valid, 1 on invalid, 2 on usage error.
func runAIBOMVerify(args []string) int {
	fs := flag.NewFlagSet("aibom verify", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON only")
	expectedKeyID := fs.String("key-id", "", "expected key ID (refuse if mismatch)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	positional := fs.Args()
	if len(positional) != 1 {
		fmt.Fprintf(os.Stderr, "aibom verify: expected exactly one envelope file argument, got %d\n", len(positional))
		aibomUsage()
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
		fmt.Fprintf(os.Stderr, "aibom verify: read %s: %v\n", path, err)
		return 1
	}
	vr, err := aibom.VerifyEnvelopeJSON(context.Background(), data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aibom verify: parse %s: %v\n", path, err)
		return 1
	}
	// Optional key-id check.
	if vr.Valid && *expectedKeyID != "" && vr.Envelope.Signature.KeyID != *expectedKeyID {
		vr.Valid = false
		vr.Reason = fmt.Sprintf("key ID mismatch: have %q, want %q",
			vr.Envelope.Signature.KeyID, *expectedKeyID)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(vr.ToJSON(), "", "  ")
		fmt.Println(string(out))
	} else {
		printAIBOMVerifyHuman(vr)
	}
	if !vr.Valid {
		return 1
	}
	return 0
}

// aibomHumanSummary returns a multi-line human-readable
// summary of a signed AIBOM envelope. Used by the CLI
// verb for pretty output.
func aibomHumanSummary(env interface{}) string {
	type summary struct {
		Type         string
		Subject      string
		Issuer       string
		KeyID        string
		SerialNumber string
	}
	// Use reflection-free JSON roundtrip: marshal the
	// envelope to a map, extract the fields we need.
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
		"AIBOM Envelope:\n"+
			"  Type:           %v\n"+
			"  Subject:        %v\n"+
			"  Issuer:         %v\n"+
			"  KeyID:          %s\n",
		m["type"], m["subject"], m["issuer"], keyID,
	)
}

// printAIBOMVerifyHuman prints a verify result in
// human-readable form.
func printAIBOMVerifyHuman(vr *aibom.VerifyResult) {
	if !vr.Valid {
		fmt.Printf("INVALID: %s\n", vr.Reason)
		if vr.Envelope != nil {
			fmt.Printf("  Type:    %s\n", vr.Envelope.Type)
			fmt.Printf("  Subject: %s\n", vr.Envelope.Subject)
			fmt.Printf("  Issuer:  %s\n", vr.Envelope.Issuer)
			fmt.Printf("  KeyID:   %s\n", vr.Envelope.Signature.KeyID)
		}
		return
	}
	out := vr.ToJSON()
	fmt.Println("VALID")
	fmt.Printf("  Type:           %s\n", out.Type)
	fmt.Printf("  Subject:        %s\n", out.Subject)
	fmt.Printf("  Issuer:         %s\n", out.Issuer)
	fmt.Printf("  KeyID:          %s\n", out.KeyID)
	fmt.Printf("  DeploymentID:   %s\n", out.DeploymentID)
	fmt.Printf("  Platform Tier:  %s\n", out.PlatformTier)
	fmt.Printf("  Platform Ver:   %s\n", out.PlatformVer)
	fmt.Printf("  Spec Version:   %s\n", out.SpecVersion)
	fmt.Printf("  Components:     %d\n", len(out.ComponentRefs))
	for _, ref := range out.ComponentRefs {
		fmt.Printf("    - %s\n", ref)
	}
}

// isAIBOMSubcommand returns true if args look like the
// "aegisgate aibom" subcommand.
func isAIBOMSubcommand(args []string) bool {
	return len(args) > 0 && args[0] == "aibom"
}

// stripAIBOMSubcommand removes the "aibom" prefix from args.
func stripAIBOMSubcommand(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	return args[1:]
}

// init wires the aibom subcommand detection hook. Runs
// BEFORE main() and BEFORE flag.Parse() consumes the args.
// Mirrors the pattern in evaluator_subcommand.go.
func init() {
	if isAIBOMSubcommand(os.Args[1:]) {
		args := stripAIBOMSubcommand(os.Args[1:])
		runAIBOMSubcommand(args)
		// Unreachable: runAIBOMSubcommand calls os.Exit.
		return
	}
}
