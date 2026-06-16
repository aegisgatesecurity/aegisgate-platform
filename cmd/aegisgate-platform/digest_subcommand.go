// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Digest CLI subcommand (TODO-601 + TODO-602)
//
// digest_subcommand.go wires pkg/digest into the
// CLI binary as:
//   - aegisgate digest generate --period=...
//   - aegisgate digest verify <signed-envelope.json>
//
// Tier gating: digest generation is Professional+
// (the digest is a customer-facing artifact). For
// the CLI (operator-only), we don't enforce tier
// at the CLI layer; the HTTP handler does.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/digest"
)

// runDigestSubcommand implements the "aegisgate
// digest" CLI subcommand.
func runDigestSubcommand(args []string) {
	if len(args) == 0 {
		digestUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	exitCode := 0
	switch verb {
	case "generate":
		exitCode = runDigestGenerate(rest)
	case "verify":
		exitCode = runDigestVerify(rest)
	case "-help", "--help", "help":
		digestUsage()
	default:
		fmt.Fprintf(os.Stderr, "digest: unknown verb %q\n", verb)
		digestUsage()
		os.Exit(2)
	}
	os.Exit(exitCode)
}

// digestUsage prints the help text.
func digestUsage() {
	fmt.Fprintf(os.Stderr, `aegisgate digest — CISO Posture Digest (TODO-601 + TODO-602)

Usage:
  aegisgate digest generate --period=PERIOD [--out=FILE] [--out-pdf=FILE]
  aegisgate digest verify <signed-envelope.json>

Flags (generate):
  --period         daily | weekly | monthly (default: weekly)
  --out            write the signed envelope to this file (default: stdout)
  --out-pdf        write the rendered PDF to this file
  --key-ring       path to the keyring file (default: ephemeral)

Flags (verify):
  --key-ring       path to the keyring file (default: ephemeral)

Examples:
  # Generate a weekly digest
  aegisgate digest generate --period=weekly

  # Generate a digest and save the PDF
  aegisgate digest generate --period=weekly --out=digest.json --out-pdf=digest.pdf

  # Verify a signed digest
  aegisgate digest verify digest.json
`)
}

// runDigestGenerate is the implementation of
// "aegisgate digest generate".
func runDigestGenerate(args []string) int {
	fs := flag.NewFlagSet("digest generate", flag.ExitOnError)
	period := fs.String("period", string(digest.PeriodWeekly), "daily | weekly | monthly")
	outFile := fs.String("out", "", "write the signed envelope to this file (default: stdout)")
	outPDF := fs.String("out-pdf", "", "write the rendered PDF to this file")
	keyRingPath := fs.String("key-ring", "", "path to the keyring file (default: ephemeral)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Load keyring.
	kr, keyRingCleanup, err := loadOrEphemeralKeyRing(*keyRingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "digest generate: keyring: %v\n", err)
		return 1
	}
	if keyRingCleanup != nil {
		defer keyRingCleanup()
	}
	// Build the digest with no sources (a v0.1
	// placeholder; v0.2 wires real sources).
	d, err := digest.BuildDigest(context.Background(), nil, digest.BuilderOptions{
		Period: digest.Period(*period),
		Clock:  digest.SystemClock{},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "digest generate: BuildDigest: %v\n", err)
		return 1
	}
	// Sign.
	env, err := digest.SignDigest(d, kr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "digest generate: SignDigest: %v\n", err)
		return 1
	}
	// Output.
	envelopeBytes, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "digest generate: marshal: %v\n", err)
		return 1
	}
	if *outFile != "" {
		if err := os.WriteFile(*outFile, envelopeBytes, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "digest generate: write %s: %v\n", *outFile, err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "Wrote signed digest to %s\n", *outFile)
	} else {
		fmt.Println(string(envelopeBytes))
	}
	// Optionally save the PDF.
	if *outPDF != "" {
		verified, pdfBytes, err := digest.VerifyDigest(env)
		if err != nil {
			fmt.Fprintf(os.Stderr, "digest generate: verify for PDF: %v\n", err)
			return 1
		}
		_ = verified
		if err := os.WriteFile(*outPDF, pdfBytes, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "digest generate: write PDF %s: %v\n", *outPDF, err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "Wrote PDF to %s\n", *outPDF)
	}
	return 0
}

// runDigestVerify is the implementation of
// "aegisgate digest verify".
func runDigestVerify(args []string) int {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "digest verify: expected exactly one envelope file argument, got %d\n", len(args))
		digestUsage()
		return 2
	}
	path := args[0]
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "digest verify: read %s: %v\n", path, err)
		return 1
	}
	var env struct {
		Type    string                 `json:"type"`
		Subject string                 `json:"subject"`
		Issuer  string                 `json:"issuer"`
		Payload map[string]interface{} `json:"payload"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		fmt.Fprintf(os.Stderr, "digest verify: parse %s: %v\n", path, err)
		return 1
	}
	fmt.Printf("Type:    %s\n", env.Type)
	fmt.Printf("Subject: %s\n", env.Subject)
	fmt.Printf("Issuer:  %s\n", env.Issuer)
	// For v0.1, we don't actually call VerifyDigest
	// here (it requires an actual *attestation.Envelope,
	// which requires the KeyRing to verify the
	// signature). The full verify path is in the
	// HTTP handler. The CLI just prints the metadata.
	fmt.Println("(CLI verify is metadata-only in v0.1; full verify is in the HTTP handler)")
	_ = time.Now()
	return 0
}

// isDigestSubcommand returns true if args look like
// the "aegisgate digest" subcommand.
func isDigestSubcommand(args []string) bool {
	return len(args) >= 1 && args[0] == "digest"
}

// stripDigestSubcommand removes the "digest" prefix
// from args.
func stripDigestSubcommand(args []string) []string {
	if len(args) < 1 {
		return nil
	}
	return args[1:]
}

// init wires the digest subcommand detection hook.
func init() {
	if isDigestSubcommand(os.Args[1:]) {
		args := stripDigestSubcommand(os.Args[1:])
		runDigestSubcommand(args)
		// Unreachable: runDigestSubcommand calls os.Exit.
	}
}
