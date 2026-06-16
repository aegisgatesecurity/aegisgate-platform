// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Agent Intent Signing CLI subcommand (TODO-303)
//
// a2a_intent_subcommand.go wires pkg/agentintentsign into
// the CLI binary as
//   - aegisgate a2a intent sign
//   - aegisgate a2a intent verify
//
// The sign verb is the agent's primary interface for
// producing a signed intent. The verify verb is the
// receiver's (or auditor's) primary interface for
// verifying a signed intent offline.
//
// CLI surface:
//
//	aegisgate a2a intent sign --agent=X --intent=Y --justification=Z
//	aegisgate a2a intent verify <envelope.json>
//	aegisgate a2a intent help
//
// The subcommand is detected from os.Args[1] == "a2a"
// (which then looks for the "intent" sub-subcommand).
// This mirrors the aegisgate evaluator / aegisgate aibom
// patterns.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/agentintentsign"
)

// runA2AIntentSubcommand implements the "aegisgate a2a
// intent" CLI subcommand. The verbs are: sign, verify.
func runA2AIntentSubcommand(args []string) {
	if len(args) == 0 {
		a2aIntentUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	exitCode := 0
	switch verb {
	case "sign":
		exitCode = runA2AIntentSign(rest)
	case "verify":
		exitCode = runA2AIntentVerify(rest)
	case "-help", "--help", "help":
		a2aIntentUsage()
	default:
		fmt.Fprintf(os.Stderr, "a2a intent: unknown verb %q\n", verb)
		a2aIntentUsage()
		os.Exit(2)
	}
	os.Exit(exitCode)
}

// a2aIntentUsage prints the help text.
func a2aIntentUsage() {
	fmt.Fprintf(os.Stderr, `aegisgate a2a intent — Agent Intent Signing (A2A intent binding)

Usage:
  aegisgate a2a intent sign [flags]
  aegisgate a2a intent verify <envelope.json> [flags]

Flags (sign):
  --agent         agent id (REQUIRED) e.g., "agent:acme-corp/customer-support@v1"
  --intent        human-readable intent declaration (REQUIRED)
  --justification reason for the intent (REQUIRED)
  --context       free-form context (e.g., session id)
  --ttl           validity period (default: 1h, max: 24h)
  --out           write the signed envelope to this file (default: stdout)
  --key-ring      path to the keyring file (default: ephemeral)
  --json          emit JSON only (default: human-readable)

Flags (verify):
  --json          emit JSON only
  --key-id        expected key ID (refuse if mismatch)

Examples:
  # Sign an A2A intent
  aegisgate a2a intent sign \
      --agent=agent:acme-corp/customer-support@v1 \
      --intent="Read the user's calendar for tomorrow" \
      --justification="User asked me to summarize their meetings"

  # Verify a signed A2A intent
  aegisgate a2a intent verify intent.json
`)
}

// runA2AIntentSign is the implementation of
// "aegisgate a2a intent sign". Returns 0 on success,
// 1 on error, 2 on usage error.
func runA2AIntentSign(args []string) int {
	fs := flag.NewFlagSet("a2a intent sign", flag.ExitOnError)
	agentID := fs.String("agent", "", "agent id (REQUIRED)")
	intentStr := fs.String("intent", "", "human-readable intent (REQUIRED)")
	justification := fs.String("justification", "", "reason for the intent (REQUIRED)")
	contextStr := fs.String("context", "", "free-form context (e.g., session id)")
	ttl := fs.Duration("ttl", agentintentsign.DefaultIntentTTL, "validity period (default: 1h, max: 24h)")
	outFile := fs.String("out", "", "write the signed envelope to this file (default: stdout)")
	keyRingPath := fs.String("key-ring", "", "path to the keyring file (default: ephemeral)")
	jsonOut := fs.Bool("json", false, "emit JSON only (default: human-readable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Required flags.
	if *agentID == "" {
		fmt.Fprintf(os.Stderr, "a2a intent sign: --agent is required\n")
		return 2
	}
	if *intentStr == "" {
		fmt.Fprintf(os.Stderr, "a2a intent sign: --intent is required\n")
		return 2
	}
	if *justification == "" {
		fmt.Fprintf(os.Stderr, "a2a intent sign: --justification is required\n")
		return 2
	}

	// Load the keyring.
	kr, keyRingCleanup, err := loadOrEphemeralKeyRing(*keyRingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "a2a intent sign: keyring: %v\n", err)
		return 1
	}
	if keyRingCleanup != nil {
		defer keyRingCleanup()
	}

	// Build the tuple.
	tuple := &agentintentsign.IntentTuple{
		AgentID:       *agentID,
		Intent:        *intentStr,
		Justification: *justification,
		Context:       *contextStr,
	}
	// Sign.
	env, err := agentintentsign.Sign(tuple, kr,
		agentintentsign.WithContext(*contextStr),
		agentintentsign.WithTTL(*ttl),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "a2a intent sign: Sign: %v\n", err)
		return 1
	}

	// Output.
	envelopeBytes, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "a2a intent sign: marshal: %v\n", err)
		return 1
	}
	if *outFile != "" {
		if err := os.WriteFile(*outFile, envelopeBytes, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "a2a intent sign: write %s: %v\n", *outFile, err)
			return 1
		}
		if !*jsonOut {
			fmt.Printf("Wrote signed intent to %s\n", *outFile)
			fmt.Println(a2aIntentHumanSummary(env))
		}
	} else {
		if !*jsonOut {
			fmt.Println(string(envelopeBytes))
			fmt.Println()
			fmt.Println(a2aIntentHumanSummary(env))
		} else {
			fmt.Println(string(envelopeBytes))
		}
	}
	return 0
}

// runA2AIntentVerify is the implementation of
// "aegisgate a2a intent verify". Returns 0 on valid,
// 1 on invalid, 2 on usage error.
func runA2AIntentVerify(args []string) int {
	fs := flag.NewFlagSet("a2a intent verify", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON only")
	expectedKeyID := fs.String("key-id", "", "expected key ID (refuse if mismatch)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	positional := fs.Args()
	if len(positional) != 1 {
		fmt.Fprintf(os.Stderr, "a2a intent verify: expected exactly one envelope file argument, got %d\n", len(positional))
		a2aIntentUsage()
		return 2
	}
	path := positional[0]
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "a2a intent verify: read %s: %v\n", path, err)
		return 1
	}
	vr, err := agentintentsign.VerifyJSON(context.Background(), data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "a2a intent verify: parse %s: %v\n", path, err)
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
		printA2AIntentVerifyHuman(vr)
	}
	if !vr.Valid {
		return 1
	}
	return 0
}

// a2aIntentHumanSummary returns a multi-line human-
// readable summary of a signed A2A intent envelope.
func a2aIntentHumanSummary(env interface{}) string {
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
		"A2A Intent Envelope:\n"+
			"  Type:    %v\n"+
			"  Subject: %v\n"+
			"  Issuer:  %v\n"+
			"  KeyID:   %s\n",
		m["type"], m["subject"], m["issuer"], keyID,
	)
}

// printA2AIntentVerifyHuman prints the verify result in
// human-readable form.
func printA2AIntentVerifyHuman(vr *agentintentsign.VerifyResult) {
	if !vr.Valid {
		fmt.Printf("INVALID: %s\n", vr.Reason)
		if vr.Envelope != nil {
			fmt.Printf("  Type:    %s\n", vr.Envelope.Type)
			fmt.Printf("  Subject: %s\n", vr.Envelope.Subject)
		}
		return
	}
	out := vr.ToJSON()
	fmt.Println("VALID")
	fmt.Printf("  Type:       %s\n", out.Type)
	fmt.Printf("  Subject:    %s\n", out.Subject)
	fmt.Printf("  Issuer:     %s\n", out.Issuer)
	fmt.Printf("  KeyID:      %s\n", out.KeyID)
	fmt.Printf("  IntentID:   %s\n", out.IntentID)
	fmt.Printf("  AgentID:    %s\n", out.AgentID)
	fmt.Printf("  IssuedAt:   %s\n", out.IssuedAt)
	fmt.Printf("  ValidUntil: %s\n", out.ValidUntil)
}

// isA2AIntentSubcommand returns true if args look like
// the "aegisgate a2a intent" subcommand.
func isA2AIntentSubcommand(args []string) bool {
	return len(args) >= 2 && args[0] == "a2a" && args[1] == "intent"
}

// stripA2AIntentSubcommand removes the "a2a intent"
// prefix from args.
func stripA2AIntentSubcommand(args []string) []string {
	if len(args) < 2 {
		return nil
	}
	return args[2:]
}

// init wires the a2a intent subcommand detection hook.
func init() {
	if isA2AIntentSubcommand(os.Args[1:]) {
		args := stripA2AIntentSubcommand(os.Args[1:])
		runA2AIntentSubcommand(args)
		// Unreachable: runA2AIntentSubcommand calls os.Exit.
	}
}
