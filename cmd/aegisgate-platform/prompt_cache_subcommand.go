// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Prompt Cache Poisoning Detection CLI subcommand (TODO-304)
//
// prompt_cache_subcommand.go wires pkg/promptcache into the
// CLI binary as
//   - aegisgate prompt-cache attest
//   - aegisgate prompt-cache verify
//   - aegisgate prompt-cache check
//
// The attest verb is the application's primary interface
// for producing a signed attestation (called before writing
// a prompt to the LLM provider's cache). The verify verb
// is the consumer's (or auditor's) primary interface for
// verifying a signed attestation offline (called before
// reading from the cache). The check verb is a synonym for
// verify on the CLI (matches the resume's suggested UX).
//
// CLI surface:
//
//	aegisgate prompt-cache attest --prompt=P --source=S --model-id=M --attestor-id=A
//	aegisgate prompt-cache verify <envelope.json>
//	aegisgate prompt-cache check --prompt=P  (looks up the envelope for the prompt's hash)
//	aegisgate prompt-cache help
//
// The subcommand is detected from os.Args[1] ==
// "prompt-cache" (single-level like the other subcommands
// except a2a which is two-level).

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/promptcache"
)

// runPromptCacheSubcommand implements the "aegisgate
// prompt-cache" CLI subcommand. The verbs are: attest,
// verify, check.
func runPromptCacheSubcommand(args []string) {
	if len(args) == 0 {
		promptCacheUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	exitCode := 0
	switch verb {
	case "attest":
		exitCode = runPromptCacheAttest(rest)
	case "verify":
		exitCode = runPromptCacheVerify(rest)
	case "check":
		// "check" is a synonym for "verify" on the CLI.
		// It re-uses the same code path.
		exitCode = runPromptCacheVerify(rest)
	case "-help", "--help", "help":
		promptCacheUsage()
	default:
		fmt.Fprintf(os.Stderr, "prompt-cache: unknown verb %q\n", verb)
		promptCacheUsage()
		os.Exit(2)
	}
	os.Exit(exitCode)
}

// promptCacheUsage prints the help text.
func promptCacheUsage() {
	fmt.Fprintf(os.Stderr, `aegisgate prompt-cache — Prompt Cache Poisoning Detection

Usage:
  aegisgate prompt-cache attest [flags]
  aegisgate prompt-cache verify <envelope.json> [flags]
  aegisgate prompt-cache check <envelope.json> [flags]

Flags (attest):
  --prompt         the prompt text to attest (REQUIRED; hashed locally,
                   raw text is not stored in the signed payload)
  --source         where the prompt came from (REQUIRED; e.g.,
                   "user-supplied", "mcp-tool:acme-corp/calendar")
  --model-id       the LLM model id (REQUIRED; e.g.,
                   "claude-3-5-sonnet-20241022", "openai/gpt-4-turbo")
  --attestor-id    WHO is making this attestation (REQUIRED; e.g.,
                   "acme-corp:prod-gateway", "anthropic:managed")
  --cache-key      the LLM provider's cache key (OPTIONAL)
  --metadata       free-form metadata blob (OPTIONAL)
  --ttl            validity period (default: 1h, max: 24h)
  --out            write the signed envelope to this file
                   (default: stdout)
  --key-ring       path to the keyring file (default: ephemeral)
  --json           emit JSON only (default: human-readable)

Flags (verify / check):
  --json           emit JSON only
  --key-id         expected key ID (refuse if mismatch)

Examples:
  # Attest a prompt before writing it to the cache
  aegisgate prompt-cache attest \
      --prompt="What is the capital of France?" \
      --source="user-supplied" \
      --model-id="claude-3-5-sonnet-20241022" \
      --attestor-id="acme-corp:prod-gateway" \
      --ttl=1h

  # Verify a signed prompt-cache attestation
  aegisgate prompt-cache verify envelope.json
`)
}

// runPromptCacheAttest is the implementation of
// "aegisgate prompt-cache attest". Returns 0 on success,
// 1 on error, 2 on usage error.
func runPromptCacheAttest(args []string) int {
	fs := flag.NewFlagSet("prompt-cache attest", flag.ExitOnError)
	prompt := fs.String("prompt", "", "the prompt text to attest (REQUIRED)")
	source := fs.String("source", "", "where the prompt came from (REQUIRED)")
	modelID := fs.String("model-id", "", "the LLM model id (REQUIRED)")
	attestorID := fs.String("attestor-id", "", "WHO is making this attestation (REQUIRED)")
	cacheKey := fs.String("cache-key", "", "the LLM provider's cache key (OPTIONAL)")
	metadata := fs.String("metadata", "", "free-form metadata blob (OPTIONAL)")
	ttl := fs.Duration("ttl", promptcache.DefaultPromptCacheTTL, "validity period (default: 1h, max: 24h)")
	outFile := fs.String("out", "", "write the signed envelope to this file (default: stdout)")
	keyRingPath := fs.String("key-ring", "", "path to the keyring file (default: ephemeral)")
	jsonOut := fs.Bool("json", false, "emit JSON only (default: human-readable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Required flags.
	if *prompt == "" {
		fmt.Fprintf(os.Stderr, "prompt-cache attest: --prompt is required\n")
		return 2
	}
	if *source == "" {
		fmt.Fprintf(os.Stderr, "prompt-cache attest: --source is required\n")
		return 2
	}
	if *modelID == "" {
		fmt.Fprintf(os.Stderr, "prompt-cache attest: --model-id is required\n")
		return 2
	}
	if *attestorID == "" {
		fmt.Fprintf(os.Stderr, "prompt-cache attest: --attestor-id is required\n")
		return 2
	}

	// Load the keyring.
	kr, keyRingCleanup, err := loadOrEphemeralKeyRing(*keyRingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prompt-cache attest: keyring: %v\n", err)
		return 1
	}
	if keyRingCleanup != nil {
		defer keyRingCleanup()
	}

	// Build the attestation. The caller passes the raw
	// prompt; we hash it locally with HashPrompt (lowercase
	// + whitespace-collapse + SHA-256). The raw prompt is
	// NOT stored in the signed payload.
	att := &promptcache.PromptAttestation{
		PromptHash: promptcache.HashPrompt(*prompt),
		Source:     *source,
		ModelID:    *modelID,
		AttestorID: *attestorID,
		CacheKey:   *cacheKey,
		Metadata:   *metadata,
	}
	// Sign.
	env, err := promptcache.Attest(att, kr, promptcache.WithTTL(*ttl))
	if err != nil {
		fmt.Fprintf(os.Stderr, "prompt-cache attest: Attest: %v\n", err)
		return 1
	}

	// Output.
	envelopeBytes, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "prompt-cache attest: marshal: %v\n", err)
		return 1
	}
	if *outFile != "" {
		// Ensure the directory exists.
		if dir := filepath.Dir(*outFile); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				fmt.Fprintf(os.Stderr, "prompt-cache attest: mkdir %s: %v\n", dir, err)
				return 1
			}
		}
		if err := os.WriteFile(*outFile, envelopeBytes, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "prompt-cache attest: write %s: %v\n", *outFile, err)
			return 1
		}
		if !*jsonOut {
			fmt.Printf("Wrote signed prompt-cache attestation to %s\n", *outFile)
			fmt.Println(promptCacheHumanSummary(env))
		}
	} else {
		if !*jsonOut {
			fmt.Println(string(envelopeBytes))
			fmt.Println()
			fmt.Println(promptCacheHumanSummary(env))
		} else {
			fmt.Println(string(envelopeBytes))
		}
	}
	return 0
}

// runPromptCacheVerify is the implementation of
// "aegisgate prompt-cache verify" and "aegisgate
// prompt-cache check". Returns 0 on valid, 1 on invalid,
// 2 on usage error.
func runPromptCacheVerify(args []string) int {
	fs := flag.NewFlagSet("prompt-cache verify", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON only")
	expectedKeyID := fs.String("key-id", "", "expected key ID (refuse if mismatch)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	positional := fs.Args()
	if len(positional) != 1 {
		fmt.Fprintf(os.Stderr, "prompt-cache verify: expected exactly one envelope file argument, got %d\n", len(positional))
		promptCacheUsage()
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
		fmt.Fprintf(os.Stderr, "prompt-cache verify: read %s: %v\n", path, err)
		return 1
	}
	vr, err := promptcache.VerifyJSON(context.Background(), data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prompt-cache verify: parse %s: %v\n", path, err)
		return 1
	}
	// Optional key-id check (consistent with the other
	// verify verbs, per TODO-303 M3).
	if vr.Valid && *expectedKeyID != "" && vr.Envelope.Signature.KeyID != *expectedKeyID {
		vr.Valid = false
		vr.Reason = fmt.Sprintf("key ID mismatch: have %q, want %q",
			vr.Envelope.Signature.KeyID, *expectedKeyID)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(vr.ToJSON(), "", "  ")
		fmt.Println(string(out))
	} else {
		printPromptCacheVerifyHuman(vr)
	}
	if !vr.Valid {
		return 1
	}
	return 0
}

// promptCacheHumanSummary returns a multi-line human-
// readable summary of a signed prompt-cache attestation
// envelope.
func promptCacheHumanSummary(env interface{}) string {
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
		"Prompt-Cache Attestation Envelope:\n"+
			"  Type:    %v\n"+
			"  Subject: %v\n"+
			"  Issuer:  %v\n"+
			"  KeyID:   %s\n",
		m["type"], m["subject"], m["issuer"], keyID,
	)
}

// printPromptCacheVerifyHuman prints the verify result in
// human-readable form.
func printPromptCacheVerifyHuman(vr *promptcache.VerifyResult) {
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
	fmt.Printf("  PromptHash: %s\n", out.PromptHash)
	fmt.Printf("  Source:     %s\n", out.Source)
	fmt.Printf("  ModelID:    %s\n", out.ModelID)
	fmt.Printf("  AttestorID: %s\n", out.AttestorID)
	fmt.Printf("  AttestedAt: %s\n", out.AttestedAt)
	fmt.Printf("  ValidUntil: %s\n", out.ValidUntil)
}

// isPromptCacheSubcommand returns true if args look like
// the "aegisgate prompt-cache" subcommand.
func isPromptCacheSubcommand(args []string) bool {
	return len(args) >= 1 && args[0] == "prompt-cache"
}

// stripPromptCacheSubcommand removes the "prompt-cache"
// prefix from args.
func stripPromptCacheSubcommand(args []string) []string {
	if len(args) < 1 {
		return nil
	}
	return args[1:]
}

// init wires the prompt-cache subcommand detection hook.
func init() {
	if isPromptCacheSubcommand(os.Args[1:]) {
		args := stripPromptCacheSubcommand(os.Args[1:])
		runPromptCacheSubcommand(args)
		// Unreachable: runPromptCacheSubcommand calls os.Exit.
	}
}

// (no unused-import guards needed: the file only imports
// the promptcache facade, matching the pattern used by
// a2a_intent_subcommand.go and aibom_subcommand.go.)
