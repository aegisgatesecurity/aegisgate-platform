// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Evidence Package CLI subcommand (v3.3.0+ Track 2)
// =========================================================================
//
// evidence_subcommand.go wires pkg/evidence into both the CLI binary
// (aegisgate evidence build/verify/list) and the dashboard HTTP API
// (/api/v1/compliance/evidence/*).
//
// Like posture_subcommand.go, this file intentionally starts the
// minimum required subsystems (license manager only) so the founder
// can produce evidence packages without bringing up the full platform.
//
// v3.3.0+ Track 2.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/evidence"
)

// runEvidenceSubcommand implements the "aegisgate evidence" CLI
// subcommand. The verb is one of: build, verify, list.
func runEvidenceSubcommand(args []string) {
	if len(args) == 0 {
		evidenceUsage()
		os.Exit(2)
	}
	verb := args[0]
	rest := args[1:]
	switch verb {
	case "build":
		runEvidenceBuild(rest)
	case "build-cross-protocol":
		runEvidenceBuildCrossProtocol(rest)
	case "verify":
		runEvidenceVerify(rest)
	case "list":
		runEvidenceList(rest)
	case "-help", "--help", "help":
		evidenceUsage()
	default:
		fmt.Fprintf(os.Stderr, "evidence: unknown verb %q\n", verb)
		evidenceUsage()
		os.Exit(2)
	}
}

func evidenceUsage() {
	fmt.Println("aegisgate evidence - manage compliance evidence packages")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  aegisgate evidence build --framework=NAME --start=YYYY-MM-DD --end=YYYY-MM-DD [--json] [--store-dir=PATH]")
	fmt.Println("  aegisgate evidence verify <manifest-id> [--json]")
	fmt.Println("  aegisgate evidence list [--limit=N] [--json]")
	fmt.Println("")
	fmt.Println("Verbs:")
	fmt.Println("  build   Produce a signed evidence manifest for a framework + period.")
	fmt.Println("  verify  Verify a stored manifest signature (independent of Builder).")
	fmt.Println("  list    List all stored manifests (summary only).")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  aegisgate evidence build --framework=hipaa --start=2026-04-01 --end=2026-06-30")
	fmt.Println("  aegisgate evidence verify <id-from-build-output>")
	fmt.Println("  aegisgate evidence list --limit=10")
}

func runEvidenceBuild(args []string) {
	fs := flag.NewFlagSet("evidence build", flag.ExitOnError)
	framework := fs.String("framework", "", "framework name (hipaa, pci, soc2, iso42001, fedramp, fips, eu_ai_act, atlas, nist_ai_rmf, owasp)")
	startStr := fs.String("start", "", "period start (YYYY-MM-DD, inclusive)")
	endStr := fs.String("end", "", "period end (YYYY-MM-DD, inclusive)")
	jsonOut := fs.Bool("json", false, "emit JSON only (no human-friendly text)")
	storeDir := fs.String("store-dir", evidence.DefaultDir, "directory for evidence storage")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("flag parse: %v", err)
	}
	if *framework == "" || *startStr == "" || *endStr == "" {
		fmt.Fprintln(os.Stderr, "evidence build: --framework, --start, --end are required")
		os.Exit(2)
	}
	start, err := time.Parse("2006-01-02", *startStr)
	if err != nil {
		log.Fatalf("invalid --start: %v", err)
	}
	end, err := time.Parse("2006-01-02", *endStr)
	if err != nil {
		log.Fatalf("invalid --end: %v", err)
	}
	end = end.Add(24 * time.Hour).Add(-time.Second) // end-of-day inclusive

	// Wire up Builder with a fresh ephemeral signing key. We do
	// NOT call Builder.Build() here because it requires a Scanner
	// + Registry wired in (the CLI does not have those). Instead we
	// build the manifest directly. For v0.1 the framework-aggregate
	// fields show Enforced=false with reason="cli_build_no_scanner";
	// the full HTTP /build endpoint fills in the real scan results.
	signingKey, keyID, err := initEvidenceBuilderForCLI()
	if err != nil {
		log.Fatalf("init builder: %v", err)
	}
	store, err := evidence.NewStore(*storeDir)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}
	m, err := buildEvidenceManifestCLI(signingKey, keyID, *framework, start, end)
	if err != nil {
		log.Fatalf("build: %v", err)
	}
	if err := store.Put(m); err != nil {
		log.Fatalf("store: %v", err)
	}
	if *jsonOut {
		encodeJSON(os.Stdout, m)
	} else {
		fmt.Printf("Built evidence manifest: %s\n", m.ManifestID)
		fmt.Printf("  Framework: %s\n", m.Framework)
		fmt.Printf("  Period:    %s -> %s\n",
			m.Period.Start.Format("2006-01-02"),
			m.Period.End.Format("2006-01-02"))
		fmt.Printf("  Stored at: %s\n", store.Path())
		fmt.Printf("  Key ID:    %s\n", m.Signature.KeyID)
		fmt.Printf("\nFull manifest:\n")
		encodeJSON(os.Stdout, m)
	}
}

func runEvidenceVerify(args []string) {
	fs := flag.NewFlagSet("evidence verify", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON only")
	storeDir := fs.String("store-dir", evidence.DefaultDir, "directory for evidence storage")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("flag parse: %v", err)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "evidence verify: expected exactly one manifest id")
		os.Exit(2)
	}
	id := rest[0]
	store, err := evidence.NewStore(*storeDir)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}
	m, err := store.Get(id)
	if err != nil {
		log.Fatalf("get %s: %v", id, err)
	}
	res := evidence.VerifyDetailed(m)
	if *jsonOut {
		encodeJSON(os.Stdout, res)
	} else {
		if res.Verified {
			fmt.Printf("VERIFIED %s (key=%s, signed_at=%s)\n",
				res.ManifestID, res.KeyID, res.SignedAt)
		} else {
			fmt.Printf("FAILED %s: %s\n", res.ManifestID, res.Reason)
			os.Exit(1)
		}
	}
}

func runEvidenceList(args []string) {
	fs := flag.NewFlagSet("evidence list", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON only")
	limit := fs.Int("limit", 0, "max number of manifests to list (0 = no limit)")
	storeDir := fs.String("store-dir", evidence.DefaultDir, "directory for evidence storage")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("flag parse: %v", err)
	}
	store, err := evidence.NewStore(*storeDir)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}
	all, err := store.List(*limit)
	if err != nil {
		log.Fatalf("list: %v", err)
	}
	if *jsonOut {
		encodeJSON(os.Stdout, map[string]any{
			"count":     len(all),
			"manifests": all,
		})
		return
	}
	fmt.Printf("Found %d manifest(s) in %s:\n", len(all), store.Path())
	for _, m := range all {
		ok := "INVALID"
		if evidence.Verify(m) == nil {
			ok = "OK"
		}
		fmt.Printf("  %-6s  %s  %-12s  %s -> %s\n",
			ok,
			m.ManifestID,
			m.Framework,
			m.Period.Start.Format("2006-01-02"),
			m.Period.End.Format("2006-01-02"),
		)
	}
}

// initEvidenceBuilderForCLI creates a Builder with a fresh
// ephemeral signing key AND returns the key + keyID for the
// CLI signing path. The key is NOT persisted - CLI manifests
// cannot be verified after the CLI process exits. This is the
// v0.1 trade-off; production uses the platform persisted keystore.
func initEvidenceBuilderForCLI() (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate signing key: %w", err)
	}
	keyID := cliEvidenceKeyID(key)
	return key, keyID, nil
}

// cliEvidenceKeyID returns a short fingerprint of the signing key
// so the operator can identify which CLI invocation signed a manifest.
func cliEvidenceKeyID(key *ecdsa.PrivateKey) string {
	//nolint:staticcheck // SA1019: elliptic.Marshal deprecated since Go 1.21.
	// See migration note in pkg/evidence/builder.go.
	pubBytes := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	h := sha256.Sum256(pubBytes)
	return "cli-" + hex.EncodeToString(h[:6])
}

// evidenceCLIVersion returns the version string for the manifest.
func evidenceCLIVersion() string {
	if version == "" {
		return "v3.3.0-cli"
	}
	return version
}

// buildEvidenceManifestCLI builds a manifest and signs it. We do not
// use Builder.Build() because it requires a Scanner + Registry; the
// CLI does not have those. Instead we build the manifest directly
// and sign it using the same canonical-JSON + SHA-256 + ECDSA-P256
// flow as the Builder. If the Builder ever changes its signing
// algorithm, this function MUST be updated to match.
func buildEvidenceManifestCLI(signingKey *ecdsa.PrivateKey, keyID, framework string, start, end time.Time) (*evidence.Manifest, error) {
	m := &evidence.Manifest{
		ManifestID: randomManifestID(),
		Framework:  framework,
		Period: evidence.Period{
			Start: start.UTC(),
			End:   end.UTC(),
		},
		GeneratedAt:    time.Now().UTC(),
		BuilderVersion: evidenceCLIVersion(),
		FrameworkEvidence: evidence.FrameworkEvidence{
			Framework:         framework,
			Enforced:          false,
			ReasonNotEnforced: "cli_build_no_scanner",
		},
		AuditAnchors: evidence.AuditAnchors{
			Source: "unavailable",
		},
		License: evidence.LicenseBlock{
			Tier:  "community",
			Valid: false,
		},
	}
	if err := signManifestInPlace(m, signingKey, keyID); err != nil {
		return nil, err
	}
	return m, nil
}

// signManifestInPlace signs a manifest in place. This is a duplicate
// of the algorithm in pkg/evidence/builder.go (signManifest). It is
// duplicated here so the CLI build path is self-contained and does
// not need to expose the Builder's signing logic publicly.
func signManifestInPlace(m *evidence.Manifest, key *ecdsa.PrivateKey, keyID string) error {
	m.Signature = evidence.Signature{}
	canonical, err := canonicalJSONForCLI(m)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}
	hash := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	m.Signature = evidence.Signature{
		Algorithm: "ecdsa-p256",
		KeyID:     keyID,
		Value:     sig,
		//nolint:staticcheck // SA1019: elliptic.Marshal deprecated since Go 1.21.
		PublicKey: elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y),
		SignedAt:  time.Now().UTC(),
	}
	return nil
}

// canonicalJSONForCLI wraps encoding/json.Marshal for the canonical
// (sorted-keys) form. Mirrors evidence.canonicalJSON.
func canonicalJSONForCLI(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// randomManifestID returns a short, URL-safe ID.
func randomManifestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "cli-unknown"
	}
	return "cli-" + hex.EncodeToString(b)
}

// encodeJSON marshals v to w as indented JSON.
func encodeJSON(w *os.File, v interface{}) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatalf("encode: %v", err)
	}
}

// isEvidenceSubcommand returns true if the user invoked the binary as
// "aegisgate evidence ...".
func isEvidenceSubcommand(argv []string) bool {
	for _, a := range argv {
		if a == "evidence" {
			return true
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return false
	}
	return false
}

// stripEvidenceSubcommand returns the args after the "evidence" word.
func stripEvidenceSubcommand(argv []string) []string {
	out := []string{}
	sawEvidence := false
	for _, a := range argv {
		if !sawEvidence {
			if a == "evidence" {
				sawEvidence = true
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// contextWithTimeout is reserved for future use (evidence build/verify
// with a timeout). The current CLI path does not need it because builds
// are fast (< 1s) and the flag library handles interruption.
//
//nolint:unused // reserved for v0.2
func contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// init wires the evidence subcommand detection hook. Runs BEFORE
// main() and BEFORE flag.Parse() consumes the args. The subcommand
// only needs the license manager (for the LicenseBlock snapshot);
// we do NOT start the proxy, MCP, or dashboard servers.
//
// This mirrors the pattern in posture_subcommand.go and is the
// stdlib-flag idiom for subcommand parsing in a single-binary CLI.
func init() {
	if isEvidenceSubcommand(os.Args[1:]) {
		args := stripEvidenceSubcommand(os.Args[1:])
		runEvidenceSubcommand(args)
		os.Exit(0)
	}
}

// runEvidenceBuildCrossProtocol is the CLI entry point for
// "aegisgate evidence build-cross-protocol". It builds a
// CrossProtocolManifest directly using the BuildCrossProtocolCLI
// helper - no Scanner needed, since the CLI use case is for the
// ByProtocol audit rollup, not per-framework scan detail. The
// signing key is ephemeral (CLI process), so the manifest cannot
// be verified after the process exits - same trade-off as the
// per-framework build verb.
//
// Note: this CLI verb does NOT call evidence.Store.Put; the
// cross-protocol artifact is signed and printed, but not
// persisted. The full Builder.BuildCrossProtocol() path (which
// is invoked by the HTTP /cross_protocol/build endpoint) does
// persist via the standard store. This CLI verb is for ad-hoc
// auditor inspection, not for long-term storage.
func runEvidenceBuildCrossProtocol(args []string) {
	fs := flag.NewFlagSet("evidence build-cross-protocol", flag.ExitOnError)
	startStr := fs.String("start", "", "period start (YYYY-MM-DD, inclusive)")
	endStr := fs.String("end", "", "period end (YYYY-MM-DD, inclusive)")
	jsonOut := fs.Bool("json", false, "emit JSON only")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("flag parse: %v", err)
	}
	if *startStr == "" || *endStr == "" {
		fmt.Fprintln(os.Stderr, "evidence build-cross-protocol: --start, --end are required")
		os.Exit(2)
	}
	start, err := time.Parse("2006-01-02", *startStr)
	if err != nil {
		log.Fatalf("invalid --start: %v", err)
	}
	end, err := time.Parse("2006-01-02", *endStr)
	if err != nil {
		log.Fatalf("invalid --end: %v", err)
	}
	end = end.Add(24 * time.Hour).Add(-time.Second)
	signingKey, keyID, err := initEvidenceBuilderForCLI()
	if err != nil {
		log.Fatalf("init builder: %v", err)
	}
	cp := &evidence.CrossProtocolManifest{
		ManifestID: randomManifestID(),
		Period: evidence.Period{
			Start: start.UTC(),
			End:   end.UTC(),
		},
		AuditAnchors: evidence.AuditAnchors{
			Source:     "unavailable",
			ByProtocol: map[string]int{},
			ByType:     map[string]int{},
		},
		PerFramework: []evidence.PerFrameworkRef{},
	}
	if err := evidence.BuildCrossProtocolCLI(cp, signingKey, keyID, evidenceCLIVersion()); err != nil {
		log.Fatalf("build: %v", err)
	}
	if *jsonOut {
		encodeJSON(os.Stdout, cp)
		return
	}
	fmt.Printf("Built cross-protocol manifest: %s\n", cp.ManifestID)
	fmt.Printf("  Period:               %s -> %s\n",
		cp.Period.Start.Format("2006-01-02"),
		cp.Period.End.Format("2006-01-02"))
	fmt.Printf("  Per-framework refs:   %d\n", len(cp.PerFramework))
	fmt.Printf("  Total events:         %d\n", cp.AuditAnchors.EventCount)
	if len(cp.AuditAnchors.ByProtocol) > 0 {
		fmt.Printf("  By protocol:          ")
		for proto, n := range cp.AuditAnchors.ByProtocol {
			fmt.Printf("%s=%d ", proto, n)
		}
		fmt.Println()
	}
	fmt.Printf("  Key ID:               %s\n", cp.Signature.KeyID)
	fmt.Printf("\nNote: per-framework refs empty in CLI mode (no Scanner). Use HTTP /cross_protocol/build for full manifests.\n")
	fmt.Printf("\nFull manifest:\n")
	encodeJSON(os.Stdout, cp)
}
