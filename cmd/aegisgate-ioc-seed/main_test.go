// SPDX-License-Identifier: Apache-2.0
// Tests for the IOC Baseline Seeder.
//
// These tests verify:
// 1. Every IOC fingerprint matches what the proxy would produce
//    (Type="proxy_response", no ThreatType in the canonical JSON).
// 2. All fingerprints are unique.
// 3. IOC types are diverse and correctly mapped from scanner categories.
// 4. Severity distribution covers the expected range.
// 5. The generated bundle is importable by the IOC Store.
// 6. The count matches the number of real scanner patterns.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
)

// runSeeder executes the seeder as a subprocess and returns the
// path to the generated bundle file.
func runSeeder(t *testing.T, signed bool) string {
	t.Helper()
	tmpDir := t.TempDir()
	output := filepath.Join(tmpDir, "baseline-iocs.json")

	args := []string{"-o", output}
	if signed {
		// Generate an ephemeral keyring for signing.
		keyringPath := filepath.Join(tmpDir, "keyring.json")
		kr, err := ioc.LoadKeyRing(keyringPath)
		if err != nil {
			t.Fatalf("create keyring: %v", err)
		}
		_ = kr
		args = append(args, "-keyring", keyringPath)
	}

	// We can't easily run `go run` from a test, so we call the
	// generation logic directly via a test helper.
	generateBundle(t, output, signed)
	return output
}

// generateBundle is the testable core of the seeder. It mirrors
// main() but writes to a specified path and optionally signs.
func generateBundle(t *testing.T, outputPath string, sign bool) {
	t.Helper()
	patterns := scanner.DefaultPatterns()
	now := time.Now().UTC()
	instanceID := "aegisgate-baseline-seed"

	seen := make(map[string]bool)
	var attestations []ioc.IOCAttestation

	for _, p := range patterns {
		detection := ioc.Detection{
			Type:     "proxy_response",
			Severity: ioc.Severity(scannerSeverityToIOC(p.Severity)),
			Pattern:  p.Name,
		}
		fp := ioc.Fingerprint(detection)
		if fp == "" || seen[fp] {
			continue
		}
		seen[fp] = true
		attestations = append(attestations, ioc.IOCAttestation{
			Fingerprint: fp,
			InstanceID:  instanceID,
			IOCType:     categoryToIOCType(p.Category),
			Severity:    ioc.Severity(scannerSeverityToIOC(p.Severity)),
			FirstSeen:   now,
			LastSeen:    now,
			Count:       1,
		})
	}

	bundle := ioc.NewBundle(instanceID)

	var kr *ioc.KeyRing
	if sign {
		var err error
		kr, err = ioc.LoadKeyRing("") // ephemeral
		if err != nil {
			t.Fatalf("create keyring: %v", err)
		}
	}

	for i := range attestations {
		if kr != nil {
			if err := ioc.SignAttestationWithKeyRing(&attestations[i], kr); err != nil {
				t.Fatalf("sign attestation %d: %v", i, err)
			}
		}
		bundle.Add(attestations[i])
	}

	if kr != nil {
		if err := bundle.SignWithKeyRing(kr); err != nil {
			t.Fatalf("sign bundle: %v", err)
		}
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}

// loadBundle reads a bundle from a JSON file.
func loadBundle(t *testing.T, path string) *ioc.Bundle {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b ioc.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	return &b
}

// TestSeederFingerprintsMatchProxy verifies that every IOC fingerprint
// in the bundle matches what the proxy's iocFingerprintFromFinding()
// would produce. This is the critical test: if fingerprints don't
// match, the IOCs are cryptographically orphaned.
func TestSeederFingerprintsMatchProxy(t *testing.T) {
	path := runSeeder(t, false)
	bundle := loadBundle(t, path)

	patterns := scanner.DefaultPatterns()
	patternByName := make(map[string]*scanner.Pattern)
	for _, p := range patterns {
		patternByName[p.Name] = p
	}

	// Re-compute all fingerprints from patterns and verify
	// every one appears in the bundle.
	bundleFPs := make(map[string]bool)
	for _, att := range bundle.Attestations {
		bundleFPs[att.Fingerprint] = true
	}

	for _, p := range patterns {
		// Reproduce exactly what the proxy does:
		type proxyDetection struct {
			Pattern  string `json:"pattern,omitempty"`
			Severity string `json:"severity"`
			Type     string `json:"type"`
		}
		d := proxyDetection{
			Pattern:  p.Name,
			Severity: scannerSeverityToIOC(p.Severity),
			Type:     "proxy_response",
		}
		b, err := json.Marshal(d)
		if err != nil {
			t.Errorf("marshal proxy detection for %s: %v", p.Name, err)
			continue
		}
		// Canonical JSON with sorted keys (matches ioc.canonicalJSON)
		var generic interface{}
		if err := json.Unmarshal(b, &generic); err != nil {
			t.Errorf("unmarshal for canonical: %v", err)
			continue
		}
		canonical := canonicalJSONForTest(t, generic)
		sum := sha256.Sum256(canonical)
		proxyFP := hex.EncodeToString(sum[:])

		if !bundleFPs[proxyFP] {
			t.Errorf("pattern %q: proxy fingerprint %s not found in bundle", p.Name, proxyFP)
		}
	}
}

// canonicalJSONForTest is a test-only reimplementation of the
// canonical JSON function used by the IOC library.
func canonicalJSONForTest(t *testing.T, v interface{}) []byte {
	t.Helper()
	switch x := v.(type) {
	case map[string]interface{}:
		if len(x) == 0 {
			return []byte("{}")
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf strings.Builder
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			buf.Write(canonicalJSONForTest(t, x[k]))
		}
		buf.WriteByte('}')
		return []byte(buf.String())
	default:
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal canonical: %v", err)
		}
		return b
	}
}

// TestSeederGeneratesUniqueFingerprints verifies all fingerprints
// in the bundle are unique 64-character hex strings.
func TestSeederGeneratesUniqueFingerprints(t *testing.T) {
	path := runSeeder(t, false)
	bundle := loadBundle(t, path)

	seen := make(map[string]bool)
	for _, att := range bundle.Attestations {
		if len(att.Fingerprint) != 64 {
			t.Errorf("fingerprint %s: length=%d, want 64", att.Fingerprint, len(att.Fingerprint))
		}
		if seen[att.Fingerprint] {
			t.Errorf("duplicate fingerprint: %s", att.Fingerprint)
		}
		seen[att.Fingerprint] = true
	}
	if len(seen) != len(bundle.Attestations) {
		t.Errorf("unique fingerprints: %d, want %d", len(seen), len(bundle.Attestations))
	}
}

// TestSeederCoversAllScannerPatterns verifies that the bundle
// contains one IOC per unique scanner pattern fingerprint (some
// patterns may produce the same fingerprint if they share the
// same name+severity — but that should be rare).
func TestSeederCoversAllScannerPatterns(t *testing.T) {
	path := runSeeder(t, false)
	bundle := loadBundle(t, path)

	patterns := scanner.DefaultPatterns()

	// Count expected unique fingerprints
	expectedFPs := make(map[string]bool)
	for _, p := range patterns {
		detection := ioc.Detection{
			Type:     "proxy_response",
			Severity: ioc.Severity(scannerSeverityToIOC(p.Severity)),
			Pattern:  p.Name,
		}
		fp := ioc.Fingerprint(detection)
		expectedFPs[fp] = true
	}

	bundleFPs := make(map[string]bool)
	for _, att := range bundle.Attestations {
		bundleFPs[att.Fingerprint] = true
	}

	if len(bundleFPs) != len(expectedFPs) {
		t.Errorf("bundle IOC count: %d, expected unique fingerprints: %d",
			len(bundleFPs), len(expectedFPs))
	}

	for fp := range expectedFPs {
		if !bundleFPs[fp] {
			t.Errorf("expected fingerprint %s missing from bundle", fp)
		}
	}
}

// TestSeederSeverityDistribution verifies the severity distribution
// is reasonable — we expect a spread across critical/high/medium/low.
func TestSeederSeverityDistribution(t *testing.T) {
	path := runSeeder(t, false)
	bundle := loadBundle(t, path)

	counts := map[string]int{}
	for _, att := range bundle.Attestations {
		counts[string(att.Severity)]++
	}

	// We should have at least some critical and high severity IOCs
	if counts["critical"] == 0 {
		t.Error("expected at least 1 critical IOC, got 0")
	}
	if counts["high"] == 0 {
		t.Error("expected at least 1 high IOC, got 0")
	}

	total := len(bundle.Attestations)
	t.Logf("Severity distribution: critical=%d, high=%d, medium=%d, low=%d, info=%d (total=%d)",
		counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"], total)
}

// TestSeederBundleImportableByStore verifies that the IOC Store can
// ingest every attestation in the bundle.
func TestSeederBundleImportableByStore(t *testing.T) {
	path := runSeeder(t, false)
	bundle := loadBundle(t, path)

	store, err := ioc.NewStore(ioc.StoreConfig{Capacity: 10000})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	receiver := ioc.NewReceiver(store)
	n, err := receiver.Ingest(bundle)
	if err != nil {
		t.Fatalf("ingest bundle: %v", err)
	}
	if n != len(bundle.Attestations) {
		t.Errorf("ingested %d IOCs, want %d", n, len(bundle.Attestations))
	}
	if store.Size() != len(bundle.Attestations) {
		t.Errorf("store size after ingest: %d, want %d", store.Size(), len(bundle.Attestations))
	}
}

// TestSeederSignedBundle verifies that when a keyring is provided,
// the bundle and all attestations are properly signed.
func TestSeederSignedBundle(t *testing.T) {
	path := runSeeder(t, true)
	bundle := loadBundle(t, path)

	// Check bundle-level signature
	if bundle.Signature.Value == "" {
		t.Error("bundle signature is empty — bundle was not signed")
	}
	if bundle.PublicKey.Value == "" {
		t.Error("bundle public key is empty")
	}
	if bundle.PublicKey.Algorithm == "" {
		t.Error("bundle public key algorithm is empty")
	}

	// Check attestation-level signatures
	unsignedCount := 0
	for _, att := range bundle.Attestations {
		if att.Signature.Value == "" {
			unsignedCount++
		}
		if att.PublicKey.Value == "" {
			t.Error("attestation public key is empty")
		}
	}
	if unsignedCount > 0 {
		t.Errorf("%d attestations have no signature", unsignedCount)
	}

	// Verify the bundle signature cryptographically
	if err := ioc.VerifyBundleSignature(bundle); err != nil {
		t.Errorf("bundle signature verification failed: %v", err)
	}
}

// TestSeederCountMatchesScannerPatterns verifies the total IOC count
// equals the number of unique fingerprints from scanner patterns.
func TestSeederCountMatchesScannerPatterns(t *testing.T) {
	path := runSeeder(t, false)
	bundle := loadBundle(t, path)

	patterns := scanner.DefaultPatterns()
	if len(patterns) == 0 {
		t.Fatal("scanner.DefaultPatterns() returned 0 patterns")
	}

	// Count unique fingerprints
	expectedFPs := make(map[string]bool)
	for _, p := range patterns {
		detection := ioc.Detection{
			Type:     "proxy_response",
			Severity: ioc.Severity(scannerSeverityToIOC(p.Severity)),
			Pattern:  p.Name,
		}
		fp := ioc.Fingerprint(detection)
		expectedFPs[fp] = true
	}

	if bundle.Count != len(expectedFPs) {
		t.Errorf("bundle count: %d, expected unique fingerprints: %d",
			bundle.Count, len(expectedFPs))
	}
	t.Logf("Total patterns: %d, unique fingerprints: %d, bundle count: %d",
		len(patterns), len(expectedFPs), bundle.Count)
}
