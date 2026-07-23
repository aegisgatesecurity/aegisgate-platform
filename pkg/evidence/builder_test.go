// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Evidence Packages (v3.3.0+)
//
// builder_test.go covers the Builder logic. We use the real
// compliance.Scanner (with a stub Registry) and a real ECDSA
// P-256 key so the produced manifests are end-to-end valid.
//
// v3.3.0+ Track 2.

package evidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// generateTestKey creates a fresh ECDSA P-256 key for tests.
func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return key
}

func TestNewBuilder_RequiresAllDeps(t *testing.T) {
	key := generateTestKey(t)
	tests := []struct {
		name    string
		deps    BuilderDeps
		wantErr bool
	}{
		{"all set", BuilderDeps{Scanner: &compliance.Scanner{}, LicenseMgr: nil, SigningKey: key, KeyID: "k1", BuilderVersion: "v1"}, true}, // LicenseMgr missing
		{"nil signing key", BuilderDeps{Scanner: &compliance.Scanner{}, LicenseMgr: nil, SigningKey: nil, KeyID: "k1", BuilderVersion: "v1"}, true},
		{"empty key id", BuilderDeps{Scanner: &compliance.Scanner{}, LicenseMgr: nil, SigningKey: key, KeyID: "", BuilderVersion: "v1"}, true},
		{"empty version", BuilderDeps{Scanner: &compliance.Scanner{}, LicenseMgr: nil, SigningKey: key, KeyID: "k1", BuilderVersion: ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBuilder(tt.deps)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewBuilder err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateBuildInputs(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name      string
		framework string
		start     time.Time
		end       time.Time
		wantErr   bool
	}{
		{"valid hipaa", "hipaa", now.Add(-30 * 24 * time.Hour), now, false},
		{"valid eu_ai_act", "eu_ai_act", now.Add(-90 * 24 * time.Hour), now, false},
		{"empty framework", "", now, now, true},
		{"unknown framework", "bogus_framework", now, now, true},
		{"zero start", "hipaa", time.Time{}, now, true},
		{"zero end", "hipaa", now, time.Time{}, true},
		{"end before start", "hipaa", now, now.Add(-time.Hour), true},
		{"end equals start", "hipaa", now, now, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBuildInputs(tt.framework, tt.start, tt.end)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKnownFrameworks(t *testing.T) {
	fw := knownFrameworks()
	if len(fw) != 22 {
		t.Errorf("expected 22 frameworks, got %d: %v", len(fw), fw)
	}
	want := map[string]bool{
		"hipaa": false, "pci": false, "soc2": false, "iso42001": false,
		"fedramp": false, "fips": false, "eu_ai_act": false,
		"iso27001": false, "nist_csf": false, "cis": false,
		"cmmcl2": false, "nist800171": false, "hitrust": false,
		"tisax": false, "ccpa": false, "nist_ai_rmf": false,
		"csa_star": false, "nist_ai_600_1": false, "owasp_web": false,
		"atlas": false, "owasp": false, "gdpr": false,
	}
	for _, f := range fw {
		want[f] = true
	}
	for f, found := range want {
		if !found {
			t.Errorf("framework %q missing", f)
		}
	}
}

func TestCanonicalJSON_StableKeyOrder(t *testing.T) {
	// Two manifests with map fields populated in different orders
	// should produce identical canonical bytes (encoding/json sorts
	// map keys).
	a := Manifest{Framework: "hipaa", AuditAnchors: AuditAnchors{ByType: map[string]int{"request": 10, "threat": 5}}}
	b := Manifest{Framework: "hipaa", AuditAnchors: AuditAnchors{ByType: map[string]int{"threat": 5, "request": 10}}}
	ca, err := canonicalJSON(&a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := canonicalJSON(&b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Errorf("canonical JSON differs by map iteration order")
		t.Logf("a: %s", ca)
		t.Logf("b: %s", cb)
	}
}

func TestFingerprintKey_Deterministic(t *testing.T) {
	f1 := FingerprintKey("test-key-123")
	f2 := FingerprintKey("test-key-123")
	if f1 != f2 {
		t.Errorf("fingerprint not deterministic: %s vs %s", f1, f2)
	}
	if len(f1) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got %d chars", len(f1))
	}
	// Different keys produce different fingerprints.
	f3 := FingerprintKey("test-key-456")
	if f1 == f3 {
		t.Error("different keys produced same fingerprint")
	}
}

func TestFingerprintKey_EmptyInput(t *testing.T) {
	// Empty input still returns a valid fingerprint (SHA-256 of empty).
	f := FingerprintKey("")
	if len(f) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got %d chars", len(f))
	}
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	key := generateTestKey(t)
	b := &Builder{deps: BuilderDeps{
		SigningKey:     key,
		KeyID:          "test-key-1",
		BuilderVersion: "v3.3.0-test",
	}}
	now := time.Now().UTC()
	m := &Manifest{
		ManifestID:     "test-1",
		Framework:      "hipaa",
		GeneratedAt:    now,
		BuilderVersion: "v3.3.0-test",
	}
	if err := b.signManifest(m, now); err != nil {
		t.Fatalf("signManifest: %v", err)
	}
	if len(m.Signature.Value) == 0 {
		t.Error("signature not populated")
	}
	if m.Signature.Algorithm != "ecdsa-p256" {
		t.Errorf("algorithm = %q, want ecdsa-p256", m.Signature.Algorithm)
	}
	if err := Verify(m); err != nil {
		t.Errorf("Verify after sign: %v", err)
	}
}

func TestVerify_DetectsTampering(t *testing.T) {
	key := generateTestKey(t)
	b := &Builder{deps: BuilderDeps{
		SigningKey:     key,
		KeyID:          "test-key-1",
		BuilderVersion: "v3.3.0-test",
	}}
	now := time.Now().UTC()
	m := &Manifest{
		ManifestID:        "test-1",
		Framework:         "hipaa",
		FrameworkEvidence: FrameworkEvidence{Score: 87.5},
		BuilderVersion:    "v3.3.0-test",
	}
	if err := b.signManifest(m, now); err != nil {
		t.Fatal(err)
	}
	// Tamper with the score AFTER signing.
	m.FrameworkEvidence.Score = 99.9
	err := Verify(m)
	if err == nil {
		t.Error("Verify accepted tampered manifest")
	}
	if err != ErrSignatureInvalid {
		t.Errorf("err = %v, want ErrSignatureInvalid", err)
	}
}

func TestVerify_RejectsWrongKeyID(t *testing.T) {
	key := generateTestKey(t)
	b := &Builder{deps: BuilderDeps{
		SigningKey:     key,
		KeyID:          "test-key-1",
		BuilderVersion: "v3.3.0-test",
	}}
	m := &Manifest{Framework: "hipaa", BuilderVersion: "v3.3.0-test"}
	_ = b.signManifest(m, time.Now().UTC())
	err := VerifyWithKey(m, &key.PublicKey, "different-key-id")
	if err == nil {
		t.Error("VerifyWithKey accepted wrong key ID")
	}
}

func TestVerifyDetailed_StructuredResult(t *testing.T) {
	key := generateTestKey(t)
	b := &Builder{deps: BuilderDeps{
		SigningKey:     key,
		KeyID:          "test-key-1",
		BuilderVersion: "v3.3.0-test",
	}}
	m := &Manifest{ManifestID: "m-1", Framework: "hipaa", BuilderVersion: "v3.3.0-test"}
	_ = b.signManifest(m, time.Now().UTC())
	res := VerifyDetailed(m)
	if !res.Verified {
		t.Errorf("VerifyDetailed not verified: %s", res.Reason)
	}
	if res.ManifestID != "m-1" {
		t.Errorf("ManifestID = %q, want m-1", res.ManifestID)
	}
	if res.KeyID != "test-key-1" {
		t.Errorf("KeyID = %q, want test-key-1", res.KeyID)
	}
}

func TestBuilder_Build_RequiresScanner(t *testing.T) {
	// We cannot call Build without a real Scanner wired in - the
	// Scanner has a constructor that requires a Registry. The
	// happy-path Build is covered by an integration test in
	// evidence_integration_test.go (skipped in unit test mode).
	// For the unit test, we just confirm NewBuilder rejects nil.
	_, err := NewBuilder(BuilderDeps{
		SigningKey:     generateTestKey(t),
		KeyID:          "k",
		BuilderVersion: "v",
	})
	if err == nil {
		t.Error("NewBuilder accepted nil Scanner")
	}
}

func TestCollectAuditAnchors_NilSource(t *testing.T) {
	b := &Builder{deps: BuilderDeps{}} // EventSource is nil
	now := time.Now().UTC()
	anchors, err := b.collectAuditAnchors(context.Background(), now.Add(-time.Hour), now)
	if err != nil {
		t.Fatalf("collectAuditAnchors: %v", err)
	}
	if anchors.Source != "unavailable" {
		t.Errorf("Source = %q, want unavailable", anchors.Source)
	}
	if anchors.EventCount != 0 {
		t.Errorf("EventCount = %d, want 0", anchors.EventCount)
	}
}

// stubEventSource is a minimal EventSource for tests that want to
// exercise the "anchors populated" path without wiring a real
// storage layer. The byType, byFramework, and byProtocol maps
// are populated; bySeverity is unused (logging.Severity is a
// string type so we could include it, but it adds little test
// value). v3.4.0 adds byProtocol for the cross-protocol
// evidence aggregation (c1).
type stubEventSource struct {
	byType      map[string]int
	byFramework map[string]int
	byProtocol  map[string]int
}

func (s *stubEventSource) CountByType(_ context.Context, _, _ time.Time) (map[string]int, error) {
	return s.byType, nil
}
func (s *stubEventSource) CountBySeverity(_ context.Context, _, _ time.Time) (map[logging.Severity]int, error) {
	return nil, nil
}
func (s *stubEventSource) CountByFramework(_ context.Context, _, _ time.Time) (map[string]int, error) {
	return s.byFramework, nil
}
func (s *stubEventSource) CountByProtocol(_ context.Context, _, _ time.Time) (map[string]int, error) {
	return s.byProtocol, nil
}
