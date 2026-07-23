// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Evidence Builder fixture tests (v3.3.0+)
//
// builder_fixture_test.go exercises the Builder.Build path with
// the shared testfixtures. The goal is to push pkg/evidence
// coverage above the 95% target by exercising the real Builder
// + real Scanner + real License manager + real RingBuffer + real
// signing key end-to-end.
//
// These tests run with the default go test (no LAB_ENABLED needed)
// because they use the in-process fixture, not the testlab stack.

package evidence

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// TestBuilder_Build_FreeFramework exercises Build() for a free
// framework (atlas, owasp, etc.) with a real Scanner and real
// signing key. Free frameworks are enforced for every tier and
// should always succeed.
func TestBuilder_Build_FreeFramework(t *testing.T) {
	b := newTestEvidenceBuilder(t)
	ctx := context.Background()
	start := time.Now().Add(-30 * 24 * time.Hour)
	end := time.Now()
	m, err := b.Build(ctx, "atlas", start, end)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m == nil {
		t.Fatal("Build returned nil manifest")
	}
	if m.Framework != "atlas" {
		t.Errorf("Framework = %q, want atlas", m.Framework)
	}
	if !m.FrameworkEvidence.Enforced {
		t.Errorf("Enforced = false, want true (atlas is free)")
	}
	if m.Signature.Algorithm != "ecdsa-p256" {
		t.Errorf("Signature.Algorithm = %q, want ecdsa-p256", m.Signature.Algorithm)
	}
	if len(m.Signature.Value) == 0 {
		t.Error("Signature.Value is empty")
	}
	// AuditAnchors.Source should be "ring_buffer" because we wired
	// a real RingBuffer into the Builder.
	if m.AuditAnchors.Source != "ring_buffer" {
		t.Errorf("AuditAnchors.Source = %q, want ring_buffer", m.AuditAnchors.Source)
	}
	// Verify roundtrip should succeed.
	if err := Verify(m); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// TestBuilder_Build_PremiumFramework exercises Build() for a
// Premium-tier framework (hipaa). The fixture uses a community
// license by default, so the framework should NOT be enforced,
// but the build should still succeed and produce a valid signed
// manifest.
func TestBuilder_Build_PremiumFramework_NotEnforced(t *testing.T) {
	b := newTestEvidenceBuilder(t)
	ctx := context.Background()
	start := time.Now().Add(-30 * 24 * time.Hour)
	end := time.Now()
	m, err := b.Build(ctx, "hipaa", start, end)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.FrameworkEvidence.Enforced {
		t.Errorf("Enforced = true, want false (community license cannot enforce HIPAA)")
	}
	if m.Signature.KeyID != "test-fixture-key" {
		t.Errorf("KeyID = %q, want test-fixture-key", m.Signature.KeyID)
	}
}

// TestBuilder_Build_UnknownFramework tests the error path for
// an unrecognized framework ID.
func TestBuilder_Build_UnknownFramework(t *testing.T) {
	b := newTestEvidenceBuilder(t)
	_, err := b.Build(context.Background(), "not-a-real-framework", time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Error("Build with unknown framework should fail")
	}
}

// TestBuilder_Build_CancelledContext tests the cancellation path.
func TestBuilder_Build_CancelledContext(t *testing.T) {
	b := newTestEvidenceBuilder(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	_, err := b.Build(ctx, "atlas", time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Error("Build with cancelled context should fail")
	}
}

// TestRingBuffer_CollectAuditAnchors_WithRealRingBuffer exercises
// the audit anchor collection path with a real RingBuffer containing
// real events. This is the path that was previously uncovered.
func TestRingBuffer_CollectAuditAnchors_WithRealRingBuffer(t *testing.T) {
	ring := newRingBufferBackedEventSource(t)
	// Add some events.
	for i := 0; i < 50; i++ {
		ring.Add(logging.Event{
			ID:                  "evt-" + hex.EncodeToString([]byte{byte(i)}),
			Type:                "request",
			Severity:            logging.SeverityInfo,
			Message:             "test event",
			ComplianceFramework: "atlas",
		})
	}
	now := time.Now()
	start := now.Add(-time.Hour)
	end := now.Add(time.Hour)
	byType, err := ring.CountByType(context.Background(), start, end)
	if err != nil {
		t.Fatal(err)
	}
	if byType["request"] != 50 {
		t.Errorf("byType[request] = %d, want 50", byType["request"])
	}
	bySev, err := ring.CountBySeverity(context.Background(), start, end)
	if err != nil {
		t.Fatal(err)
	}
	if bySev[logging.SeverityInfo] != 50 {
		t.Errorf("bySev[info] = %d, want 50", bySev[logging.SeverityInfo])
	}
	byFw, err := ring.CountByFramework(context.Background(), start, end)
	if err != nil {
		t.Fatal(err)
	}
	if byFw["atlas"] != 50 {
		t.Errorf("byFw[atlas] = %d, want 50", byFw["atlas"])
	}
}

// TestBuilder_Build_LicenseBlock exercises the LicenseSnapshot
// path with no license set (Community tier).
func TestBuilder_Build_LicenseBlock_NoLicense(t *testing.T) {
	b := newTestEvidenceBuilder(t)
	m, err := b.Build(context.Background(), "atlas", time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Without a license set, the block should show tier=community and Valid=false.
	if m.License.Tier != "community" {
		t.Errorf("License.Tier = %q, want community", m.License.Tier)
	}
	if m.License.Valid {
		t.Error("License.Valid = true, want false (no license configured)")
	}
}

// TestScannerFrameworkID verifies the framework ID translation
// between the evidence package (lowercase IDs) and the compliance
// Scanner (uppercase constants).
func TestScannerFrameworkID(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"atlas", "atlas"},
		{"owasp", "owasp"},
		{"nist_ai_rmf", "nist_ai_rmf"},
		{"hipaa", "hipaa"},         // paid module - passthrough
		{"pci", "pci"},             // paid module - passthrough
		{"eu_ai_act", "eu_ai_act"}, // paid module - passthrough
	}
	for _, c := range cases {
		got := scannerFrameworkID(c.in)
		if got != c.want {
			t.Errorf("scannerFrameworkID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
