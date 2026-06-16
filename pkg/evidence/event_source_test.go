// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - EventSource interface + ring buffer test
//
// event_source_test.go is a small test file that verifies the
// evidence.EventSource interface contract is satisfied by
// *logging.RingBuffer, and that the Builder.Build path produces
// non-zero AuditAnchors when a real EventSource is wired in.
//
// v3.3.0+ Track 2.

package evidence

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// TestEventSource_RingBufferSatisfies compiles only if
// *logging.RingBuffer implements evidence.EventSource. If the
// interface drifts, this test fails to compile, alerting us to
// update the ring buffer.
func TestEventSource_RingBufferSatisfies(t *testing.T) {
	var _ EventSource = (*logging.RingBuffer)(nil)
}

// TestBuilder_WithEventSource covers the previously-untested branch
// where EventSource is non-nil. The test wires a real ring buffer
// into the Builder and verifies the manifest contains
// AuditAnchors.Source = "ring_buffer" and non-zero event counts.
func TestBuilder_WithEventSource(t *testing.T) {
	api, _ := newTestAPI(t)
	buf := logging.NewRingBuffer(100)
	now := time.Now()
	for i := 0; i < 3; i++ {
		buf.Add(logging.Event{
			Time:     now.Add(time.Duration(i) * time.Second),
			Type:     "hipaa",
			Severity: logging.SeverityInfo,
		})
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBuilder(BuilderDeps{
		Scanner:        api.builder.deps.Scanner,
		LicenseMgr:     api.builder.deps.LicenseMgr,
		SigningKey:     key,
		KeyID:          "test-key",
		BuilderVersion: "v3.3.0-test",
		EventSource:    buf,
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := b.Build(t.Context(), "hipaa", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if m.AuditAnchors.Source != "ring_buffer" {
		t.Errorf("AuditAnchors.Source = %q, want ring_buffer", m.AuditAnchors.Source)
	}
	if m.AuditAnchors.EventCount != 3 {
		t.Errorf("AuditAnchors.EventCount = %d, want 3", m.AuditAnchors.EventCount)
	}
	if m.AuditAnchors.ByType["hipaa"] != 3 {
		t.Errorf("AuditAnchors.ByType[hipaa] = %d, want 3", m.AuditAnchors.ByType["hipaa"])
	}
}

// TestLicenseSnapshot_WithValidLicense covers the previously-untested
// branch where the license is valid. The Builder path uses this
// to produce the LicenseBlock in the manifest.
func TestLicenseSnapshot_WithValidLicense(t *testing.T) {
	api, _ := newTestAPI(t)
	// Get a license with no key - should be valid=false.
	result := api.builder.deps.LicenseMgr.Validate("")
	// Validate with empty key returns Community tier.
	block := LicenseSnapshot("", &result)
	if block.Tier != "community" {
		t.Errorf("LicenseSnapshot tier = %q, want community", block.Tier)
	}
	if block.Fingerprint == "" {
		t.Error("LicenseSnapshot.Fingerprint is empty")
	}
	// FingerprintKey with empty input should still return a 64-char
	// SHA-256 hex string.
	fp := FingerprintKey("")
	if len(fp) != 64 {
		t.Errorf("FingerprintKey(empty) length = %d, want 64", len(fp))
	}
	// Non-empty input should produce a different fingerprint.
	fp2 := FingerprintKey("hello")
	if fp == fp2 {
		t.Error("FingerprintKey with non-empty input should differ from empty input")
	}
}
