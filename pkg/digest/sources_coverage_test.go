// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Digest sources coverage (D24, audit P2 #10)
//
// sources_coverage_test.go covers the previously-untested
// 0% coverage paths in pkg/digest/sources.go:
//   - PostureSource.Name
//   - IOCSource.Name
//   - AuditLogSource.Name
//   - AuditSource.Name
//   - NewPostureSource
//   - NewAuditLogSource
//   - NewAuditSource
//   - AuditLogSource.Collect (nil ring path)
//   - AuditSource.Collect (nil dispatcher path)
//
// The deep tests for IOCSource.Collect and AuditLogSource.Collect
// happy paths already exist in sources_test.go. This file
// complements them with the minimal-surface tests needed to
// cover the 0% functions and the nil-pointer defense paths.

package digest

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// TestPostureSource_Name covers the previously 0% Name() method.
func TestPostureSource_Name(t *testing.T) {
	src := &PostureSource{}
	if got := src.Name(); got != "posture" {
		t.Errorf("PostureSource.Name() = %q, want %q", got, "posture")
	}
}

// TestNewPostureSource covers the previously 0% constructor.
func TestNewPostureSource(t *testing.T) {
	src := NewPostureSource(nil)
	if src == nil {
		t.Fatal("NewPostureSource returned nil")
	}
	if src.checker != nil {
		t.Error("NewPostureSource(nil).checker should be nil")
	}
}

// TestPostureSource_Collect_NilChecker covers the nil-checker
// defense path in PostureSource.Collect.
func TestPostureSource_Collect_NilChecker(t *testing.T) {
	src := NewPostureSource(nil)
	d, err := src.Collect(context.Background(), time.Now(), time.Now())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d == nil {
		t.Fatal("Collect returned nil Digest")
	}
	if d.Posture == nil {
		t.Fatal("Posture should be non-nil (default \"unknown\")")
	}
	if d.Posture.Overall != "unknown" {
		t.Errorf("Posture.Overall = %q, want %q", d.Posture.Overall, "unknown")
	}
}

// TestIOCSource_Name covers the previously 0% Name() method.
func TestIOCSource_Name(t *testing.T) {
	src := &IOCSource{}
	if got := src.Name(); got != "ioc" {
		t.Errorf("IOCSource.Name() = %q, want %q", got, "ioc")
	}
}

// TestAuditLogSource_Name covers the previously 0% Name() method.
func TestAuditLogSource_Name(t *testing.T) {
	src := &AuditLogSource{}
	if got := src.Name(); got != "audit_log" {
		t.Errorf("AuditLogSource.Name() = %q, want %q", got, "audit_log")
	}
}

// TestNewAuditLogSource covers the previously 0% constructor.
func TestNewAuditLogSource(t *testing.T) {
	src := NewAuditLogSource(nil)
	if src == nil {
		t.Fatal("NewAuditLogSource returned nil")
	}
	if src.ring != nil {
		t.Error("NewAuditLogSource(nil).ring should be nil")
	}
}

// TestAuditLogSource_Collect_NilRing covers the nil-ring
// defense path in AuditLogSource.Collect. (The happy
// path is in sources_test.go.)
func TestAuditLogSource_Collect_NilRing(t *testing.T) {
	src := NewAuditLogSource(nil)
	d, err := src.Collect(context.Background(), time.Now(), time.Now())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d == nil {
		t.Fatal("Collect returned nil Digest")
	}
	if d.IOCsBlocked == nil {
		t.Fatal("IOCsBlocked should be non-nil")
	}
	if d.AnomaliesDetected == nil {
		t.Fatal("AnomaliesDetected should be non-nil")
	}
	if d.IOCsBlocked.Total != 0 {
		t.Errorf("Total = %d, want 0", d.IOCsBlocked.Total)
	}
	if d.AnomaliesDetected.Total != 0 {
		t.Errorf("AnomaliesDetected.Total = %d, want 0", d.AnomaliesDetected.Total)
	}
	if len(d.IOCsBlocked.ByCategory) != 0 {
		t.Errorf("ByCategory should be empty, got %d entries", len(d.IOCsBlocked.ByCategory))
	}
}

// TestAuditSource_Name covers the previously 0% Name() method.
func TestAuditSource_Name(t *testing.T) {
	src := &AuditSource{}
	if got := src.Name(); got != "audit" {
		t.Errorf("AuditSource.Name() = %q, want %q", got, "audit")
	}
}

// TestNewAuditSource covers the previously 0% constructor.
func TestNewAuditSource(t *testing.T) {
	src := NewAuditSource(nil)
	if src == nil {
		t.Fatal("NewAuditSource returned nil")
	}
	if src.dispatcher != nil {
		t.Error("NewAuditSource(nil).dispatcher should be nil")
	}
}

// TestAuditSource_Collect_NilDispatcher covers the nil-dispatcher
// defense path in AuditSource.Collect. The happy path
// requires a real SIEMDispatcher which is heavy to set up;
// that test belongs in audit_coverage_test.go (separate concern).
func TestAuditSource_Collect_NilDispatcher(t *testing.T) {
	src := NewAuditSource(nil)
	d, err := src.Collect(context.Background(), time.Now(), time.Now())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d == nil {
		t.Fatal("Collect returned nil Digest")
	}
	// v0.2: AuditSource.Collect returns an empty Digest
	// (the heavy lifting is in AuditLogSource). The
	// function is allowed to silently return an empty
	// digest when the dispatcher is nil.
	if d.IOCsBlocked != nil {
		t.Errorf("IOCsBlocked should be nil for empty digest, got %+v", d.IOCsBlocked)
	}
}

// TestAuditLogSource_Collect_HappyPath covers the main path
// of AuditLogSource.Collect: pulls breakdowns from the ring
// buffer and filters anomalies to high/critical severity.
// This drives the Coverage from 80% to 90%+ for AuditLogSource.
func TestAuditLogSource_Collect_HappyPath(t *testing.T) {
	now := time.Now().UTC()
	ring := logging.NewRingBuffer(logging.DefaultCapacity)
	ring.Add(logging.Event{
		Time:     now.Add(-1 * time.Hour),
		ID:       "evt-1",
		Type:     "test.event",
		Severity: logging.SeverityHigh,
	})
	ring.Add(logging.Event{
		Time:     now.Add(-30 * time.Minute),
		ID:       "evt-2",
		Type:     "test.event",
		Severity: logging.SeverityCritical,
	})
	ring.Add(logging.Event{
		Time:     now.Add(-15 * time.Minute),
		ID:       "evt-3",
		Type:     "test.event",
		Severity: logging.SeverityLow, // should NOT be counted as anomaly
	})
	src := NewAuditLogSource(ring)
	d, err := src.Collect(context.Background(), now.Add(-7*24*time.Hour), now)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d == nil {
		t.Fatal("Collect returned nil Digest")
	}
	// Two anomalies (high + critical), one low event ignored.
	if d.AnomaliesDetected.Total != 2 {
		t.Errorf("AnomaliesDetected.Total = %d, want 2", d.AnomaliesDetected.Total)
	}
	if d.AnomaliesDetected.BySeverity["high"] != 1 {
		t.Errorf("BySeverity[high] = %d, want 1", d.AnomaliesDetected.BySeverity["high"])
	}
	if d.AnomaliesDetected.BySeverity["critical"] != 1 {
		t.Errorf("BySeverity[critical] = %d, want 1", d.AnomaliesDetected.BySeverity["critical"])
	}
	// ByFramework and ByProtocol maps should be initialized
	// (the ring buffer has no framework metadata, so they
	// are empty maps, not nil).
	if d.IOCsBlocked.ByFramework == nil {
		t.Error("ByFramework should be non-nil")
	}
	if d.IOCsBlocked.ByProtocol == nil {
		t.Error("ByProtocol should be non-nil")
	}
}
