// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Digest source pipeline tests (v0.2 wiring)
//
// sources_test.go covers the v0.2 wiring of the
// CISO Digest's source pipeline:
//   - IOCSource: time-range query against the IOC store
//   - AuditLogSource: time-windowed aggregations from the
//     audit log ring buffer
//   - mergeIOCSummary: field-level merge of two
//     IOCSummary values (totals sum, maps merge)
//   - mergeAnomalySummary: same for AnomalySummary
//
// The v0.1 source tests (in digest_test.go) cover the
// Source interface contract; the v0.2 tests here cover
// the data flow.

package digest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// =====================================================================
// Test helpers
// =====================================================================

// fakeFingerprint returns a valid 64-char SHA-256
// fingerprint for a given string. Used to satisfy
// ioc.Valid() (which requires Fingerprint != "").
func fakeFingerprint(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// newTestIOCStore returns an in-memory IOC store
// pre-populated with the given IOCs. Each IOC must
// have a valid Fingerprint (64 hex chars), Type, and
// non-zero FirstSeen + LastSeen + Count (i.e., it
// must pass ioc.Valid()).
func newTestIOCStore(t *testing.T, iocs ...ioc.IOC) *ioc.Store {
	t.Helper()
	store, err := ioc.NewStore(ioc.StoreConfig{})
	if err != nil {
		t.Fatalf("ioc.NewStore: %v", err)
	}
	now := time.Now().UTC()
	for _, i := range iocs {
		if i.FirstSeen.IsZero() {
			i.FirstSeen = now
		}
		if i.LastSeen.IsZero() {
			i.LastSeen = now
		}
		if i.Count == 0 {
			i.Count = 1
		}
		if _, err := store.Observe(i); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}
	return store
}

// newTestRingBuffer returns a ring buffer
// pre-populated with the given events.
func newTestRingBuffer(events ...logging.Event) *logging.RingBuffer {
	ring := logging.NewRingBuffer(logging.DefaultCapacity)
	for _, e := range events {
		ring.Add(e)
	}
	return ring
}

// =====================================================================
// IOCSource
// =====================================================================

func TestIOCSource_HappyPath(t *testing.T) {
	now := time.Now().UTC()
	store := newTestIOCStore(t,
		ioc.IOC{
			Fingerprint: fakeFingerprint("pi-1"),
			Type:        ioc.IOCTypePromptInjection,
			Severity:    ioc.SeverityHigh,
			FirstSeen:   now.Add(-1 * time.Hour),
		},
		ioc.IOC{
			Fingerprint: fakeFingerprint("sl-1"),
			Type:        ioc.IOCTypeSecretLeak,
			Severity:    ioc.SeverityCritical,
			FirstSeen:   now.Add(-30 * time.Minute),
		},
	)
	src := NewIOCSource(store)
	d, err := src.Collect(context.Background(), now.Add(-7*24*time.Hour), now)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d.IOCsBlocked == nil {
		t.Fatal("IOCsBlocked is nil")
	}
	if d.IOCsBlocked.Total != 2 {
		t.Errorf("Total = %d, want 2", d.IOCsBlocked.Total)
	}
	if d.IOCsBlocked.ByCategory["prompt_injection"] != 1 {
		t.Errorf("ByCategory[prompt_injection] = %d, want 1", d.IOCsBlocked.ByCategory["prompt_injection"])
	}
	if d.IOCsBlocked.ByCategory["secret_leak"] != 1 {
		t.Errorf("ByCategory[secret_leak] = %d, want 1", d.IOCsBlocked.ByCategory["secret_leak"])
	}
}

func TestIOCSource_NilStore(t *testing.T) {
	src := NewIOCSource(nil)
	d, err := src.Collect(context.Background(), time.Now(), time.Now())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d.IOCsBlocked == nil {
		t.Fatal("IOCsBlocked is nil")
	}
	if d.IOCsBlocked.Total != 0 {
		t.Errorf("Total = %d, want 0", d.IOCsBlocked.Total)
	}
}

func TestIOCSource_FilterByEnd(t *testing.T) {
	// IOCs FirstSeen AFTER the digest's end should not
	// be counted.
	now := time.Now().UTC()
	store := newTestIOCStore(t,
		ioc.IOC{
			Fingerprint: fakeFingerprint("pi-old"),
			Type:        ioc.IOCTypePromptInjection,
			Severity:    ioc.SeverityHigh,
			FirstSeen:   now.Add(-1 * time.Hour), // in range
		},
		ioc.IOC{
			Fingerprint: fakeFingerprint("pi-future"),
			Type:        ioc.IOCTypePromptInjection,
			Severity:    ioc.SeverityHigh,
			FirstSeen:   now.Add(1 * time.Hour), // out of range (future)
		},
	)
	src := NewIOCSource(store)
	d, err := src.Collect(context.Background(), now.Add(-7*24*time.Hour), now)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d.IOCsBlocked.Total != 1 {
		t.Errorf("Total = %d, want 1 (future IOC should be excluded)", d.IOCsBlocked.Total)
	}
}

// =====================================================================
// AuditLogSource
// =====================================================================

func TestAuditLogSource_HappyPath(t *testing.T) {
	now := time.Now().UTC()
	ring := newTestRingBuffer(
		logging.Event{
			Time:               now.Add(-30 * time.Minute),
			Type:               "response_scan",
			Severity:           "high",
			ComplianceFramework: "GDPR",
		},
		logging.Event{
			Time:               now.Add(-15 * time.Minute),
			Type:               "response_scan",
			Severity:           "high",
			ComplianceFramework: "GDPR",
		},
		logging.Event{
			Time:               now.Add(-10 * time.Minute),
			Type:               "mcp_tool_call",
			Severity:           "critical",
			ComplianceFramework: "HIPAA",
		},
	)
	src := NewAuditLogSource(ring)
	d, err := src.Collect(context.Background(), now.Add(-1*time.Hour), now)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Anomalies: 3 (all events are high/critical)
	if d.AnomaliesDetected.Total != 3 {
		t.Errorf("Anomalies Total = %d, want 3", d.AnomaliesDetected.Total)
	}
	// By severity: 2 high + 1 critical
	if d.AnomaliesDetected.BySeverity["high"] != 2 {
		t.Errorf("BySeverity[high] = %d, want 2", d.AnomaliesDetected.BySeverity["high"])
	}
	if d.AnomaliesDetected.BySeverity["critical"] != 1 {
		t.Errorf("BySeverity[critical] = %d, want 1", d.AnomaliesDetected.BySeverity["critical"])
	}
	// By protocol: 2 http + 1 mcp
	if d.AnomaliesDetected.ByProtocol["http"] != 2 {
		t.Errorf("ByProtocol[http] = %d, want 2", d.AnomaliesDetected.ByProtocol["http"])
	}
	if d.AnomaliesDetected.ByProtocol["mcp"] != 1 {
		t.Errorf("ByProtocol[mcp] = %d, want 1", d.AnomaliesDetected.ByProtocol["mcp"])
	}
	// IOCsBlocked.ByFramework: GDPR:2, HIPAA:1
	if d.IOCsBlocked.ByFramework["GDPR"] != 2 {
		t.Errorf("ByFramework[GDPR] = %d, want 2", d.IOCsBlocked.ByFramework["GDPR"])
	}
	if d.IOCsBlocked.ByFramework["HIPAA"] != 1 {
		t.Errorf("ByFramework[HIPAA] = %d, want 1", d.IOCsBlocked.ByFramework["HIPAA"])
	}
	// IOCsBlocked.ByProtocol: http:2, mcp:1
	if d.IOCsBlocked.ByProtocol["http"] != 2 {
		t.Errorf("ByProtocol[http] = %d, want 2", d.IOCsBlocked.ByProtocol["http"])
	}
	if d.IOCsBlocked.ByProtocol["mcp"] != 1 {
		t.Errorf("ByProtocol[mcp] = %d, want 1", d.IOCsBlocked.ByProtocol["mcp"])
	}
}

func TestAuditLogSource_NilRing(t *testing.T) {
	src := NewAuditLogSource(nil)
	d, err := src.Collect(context.Background(), time.Now(), time.Now())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d.AnomaliesDetected == nil {
		t.Fatal("AnomaliesDetected is nil")
	}
	if d.AnomaliesDetected.Total != 0 {
		t.Errorf("Anomalies Total = %d, want 0", d.AnomaliesDetected.Total)
	}
}

func TestAuditLogSource_LowSeverityNotCountedAsAnomaly(t *testing.T) {
	now := time.Now().UTC()
	ring := newTestRingBuffer(
		logging.Event{
			Time:     now.Add(-1 * time.Minute),
			Type:     "response_scan",
			Severity: "low", // not an anomaly
		},
		logging.Event{
			Time:     now.Add(-2 * time.Minute),
			Type:     "response_scan",
			Severity: "info", // not an anomaly
		},
		logging.Event{
			Time:     now.Add(-3 * time.Minute),
			Type:     "response_scan",
			Severity: "high", // IS an anomaly
		},
	)
	src := NewAuditLogSource(ring)
	d, err := src.Collect(context.Background(), now.Add(-1*time.Hour), now)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d.AnomaliesDetected.Total != 1 {
		t.Errorf("Anomalies Total = %d, want 1 (only high)", d.AnomaliesDetected.Total)
	}
	// But the framework counts include ALL events
	if d.IOCsBlocked.ByFramework[""] != 3 {
		t.Errorf("ByFramework count = %d, want 3 (all events)", d.IOCsBlocked.ByFramework[""])
	}
}

// =====================================================================
// Merge logic (the bug fix in BuildDigest)
// =====================================================================

func TestMergeIOCSummary_Accumulates(t *testing.T) {
	// This is the bug that motivated the merge fix:
	// the IOC source sets Total + ByCategory, the
	// audit log source sets ByFramework + ByProtocol.
	// The merge must NOT clobber the Total.
	a := &IOCSummary{
		Total:       5,
		ByCategory:  map[string]int{"pi": 3, "sl": 2},
		ByFramework: map[string]int{},
		ByProtocol:  map[string]int{},
	}
	b := &IOCSummary{
		Total:       0,
		ByCategory:  map[string]int{},
		ByFramework: map[string]int{"GDPR": 10, "HIPAA": 2},
		ByProtocol:  map[string]int{"http": 8, "mcp": 4},
	}
	merged := mergeIOCSummary(a, b)
	if merged.Total != 5 {
		t.Errorf("merged.Total = %d, want 5 (sum)", merged.Total)
	}
	if merged.ByCategory["pi"] != 3 {
		t.Errorf("merged.ByCategory[pi] = %d, want 3", merged.ByCategory["pi"])
	}
	if merged.ByFramework["GDPR"] != 10 {
		t.Errorf("merged.ByFramework[GDPR] = %d, want 10", merged.ByFramework["GDPR"])
	}
	if merged.ByProtocol["http"] != 8 {
		t.Errorf("merged.ByProtocol[http] = %d, want 8", merged.ByProtocol["http"])
	}
}

func TestMergeIOCSummary_NilSafe(t *testing.T) {
	// a=nil, b=valid -> b
	b := &IOCSummary{Total: 5, ByCategory: map[string]int{"x": 1}}
	merged := mergeIOCSummary(nil, b)
	if merged.Total != 5 {
		t.Errorf("merged.Total = %d, want 5", merged.Total)
	}
	// a=valid, b=nil -> a
	a := &IOCSummary{Total: 3}
	merged = mergeIOCSummary(a, nil)
	if merged.Total != 3 {
		t.Errorf("merged.Total = %d, want 3", merged.Total)
	}
	// both nil -> empty
	merged = mergeIOCSummary(nil, nil)
	if merged == nil {
		t.Fatal("merged is nil; want non-nil empty IOCSummary")
	}
	if merged.Total != 0 {
		t.Errorf("merged.Total = %d, want 0", merged.Total)
	}
}

func TestMergeAnomalySummary_Accumulates(t *testing.T) {
	a := &AnomalySummary{
		Total:      3,
		ByProtocol: map[string]int{"http": 2, "mcp": 1},
		BySeverity: map[string]int{"high": 3},
	}
	b := &AnomalySummary{
		Total:      2,
		ByProtocol: map[string]int{"a2a": 2},
		BySeverity: map[string]int{"critical": 2},
	}
	merged := mergeAnomalySummary(a, b)
	if merged.Total != 5 {
		t.Errorf("Total = %d, want 5", merged.Total)
	}
	if merged.ByProtocol["http"] != 2 {
		t.Errorf("http = %d, want 2", merged.ByProtocol["http"])
	}
	if merged.ByProtocol["a2a"] != 2 {
		t.Errorf("a2a = %d, want 2", merged.ByProtocol["a2a"])
	}
	if merged.BySeverity["high"] != 3 {
		t.Errorf("high = %d, want 3", merged.BySeverity["high"])
	}
	if merged.BySeverity["critical"] != 2 {
		t.Errorf("critical = %d, want 2", merged.BySeverity["critical"])
	}
}

// =====================================================================
// End-to-end: BuildDigest with multiple sources
// =====================================================================

func TestBuildDigest_MergesMultipleSources(t *testing.T) {
	now := time.Now().UTC()
	store := newTestIOCStore(t,
		ioc.IOC{
			Fingerprint: fakeFingerprint("pi-1"),
			Type:        ioc.IOCTypePromptInjection,
			Severity:    ioc.SeverityHigh,
			FirstSeen:   now.Add(-1 * time.Hour),
		},
	)
	ring := newTestRingBuffer(
		logging.Event{
			Time:               now.Add(-30 * time.Minute),
			Type:               "response_scan",
			Severity:           "high",
			ComplianceFramework: "GDPR",
		},
	)
	sources := []Source{
		NewIOCSource(store),
		NewAuditLogSource(ring),
		NewPostureSource(nil),
	}
	d, err := BuildDigest(context.Background(), sources, BuilderOptions{
		Period: PeriodWeekly,
		Now:    now,
	})
	if err != nil {
		t.Fatalf("BuildDigest: %v", err)
	}
	// The IOC source contributed 1 IOC.
	if d.IOCsBlocked.Total != 1 {
		t.Errorf("IOCsBlocked.Total = %d, want 1", d.IOCsBlocked.Total)
	}
	if d.IOCsBlocked.ByCategory["prompt_injection"] != 1 {
		t.Errorf("ByCategory[prompt_injection] = %d, want 1", d.IOCsBlocked.ByCategory["prompt_injection"])
	}
	// The audit log source contributed the framework
	// and protocol breakdowns.
	if d.IOCsBlocked.ByFramework["GDPR"] != 1 {
		t.Errorf("ByFramework[GDPR] = %d, want 1", d.IOCsBlocked.ByFramework["GDPR"])
	}
	if d.IOCsBlocked.ByProtocol["http"] != 1 {
		t.Errorf("ByProtocol[http] = %d, want 1", d.IOCsBlocked.ByProtocol["http"])
	}
	// The audit log source contributed the anomaly
	// count.
	if d.AnomaliesDetected.Total != 1 {
		t.Errorf("Anomalies.Total = %d, want 1", d.AnomaliesDetected.Total)
	}
	if d.OverallStatus != "yellow" {
		t.Errorf("OverallStatus = %q, want yellow (1 IOC, 1 anomaly)", d.OverallStatus)
	}
}

// silence unused import warning for "strings" if all
// helpers are moved
var _ = strings.Contains
