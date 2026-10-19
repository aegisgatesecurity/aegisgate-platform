// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Digest Phase 1b coverage tests
//
// digest_phase1b_test.go targets the uncovered paths in
// pkg/digest to push coverage from 84.1% to 90%+.
//
// Uncovered functions targeted:
//  1. mergeInto (75.0%) — nil partial, TopSources, TopThreats
//  2. mergeAnomalySummary (79.2%) — nil a, nil b, both nil
//  3. computeOverallStatus (81.8%) — critical, warning, healthy
//  4. generateDigestID (75.0%) — format and length
//  5. hashSHA256HexShort (80.0%) — empty and normal strings
//  6. buildPDFSections (75.0%) — nil data, with frameworks
//  7. SignDigest (80.0%) — invalid digest path
//  8. VerifyDigest (80.0%) — invalid sig, no digest, unmarshal error
//  9. PostureSource.Collect (22.2%) — real checker + error path
//  10. AuditSource.Collect (28.6%) — non-nil dispatcher

package digest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/audit"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/posture"
)

// =====================================================================
// mergeInto
// =====================================================================

// TestPhase1bMergeInto_NilPartial verifies that merging a nil
// partial leaves the merged digest unchanged.
func TestPhase1bMergeInto_NilPartial(t *testing.T) {
	merged := &Digest{
		ID:            "merged-1",
		OverallStatus: "green",
		Posture:       &PostureSummary{Overall: "green"},
	}
	mergeInto(merged, nil)
	if merged.ID != "merged-1" {
		t.Errorf("ID changed: %q", merged.ID)
	}
	if merged.OverallStatus != "green" {
		t.Errorf("OverallStatus changed: %q", merged.OverallStatus)
	}
	if merged.Posture == nil || merged.Posture.Overall != "green" {
		t.Errorf("Posture changed")
	}
}

// TestPhase1bMergeInto_TopSourcesAndThreats covers the TopSources
// and TopThreats assignment branches in mergeInto.
func TestPhase1bMergeInto_TopSourcesAndThreats(t *testing.T) {
	merged := &Digest{}
	partial := &Digest{
		TopSources: []SourceSummary{
			{Source: "src-1", EventCount: 100, ThreatCount: 5},
			{Source: "src-2", EventCount: 50, ThreatCount: 2},
		},
		TopThreats: []ThreatSummary{
			{ThreatType: "prompt_injection", EventCount: 30, Severity: "high"},
			{ThreatType: "data_exfil", EventCount: 10, Severity: "critical"},
		},
	}
	mergeInto(merged, partial)
	if len(merged.TopSources) != 2 {
		t.Errorf("TopSources len = %d, want 2", len(merged.TopSources))
	}
	if merged.TopSources[0].Source != "src-1" {
		t.Errorf("TopSources[0].Source = %q, want src-1", merged.TopSources[0].Source)
	}
	if len(merged.TopThreats) != 2 {
		t.Errorf("TopThreats len = %d, want 2", len(merged.TopThreats))
	}
	if merged.TopThreats[0].ThreatType != "prompt_injection" {
		t.Errorf("TopThreats[0].ThreatType = %q, want prompt_injection", merged.TopThreats[0].ThreatType)
	}
}

// TestPhase1bMergeInto_PostureAndIOCs covers the Posture and
// IOCsBlocked merge branches in mergeInto.
func TestPhase1bMergeInto_PostureAndIOCs(t *testing.T) {
	merged := &Digest{}
	partial := &Digest{
		Posture: &PostureSummary{
			Overall: "yellow",
			Uptime:  "5d",
		},
		IOCsBlocked: &IOCSummary{
			Total:      10,
			ByCategory: map[string]int{"phishing": 5, "malware": 5},
		},
		AnomaliesDetected: &AnomalySummary{
			Total:      3,
			BySeverity: map[string]int{"high": 2, "critical": 1},
		},
	}
	mergeInto(merged, partial)
	if merged.Posture == nil || merged.Posture.Overall != "yellow" {
		t.Errorf("Posture not merged correctly")
	}
	if merged.IOCsBlocked == nil || merged.IOCsBlocked.Total != 10 {
		t.Errorf("IOCsBlocked not merged correctly")
	}
	if merged.AnomaliesDetected == nil || merged.AnomaliesDetected.Total != 3 {
		t.Errorf("AnomaliesDetected not merged correctly")
	}
}

// TestPhase1bMergeInto_EmptyTopSourcesNotCopied verifies that
// empty (but non-nil) TopSources slices are NOT copied (the
// mergeInto check is len > 0, not != nil).
func TestPhase1bMergeInto_EmptyTopSourcesNotCopied(t *testing.T) {
	merged := &Digest{
		TopSources: []SourceSummary{{Source: "existing", EventCount: 1}},
	}
	partial := &Digest{
		TopSources: []SourceSummary{},
		TopThreats: []ThreatSummary{},
	}
	mergeInto(merged, partial)
	if len(merged.TopSources) != 1 {
		t.Errorf("TopSources should be unchanged (len=%d), want 1", len(merged.TopSources))
	}
	if merged.TopSources[0].Source != "existing" {
		t.Errorf("TopSources[0].Source = %q, want existing", merged.TopSources[0].Source)
	}
}

// =====================================================================
// mergeAnomalySummary
// =====================================================================

// TestPhase1bMergeAnomalySummary_NilCases covers the nil-a,
// nil-b, and both-nil paths in mergeAnomalySummary.
func TestPhase1bMergeAnomalySummary_NilCases(t *testing.T) {
	// Case 1: both nil → empty AnomalySummary with initialized maps.
	merged := mergeAnomalySummary(nil, nil)
	if merged == nil {
		t.Fatal("mergeAnomalySummary(nil, nil) returned nil")
	}
	if merged.Total != 0 {
		t.Errorf("Total = %d, want 0", merged.Total)
	}
	if merged.ByProtocol == nil {
		t.Error("ByProtocol should be initialized")
	}
	if merged.BySeverity == nil {
		t.Error("BySeverity should be initialized")
	}

	// Case 2: a=nil, b=valid → copy of b with initialized maps.
	b := &AnomalySummary{
		Total:      5,
		ByProtocol: map[string]int{"http": 3},
		BySeverity: map[string]int{"high": 5},
	}
	merged = mergeAnomalySummary(nil, b)
	if merged.Total != 5 {
		t.Errorf("Total = %d, want 5", merged.Total)
	}
	if merged.ByProtocol["http"] != 3 {
		t.Errorf("ByProtocol[http] = %d, want 3", merged.ByProtocol["http"])
	}
	if merged.BySeverity["high"] != 5 {
		t.Errorf("BySeverity[high] = %d, want 5", merged.BySeverity["high"])
	}

	// Case 3: a=valid, b=nil → copy of a with initialized ByProtocol.
	a := &AnomalySummary{
		Total:      7,
		ByProtocol: map[string]int{"mcp": 4},
		BySeverity: map[string]int{"critical": 7},
	}
	merged = mergeAnomalySummary(a, nil)
	if merged.Total != 7 {
		t.Errorf("Total = %d, want 7", merged.Total)
	}
	if merged.ByProtocol["mcp"] != 4 {
		t.Errorf("ByProtocol[mcp] = %d, want 4", merged.ByProtocol["mcp"])
	}
	if merged.BySeverity["critical"] != 7 {
		t.Errorf("BySeverity[critical] = %d, want 7", merged.BySeverity["critical"])
	}
	if merged.ByProtocol == nil {
		t.Error("ByProtocol should be initialized (b=nil path)")
	}
}

// TestPhase1bMergeAnomalySummary_WithNilMaps covers the case
// where one side has nil maps that need initialization.
func TestPhase1bMergeAnomalySummary_BWithNilMaps(t *testing.T) {
	b := &AnomalySummary{Total: 3} // maps are nil
	merged := mergeAnomalySummary(nil, b)
	if merged.ByProtocol == nil {
		t.Error("ByProtocol should be initialized when b has nil maps")
	}
	if merged.BySeverity == nil {
		t.Error("BySeverity should be initialized when b has nil maps")
	}
}

// =====================================================================
// computeOverallStatus
// =====================================================================

// TestPhase1bComputeOverallStatus_CriticalPosture covers the
// "critical" case (maps to "red").
func TestPhase1bComputeOverallStatus_CriticalPosture(t *testing.T) {
	d := &Digest{
		Posture: &PostureSummary{Overall: "critical"},
	}
	if got := computeOverallStatus(d); got != "red" {
		t.Errorf("computeOverallStatus(critical) = %q, want red", got)
	}
}

// TestPhase1bComputeOverallStatus_WarningPosture covers the
// "warning" case (maps to "yellow").
func TestPhase1bComputeOverallStatus_WarningPosture(t *testing.T) {
	d := &Digest{
		Posture: &PostureSummary{Overall: "warning"},
	}
	if got := computeOverallStatus(d); got != "yellow" {
		t.Errorf("computeOverallStatus(warning) = %q, want yellow", got)
	}
}

// TestPhase1bComputeOverallStatus_YellowPosture covers the
// "yellow" case (maps to "yellow").
func TestPhase1bComputeOverallStatus_YellowPosture(t *testing.T) {
	d := &Digest{
		Posture: &PostureSummary{Overall: "yellow"},
	}
	if got := computeOverallStatus(d); got != "yellow" {
		t.Errorf("computeOverallStatus(yellow) = %q, want yellow", got)
	}
}

// TestPhase1bComputeOverallStatus_HealthyPostureWithAnomalies
// covers the "healthy" case which falls through to anomaly
// checking.
func TestPhase1bComputeOverallStatus_HealthyPostureWithAnomalies(t *testing.T) {
	d := &Digest{
		Posture:           &PostureSummary{Overall: "healthy"},
		AnomaliesDetected: &AnomalySummary{Total: 5},
	}
	if got := computeOverallStatus(d); got != "yellow" {
		t.Errorf("computeOverallStatus(healthy + anomalies) = %q, want yellow", got)
	}
}

// TestPhase1bComputeOverallStatus_HealthyPostureClean covers
// the "healthy" case with no anomalies or IOCs.
func TestPhase1bComputeOverallStatus_HealthyPostureClean(t *testing.T) {
	d := &Digest{
		Posture: &PostureSummary{Overall: "healthy"},
	}
	if got := computeOverallStatus(d); got != "green" {
		t.Errorf("computeOverallStatus(healthy, clean) = %q, want green", got)
	}
}

// TestPhase1bComputeOverallStatus_NoPostureWithIOCs covers
// the path where posture is nil but IOCs are present.
func TestPhase1bComputeOverallStatus_NoPostureWithIOCs(t *testing.T) {
	d := &Digest{
		IOCsBlocked: &IOCSummary{Total: 42},
	}
	if got := computeOverallStatus(d); got != "yellow" {
		t.Errorf("computeOverallStatus(no posture, IOCs) = %q, want yellow", got)
	}
}

// TestPhase1bComputeOverallStatus_GreenPostureWithIOCs covers
// the fallthrough from "green" posture to IOC checking.
func TestPhase1bComputeOverallStatus_GreenPostureWithIOCs(t *testing.T) {
	d := &Digest{
		Posture:     &PostureSummary{Overall: "green"},
		IOCsBlocked: &IOCSummary{Total: 1},
	}
	if got := computeOverallStatus(d); got != "yellow" {
		t.Errorf("computeOverallStatus(green + IOCs) = %q, want yellow", got)
	}
}

// TestPhase1bComputeOverallStatus_UnknownPosture covers the
// default fallthrough for an unrecognized posture status.
func TestPhase1bComputeOverallStatus_UnknownPosture(t *testing.T) {
	d := &Digest{
		Posture: &PostureSummary{Overall: "unknown"},
	}
	if got := computeOverallStatus(d); got != "green" {
		t.Errorf("computeOverallStatus(unknown posture, no data) = %q, want green", got)
	}
}

// TestPhase1bComputeOverallStatus_EmptyDigest covers the case
// where the digest has no posture, no anomalies, no IOCs.
func TestPhase1bComputeOverallStatus_EmptyDigest(t *testing.T) {
	d := &Digest{}
	if got := computeOverallStatus(d); got != "green" {
		t.Errorf("computeOverallStatus(empty) = %q, want green", got)
	}
}

// =====================================================================
// generateDigestID
// =====================================================================

// TestPhase1bGenerateDigestID_Format verifies the ID format
// (prefix "digest-" + 16 hex chars).
func TestPhase1bGenerateDigestID_Format(t *testing.T) {
	id := generateDigestID()
	if !strings.HasPrefix(id, "digest-") {
		t.Errorf("ID = %q, want prefix 'digest-'", id)
	}
	hexPart := strings.TrimPrefix(id, "digest-")
	if len(hexPart) != 16 {
		t.Errorf("hex part length = %d, want 16", len(hexPart))
	}
	for _, c := range hexPart {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("hex part contains non-hex char %q in %q", c, hexPart)
		}
	}
}

// TestPhase1bGenerateDigestID_Uniqueness verifies that multiple
// calls produce unique IDs.
func TestPhase1bGenerateDigestID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateDigestID()
		if ids[id] {
			t.Errorf("Duplicate ID generated: %q", id)
		}
		ids[id] = true
	}
}

// =====================================================================
// hashSHA256HexShort
// =====================================================================

// TestPhase1bHashSHA256HexShort_EmptyString verifies hashing
// of an empty string.
func TestPhase1bHashSHA256HexShort_EmptyString(t *testing.T) {
	got := hashSHA256HexShort("")
	if len(got) != 16 {
		t.Errorf("len = %d, want 16", len(got))
	}
	// SHA-256 of empty string is well-known:
	// e3b0c44298fc1c149afbf4c8996fb924...
	want := "e3b0c44298fc1c14"
	if got != want {
		t.Errorf("hashSHA256HexShort('') = %q, want %q", got, want)
	}
}

// TestPhase1bHashSHA256HexShort_NormalString verifies hashing
// of a normal string.
func TestPhase1bHashSHA256HexShort_NormalString(t *testing.T) {
	got := hashSHA256HexShort("hello world")
	if len(got) != 16 {
		t.Errorf("len = %d, want 16", len(got))
	}
	// SHA-256("hello world") = b94d27b9934d3e08a52e52d7da7dabfa...
	want := "b94d27b9934d3e08"
	if got != want {
		t.Errorf("hashSHA256HexShort('hello world') = %q, want %q", got, want)
	}
}

// TestPhase1bHashSHA256HexShort_Deterministic verifies that
// the same input always produces the same output.
func TestPhase1bHashSHA256HexShort_Deterministic(t *testing.T) {
	a := hashSHA256HexShort("test-input")
	b := hashSHA256HexShort("test-input")
	if a != b {
		t.Errorf("Non-deterministic: %q vs %q", a, b)
	}
}

// TestPhase1bHashSHA256HexShort_DifferentInputs verifies that
// different inputs produce different outputs.
func TestPhase1bHashSHA256HexShort_DifferentInputs(t *testing.T) {
	a := hashSHA256HexShort("input-a")
	b := hashSHA256HexShort("input-b")
	if a == b {
		t.Errorf("Different inputs produced same hash: %q", a)
	}
}

// =====================================================================
// hexEncode
// =====================================================================

// TestPhase1bHexEncode verifies the hexEncode helper.
func TestPhase1bHexEncode(t *testing.T) {
	// Empty input.
	if got := hexEncode([]byte{}); got != "" {
		t.Errorf("hexEncode([]byte{}) = %q, want empty", got)
	}
	// Known value: {0x00, 0xff} → "00ff"
	got := hexEncode([]byte{0x00, 0xff})
	if got != "00ff" {
		t.Errorf("hexEncode([0x00, 0xff]) = %q, want 00ff", got)
	}
	// All nibbles: {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	got = hexEncode([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	if got != "0123456789abcdef" {
		t.Errorf("hexEncode(all nibbles) = %q, want 0123456789abcdef", got)
	}
}

// =====================================================================
// buildPDFSections
// =====================================================================

// TestPhase1bBuildPDFSections_AllNilData covers the paths where
// IOCsBlocked, AnomaliesDetected, and Posture are all nil.
func TestPhase1bBuildPDFSections_AllNilData(t *testing.T) {
	d := &Digest{
		ID:            "test-nil",
		Period:        PeriodWeekly,
		StartTime:     time.Now().Add(-7 * 24 * time.Hour),
		EndTime:       time.Now(),
		GeneratedAt:   time.Now(),
		OverallStatus: "green",
	}
	sections := buildPDFSections(d)
	if len(sections) == 0 {
		t.Fatal("Expected non-empty sections")
	}
	// Verify that the "No IOC data available" paragraph is present.
	foundNoIOC := false
	foundNoAnomaly := false
	foundNoPosture := false
	for _, s := range sections {
		if s.Text == "No IOC data available." {
			foundNoIOC = true
		}
		if s.Text == "No anomaly data available." {
			foundNoAnomaly = true
		}
		if s.Text == "No posture data available." {
			foundNoPosture = true
		}
	}
	if !foundNoIOC {
		t.Error("Expected 'No IOC data available.' paragraph")
	}
	if !foundNoAnomaly {
		t.Error("Expected 'No anomaly data available.' paragraph")
	}
	if !foundNoPosture {
		t.Error("Expected 'No posture data available.' paragraph")
	}
}

// TestPhase1bBuildPDFSections_WithPostureAndFrameworks covers
// the posture path with compliance frameworks and uptime.
func TestPhase1bBuildPDFSections_WithPostureAndFrameworks(t *testing.T) {
	d := &Digest{
		ID:            "test-posture",
		Period:        PeriodWeekly,
		StartTime:     time.Now().Add(-7 * 24 * time.Hour),
		EndTime:       time.Now(),
		GeneratedAt:   time.Now(),
		OverallStatus: "green",
		Posture: &PostureSummary{
			Overall: "green",
			Uptime:  "30d 0h 0m",
			ComplianceFrameworks: []ComplianceFrameworkStatus{
				{Framework: "soc2", DisplayName: "SOC 2", Enforced: true, HasImplementation: true},
				{Framework: "hipaa", DisplayName: "HIPAA", Enforced: true, HasImplementation: false},
			},
		},
	}
	sections := buildPDFSections(d)
	// Verify the uptime paragraph is present.
	foundUptime := false
	foundOverall := false
	for _, s := range sections {
		if strings.Contains(s.Text, "Uptime:") && strings.Contains(s.Text, "30d") {
			foundUptime = true
		}
		if strings.Contains(s.Text, "Overall:") && strings.Contains(s.Text, "green") {
			foundOverall = true
		}
	}
	if !foundUptime {
		t.Error("Expected uptime paragraph")
	}
	if !foundOverall {
		t.Error("Expected overall posture paragraph")
	}
	// Verify there's at least one table section (for compliance frameworks).
	foundTable := false
	for _, s := range sections {
		if len(s.Table.Rows) > 0 {
			foundTable = true
			break
		}
	}
	if !foundTable {
		t.Error("Expected at least one table section for compliance frameworks")
	}
}

// TestPhase1bBuildPDFSections_WithIOCAndAnomalyMaps covers the
// paths where IOC and anomaly maps are populated (triggering
// table generation).
func TestPhase1bBuildPDFSections_WithIOCAndAnomalyMaps(t *testing.T) {
	d := &Digest{
		ID:            "test-maps",
		Period:        PeriodWeekly,
		StartTime:     time.Now().Add(-7 * 24 * time.Hour),
		EndTime:       time.Now(),
		GeneratedAt:   time.Now(),
		OverallStatus: "yellow",
		IOCsBlocked: &IOCSummary{
			Total:       10,
			ByCategory:  map[string]int{"phishing": 5, "malware": 5},
			ByFramework: map[string]int{"GDPR": 8, "HIPAA": 2},
			ByProtocol:  map[string]int{"http": 7, "mcp": 3},
		},
		AnomaliesDetected: &AnomalySummary{
			Total:      4,
			ByProtocol: map[string]int{"http": 3, "a2a": 1},
			BySeverity: map[string]int{"high": 3, "critical": 1},
		},
	}
	sections := buildPDFSections(d)
	// Verify IOC total paragraph is present.
	foundIOCTotal := false
	foundAnomalyTotal := false
	for _, s := range sections {
		if strings.Contains(s.Text, "10 IOCs blocked") {
			foundIOCTotal = true
		}
		if strings.Contains(s.Text, "4 anomalies detected") {
			foundAnomalyTotal = true
		}
	}
	if !foundIOCTotal {
		t.Error("Expected IOC total paragraph")
	}
	if !foundAnomalyTotal {
		t.Error("Expected anomaly total paragraph")
	}
	// Verify multiple table sections are generated (ByCategory, ByFramework,
	// ByProtocol, ByProtocol for anomalies, BySeverity).
	tableCount := 0
	for _, s := range sections {
		if len(s.Table.Rows) > 0 {
			tableCount++
		}
	}
	if tableCount < 5 {
		t.Errorf("Expected at least 5 table sections, got %d", tableCount)
	}
}

// TestPhase1bBuildPDFSections_NoRegulatorMappings covers the
// path where RegulatorMappings is empty (no regulator section).
func TestPhase1bBuildPDFSections_NoRegulatorMappings(t *testing.T) {
	d := &Digest{
		ID:            "test-no-reg",
		Period:        PeriodWeekly,
		StartTime:     time.Now().Add(-7 * 24 * time.Hour),
		EndTime:       time.Now(),
		GeneratedAt:   time.Now(),
		OverallStatus: "green",
	}
	sections := buildPDFSections(d)
	// Verify no "Regulator Mappings" heading is present.
	for _, s := range sections {
		if s.Text == "Regulator Mappings" {
			t.Error("Should not have Regulator Mappings heading when empty")
		}
	}
}

// TestPhase1bBuildPDFSections_WithRegulatorMappings covers the
// path where RegulatorMappings is populated.
func TestPhase1bBuildPDFSections_WithRegulatorMappings(t *testing.T) {
	d := &Digest{
		ID:            "test-reg",
		Period:        PeriodWeekly,
		StartTime:     time.Now().Add(-7 * 24 * time.Hour),
		EndTime:       time.Now(),
		GeneratedAt:   time.Now(),
		OverallStatus: "green",
		RegulatorMappings: []RegulatorMapping{
			{Framework: "soc2", ControlID: "CC7.2", ControlName: "Monitoring", AegisGateFeature: "IOC blocking"},
			{Framework: "hipaa", ControlID: "164.312(b)", ControlName: "Audit controls", AegisGateFeature: "Audit logging"},
		},
	}
	sections := buildPDFSections(d)
	foundRegHeading := false
	for _, s := range sections {
		if s.Text == "Regulator Mappings" {
			foundRegHeading = true
		}
	}
	if !foundRegHeading {
		t.Error("Expected 'Regulator Mappings' heading")
	}
}

// =====================================================================
// SignDigest
// =====================================================================

// TestPhase1bSignDigest_InvalidDigest covers the path where
// the digest fails validation (RenderDigestPDF returns an error).
func TestPhase1bSignDigest_InvalidDigest(t *testing.T) {
	kr := makeTestKeyRing(t)
	d := &Digest{} // invalid: no Period, no StartTime, no EndTime
	_, err := SignDigest(d, kr)
	if err == nil {
		t.Errorf("SignDigest with invalid digest should fail")
	}
	if !strings.Contains(err.Error(), "validate") {
		t.Errorf("Error should mention validation, got: %v", err)
	}
}

// TestPhase1bSignDigest_ValidWithPosture covers signing a
// fully-populated digest including posture with compliance
// frameworks.
func TestPhase1bSignDigest_ValidWithPosture(t *testing.T) {
	kr := makeTestKeyRing(t)
	d := &Digest{
		ID:            "phase1b-sign-1",
		Period:        PeriodWeekly,
		StartTime:     time.Now().Add(-7 * 24 * time.Hour),
		EndTime:       time.Now(),
		GeneratedAt:   time.Now(),
		Title:         "Phase 1b Sign Test",
		OverallStatus: "green",
		Posture: &PostureSummary{
			Overall: "green",
			Uptime:  "5d",
			ComplianceFrameworks: []ComplianceFrameworkStatus{
				{Framework: "soc2", DisplayName: "SOC 2", Enforced: true, HasImplementation: true},
			},
		},
		IOCsBlocked: &IOCSummary{
			Total:       5,
			ByCategory:  map[string]int{"pi": 3, "sl": 2},
			ByFramework: map[string]int{"GDPR": 5},
			ByProtocol:  map[string]int{"http": 5},
		},
		AnomaliesDetected: &AnomalySummary{
			Total:      2,
			ByProtocol: map[string]int{"http": 2},
			BySeverity: map[string]int{"high": 2},
		},
		RegulatorMappings: []RegulatorMapping{
			{Framework: "soc2", ControlID: "CC7.2", ControlName: "Monitoring", AegisGateFeature: "IOC blocking"},
		},
	}
	env, err := SignDigest(d, kr)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if env.Type != attestation.TypeDigest {
		t.Errorf("Type = %q, want %q", env.Type, attestation.TypeDigest)
	}
	if !strings.HasPrefix(env.Subject, "aegisgate://digest/") {
		t.Errorf("Subject = %q, want prefix", env.Subject)
	}
	// Verify the roundtrip works.
	verified, pdfBytes, err := VerifyDigest(env)
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if verified.ID != d.ID {
		t.Errorf("Verified ID = %q, want %q", verified.ID, d.ID)
	}
	if len(pdfBytes) == 0 {
		t.Error("PDF bytes should be non-empty")
	}
}

// =====================================================================
// VerifyDigest
// =====================================================================

// TestPhase1bVerifyDigest_InvalidSignature covers the path
// where the envelope's signature is invalid (corrupted).
func TestPhase1bVerifyDigest_InvalidSignature(t *testing.T) {
	kr := makeTestKeyRing(t)
	env, err := attestation.Sign(
		[]byte(`{"digest":{"id":"test"},"pdf_bytes":[]}`),
		"aegisgate://digest/test",
		attestation.TypeDigest,
		"digest:shortfp:"+hashSHA256HexShort("test")+":"+kr.CurrentKeyID(),
		kr,
		0,
	)
	if err != nil {
		t.Fatalf("attestation.Sign: %v", err)
	}
	// Corrupt the signature value.
	if len(env.Signature.Value) > 0 {
		env.Signature.Value[0] ^= 0xFF
	} else {
		env.Signature.Value = []byte{0x00, 0x01, 0x02}
	}
	_, _, err = VerifyDigest(env)
	if err == nil {
		t.Errorf("VerifyDigest with corrupted signature should fail")
	}
}

// TestPhase1bVerifyDigest_NoDigestInPayload covers the path
// where the envelope verifies but the payload doesn't contain
// a digest (ErrDigestNotFound).
func TestPhase1bVerifyDigest_NoDigestInPayload(t *testing.T) {
	kr := makeTestKeyRing(t)
	// Sign an empty JSON object — no "digest" field.
	env, err := attestation.Sign(
		[]byte(`{}`),
		"aegisgate://digest/empty",
		attestation.TypeDigest,
		"digest:shortfp:"+hashSHA256HexShort("empty")+":"+kr.CurrentKeyID(),
		kr,
		0,
	)
	if err != nil {
		t.Fatalf("attestation.Sign: %v", err)
	}
	_, _, err = VerifyDigest(env)
	if err == nil {
		t.Errorf("VerifyDigest should fail when payload has no digest")
	}
	if !errors.Is(err, ErrDigestNotFound) {
		t.Errorf("Expected ErrDigestNotFound, got: %v", err)
	}
}

// TestPhase1bVerifyDigest_UnmarshalError covers the path where
// the envelope verifies and the payload is valid JSON, but the
// "digest" field has an incompatible type (causes unmarshal error).
func TestPhase1bVerifyDigest_UnmarshalError(t *testing.T) {
	kr := makeTestKeyRing(t)
	// Sign a JSON object with "digest" as a string (not a struct).
	env, err := attestation.Sign(
		[]byte(`{"digest":"not-a-digest","pdf_bytes":[]}`),
		"aegisgate://digest/badtype",
		attestation.TypeDigest,
		"digest:shortfp:"+hashSHA256HexShort("badtype")+":"+kr.CurrentKeyID(),
		kr,
		0,
	)
	if err != nil {
		t.Fatalf("attestation.Sign: %v", err)
	}
	_, _, err = VerifyDigest(env)
	if err == nil {
		t.Errorf("VerifyDigest should fail when payload has incompatible types")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("Error should mention unmarshal, got: %v", err)
	}
}

// =====================================================================
// PostureSource.Collect (22.2% → target 90%+)
// =====================================================================

// TestPhase1bPostureSource_Collect_WithChecker covers the happy
// path where a real posture.Checker is used. This exercises the
// checker.Check → Report → PostureSummary conversion including
// the compliance frameworks loop.
func TestPhase1bPostureSource_Collect_WithChecker(t *testing.T) {
	checker := posture.NewChecker(posture.Deps{
		Version:   "v0.1-test",
		StartTime: time.Now().Add(-1 * time.Hour),
	})
	src := NewPostureSource(checker)
	d, err := src.Collect(context.Background(), time.Now().Add(-7*24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d == nil {
		t.Fatal("Collect returned nil Digest")
	}
	if d.Posture == nil {
		t.Fatal("Posture should be non-nil")
	}
	// The checker with no license should produce "unknown" or
	// "degraded" overall (depends on compliance gating).
	if d.Posture.Overall == "" {
		t.Error("Posture.Overall should not be empty")
	}
	// Uptime should be populated since StartTime was set.
	if d.Posture.Uptime == "" {
		t.Error("Posture.Uptime should be non-empty (StartTime was set)")
	}
	// Compliance frameworks should be populated (the checker
	// evaluates all known frameworks).
	if len(d.Posture.ComplianceFrameworks) == 0 {
		t.Error("ComplianceFrameworks should be non-empty")
	}
	// Verify the first framework has expected fields.
	fw := d.Posture.ComplianceFrameworks[0]
	if fw.Framework == "" {
		t.Error("First framework should have a non-empty Framework")
	}
	if fw.DisplayName == "" {
		t.Error("First framework should have a non-empty DisplayName")
	}
}

// TestPhase1bPostureSource_Collect_CheckError covers the error
// path where checker.Check returns an error (cancelled context).
func TestPhase1bPostureSource_Collect_CheckError(t *testing.T) {
	checker := posture.NewChecker(posture.Deps{})
	src := NewPostureSource(checker)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to trigger ctx.Err()
	_, err := src.Collect(ctx, time.Now(), time.Now())
	if err == nil {
		t.Errorf("Collect with cancelled context should fail")
	}
	if !strings.Contains(err.Error(), "posture") {
		t.Errorf("Error should mention posture, got: %v", err)
	}
}

// =====================================================================
// AuditSource.Collect (28.6% → target 90%+)
// =====================================================================

// TestPhase1bAuditSource_Collect_WithDispatcher covers the path
// where the dispatcher is non-nil (the community edition
// SIEMDispatcher is a zero-field struct that can be instantiated
// directly).
func TestPhase1bAuditSource_Collect_WithDispatcher(t *testing.T) {
	disp := &audit.SIEMDispatcher{}
	src := NewAuditSource(disp)
	d, err := src.Collect(context.Background(), time.Now(), time.Now())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d == nil {
		t.Fatal("Collect returned nil Digest")
	}
	// v0.2: AuditSource.Collect returns an empty Digest even
	// with a non-nil dispatcher (the heavy lifting is in
	// AuditLogSource).
	if d.IOCsBlocked != nil {
		t.Errorf("IOCsBlocked should be nil, got %+v", d.IOCsBlocked)
	}
	if d.AnomaliesDetected != nil {
		t.Errorf("AnomaliesDetected should be nil, got %+v", d.AnomaliesDetected)
	}
}

// =====================================================================
// ShortFingerprint (uses hashSHA256HexShort)
// =====================================================================

// TestPhase1bShortFingerprint verifies the shortFingerprint
// helper produces 16-char hex output.
func TestPhase1bShortFingerprint(t *testing.T) {
	fp := shortFingerprint("aegisgate://digest/test-1")
	if len(fp) != 16 {
		t.Errorf("len = %d, want 16", len(fp))
	}
	// Should be deterministic.
	fp2 := shortFingerprint("aegisgate://digest/test-1")
	if fp != fp2 {
		t.Errorf("Non-deterministic: %q vs %q", fp, fp2)
	}
	// Different inputs should produce different fingerprints.
	fp3 := shortFingerprint("aegisgate://digest/test-2")
	if fp == fp3 {
		t.Errorf("Different inputs produced same fingerprint: %q", fp)
	}
}
