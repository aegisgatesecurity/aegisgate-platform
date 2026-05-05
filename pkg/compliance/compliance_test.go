// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 AegisGate Security

package compliance

import (
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Tier Manager Tests
// ============================================================================

func TestTierManager_New(t *testing.T) {
	tm := NewTierManager()
	if tm == nil {
		t.Fatal("NewTierManager returned nil")
	}
}

func TestTierManager_SetAndGetTier(t *testing.T) {
	tm := NewTierManager()

	tm.SetTier(TierCommunity)
	if tm.GetTier() != TierCommunity {
		t.Error("GetTier mismatch for Community")
	}

	tm.SetTier(TierEnterprise)
	if tm.GetTier() != TierEnterprise {
		t.Error("GetTier mismatch for Enterprise")
	}

	tm.SetTier(TierPremium)
	if tm.GetTier() != TierPremium {
		t.Error("GetTier mismatch for Premium")
	}
}

func TestTierManager_IsFrameworkAllowed_Community(t *testing.T) {
	tm := NewTierManager()
	tm.SetTier(TierCommunity)

	if !tm.IsFrameworkAllowed("atlas") {
		t.Error("Community should allow atlas")
	}
}

func TestTierManager_IsFrameworkAllowed_Premium(t *testing.T) {
	tm := NewTierManager()
	tm.SetTier(TierPremium)

	if !tm.IsFrameworkAllowed("atlas") {
		t.Error("Premium should allow atlas")
	}
	if !tm.IsFrameworkAllowed("soc2") {
		t.Error("Premium should allow soc2")
	}
	if !tm.IsFrameworkAllowed("hipaa") {
		t.Error("Premium should allow hipaa")
	}
}

func TestTierManager_IsFrameworkAllowed_Unknown(t *testing.T) {
	tm := NewTierManager()

	if tm.IsFrameworkAllowed("unknown-framework") {
		t.Error("Unknown framework should return false")
	}
}

func TestTierManager_GetAllFrameworks(t *testing.T) {
	tm := NewTierManager()
	frameworks := tm.GetAllFrameworks()

	if len(frameworks) == 0 {
		t.Error("Expected at least one framework")
	}
}

func TestTierManager_GetCommunityFrameworks(t *testing.T) {
	tm := NewTierManager()
	frameworks := tm.GetCommunityFrameworks()

	if len(frameworks) == 0 {
		t.Error("Expected community frameworks")
	}
}

func TestTierManager_GetEnterpriseFrameworks(t *testing.T) {
	tm := NewTierManager()
	frameworks := tm.GetEnterpriseFrameworks()

	// May be empty but should not be nil
	if frameworks == nil {
		t.Error("Expected non-nil enterprise frameworks")
	}
}

func TestTierManager_GetPremiumFrameworks(t *testing.T) {
	tm := NewTierManager()
	frameworks := tm.GetPremiumFrameworks()

	// May be empty but should not be nil
	if frameworks == nil {
		t.Error("Expected non-nil premium frameworks")
	}
}

func TestTierManager_ValidateLicense(t *testing.T) {
	tm := NewTierManager()

	if !tm.ValidateLicense("", TierCommunity) {
		t.Error("Community tier should not require license")
	}

	if tm.ValidateLicense("", TierEnterprise) {
		t.Error("Enterprise tier requires license key")
	}
	if !tm.ValidateLicense("valid-key", TierEnterprise) {
		t.Error("Enterprise tier with valid key should pass")
	}
}

func TestTierManager_ConcurrentAccess(t *testing.T) {
	tm := NewTierManager()
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tm.SetTier(TierCommunity)
			tm.GetAllFrameworks()
			tm.IsFrameworkAllowed("atlas")
		}()
	}

	wg.Wait()
}

func TestTierManager_TierString(t *testing.T) {
	tm := NewTierManager()

	s := tm.GetTier().String()
	if s == "" {
		t.Error("Tier.String() should not return empty")
	}
}

func TestTierManager_RegisterFramework(t *testing.T) {
	tm := NewTierManager()

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "custom-fw",
		Name:        "Custom Framework",
		Tier:        TierCommunity,
		Description: "Custom test framework",
		Features:    []string{"test"},
	})

	if !tm.IsFrameworkAllowed("custom-fw") {
		t.Error("Custom framework should be registered")
	}
}

// ============================================================================
// Manager Tests
// ============================================================================

func TestNewManager_WithDefaults(t *testing.T) {
	mgr, err := NewManager(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
}

func TestManager_Check_NormalContent(t *testing.T) {
	mgr, err := NewManager(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	result, err := mgr.Check("normal request content", "inbound")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("Check returned nil result")
	}
}

func TestManager_Check_EmptyContent(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	result, err := mgr.Check("", "inbound")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("Check returned nil for empty content")
	}
}

func TestManager_Check_Direction(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	for _, dir := range []string{"inbound", "outbound", "internal"} {
		result, err := mgr.Check("test content", dir)
		if err != nil {
			t.Fatalf("Check with direction %q failed: %v", dir, err)
		}
		if result == nil {
			t.Fatalf("Check with direction %q returned nil", dir)
		}
	}
}

func TestManager_GenerateReport(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())
	mgr.Check("test", "inbound")

	report, err := mgr.GenerateReport()
	if err != nil {
		t.Fatal(err)
	}
	if report == "" {
		t.Error("Expected non-empty report")
	}
}

func TestManager_GetStatus(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	status := mgr.GetStatus()
	if status == nil {
		t.Error("GetStatus returned nil")
	}
}

func TestManager_ClearHistory(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	for i := 0; i < 5; i++ {
		mgr.Check("test", "inbound")
	}

	mgr.ClearHistory()
}

func TestManager_GetReportHistory(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())
	mgr.Check("test1", "inbound")
	mgr.Check("test2", "inbound")

	history := mgr.GetReportHistory(0)
	if history == nil {
		t.Error("GetReportHistory should not return nil")
	}
}

func TestManager_GetActiveFrameworks(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	frameworks := mgr.GetActiveFrameworks()
	if len(frameworks) < 1 {
		t.Error("Expected at least one active framework")
	}
}

func TestManager_DetectFrameworks(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	frameworks := mgr.DetectFrameworks("content mentioning AI and machine learning")
	if frameworks == nil {
		t.Error("DetectFrameworks returned nil")
	}
}

func TestManager_DetectFrameworks_Empty(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	// Empty content should not panic
	frameworks := mgr.DetectFrameworks("")
	_ = frameworks // May be nil or empty
}

func TestManager_CheckFramework_Atlas(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	result, err := mgr.CheckFramework("test content", FrameworkATLAS)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("CheckFramework returned nil")
	}
}

func TestManager_CheckFramework_NIST(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	// FAIL-CLOSED: NIST is an Enterprise-tier framework. With DefaultConfig()
	// (Community tier), it's not registered, so CheckFramework must return an error
	// rather than silently returning Passed=true.
	result, err := mgr.CheckFramework("test content", FrameworkNIST1500)
	if err == nil {
		t.Error("CheckFramework for unregistered NIST framework should return error (fail-closed)")
	}
	if result != nil && result.Passed {
		t.Error("unregistered framework should NOT return Passed=true (fail-closed)")
	}
}

func TestManager_ExportFindings_JSON(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())
	mgr.Check("test", "inbound")

	data, err := mgr.ExportFindings("json")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("ExportFindings returned empty data")
	}
}

func TestManager_ExportFindings_CSV(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())
	mgr.Check("test", "inbound")

	data, err := mgr.ExportFindings("csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("ExportFindings(csv) returned empty")
	}
}

func TestManager_Check_MultipleFrameworks(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	// FAIL-CLOSED: Only ATLAS is registered in Community tier (DefaultConfig).
	// NIST is Enterprise-tier and should fail (not silently pass).
	for _, fw := range []Framework{FrameworkATLAS} {
		result, err := mgr.CheckFramework("test", fw)
		if err != nil {
			t.Fatalf("CheckFramework(%v) failed: %v", fw, err)
		}
		if result == nil {
			t.Fatalf("CheckFramework(%v) returned nil", fw)
		}
	}

	// NIST is NOT registered in Community tier — must return error (fail-closed)
	_, err := mgr.CheckFramework("test", FrameworkNIST1500)
	if err == nil {
		t.Error("CheckFramework for unregistered NIST framework should return error (fail-closed)")
	}
}

func TestManager_Check_AllDirections(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	directions := []string{"inbound", "outbound", "internal"}
	for _, dir := range directions {
		result, err := mgr.Check("direction test", dir)
		if err != nil {
			t.Fatalf("Check with direction %q failed: %v", dir, err)
		}
		if result == nil {
			t.Fatalf("Check with direction %q returned nil", dir)
		}
	}
}

func TestManager_Check_LongContent(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	longContent := make([]byte, 10000)
	for i := range longContent {
		longContent[i] = 'x'
	}

	result, err := mgr.Check(string(longContent), "inbound")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("Check returned nil for long content")
	}
}

func TestManager_GetFindingsByTechnique(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())
	mgr.Check("test with T1001 technique", "inbound")

	findings := mgr.GetFindingsByTechnique("T1001")
	if findings != nil && len(findings) > 0 {
	}
}

func TestManager_GetFindingsBySeverity(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())
	mgr.Check("test content", "inbound")

	findings := mgr.GetFindingsBySeverity(SeverityHigh)
	if findings != nil && len(findings) > 0 {
	}
}

func TestManager_GetStatus_WithChecks(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())

	mgr.Check("test1", "inbound")
	mgr.Check("test2", "outbound")

	status := mgr.GetStatus()
	if status == nil {
		t.Fatal("GetStatus returned nil")
	}
	if len(status) == 0 {
		t.Error("Status should not be empty after checks")
	}
}

// ============================================================================
// Result/Finding/Pattern Tests
// ============================================================================

func TestResult_Fields(t *testing.T) {
	r := &Result{
		Passed:            true,
		Findings:          []Finding{},
		FrameworksChecked: []Framework{FrameworkATLAS},
		CheckedAt:         time.Now(),
		Duration:          50 * time.Millisecond,
	}

	if !r.Passed {
		t.Error("Expected Passed=true")
	}
}

func TestResult_WithFindings(t *testing.T) {
	r := &Result{
		Passed: false,
		Findings: []Finding{
			{ID: "F1", Framework: FrameworkATLAS, Technique: "T1001", Severity: SeverityHigh, Category: "cat1", Description: "desc1"},
		},
		FrameworksChecked: []Framework{FrameworkATLAS},
		CheckedAt:         time.Now(),
		Duration:          100 * time.Millisecond,
	}

	if r.Passed {
		t.Error("Expected Passed=false for result with findings")
	}
	if len(r.Findings) != 1 {
		t.Error("Expected 1 finding")
	}
}

func TestFinding_Fields(t *testing.T) {
	f := Finding{
		ID:          "TEST-001",
		Framework:   FrameworkATLAS,
		Technique:   "T1001",
		Severity:    SeverityHigh,
		Category:    "test-category",
		Description: "Test finding description",
		Timestamp:   time.Now(),
	}

	if f.ID != "TEST-001" {
		t.Error("ID mismatch")
	}
	if f.Framework != FrameworkATLAS {
		t.Error("Framework mismatch")
	}
}

func TestFramework_String(t *testing.T) {
	for _, fw := range []Framework{FrameworkATLAS, FrameworkNIST1500, FrameworkOWASP} {
		if fw.String() == "" {
			t.Errorf("Framework.String() returned empty for %v", fw)
		}
	}
}

func TestSeverity_String(t *testing.T) {
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if sev.String() == "" {
			t.Errorf("Severity.String() returned empty for %v", sev)
		}
	}
}

func TestCheckDuration(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())
	result, _ := mgr.Check("test", "inbound")

	if result.Duration < 0 {
		t.Error("Duration should be non-negative")
	}
}

// ============================================================================
// Config Tests
// ============================================================================

func TestConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.EnableAtlas != true {
		t.Error("ATLAS should be enabled by default")
	}
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestManager_ConcurrentChecks(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			content := "test content"
			if n%2 == 0 {
				content = "attack attempt"
			}
			mgr.Check(content, "inbound")
		}(i)
	}

	wg.Wait()
}

func TestManager_ConcurrentReports(t *testing.T) {
	mgr, _ := NewManager(DefaultConfig())
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.GenerateReport()
			mgr.GetStatus()
		}()
	}

	wg.Wait()
}

// ============================================================================
// ATLAS Framework Tests
// ============================================================================

func TestAtlasFramework_GetName(t *testing.T) {
	fw := NewATLASFramework(0)
	name := fw.GetName()
	if name == "" {
		t.Error("GetName should not return empty")
	}
}

func TestAtlasFramework_String(t *testing.T) {
	fw := NewATLASFramework(0)
	s := fw.String()
	if s == "" {
		t.Error("ATLAS String should not be empty")
	}
}
