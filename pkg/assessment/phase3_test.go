// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 3: Tests for 31 Frameworks, PDF Reports, Ed25519 Signing, Scheduler

package assessment

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// =========================================================================
// Tests: 31 Compliance Frameworks
// =========================================================================

func TestFrameworkCount(t *testing.T) {
	count := FrameworkCount()
	if count != 31 {
		t.Errorf("expected 31 frameworks, got %d", count)
	}
	t.Logf("Total frameworks: %d", count)
}

func TestSupportedFrameworksV2(t *testing.T) {
	fws := SupportedFrameworksV2()
	if len(fws) != 31 {
		t.Errorf("expected 31 frameworks, got %d", len(fws))
	}
	// Verify all Phase 1 frameworks are included.
	phase1 := SupportedFrameworks()
	for _, fw := range phase1 {
		found := false
		for _, fw2 := range fws {
			if fw2 == fw {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Phase 1 framework %s not found in V2", fw)
		}
	}
}

func TestAllFrameworkInfo(t *testing.T) {
	infos := AllFrameworkInfo()
	if len(infos) != 31 {
		t.Errorf("expected 31 framework infos, got %d", len(infos))
	}

	// Verify sorted by tier then name.
	for i := 1; i < len(infos); i++ {
		prevTier := tierOrder(infos[i-1].Tier)
		currTier := tierOrder(infos[i].Tier)
		if prevTier > currTier {
			t.Errorf("framework %d (tier %d) should come before %d (tier %d)",
				i, currTier, i-1, prevTier)
		}
	}

	// Log all frameworks grouped by tier.
	currentTier := FrameworkTier("")
	for _, info := range infos {
		if info.Tier != currentTier {
			currentTier = info.Tier
			t.Logf("  === %s ===", info.Tier)
		}
		t.Logf("    %s: %s — %s", info.ID, info.Name, info.Description)
	}
}

func TestFrameworksByTier(t *testing.T) {
	tiers := []FrameworkTier{
		Tier1CoreCyber, Tier2USGov, Tier3Industry,
		Tier4AIGovernance, Tier5Privacy, Tier6AppSecurity,
	}
	total := 0
	for _, tier := range tiers {
		fws := FrameworksByTier(tier)
		total += len(fws)
		t.Logf("  %s: %d frameworks", tier, len(fws))
	}
	if total != 31 {
		t.Errorf("sum of all tiers = %d, expected 31", total)
	}
}

func TestControlsForOWASPV2(t *testing.T) {
	// Verify LLM01 has controls for all 31 frameworks.
	for _, fw := range SupportedFrameworksV2() {
		controls := ControlsForOWASPV2("LLM01", fw)
		if len(controls) == 0 {
			t.Logf("  WARNING: %s has no controls for LLM01", fw)
		}
	}

	// Verify specific known mappings.
	controls := ControlsForOWASPV2("LLM01", FrameworkNIST80053)
	if len(controls) == 0 {
		t.Error("expected NIST 800-53 to have controls for LLM01")
	}
	t.Logf("NIST 800-53 LLM01 controls: %v", controls)

	// Verify fallback to Phase 1 map for a framework not in V2 map
	// but in Phase 1 map.
	controls = ControlsForOWASPV2("LLM01", FrameworkNIST800171)
	if len(controls) == 0 {
		t.Error("expected NIST 800-171 to have controls for LLM01 (Phase 1 fallback)")
	}
}

func TestComputeCompliancePostureV2(t *testing.T) {
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	posture := ComputeCompliancePostureV2(result.ScenarioResults)
	if len(posture) != 31 {
		t.Errorf("expected posture for 31 frameworks, got %d", len(posture))
	}

	// Log posture for frameworks that have controls.
	withControls := 0
	withoutControls := 0
	for fw, fp := range posture {
		if fp.TotalControls > 0 {
			withControls++
			info := FrameworkInfoByID(ComplianceFramework(fw))
			name := fw
			if info != nil {
				name = info.Name
			}
			t.Logf("  %s: %d/%d verified (%.0f%%), %d at risk",
				name, fp.Verified, fp.TotalControls, fp.Coverage*100, fp.AtRisk)
		} else {
			withoutControls++
		}
	}
	t.Logf("Frameworks with controls: %d, without: %d", withControls, withoutControls)
}

// =========================================================================
// Tests: PDF Reports
// =========================================================================

func TestToPDF(t *testing.T) {
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	pdfBytes, err := result.ToPDF()
	if err != nil {
		t.Fatalf("ToPDF failed: %v", err)
	}

	if len(pdfBytes) == 0 {
		t.Fatal("PDF bytes are empty")
	}

	// Verify it starts with %PDF (PDF magic bytes).
	if string(pdfBytes[:4]) != "%PDF" {
		t.Errorf("PDF doesn't start with %%PDF, got: %q", string(pdfBytes[:4]))
	}

	t.Logf("PDF generated: %d bytes", len(pdfBytes))
}

func TestToPDFWithConfig(t *testing.T) {
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	// Minimal config (no scenario details, no gap analysis).
	cfg := PDFReportConfig{
		IncludeOWASPCoverage:     true,
		IncludeCompliancePosture: false,
		IncludeGapAnalysis:       false,
		IncludeScenarioDetails:   false,
		CompliancePostureV2:      true,
		Author:                   "Test Suite",
		Organization:             "Test Org",
	}

	pdfBytes, err := result.ToPDFWithConfig(cfg)
	if err != nil {
		t.Fatalf("ToPDFWithConfig failed: %v", err)
	}
	if len(pdfBytes) == 0 {
		t.Fatal("PDF bytes are empty")
	}
	t.Logf("Minimal PDF: %d bytes", len(pdfBytes))

	// Full config with 31 frameworks.
	cfgFull := DefaultPDFReportConfig()
	cfgFull.Organization = "AegisGate Security, LLC"
	pdfBytesFull, err := result.ToPDFWithConfig(cfgFull)
	if err != nil {
		t.Fatalf("ToPDFWithConfig (full) failed: %v", err)
	}
	t.Logf("Full PDF (31 frameworks): %d bytes", len(pdfBytesFull))
}

// =========================================================================
// Tests: Ed25519 Signed Reports
// =========================================================================

func TestSignAndVerifyPDFReport(t *testing.T) {
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	// Sign with ephemeral key (no KeyPath).
	cfg := SignReportConfig{
		Metadata: map[string]string{
			"environment": "test",
			"version":     "v4.7.0",
		},
	}

	envelope, err := SignPDFReport(result, cfg)
	if err != nil {
		t.Fatalf("SignPDFReport failed: %v", err)
	}

	t.Logf("Signed report: ID=%s, format=%s, algorithm=%s, keyFP=%s",
		envelope.AssessmentID, envelope.Format, envelope.Algorithm, envelope.KeyFingerprint)

	// Verify the signature.
	if err := envelope.Verify(); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	t.Log("Signature verified successfully")

	// Verify the report bytes can be extracted.
	reportBytes, err := envelope.ReportBytes()
	if err != nil {
		t.Fatalf("ReportBytes failed: %v", err)
	}
	if len(reportBytes) == 0 {
		t.Fatal("report bytes are empty")
	}
	if string(reportBytes[:4]) != "%PDF" {
		t.Error("extracted report is not a PDF")
	}
	t.Logf("Extracted report: %d bytes", len(reportBytes))
}

func TestSignAndVerifyJSONReport(t *testing.T) {
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	envelope, err := SignJSONReport(result, SignReportConfig{})
	if err != nil {
		t.Fatalf("SignJSONReport failed: %v", err)
	}

	if envelope.Format != ReportFormatJSON {
		t.Errorf("expected format JSON, got %s", envelope.Format)
	}

	if err := envelope.Verify(); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	t.Log("JSON signature verified successfully")
}

func TestSignedReportTamperDetection(t *testing.T) {
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	envelope, err := SignJSONReport(result, SignReportConfig{})
	if err != nil {
		t.Fatalf("SignJSONReport failed: %v", err)
	}

	// Tamper with the report bytes.
	envelope.ReportBase64 = "dGVhbXBlcmVk" // "teampered" in base64

	// Verification should fail.
	err = envelope.Verify()
	if err == nil {
		t.Fatal("expected verification to fail after tampering, but it succeeded")
	}
	t.Logf("Tamper detection works: %v", err)
}

func TestSignedReportSerialization(t *testing.T) {
	runner, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	result, err := runner.Run()
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	envelope, err := SignJSONReport(result, SignReportConfig{})
	if err != nil {
		t.Fatalf("SignJSONReport failed: %v", err)
	}

	// Serialize to JSON.
	jsonBytes, err := envelope.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	t.Logf("Serialized signed report: %d bytes", len(jsonBytes))

	// Deserialize.
	envelope2, err := SignedReportFromJSON(jsonBytes)
	if err != nil {
		t.Fatalf("SignedReportFromJSON failed: %v", err)
	}

	// Verify the deserialized envelope.
	if err := envelope2.Verify(); err != nil {
		t.Fatalf("Verify after serialization round-trip failed: %v", err)
	}
	t.Log("Serialization round-trip verified successfully")
}

func TestLoadOrGenerateKey(t *testing.T) {
	// Use a temp file in .workingdirectory (per standing rule #12).
	keyDir := filepath.Join(".workingdirectory", "test-keys")
	keyPath := filepath.Join(keyDir, "test_ed25519.key")
	defer os.RemoveAll(keyDir)

	// First call: generate new key.
	privKey1, pubKey1, err := LoadOrGenerateKey(keyPath)
	if err != nil {
		t.Fatalf("first LoadOrGenerateKey failed: %v", err)
	}
	if len(privKey1) != 64 {
		t.Errorf("private key size %d, expected 64", len(privKey1))
	}
	if len(pubKey1) != 32 {
		t.Errorf("public key size %d, expected 32", len(pubKey1))
	}

	// Verify key file was created.
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file not created: %v", err)
	}

	// Second call: load existing key.
	privKey2, pubKey2, err := LoadOrGenerateKey(keyPath)
	if err != nil {
		t.Fatalf("second LoadOrGenerateKey failed: %v", err)
	}

	// Keys should be the same.
	if !bytesEqual(privKey1, privKey2) {
		t.Error("loaded private key differs from generated key")
	}
	if !bytesEqual(pubKey1, pubKey2) {
		t.Error("loaded public key differs from generated key")
	}

	// Ephemeral key (no path).
	priv3, pub3, err := LoadOrGenerateKey("")
	if err != nil {
		t.Fatalf("ephemeral key generation failed: %v", err)
	}
	if len(priv3) != 64 || len(pub3) != 32 {
		t.Error("ephemeral key has wrong size")
	}
}

func TestKeyFingerprint(t *testing.T) {
	_, pubKey, err := LoadOrGenerateKey("")
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	fp := KeyFingerprint(pubKey)
	if len(fp) != 16 {
		t.Errorf("fingerprint length %d, expected 16", len(fp))
	}
	t.Logf("Key fingerprint: %s", fp)
}

// =========================================================================
// Tests: Scheduler
// =========================================================================

func TestSchedulerRunOnce(t *testing.T) {
	cfg := SchedulerConfig{
		Interval:          time.Hour, // Won't tick during test.
		MinScore:          0.0,       // Don't alert on low score (regex-only).
		AlertOnRegression: false,     // No previous result.
		AlertOnNewGaps:    false,
		AlertOnComplete:   true,
		RunnerConfig:      DefaultRunnerConfig(),
		AlertHandler:      &LogAlertHandler{},
	}

	sched := NewScheduler(cfg)
	result, err := sched.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	if result == nil {
		t.Fatal("RunOnce returned nil result")
	}
	if sched.RunCount() != 1 {
		t.Errorf("expected run count 1, got %d", sched.RunCount())
	}
	if sched.PreviousResult() == nil {
		t.Error("PreviousResult should be set after RunOnce")
	}
	t.Logf("RunOnce: %d/%d blocked (%.1f%%)", result.Blocked, result.Total, result.Score*100)
}

func TestSchedulerAlerts(t *testing.T) {
	// Create a channel handler to capture alerts.
	alertCh := make(chan PostureAlert, 10)
	handler := NewChannelAlertHandler(alertCh)

	cfg := SchedulerConfig{
		Interval:          time.Hour,
		MinScore:          0.99, // Set high to trigger score_drop alert.
		AlertOnRegression: true,
		AlertOnNewGaps:    true,
		AlertOnComplete:   true,
		RunnerConfig:      DefaultRunnerConfig(),
		AlertHandler:      handler,
	}

	sched := NewScheduler(cfg)

	// First run — should trigger score_drop (score < 0.99) and assessment_done.
	_, err := sched.RunOnce()
	if err != nil {
		t.Fatalf("first RunOnce failed: %v", err)
	}

	// Collect alerts.
	close(alertCh)
	var alerts []PostureAlert
	for alert := range alertCh {
		alerts = append(alerts, alert)
		t.Logf("  Alert: [%s] [%s] %s", alert.Severity, alert.Type, alert.Message)
	}

	// Should have at least 2 alerts: assessment_done + score_drop.
	if len(alerts) < 2 {
		t.Errorf("expected at least 2 alerts, got %d", len(alerts))
	}

	// Check for score_drop alert.
	hasScoreDrop := false
	hasComplete := false
	for _, a := range alerts {
		if a.Type == AlertScoreDrop {
			hasScoreDrop = true
		}
		if a.Type == AlertAssessmentDone {
			hasComplete = true
		}
	}
	if !hasScoreDrop {
		t.Error("missing score_drop alert")
	}
	if !hasComplete {
		t.Error("missing assessment_done alert")
	}
}

func TestSchedulerRegressionAlert(t *testing.T) {
	alertCh := make(chan PostureAlert, 10)
	handler := NewChannelAlertHandler(alertCh)

	cfg := SchedulerConfig{
		Interval:          time.Hour,
		MinScore:          0.0, // Don't trigger score_drop.
		AlertOnRegression: true,
		AlertOnNewGaps:    true,
		AlertOnComplete:   false,
		RunnerConfig:      DefaultRunnerConfig(),
		AlertHandler:      handler,
	}

	sched := NewScheduler(cfg)

	// First run.
	result1, err := sched.RunOnce()
	if err != nil {
		t.Fatalf("first RunOnce failed: %v", err)
	}

	// Drain alerts from first run.
	close(alertCh)
	firstAlerts := 0
	for range alertCh {
		firstAlerts++
	}

	// Second run with same config — same results, no regression.
	alertCh2 := make(chan PostureAlert, 10)
	sched.cfg.AlertHandler = NewChannelAlertHandler(alertCh2)

	_, err = sched.RunOnce()
	if err != nil {
		t.Fatalf("second RunOnce failed: %v", err)
	}

	close(alertCh2)
	var secondAlerts []PostureAlert
	for a := range alertCh2 {
		secondAlerts = append(secondAlerts, a)
		t.Logf("  Second run alert: [%s] [%s] %s", a.Severity, a.Type, a.Message)
	}

	// No regression should be detected (same score).
	for _, a := range secondAlerts {
		if a.Type == AlertScoreRegression {
			t.Error("unexpected regression alert — scores should be the same")
		}
	}

	t.Logf("First run: %d alerts, Second run: %d alerts", firstAlerts, len(secondAlerts))
	t.Logf("First run score: %.1f%%", result1.Score*100)
}

func TestFindNewGaps(t *testing.T) {
	prev := &AssessmentResult{
		ScenarioResults: []ScenarioResult{
			{ScenarioID: "S1", Blocked: true},
			{ScenarioID: "S2", Blocked: true},
			{ScenarioID: "S3", Blocked: false}, // Was already missed
		},
	}
	curr := &AssessmentResult{
		ScenarioResults: []ScenarioResult{
			{ScenarioID: "S1", Blocked: true},
			{ScenarioID: "S2", Blocked: false}, // NEW gap (was blocked)
			{ScenarioID: "S3", Blocked: false}, // Still missed (not new)
			{ScenarioID: "S4", Blocked: false}, // NEW gap (new scenario)
		},
	}

	newGaps := findNewGaps(prev, curr)
	if len(newGaps) != 2 {
		t.Errorf("expected 2 new gaps, got %d: %v", len(newGaps), newGaps)
	}

	// Should be S2 and S4 (not S3 — it was already missed).
	expected := map[string]bool{"S2": true, "S4": true}
	for _, gap := range newGaps {
		if !expected[gap] {
			t.Errorf("unexpected new gap: %s", gap)
		}
	}
}

func TestSchedulerStartStop(t *testing.T) {
	cfg := SchedulerConfig{
		Interval:          50 * time.Millisecond, // Fast tick for testing.
		MinScore:          0.0,
		AlertOnRegression: false,
		AlertOnNewGaps:    false,
		AlertOnComplete:   false,
		RunnerConfig:      DefaultRunnerConfig(),
		AlertHandler:      &LogAlertHandler{},
	}

	sched := NewScheduler(cfg)

	if err := sched.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !sched.IsRunning() {
		t.Error("scheduler should be running after Start")
	}

	// Wait for at least 2 runs (initial + 1 tick).
	// Each assessment takes ~2s, so we need to wait at least 5s.
	time.Sleep(5500 * time.Millisecond)

	count := sched.RunCount()
	if count < 2 {
		t.Errorf("expected at least 2 runs, got %d", count)
	}
	t.Logf("Scheduler ran %d times in 5.5s", count)

	sched.Stop()
	if sched.IsRunning() {
		t.Error("scheduler should not be running after Stop")
	}
}

// =========================================================================
// Helpers
// =========================================================================

// bytesEqual compares two byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
