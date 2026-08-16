// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Vendor Questionnaire Auto-Answer Tests
// =========================================================================

package questionnaire

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Core Engine Tests
// =============================================================================

func TestNewQuestionnaireEngine(t *testing.T) {
	qe := NewQuestionnaireEngine()
	if qe == nil {
		t.Fatal("NewQuestionnaireEngine returned nil")
	}
	if len(qe.sigBank) == 0 {
		t.Error("SIG question bank is empty")
	}
	if len(qe.caiqBank) == 0 {
		t.Error("CAIQ question bank is empty")
	}
	if len(qe.answerMap) == 0 {
		t.Error("Answer map is empty")
	}
}

// =============================================================================
// SIG Bank Tests
// =============================================================================

func TestSIGBankMinimumSize(t *testing.T) {
	qe := NewQuestionnaireEngine()
	bank := qe.GetSIGBank()
	if len(bank) < 100 {
		t.Errorf("SIG bank has %d questions, expected at least 100", len(bank))
	}
}

func TestSIGBankCategories(t *testing.T) {
	qe := NewQuestionnaireEngine()
	bank := qe.GetSIGBank()

	expectedCategories := map[string]int{
		"Security":             25,
		"Availability":         20,
		"Processing Integrity": 20,
		"Confidentiality":      20,
		"Privacy":              15,
	}

	categoryCounts := make(map[string]int)
	for _, q := range bank {
		categoryCounts[q.Category]++
	}

	for cat, expected := range expectedCategories {
		actual := categoryCounts[cat]
		if actual != expected {
			t.Errorf("SIG category %q: got %d questions, expected %d", cat, actual, expected)
		}
	}
}

func TestSIGBankQuestionIDs(t *testing.T) {
	qe := NewQuestionnaireEngine()
	bank := qe.GetSIGBank()

	seenIDs := make(map[string]bool)
	for _, q := range bank {
		if !strings.HasPrefix(q.ID, "SIG-") {
			t.Errorf("SIG question ID %q does not have SIG- prefix", q.ID)
		}
		if seenIDs[q.ID] {
			t.Errorf("Duplicate SIG question ID: %q", q.ID)
		}
		seenIDs[q.ID] = true
		if q.Text == "" {
			t.Errorf("SIG question %q has empty text", q.ID)
		}
	}
}

// =============================================================================
// CAIQ Bank Tests
// =============================================================================

func TestCAIQBankMinimumSize(t *testing.T) {
	qe := NewQuestionnaireEngine()
	bank := qe.GetCAIQBank()
	if len(bank) < 150 {
		t.Errorf("CAIQ bank has %d questions, expected at least 150", len(bank))
	}
}

func TestCAIQBankCategories(t *testing.T) {
	qe := NewQuestionnaireEngine()
	bank := qe.GetCAIQBank()

	expectedCategories := map[string]int{
		"Cloud Security":    35,
		"Compliance":        30,
		"Data Privacy":      30,
		"Incident Response": 30,
		"Risk Management":   25,
	}

	categoryCounts := make(map[string]int)
	for _, q := range bank {
		categoryCounts[q.Category]++
	}

	for cat, expected := range expectedCategories {
		actual := categoryCounts[cat]
		if actual != expected {
			t.Errorf("CAIQ category %q: got %d questions, expected %d", cat, actual, expected)
		}
	}
}

func TestCAIQBankQuestionIDs(t *testing.T) {
	qe := NewQuestionnaireEngine()
	bank := qe.GetCAIQBank()

	seenIDs := make(map[string]bool)
	for _, q := range bank {
		if !strings.HasPrefix(q.ID, "CAIQ-") {
			t.Errorf("CAIQ question ID %q does not have CAIQ- prefix", q.ID)
		}
		if seenIDs[q.ID] {
			t.Errorf("Duplicate CAIQ question ID: %q", q.ID)
		}
		seenIDs[q.ID] = true
		if q.Text == "" {
			t.Errorf("CAIQ question %q has empty text", q.ID)
		}
	}
}

// =============================================================================
// AutoAnswer Tests
// =============================================================================

func TestAutoAnswerEmptyResults(t *testing.T) {
	qe := NewQuestionnaireEngine()
	_, err := qe.AutoAnswer(map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for empty scanner results")
	}
}

func TestAutoAnswerWithResults(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                   true,
		"encryption_at_rest":    "aes-256",
		"encryption_in_transit": "tls_1.3",
		"access_control":        "rbac",
	}
	resp, err := qe.AutoAnswer(scanResults)
	if err != nil {
		t.Fatalf("AutoAnswer failed: %v", err)
	}
	if resp.Framework != "SIG" {
		t.Errorf("Expected framework SIG, got %q", resp.Framework)
	}
	if len(resp.Questions) != len(qe.sigBank) {
		t.Errorf("Expected %d questions, got %d", len(qe.sigBank), len(resp.Questions))
	}
}

func TestAutoAnswerConfidenceScoring(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa": true,
	}
	resp, err := qe.AutoAnswer(scanResults)
	if err != nil {
		t.Fatalf("AutoAnswer failed: %v", err)
	}

	// Find a security question that should match MFA.
	foundHighConfidence := false
	foundManualReview := false
	for _, q := range resp.Questions {
		if q.Confidence >= 0.8 && q.Source == "automated_scan" {
			foundHighConfidence = true
		}
		if q.Confidence == 0.0 && q.Source == "manual_review" {
			foundManualReview = true
		}
	}

	if !foundHighConfidence {
		t.Error("Expected at least one question with confidence >= 0.8 from automated_scan")
	}
	if !foundManualReview {
		t.Error("Expected at least one question requiring manual review")
	}
}

func TestAutoAnswerMFAMapping(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa": true,
	}
	resp, err := qe.AutoAnswer(scanResults)
	if err != nil {
		t.Fatalf("AutoAnswer failed: %v", err)
	}

	// At least one question should get the MFA answer.
	foundMFA := false
	for _, q := range resp.Questions {
		if strings.Contains(q.Answer, "multi-factor authentication") {
			foundMFA = true
			if q.Confidence < 0.8 {
				t.Errorf("MFA answer should have confidence >= 0.8, got %.2f", q.Confidence)
			}
			if q.Source != "automated_scan" {
				t.Errorf("MFA answer source should be automated_scan, got %q", q.Source)
			}
		}
	}
	if !foundMFA {
		t.Error("Expected at least one question to receive the MFA answer")
	}
}

func TestAutoAnswerEncryptionAtRestMapping(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"encryption_at_rest": "aes-256",
	}
	resp, err := qe.AutoAnswer(scanResults)
	if err != nil {
		t.Fatalf("AutoAnswer failed: %v", err)
	}

	foundEnc := false
	for _, q := range resp.Questions {
		if strings.Contains(q.Answer, "encrypted at rest") && strings.Contains(q.Answer, "AES-256") {
			foundEnc = true
			if q.Confidence < 0.8 {
				t.Errorf("Encryption at rest answer should have confidence >= 0.8, got %.2f", q.Confidence)
			}
		}
	}
	if !foundEnc {
		t.Error("Expected at least one question to receive the encryption at rest answer")
	}
}

// =============================================================================
// GenerateSIG Tests
// =============================================================================

func TestGenerateSIGEmptyOrgName(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{"mfa": true}
	_, err := qe.GenerateSIG("", scanResults)
	if err == nil {
		t.Error("Expected error for empty organization name")
	}
}

func TestGenerateSIGEmptyResults(t *testing.T) {
	qe := NewQuestionnaireEngine()
	_, err := qe.GenerateSIG("Acme Corp", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for empty scan results")
	}
}

func TestGenerateSIGValid(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                   true,
		"encryption_at_rest":    "aes-256",
		"encryption_in_transit": "tls_1.3",
		"access_control":        "rbac",
		"firewall":              "cloud_waf",
		"vulnerability_scan":    "qualys",
	}
	resp, err := qe.GenerateSIG("Acme Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}
	if resp.Framework != "SIG" {
		t.Errorf("Expected framework SIG, got %q", resp.Framework)
	}
	if resp.OrganizationName != "Acme Corp" {
		t.Errorf("Expected organization 'Acme Corp', got %q", resp.OrganizationName)
	}
	if resp.Version != "4.0" {
		t.Errorf("Expected version 4.0, got %q", resp.Version)
	}
	if resp.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should not be zero")
	}
	if len(resp.Questions) != len(qe.sigBank) {
		t.Errorf("Expected %d questions, got %d", len(qe.sigBank), len(resp.Questions))
	}
}

func TestGenerateSIGQuestionCategories(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{"mfa": true}
	resp, err := qe.GenerateSIG("Test Org", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	categories := make(map[string]int)
	for _, q := range resp.Questions {
		categories[q.Category]++
	}

	expectedCats := []string{"Security", "Availability", "Processing Integrity", "Confidentiality", "Privacy"}
	for _, cat := range expectedCats {
		if categories[cat] == 0 {
			t.Errorf("SIG response missing category: %q", cat)
		}
	}
}

// =============================================================================
// GenerateCAIQ Tests
// =============================================================================

func TestGenerateCAIQEmptyOrgName(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{"mfa": true}
	_, err := qe.GenerateCAIQ("", scanResults)
	if err == nil {
		t.Error("Expected error for empty organization name")
	}
}

func TestGenerateCAIQEmptyResults(t *testing.T) {
	qe := NewQuestionnaireEngine()
	_, err := qe.GenerateCAIQ("Acme Corp", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for empty scan results")
	}
}

func TestGenerateCAIQValid(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                   true,
		"encryption_at_rest":    "aes-256",
		"encryption_in_transit": "tls_1.3",
		"iam":                   "okta",
		"security_logging":      "splunk",
		"vulnerability_scan":    "qualys",
		"incident_response":     "pagerduty",
		"risk_assessment":       "annually",
		"privacy_policy":        "published",
		"data_retention":        "365_days",
	}
	resp, err := qe.GenerateCAIQ("CloudVenture Inc", scanResults)
	if err != nil {
		t.Fatalf("GenerateCAIQ failed: %v", err)
	}
	if resp.Framework != "CAIQ" {
		t.Errorf("Expected framework CAIQ, got %q", resp.Framework)
	}
	if resp.OrganizationName != "CloudVenture Inc" {
		t.Errorf("Expected organization 'CloudVenture Inc', got %q", resp.OrganizationName)
	}
	if resp.Version != "4.0.1" {
		t.Errorf("Expected version 4.0.1, got %q", resp.Version)
	}
	if len(resp.Questions) != len(qe.caiqBank) {
		t.Errorf("Expected %d questions, got %d", len(qe.caiqBank), len(resp.Questions))
	}
}

func TestGenerateCAIQQuestionCategories(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{"mfa": true}
	resp, err := qe.GenerateCAIQ("Test Org", scanResults)
	if err != nil {
		t.Fatalf("GenerateCAIQ failed: %v", err)
	}

	categories := make(map[string]int)
	for _, q := range resp.Questions {
		categories[q.Category]++
	}

	expectedCats := []string{"Cloud Security", "Compliance", "Data Privacy", "Incident Response", "Risk Management"}
	for _, cat := range expectedCats {
		if categories[cat] == 0 {
			t.Errorf("CAIQ response missing category: %q", cat)
		}
	}
}

// =============================================================================
// Confidence Scoring Tests
// =============================================================================

func TestConfidenceScoringRanges(t *testing.T) {
	qe := NewQuestionnaireEngine()

	// Automated scan evidence should yield 0.8-1.0.
	scanResults := map[string]interface{}{
		"mfa":                true,
		"encryption_at_rest": "aes-256",
		"firewall":           "cloud_waf",
		"security_logging":   "splunk",
	}
	resp, err := qe.GenerateSIG("ConfidenceTest Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	autoCount := 0
	policyCount := 0
	manualCount := 0
	for _, q := range resp.Questions {
		switch q.Source {
		case "automated_scan":
			autoCount++
			if q.Confidence < 0.8 || q.Confidence > 1.0 {
				t.Errorf("Automated scan answer confidence %.2f outside range [0.8, 1.0] for %s", q.Confidence, q.ID)
			}
		case "policy_inference":
			policyCount++
			if q.Confidence < 0.5 || q.Confidence > 0.7 {
				t.Errorf("Policy inference answer confidence %.2f outside range [0.5, 0.7] for %s", q.Confidence, q.ID)
			}
		case "manual_review":
			manualCount++
			if q.Confidence > 0.4 {
				t.Errorf("Manual review answer confidence %.2f should be <= 0.4 for %s", q.Confidence, q.ID)
			}
		}
	}

	t.Logf("Confidence distribution: auto=%d, policy=%d, manual=%d", autoCount, policyCount, manualCount)
}

func TestConfidenceScoringPolicyInference(t *testing.T) {
	qe := NewQuestionnaireEngine()

	// Only policy inference keywords.
	scanResults := map[string]interface{}{
		"privacy_policy":     "published",
		"data_retention":     "365_days",
		"consent_management": "one_trust",
		"third_party_risk":   "assessed",
	}
	resp, err := qe.GenerateSIG("PolicyTest Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	policyCount := 0
	for _, q := range resp.Questions {
		if q.Source == "policy_inference" {
			policyCount++
		}
	}
	if policyCount == 0 {
		t.Error("Expected at least one policy_inference answer")
	}
}

func TestConfidenceScoringManualReview(t *testing.T) {
	qe := NewQuestionnaireEngine()

	// Minimal scan results — most questions should be manual_review.
	scanResults := map[string]interface{}{
		"mfa": true,
	}
	resp, err := qe.GenerateSIG("MinimalTest Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	manualCount := 0
	for _, q := range resp.Questions {
		if q.Source == "manual_review" {
			manualCount++
			if q.Confidence > 0.4 {
				t.Errorf("Manual review confidence should be <= 0.4, got %.2f for %s", q.Confidence, q.ID)
			}
		}
	}
	// With only MFA evidence, the vast majority should be manual review.
	if manualCount < 70 {
		t.Errorf("Expected at least 70 manual review questions with minimal scan data, got %d", manualCount)
	}
}

// =============================================================================
// Flatten Results Tests
// =============================================================================

func TestFlattenResultsStringValues(t *testing.T) {
	results := map[string]interface{}{
		"mfa": "enabled",
	}
	flat := flattenResults(results)
	if flat["mfa"] != "enabled" {
		t.Errorf("Expected 'enabled', got %q", flat["mfa"])
	}
}

func TestFlattenResultsBoolValues(t *testing.T) {
	results := map[string]interface{}{
		"mfa": true,
	}
	flat := flattenResults(results)
	if flat["mfa"] != "true" {
		t.Errorf("Expected 'true', got %q", flat["mfa"])
	}
}

func TestFlattenResultsFloatValues(t *testing.T) {
	results := map[string]interface{}{
		"score": float64(95.5),
	}
	flat := flattenResults(results)
	if flat["score"] != "95.50" {
		t.Errorf("Expected '95.50', got %q", flat["score"])
	}
}

func TestFlattenResultsNestedMaps(t *testing.T) {
	results := map[string]interface{}{
		"security": map[string]interface{}{
			"mfa":      true,
			"firewall": "enabled",
		},
	}
	flat := flattenResults(results)
	if flat["security.mfa"] != "true" {
		t.Errorf("Expected nested 'security.mfa' = 'true', got %q", flat["security.mfa"])
	}
	if flat["security.firewall"] != "enabled" {
		t.Errorf("Expected nested 'security.firewall' = 'enabled', got %q", flat["security.firewall"])
	}
	// Short keys should also be indexed.
	if flat["mfa"] != "true" {
		t.Errorf("Expected short key 'mfa' = 'true', got %q", flat["mfa"])
	}
}

func TestFlattenResultsArrayValues(t *testing.T) {
	results := map[string]interface{}{
		"findings": []interface{}{"CVE-2023-0001", "CVE-2023-0002"},
	}
	flat := flattenResults(results)
	if !strings.Contains(flat["findings"], "CVE-2023-0001") {
		t.Errorf("Expected findings to contain CVEs, got %q", flat["findings"])
	}
}

// =============================================================================
// CSV Export Tests
// =============================================================================

func TestExportToCSVNil(t *testing.T) {
	_, err := ExportToCSV(nil)
	if err == nil {
		t.Error("Expected error for nil response")
	}
}

func TestExportToCSVValid(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                true,
		"encryption_at_rest": "aes-256",
	}
	resp, err := qe.GenerateSIG("CSV Test Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	csvBytes, err := ExportToCSV(resp)
	if err != nil {
		t.Fatalf("ExportToCSV failed: %v", err)
	}

	reader := csv.NewReader(bytes.NewReader(csvBytes))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	// Header + 100 question rows.
	expectedRows := len(qe.sigBank) + 1
	if len(records) != expectedRows {
		t.Errorf("Expected %d CSV rows, got %d", expectedRows, len(records))
	}

	// Check header.
	header := records[0]
	expectedHeader := []string{"ID", "Category", "Text", "Answer", "Confidence", "Source", "Evidence"}
	for i, h := range expectedHeader {
		if header[i] != h {
			t.Errorf("CSV header column %d: expected %q, got %q", i, h, header[i])
		}
	}

	// Check that at least some rows have non-empty answers.
	nonEmptyAnswers := 0
	for _, row := range records[1:] {
		if row[3] != "" {
			nonEmptyAnswers++
		}
	}
	if nonEmptyAnswers == 0 {
		t.Error("Expected at least one non-empty answer in CSV export")
	}
}

func TestExportToCSVContainsExpectedData(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa": true,
	}
	resp, err := qe.GenerateSIG("CSV Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	csvBytes, err := ExportToCSV(resp)
	if err != nil {
		t.Fatalf("ExportToCSV failed: %v", err)
	}

	csvStr := string(csvBytes)

	// Should contain the SIG question IDs.
	if !strings.Contains(csvStr, "SIG-SEC-001") {
		t.Error("CSV should contain SIG-SEC-001")
	}
	if !strings.Contains(csvStr, "SIG-SEC-025") {
		t.Error("CSV should contain SIG-SEC-025")
	}
	// Should contain the organization name in the text (it's in the response metadata,
	// not in the CSV rows directly, but the question answers should be present).
	if !strings.Contains(csvStr, "multi-factor authentication") {
		t.Error("CSV should contain MFA answer text")
	}
}

// =============================================================================
// PDF Export Tests
// =============================================================================

func TestExportToPDFNil(t *testing.T) {
	_, err := ExportToPDF(nil)
	if err == nil {
		t.Error("Expected error for nil response")
	}
}

func TestExportToPDFValid(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                true,
		"encryption_at_rest": "aes-256",
	}
	resp, err := qe.GenerateSIG("PDF Test Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	pdfBytes, err := ExportToPDF(resp)
	if err != nil {
		t.Fatalf("ExportToPDF failed: %v", err)
	}

	// Should produce valid PDF bytes (PDF header starts with %PDF-).
	if len(pdfBytes) == 0 {
		t.Fatal("ExportToPDF should return non-empty bytes")
	}
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-")) {
		t.Errorf("ExportToPDF should produce a valid PDF document, got prefix: %q", string(pdfBytes[:min(20, len(pdfBytes))]))
	}

	// The PDF should contain the organization name and framework in metadata.
	pdfStr := string(pdfBytes)
	if !strings.Contains(pdfStr, "SIG Questionnaire") {
		t.Error("PDF export should contain framework header in metadata")
	}
	if !strings.Contains(pdfStr, "PDF Test Corp") {
		t.Error("PDF export should contain organization name")
	}
	if !strings.Contains(pdfStr, "4.0") {
		t.Error("PDF export should contain version")
	}
}

func TestExportToPDFCAIQ(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                true,
		"encryption_at_rest": "aes-256",
	}
	resp, err := qe.GenerateCAIQ("PDF CAIQ Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateCAIQ failed: %v", err)
	}

	pdfBytes, err := ExportToPDF(resp)
	if err != nil {
		t.Fatalf("ExportToPDF failed: %v", err)
	}

	// Should produce valid PDF bytes.
	if len(pdfBytes) == 0 {
		t.Fatal("ExportToPDF should return non-empty bytes")
	}
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-")) {
		t.Errorf("ExportToPDF should produce a valid PDF document, got prefix: %q", string(pdfBytes[:min(20, len(pdfBytes))]))
	}

	pdfStr := string(pdfBytes)
	if !strings.Contains(pdfStr, "CAIQ Questionnaire") {
		t.Error("PDF export should contain CAIQ framework header")
	}
	if !strings.Contains(pdfStr, "4.0.1") {
		t.Error("PDF export should contain CAIQ version")
	}
}

// =============================================================================
// Question Struct Validation Tests
// =============================================================================

func TestQuestionStructFields(t *testing.T) {
	q := Question{
		ID:         "TEST-001",
		Category:   "Security",
		Text:       "Is MFA enabled?",
		Answer:     "Yes",
		Confidence: 0.95,
		Source:     "automated_scan",
		Evidence:   []string{"mfa=true"},
	}
	if q.ID != "TEST-001" {
		t.Errorf("Question ID mismatch: got %q", q.ID)
	}
	if q.Category != "Security" {
		t.Errorf("Question Category mismatch: got %q", q.Category)
	}
	if q.Text != "Is MFA enabled?" {
		t.Errorf("Question Text mismatch: got %q", q.Text)
	}
	if q.Answer != "Yes" {
		t.Errorf("Question Answer mismatch: got %q", q.Answer)
	}
	if q.Confidence != 0.95 {
		t.Errorf("Question Confidence mismatch: got %.2f", q.Confidence)
	}
	if q.Source != "automated_scan" {
		t.Errorf("Question Source mismatch: got %q", q.Source)
	}
	if len(q.Evidence) != 1 || q.Evidence[0] != "mfa=true" {
		t.Errorf("Question Evidence mismatch: got %v", q.Evidence)
	}
}

func TestQuestionnaireResponseStructFields(t *testing.T) {
	now := time.Now().UTC()
	resp := &QuestionnaireResponse{
		Framework:        "SIG",
		Version:          "4.0",
		Questions:        []Question{{ID: "SIG-SEC-001"}},
		GeneratedAt:      now,
		OrganizationName: "Test Corp",
	}
	if resp.Framework != "SIG" {
		t.Errorf("Framework mismatch: got %q", resp.Framework)
	}
	if resp.Version != "4.0" {
		t.Errorf("Version mismatch: got %q", resp.Version)
	}
	if resp.OrganizationName != "Test Corp" {
		t.Errorf("OrganizationName mismatch: got %q", resp.OrganizationName)
	}
	if len(resp.Questions) != 1 {
		t.Errorf("Questions length mismatch: got %d", len(resp.Questions))
	}
}

// =============================================================================
// Answer Rule Tests
// =============================================================================

func TestAnswerRuleMFAMapping(t *testing.T) {
	rules := defaultAnswerMap()
	rule, ok := rules["mfa"]
	if !ok {
		t.Fatal("Expected mfa rule in default answer map")
	}
	if rule.Answer != "Yes, multi-factor authentication is enabled" {
		t.Errorf("MFA answer mismatch: got %q", rule.Answer)
	}
	if rule.Confidence < 0.8 {
		t.Errorf("MFA confidence should be >= 0.8, got %.2f", rule.Confidence)
	}
	if rule.Source != "automated_scan" {
		t.Errorf("MFA source should be automated_scan, got %q", rule.Source)
	}
}

func TestAnswerRuleEncryptionAtRestMapping(t *testing.T) {
	rules := defaultAnswerMap()
	rule, ok := rules["encryption_at_rest"]
	if !ok {
		t.Fatal("Expected encryption_at_rest rule in default answer map")
	}
	if !strings.Contains(rule.Answer, "AES-256") {
		t.Errorf("Encryption at rest answer should mention AES-256, got %q", rule.Answer)
	}
	if rule.Confidence < 0.8 {
		t.Errorf("Encryption at rest confidence should be >= 0.8, got %.2f", rule.Confidence)
	}
}

func TestAnswerRuleCoverage(t *testing.T) {
	rules := defaultAnswerMap()
	// Ensure we have rules for the key compliance areas.
	expectedRules := []string{
		"mfa", "encryption_at_rest", "encryption_in_transit",
		"access_control", "firewall", "vulnerability_scan",
		"patch_management", "security_logging", "backup",
		"disaster_recovery", "incident_response", "risk_assessment",
		"privacy_policy", "data_retention", "third_party_risk",
		"audit_trail", "change_management", "data_classification",
	}
	for _, key := range expectedRules {
		if _, ok := rules[key]; !ok {
			t.Errorf("Missing answer rule for key: %q", key)
		}
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestGetSIGBank(t *testing.T) {
	qe := NewQuestionnaireEngine()
	bank := qe.GetSIGBank()
	if len(bank) < 100 {
		t.Errorf("SIG bank should have at least 100 questions, got %d", len(bank))
	}
	// Verify it's a copy — modifying the returned slice should not affect the engine.
	originalLen := len(bank)
	_ = append(bank[:1], bank[2:]...) // modify returned slice
	if len(qe.GetSIGBank()) != originalLen {
		t.Error("GetSIGBank should return a copy, not a reference")
	}
}

func TestGetCAIQBank(t *testing.T) {
	qe := NewQuestionnaireEngine()
	bank := qe.GetCAIQBank()
	if len(bank) < 150 {
		t.Errorf("CAIQ bank should have at least 150 questions, got %d", len(bank))
	}
}

func TestSummaryStats(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                true,
		"encryption_at_rest": "aes-256",
		"privacy_policy":     "published",
		"risk_assessment":    "annual",
	}
	resp, err := qe.GenerateSIG("Stats Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	total, autoCount, policyCount, manualCount, avgConf := SummaryStats(resp)
	if total != len(qe.sigBank) {
		t.Errorf("Expected total %d, got %d", len(qe.sigBank), total)
	}
	if autoCount == 0 {
		t.Error("Expected at least one automated_scan answer")
	}
	if autoCount+policyCount+manualCount != total {
		t.Errorf("Source counts (%d+%d+%d=%d) should equal total (%d)",
			autoCount, policyCount, manualCount, autoCount+policyCount+manualCount, total)
	}
	if avgConf <= 0 {
		t.Errorf("Average confidence should be > 0, got %.4f", avgConf)
	}
}

func TestSummaryStatsNil(t *testing.T) {
	total, auto, policy, manual, avg := SummaryStats(nil)
	if total != 0 || auto != 0 || policy != 0 || manual != 0 || avg != 0 {
		t.Error("SummaryStats(nil) should return all zeros")
	}
}

func TestSortQuestionsByConfidence(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                true,
		"encryption_at_rest": "aes-256",
		"privacy_policy":     "published",
	}
	resp, err := qe.GenerateSIG("Sort Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	SortQuestionsByConfidence(resp)

	// Verify descending order.
	for i := 1; i < len(resp.Questions); i++ {
		if resp.Questions[i-1].Confidence < resp.Questions[i].Confidence {
			t.Errorf("Questions not sorted by confidence: q[%d]=%.2f < q[%d]=%.2f",
				i-1, resp.Questions[i-1].Confidence, i, resp.Questions[i].Confidence)
		}
	}
}

func TestSortQuestionsByConfidenceNil(t *testing.T) {
	// Should not panic on nil.
	SortQuestionsByConfidence(nil)
}

func TestFilterByConfidence(t *testing.T) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                true,
		"encryption_at_rest": "aes-256",
	}
	resp, err := qe.GenerateSIG("Filter Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	// Filter for high-confidence answers only.
	highConf := FilterByConfidence(resp, 0.8)
	for _, q := range highConf {
		if q.Confidence < 0.8 {
			t.Errorf("Filtered question %s has confidence %.2f < 0.8", q.ID, q.Confidence)
		}
	}

	// Filter for all non-manual-review answers.
	nonManual := FilterByConfidence(resp, 0.5)
	for _, q := range nonManual {
		if q.Confidence < 0.5 {
			t.Errorf("Filtered question %s has confidence %.2f < 0.5", q.ID, q.Confidence)
		}
	}
}

func TestFilterByConfidenceNil(t *testing.T) {
	result := FilterByConfidence(nil, 0.5)
	if result != nil {
		t.Error("FilterByConfidence(nil) should return nil")
	}
}

// =============================================================================
// Category Keyword Map Tests
// =============================================================================

func TestCategoryKeywordMap(t *testing.T) {
	ckm := categoryKeywordMap()
	expectedCategories := []string{
		"Security", "Availability", "Processing Integrity",
		"Confidentiality", "Privacy", "Cloud Security",
		"Compliance", "Data Privacy", "Incident Response",
		"Risk Management",
	}
	for _, cat := range expectedCategories {
		if _, ok := ckm[cat]; !ok {
			t.Errorf("Missing category keyword mapping for: %q", cat)
		}
	}
}

// =============================================================================
// Integration-style Tests
// =============================================================================

func TestEndToEndSIGWorkflow(t *testing.T) {
	qe := NewQuestionnaireEngine()

	// Simulate scanner output from AegisGate compliance scan.
	scanResults := map[string]interface{}{
		"mfa":                   true,
		"encryption_at_rest":    "aes-256",
		"encryption_in_transit": "tls_1.3",
		"access_control":        "rbac",
		"firewall":              "cloud_waf",
		"vulnerability_scan":    "qualys",
		"patch_management":      "automated",
		"security_logging":      "splunk",
		"backup":                "daily",
		"disaster_recovery":     "tested",
		"incident_response":     "documented",
		"risk_assessment":       "annual",
		"privacy_policy":        "published",
		"data_retention":        "365_days",
		"consent_management":    "one_trust",
		"data_classification":   "three_tier",
		"third_party_risk":      "assessed",
		"audit_trail":           "enabled",
		"dpias":                 "conducted",
		"change_management":     "documented",
	}

	resp, err := qe.GenerateSIG("EndToEnd Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	if resp.Framework != "SIG" {
		t.Errorf("Expected SIG, got %q", resp.Framework)
	}
	if resp.OrganizationName != "EndToEnd Corp" {
		t.Errorf("Expected 'EndToEnd Corp', got %q", resp.OrganizationName)
	}

	// Export to CSV.
	csvBytes, err := ExportToCSV(resp)
	if err != nil {
		t.Fatalf("ExportToCSV failed: %v", err)
	}
	if len(csvBytes) == 0 {
		t.Error("CSV export produced empty output")
	}

	// Export to PDF.
	pdfBytes, err := ExportToPDF(resp)
	if err != nil {
		t.Fatalf("ExportToPDF failed: %v", err)
	}
	if len(pdfBytes) == 0 {
		t.Error("PDF export produced empty output")
	}

	// Get summary stats.
	total, auto, policy, manual, avg := SummaryStats(resp)
	if total != 100 {
		t.Errorf("Expected 100 questions, got %d", total)
	}
	if auto == 0 {
		t.Error("Expected at least some automated_scan answers")
	}
	if avg <= 0 {
		t.Errorf("Expected positive average confidence, got %.4f", avg)
	}

	// Filter high-confidence answers.
	highConf := FilterByConfidence(resp, 0.8)
	if len(highConf) == 0 {
		t.Error("Expected at least one high-confidence answer")
	}

	t.Logf("End-to-end SIG: total=%d, auto=%d, policy=%d, manual=%d, avgConf=%.4f",
		total, auto, policy, manual, avg)
}

func TestEndToEndCAIQWorkflow(t *testing.T) {
	qe := NewQuestionnaireEngine()

	scanResults := map[string]interface{}{
		"mfa":                true,
		"encryption_at_rest": "aes-256",
		"iam":                "okta",
		"network_security":   "segmented",
		"vulnerability_scan": "qualys",
		"security_logging":   "splunk",
		"incident_response":  "documented",
		"risk_assessment":    "annual",
		"privacy_policy":     "published",
		"data_retention":     "365_days",
		"consent_management": "one_trust",
		"third_party_risk":   "assessed",
		"audit_trail":        "enabled",
	}

	resp, err := qe.GenerateCAIQ("CloudVenture Inc", scanResults)
	if err != nil {
		t.Fatalf("GenerateCAIQ failed: %v", err)
	}

	if resp.Framework != "CAIQ" {
		t.Errorf("Expected CAIQ, got %q", resp.Framework)
	}

	// Export.
	csvBytes, err := ExportToCSV(resp)
	if err != nil {
		t.Fatalf("ExportToCSV failed: %v", err)
	}
	if len(csvBytes) == 0 {
		t.Error("CSV export produced empty output")
	}

	t.Logf("End-to-end CAIQ: %d questions generated for %s",
		len(resp.Questions), resp.OrganizationName)
}

func TestNestedScanResults(t *testing.T) {
	qe := NewQuestionnaireEngine()

	// Test deeply nested scan results.
	scanResults := map[string]interface{}{
		"security": map[string]interface{}{
			"mfa":      true,
			"firewall": "cloud_waf",
		},
		"compliance": map[string]interface{}{
			"audit_trail": "enabled",
		},
	}

	resp, err := qe.GenerateSIG("Nested Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	// MFA-related questions should get automated answers.
	foundMFA := false
	for _, q := range resp.Questions {
		if strings.Contains(q.Answer, "multi-factor authentication") {
			foundMFA = true
		}
	}
	if !foundMFA {
		t.Error("Expected MFA answer from nested scan results")
	}
}

func TestMultipleKeywordsMatchSameQuestion(t *testing.T) {
	qe := NewQuestionnaireEngine()

	// Provide multiple keywords that could match the same question.
	scanResults := map[string]interface{}{
		"mfa":               true,
		"2fa":               true,
		"multi_factor_auth": true,
	}

	resp, err := qe.GenerateSIG("KeywordTest Corp", scanResults)
	if err != nil {
		t.Fatalf("GenerateSIG failed: %v", err)
	}

	// The MFA answer should be generated from the first matching keyword.
	foundMFA := false
	for _, q := range resp.Questions {
		if strings.Contains(q.Answer, "multi-factor authentication") {
			foundMFA = true
			// The answer should have high confidence from automated_scan.
			if q.Confidence < 0.8 {
				t.Errorf("MFA answer should have high confidence, got %.2f", q.Confidence)
			}
		}
	}
	if !foundMFA {
		t.Error("Expected MFA answer from multiple keyword matches")
	}
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkGenerateSIG(b *testing.B) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                   true,
		"encryption_at_rest":    "aes-256",
		"encryption_in_transit": "tls_1.3",
		"access_control":        "rbac",
		"firewall":              "cloud_waf",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := qe.GenerateSIG(fmt.Sprintf("BenchCorp-%d", i), scanResults)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateCAIQ(b *testing.B) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                   true,
		"encryption_at_rest":    "aes-256",
		"encryption_in_transit": "tls_1.3",
		"iam":                   "okta",
		"security_logging":      "splunk",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := qe.GenerateCAIQ(fmt.Sprintf("BenchCorp-%d", i), scanResults)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExportToCSV(b *testing.B) {
	qe := NewQuestionnaireEngine()
	scanResults := map[string]interface{}{
		"mfa":                true,
		"encryption_at_rest": "aes-256",
	}
	resp, err := qe.GenerateSIG("BenchCorp", scanResults)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ExportToCSV(resp)
		if err != nil {
			b.Fatal(err)
		}
	}
}
