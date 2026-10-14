// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — SARIF Output Formatter Tests
// =========================================================================

package sarifoutput

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
)

// helper: create a Platform scanner Finding
func makeFinding(patternName, desc string, sev scanner.Severity, cat scanner.Category, match string, pos int) scanner.Finding {
	return scanner.Finding{
		Pattern: &scanner.Pattern{
			Name:        patternName,
			Severity:    sev,
			Category:    cat,
			Description: desc,
		},
		Match:    match,
		Position: pos,
		Context:  "some context here",
	}
}

func TestFormatSARIF_EmptyFindings(t *testing.T) {
	findings := []scanner.Finding{}
	ctx := &ScanContext{Host: "api.openai.com", Path: "/v1/chat", Direction: "request"}

	data, err := FormatSARIF(findings, ctx, "v4.5.3")
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(log.Runs[0].Results))
	}
	if log.Runs[0].Tool.Driver.Name != "aegisgate-platform" {
		t.Errorf("expected tool name aegisgate-platform, got %s", log.Runs[0].Tool.Driver.Name)
	}
}

func TestFormatSARIF_SingleFinding(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("pii_credit_card_visa", "Visa credit card number", scanner.Critical, scanner.CategoryFinancial, "4111111111111111", 42),
	}
	ctx := &ScanContext{Host: "api.openai.com", Path: "/v1/chat/completions", Direction: "request"}

	data, err := FormatSARIF(findings, ctx, "v4.5.3")
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(log.Runs[0].Results))
	}

	r := log.Runs[0].Results[0]
	if r.RuleID != "pii_credit_card_visa" {
		t.Errorf("expected ruleId pii_credit_card_visa, got %s", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("expected level error for critical, got %s", r.Level)
	}
	if len(r.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r.Locations))
	}
	uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI
	if !strings.Contains(uri, "request") {
		t.Errorf("expected URI to contain 'request', got %s", uri)
	}
	if !strings.Contains(uri, "api.openai.com") {
		t.Errorf("expected URI to contain host, got %s", uri)
	}
}

func TestFormatSARIF_MultipleFindings(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("pii_ssn", "SSN", scanner.Critical, scanner.CategoryPII, "123-45-6789", 10),
		makeFinding("secret_rsa_private_key", "RSA private key", scanner.Critical, scanner.CategoryCryptographic, "-----BEGIN", 50),
		makeFinding("pii_credit_card_visa", "Visa", scanner.Critical, scanner.CategoryFinancial, "4111", 100),
	}
	ctx := &ScanContext{Host: "api.anthropic.com", Path: "/v1/messages", Direction: "response"}

	data, err := FormatSARIF(findings, ctx, "v4.5.3")
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(log.Runs[0].Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(log.Runs[0].Results))
	}

	// Should have 3 unique rules (all different names)
	if len(log.Runs[0].Tool.Driver.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}
}

func TestFormatSARIF_DuplicateRules(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("pii_ssn", "SSN", scanner.Critical, scanner.CategoryPII, "123-45-6789", 10),
		makeFinding("pii_ssn", "SSN", scanner.Critical, scanner.CategoryPII, "987-65-4321", 50),
		makeFinding("pii_ssn", "SSN", scanner.Critical, scanner.CategoryPII, "111-22-3333", 100),
	}
	ctx := &ScanContext{Host: "api.openai.com", Path: "/v1/chat", Direction: "request"}

	data, err := FormatSARIF(findings, ctx, "v4.5.3")
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// 3 results but only 1 unique rule
	if len(log.Runs[0].Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(log.Runs[0].Results))
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 unique rule, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}
}

func TestFormatSARIF_SeverityMapping(t *testing.T) {
	tests := []struct {
		sev    scanner.Severity
		expect string
	}{
		{scanner.Critical, "error"},
		{scanner.High, "error"},
		{scanner.Medium, "warning"},
		{scanner.Low, "note"},
		{scanner.Info, "none"},
	}

	for _, tt := range tests {
		findings := []scanner.Finding{
			makeFinding("test_rule", "Test", tt.sev, scanner.CategoryPII, "match", 0),
		}
		ctx := &ScanContext{Host: "h", Path: "/p", Direction: "request"}

		data, err := FormatSARIF(findings, ctx, "v1")
		if err != nil {
			t.Fatalf("FormatSARIF failed: %v", err)
		}

		var log sarifLog
		json.Unmarshal(data, &log)

		if len(log.Runs[0].Results) != 1 {
			t.Fatalf("expected 1 result")
		}
		if log.Runs[0].Results[0].Level != tt.expect {
			t.Errorf("severity %v → expected %s, got %s", tt.sev, tt.expect, log.Runs[0].Results[0].Level)
		}
	}
}

func TestFormatSARIF_NilContext(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("test_rule", "Test", scanner.High, scanner.CategoryPII, "match", 0),
	}

	data, err := FormatSARIF(findings, nil, "v1")
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	var log sarifLog
	json.Unmarshal(data, &log)

	uri := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if uri != "unknown" {
		t.Errorf("expected 'unknown' URI for nil context, got %s", uri)
	}
}

func TestFormatSARIF_NilPattern(t *testing.T) {
	findings := []scanner.Finding{
		{Pattern: nil, Match: "test", Position: 5, Context: ""},
	}
	ctx := &ScanContext{Host: "h", Path: "/p", Direction: "request"}

	data, err := FormatSARIF(findings, ctx, "v1")
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	var log sarifLog
	json.Unmarshal(data, &log)

	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result")
	}
	// RuleID should be empty for nil pattern
	if log.Runs[0].Results[0].RuleID != "" {
		t.Errorf("expected empty ruleId for nil pattern, got %s", log.Runs[0].Results[0].RuleID)
	}
}

func TestFormatFindingsSARIF_Convenience(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("pii_ssn", "SSN", scanner.Critical, scanner.CategoryPII, "123-45-6789", 10),
	}

	data, err := FormatFindingsSARIF(findings, "api.openai.com", "/v1/chat", "request", "v4.5.3")
	if err != nil {
		t.Fatalf("FormatFindingsSARIF failed: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	uri := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if !strings.Contains(uri, "api.openai.com") {
		t.Errorf("expected URI to contain host, got %s", uri)
	}
}

func TestFormatSARIF_RuleProperties(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("pii_credit_card_visa", "Visa credit card number", scanner.Critical, scanner.CategoryFinancial, "4111", 0),
	}
	ctx := &ScanContext{Host: "h", Path: "/p", Direction: "request"}

	data, err := FormatSARIF(findings, ctx, "v1")
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	var log sarifLog
	json.Unmarshal(data, &log)

	if len(log.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule")
	}

	rule := log.Runs[0].Tool.Driver.Rules[0]
	if rule.ID != "pii_credit_card_visa" {
		t.Errorf("expected rule ID pii_credit_card_visa, got %s", rule.ID)
	}
	if rule.Properties.Severity != "Critical" {
		t.Errorf("expected severity 'Critical', got %s", rule.Properties.Severity)
	}
	if rule.Properties.Category != "Financial" {
		t.Errorf("expected category 'Financial', got %s", rule.Properties.Category)
	}
	// Should have security tags
	if len(rule.Properties.Tags) == 0 {
		t.Error("expected non-empty tags")
	}
}

func TestFormatSARIF_RulesSorted(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("zzz_rule", "Z", scanner.High, scanner.CategoryPII, "z", 0),
		makeFinding("aaa_rule", "A", scanner.High, scanner.CategoryPII, "a", 0),
		makeFinding("mmm_rule", "M", scanner.High, scanner.CategoryPII, "m", 0),
	}
	ctx := &ScanContext{Host: "h", Path: "/p", Direction: "request"}

	data, err := FormatSARIF(findings, ctx, "v1")
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	var log sarifLog
	json.Unmarshal(data, &log)

	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	if rules[0].ID != "aaa_rule" {
		t.Errorf("expected first rule aaa_rule, got %s", rules[0].ID)
	}
	if rules[2].ID != "zzz_rule" {
		t.Errorf("expected last rule zzz_rule, got %s", rules[2].ID)
	}
}

func TestFormatSARIF_Fingerprint(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("pii_ssn", "SSN", scanner.Critical, scanner.CategoryPII, "123-45-6789", 42),
	}
	ctx := &ScanContext{Host: "api.openai.com", Path: "/v1/chat", Direction: "request"}

	data, err := FormatSARIF(findings, ctx, "v1")
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	var log sarifLog
	json.Unmarshal(data, &log)

	fp := log.Runs[0].Results[0].PartialFingerprints.PrimaryLocationLineHash
	if !strings.Contains(fp, "pii_ssn") {
		t.Errorf("expected fingerprint to contain rule ID, got %s", fp)
	}
	if !strings.Contains(fp, "42") {
		t.Errorf("expected fingerprint to contain position, got %s", fp)
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 100) != "short" {
		t.Error("short string should be unchanged")
	}
	result := truncate("this is a very long string that exceeds the limit", 20)
	if len(result) > 20 {
		t.Errorf("truncated string too long: %d", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Error("truncated string should end with ...")
	}
}

func TestBuildArtifactURI(t *testing.T) {
	tests := []struct {
		ctx    *ScanContext
		expect string
	}{
		{&ScanContext{Host: "api.openai.com", Path: "/v1/chat", Direction: "request"}, "request:api.openai.com/v1/chat"},
		{&ScanContext{Host: "api.openai.com", Path: "", Direction: "response"}, "response:api.openai.com/"},
		{&ScanContext{Host: "", Path: "/p", Direction: ""}, "unknown:unknown/p"},
		{nil, "unknown"},
	}

	for _, tt := range tests {
		result := buildArtifactURI(tt.ctx)
		if result != tt.expect {
			t.Errorf("expected %s, got %s", tt.expect, result)
		}
	}
}

func TestBuildRuleTags(t *testing.T) {
	tests := []struct {
		category     string
		expectSubstr string
	}{
		{"PII", "pii"},
		{"Credential", "credentials"},
		{"XSS", "xss"},
		{"Compliance", "compliance"},
		{"Network", "network"},
		{"Cryptographic", "cryptographic"},
		{"Prompt", "prompt-injection"},
		{"unknown", ""}, // should still have security + ai-security
	}

	for _, tt := range tests {
		tags := buildRuleTags(tt.category)
		if !containsStr(tags, "security") {
			t.Errorf("expected 'security' tag for category %s", tt.category)
		}
		if !containsStr(tags, "ai-security") {
			t.Errorf("expected 'ai-security' tag for category %s", tt.category)
		}
		if tt.expectSubstr != "" && !containsStr(tags, tt.expectSubstr) {
			t.Errorf("expected tag '%s' for category %s, got %v", tt.expectSubstr, tt.category, tags)
		}
	}
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}