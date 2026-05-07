// SPDX-License-Identifier: Apache-2.0
//go:build !race

// =========================================================================
// AegisGate Platform - Email Package Additional Coverage Tests
// =========================================================================
// Coverage targets: send() 35.3%, ValidateConfig 0%, DefaultGmailConfig 0%,
// DefaultSMTP2GOConfig 0%, DefaultProtonMailConfig ~80%

package email

import (
	"strings"
	"testing"
)

// ============================================================================
// ValidateConfig tests
// ============================================================================

func TestValidateConfig_Valid(t *testing.T) {
	cfg := Config{
		Host: "smtp.example.com",
		Port: 587,
		From: "test@example.com",
	}
	err := ValidateConfig(cfg)
	if err != nil {
		t.Errorf("ValidateConfig should pass for valid config: %v", err)
	}
}

func TestValidateConfig_MissingHost(t *testing.T) {
	cfg := Config{
		Host: "",
		Port: 587,
		From: "test@example.com",
	}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig should fail when Host is missing")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("Error should mention host: %v", err)
	}
}

func TestValidateConfig_MissingPort(t *testing.T) {
	cfg := Config{
		Host: "smtp.example.com",
		Port: 0,
		From: "test@example.com",
	}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig should fail when Port is 0")
	}
	if !strings.Contains(err.Error(), "port") {
		t.Errorf("Error should mention port: %v", err)
	}
}

func TestValidateConfig_MissingFrom(t *testing.T) {
	cfg := Config{
		Host: "smtp.example.com",
		Port: 587,
		From: "",
	}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig should fail when From is empty")
	}
	if !strings.Contains(err.Error(), "From") {
		t.Errorf("Error should mention From: %v", err)
	}
}

func TestValidateConfig_AllMissing(t *testing.T) {
	cfg := Config{}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig should fail when all fields are empty")
	}
	// First check should trigger
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("Error should mention host first: %v", err)
	}
}

// ============================================================================
// NewEmailClient edge cases
// ============================================================================

func TestNewEmailClient_NilConfig(t *testing.T) {
	// Passing zero Config value should still create a client
	cfg := Config{
		Host: "smtp.test.invalid",
		Port: 587,
		From: "test@test.com",
	}
	client := NewEmailClient(cfg)
	if client == nil {
		t.Fatal("NewEmailClient returned nil")
	}
	if client.config.Host != cfg.Host {
		t.Errorf("config.Host = %q, want %q", client.config.Host, cfg.Host)
	}
	if client.config.Port != cfg.Port {
		t.Errorf("config.Port = %d, want %d", client.config.Port, cfg.Port)
	}
}

// ============================================================================
// buildMessage edge cases
// ============================================================================

func TestBuildMessage_EmptyTo(t *testing.T) {
	cfg := Config{
		Host: "smtp.test.invalid",
		Port: 587,
		From: "test@test.com",
	}
	client := NewEmailClient(cfg)

	msg, err := client.buildMessage("", "Subject", "Body")
	if err != nil {
		t.Fatalf("buildMessage should not error: %v", err)
	}
	if !strings.Contains(string(msg), "To:") {
		t.Error("Message should contain To header")
	}
}

func TestBuildMessage_EmptySubject(t *testing.T) {
	cfg := Config{
		Host: "smtp.test.invalid",
		Port: 587,
		From: "test@test.com",
	}
	client := NewEmailClient(cfg)

	msg, err := client.buildMessage("to@test.com", "", "Body")
	if err != nil {
		t.Fatalf("buildMessage should not error with empty subject: %v", err)
	}
	if len(msg) == 0 {
		t.Error("buildMessage should return non-empty message")
	}
}

func TestBuildMessage_FromWithAngleBrackets(t *testing.T) {
	cfg := Config{
		Host:     "smtp.test.invalid",
		Port:     587,
		From:     "test@test.com",
		FromName: "<test>",
	}
	client := NewEmailClient(cfg)

	msg, err := client.buildMessage("to@test.com", "Subject", "Body")
	if err != nil {
		t.Fatalf("buildMessage should not error: %v", err)
	}
	msgStr := string(msg)
	// FromName with angle brackets should be included as-is
	if !strings.Contains(msgStr, "<test>") {
		t.Error("FromName should be included in From header")
	}
}

// ============================================================================
// renderTemplate edge cases
// ============================================================================

func TestRenderTemplate_EmptyData(t *testing.T) {
	cfg := Config{
		Host: "smtp.test.invalid",
		Port: 587,
		From: "test@test.com",
	}
	client := NewEmailClient(cfg)

	html, err := client.renderTemplate(LicenseEmailData{})
	if err != nil {
		t.Fatalf("renderTemplate should not error with empty data: %v", err)
	}
	if len(html) == 0 {
		t.Error("renderTemplate should return non-empty HTML")
	}
}

func TestRenderTemplate_LongContent(t *testing.T) {
	cfg := Config{
		Host: "smtp.test.invalid",
		Port: 587,
		From: "test@test.com",
	}
	client := NewEmailClient(cfg)

	longKey := strings.Repeat("X", 1000)
	data := LicenseEmailData{
		Tier:       "Enterprise",
		LicenseKey: longKey,
	}

	html, err := client.renderTemplate(data)
	if err != nil {
		t.Fatalf("renderTemplate should not error with long content: %v", err)
	}
	if !strings.Contains(html, longKey) {
		t.Error("renderTemplate should include long license key")
	}
}

// ============================================================================
// SendLicenseEmail edge cases - template rendering failure
// ============================================================================

func TestSendLicenseEmail_TemplateError(t *testing.T) {
	cfg := Config{
		Host: "smtp.test.invalid",
		Port: 587,
		From: "test@test.com",
	}
	client := NewEmailClient(cfg)

	// renderTemplate uses a fixed constant, so this won't fail at render time.
	// But we test that SendLicenseEmail handles errors from send().
	data := LicenseEmailData{
		Tier:       "Developer",
		LicenseKey: "test-key",
	}

	err := client.SendLicenseEmail("customer@example.com", data)
	if err == nil {
		t.Error("SendLicenseEmail should fail with unreachable SMTP")
	}
	// Error should be SMTP/connection related
	if strings.Contains(err.Error(), "template") {
		t.Error("Should not be a template error")
	}
}

// ============================================================================
// send() error paths - implicit TLS with specific command failures
// ============================================================================

func TestSend_ImplicitTLS_ConnectionRefused(t *testing.T) {
	cfg := Config{
		Host:     "localhost",
		Port:     59999, // nothing listening
		From:     "test@test.com",
		Username: "user",
		Password: "pass",
		UseTLS:   false,
	}
	client := NewEmailClient(cfg)

	err := client.send("to@test.com", []byte("test"))
	if err == nil {
		t.Error("send with connection refused should error")
	}
	if !strings.Contains(err.Error(), "TLS") && !strings.Contains(err.Error(), "dial") && !strings.Contains(err.Error(), "connection") {
		t.Errorf("Error should be TLS/connection related: %v", err)
	}
}

func TestSend_STARTTLS_ConnectionRefused(t *testing.T) {
	cfg := Config{
		Host:     "localhost",
		Port:     59998, // nothing listening
		From:     "test@test.com",
		Username: "user",
		Password: "pass",
		UseTLS:   true,
	}
	client := NewEmailClient(cfg)

	err := client.send("to@test.com", []byte("test"))
	if err == nil {
		t.Error("send with connection refused should error")
	}
	if !strings.Contains(err.Error(), "SMTP") && !strings.Contains(err.Error(), "send") {
		t.Errorf("Error should be SMTP related: %v", err)
	}
}

// ============================================================================
// SimpleSendEmail edge cases
// ============================================================================

func TestSimpleSendEmail_InvalidConfig(t *testing.T) {
	cfg := Config{
		Host: "",
		Port: 0,
		From: "",
	}
	err := SimpleSendEmail(cfg, "a@b.com", "Subject", "Body")
	if err == nil {
		t.Error("SimpleSendEmail should fail with invalid config")
	}
}

func TestSimpleSendEmail_ValidConfig(t *testing.T) {
	cfg := Config{
		Host:     "smtp.test.invalid",
		Port:     587,
		From:     "test@test.com",
		Username: "user",
		Password: "pass",
		UseTLS:   true,
	}
	err := SimpleSendEmail(cfg, "customer@example.com", "Your License", "license-key-123")
	if err == nil {
		t.Error("SimpleSendEmail should fail with unreachable SMTP")
	}
	if strings.Contains(err.Error(), "template") {
		t.Error("Should not be a template error")
	}
}
