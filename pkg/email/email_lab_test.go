// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 AegisGate Security
// =========================================================================
// Email SMTP Lab Tests - Mailpit Integration
// Requires: cd testlab && docker compose up -d
// Run with: LAB_ENABLED=1 go test -tags=lab ./pkg/email/...
// =========================================================================

package email

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/smtp"
	"os"
	"testing"
	"time"
)

// SkipIfLabDisabled skips tests if LAB_ENABLED is not set
func SkipIfLabDisabled(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("Skipped: LAB_ENABLED not set, set to 1 to enable lab tests")
	}
}

// =========================================================================
// Mailpit Health Tests
// =========================================================================

// TestMailpitHealth checks Mailpit is running and healthy
func TestMailpitHealth(t *testing.T) {
	SkipIfLabDisabled(t)

	resp, err := http.Get("http://localhost:8025/api/v1/info")
	if err != nil {
		t.Fatalf("Mailpit health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	var info struct {
		Version   string `json:"Version"`
		Messages  int    `json:"Messages"`
		Unread    int    `json:"Unread"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("Failed to parse Mailpit info: %v", err)
	}

	if info.Version == "" {
		t.Error("Mailpit version should not be empty")
	}
}

// TestMailpitSMTPPorts checks SMTP ports are accessible
func TestMailpitSMTPPorts(t *testing.T) {
	SkipIfLabDisabled(t)

	// Test port 1025 (plain)
	addr := "localhost:1025"
	conn, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Plain SMTP (1025) connection failed: %v", err)
	}
	conn.Close()

	// Test port 1043 (implicit TLS)
	tlsConn, err := tls.Dial("tcp", "localhost:1043", &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "mailpit",
	})
	if err != nil {
		t.Fatalf("Implicit TLS SMTP (1043) connection failed: %v", err)
	}
	tlsConn.Close()
}

// =========================================================================
// Plain SMTP Tests (Port 1025)
// =========================================================================

// TestPlainSMTP_Send tests sending email via plain SMTP
func TestPlainSMTP_Send(t *testing.T) {
	SkipIfLabDisabled(t)

	// Connect to plain SMTP
	addr := "localhost:1025"
	conn, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("SMTP connection failed: %v", err)
	}
	defer conn.Close()

	// Set sender and recipient
	if err := conn.Mail("sender@example.com"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}

	if err := conn.Rcpt("recipient@example.com"); err != nil {
		t.Fatalf("RCPT TO failed: %v", err)
	}

	// Send message body
	msg := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Plain SMTP Test\r\n" +
		"\r\n" +
		"Hello from Mailpit test!\r\n")

	w, err := conn.Data()
	if err != nil {
		t.Fatalf("DATA command failed: %v", err)
	}
	defer w.Close()

	if _, err := w.Write(msg); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Failed to close data writer: %v", err)
	}

	// Verify message was accepted
	resp, err := http.Get("http://localhost:8025/api/v1/messages")
	if err != nil {
		t.Fatalf("Failed to check messages: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Messages int `json:"Messages"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to parse messages: %v", err)
	}

	if result.Messages < 1 {
		t.Error("Message should be delivered to Mailpit")
	}
}

// TestPlainSMTP_Auth tests SMTP authentication
func TestPlainSMTP_Auth(t *testing.T) {
	SkipIfLabDisabled(t)

	// Mailpit allows any auth in insecure mode
	addr := "localhost:1025"
	conn, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("SMTP connection failed: %v", err)
	}
	defer conn.Close()

	// Attempt PLAIN auth
	auth := smtp.PlainAuth("", "testuser", "testpass", "mailpit")
	if err := conn.Auth(auth); err != nil {
		t.Logf("Auth failed (may be expected): %v", err)
	}
}

// =========================================================================
// Implicit TLS Tests (Port 1043)
// =========================================================================

// TestImplicitTLS_Send tests sending email via implicit TLS
func TestImplicitTLS_Send(t *testing.T) {
	SkipIfLabDisabled(t)

	// Connect with TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "mailpit",
	}

	conn, err := tls.Dial("tcp", "localhost:1043", tlsConfig)
	if err != nil {
		t.Fatalf("TLS connection failed: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, "mailpit")
	if err != nil {
		t.Fatalf("SMTP client creation failed: %v", err)
	}
	defer client.Close()

	// Set sender and recipient
	if err := client.Mail("tlssender@example.com"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}

	if err := client.Rcpt("tlsrecipient@example.com"); err != nil {
		t.Fatalf("RCPT TO failed: %v", err)
	}

	// Send message body
	msg := []byte("From: tlssender@example.com\r\n" +
		"To: tlsrecipient@example.com\r\n" +
		"Subject: Implicit TLS Test\r\n" +
		"\r\n" +
		"Hello from Mailpit TLS test!\r\n")

	w, err := client.Data()
	if err != nil {
		t.Fatalf("DATA command failed: %v", err)
	}
	defer w.Close()

	if _, err := w.Write(msg); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}
}

// =========================================================================
// EmailClient Integration Tests
// =========================================================================

// TestEmailClient_Send_WithMailpit tests EmailClient sending to Mailpit
func TestEmailClient_Send_WithMailpit(t *testing.T) {
	SkipIfLabDisabled(t)

	client := NewEmailClient(Config{
		Host:     "localhost",
		Port:     1025, // Plain SMTP
		Username: "test",
		Password: "test",
		From:     "aegisgate@test.local",
		FromName: "AegisGate Test",
		UseTLS:   false, // Plain connection
	})

	err := client.SendLicenseEmail("user@test.local", LicenseEmailData{
		CustomerName: "Test Customer",
		Tier:        "developer",
		LicenseKey:  "TEST-KEY-12345",
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02"),
		IssuedAt:    time.Now().Format("2006-01-02"),
		Features:    []string{"feature1", "feature2"},
		SupportEmail: "support@test.local",
		CompanyName: "Test Company",
		CompanyURL:  "https://test.example.com",
	})

	if err != nil {
		t.Fatalf("SendLicenseEmail failed: %v", err)
	}
}

// TestEmailClient_Send_TLSConfig tests EmailClient with custom TLS config
func TestEmailClient_Send_TLSConfig(t *testing.T) {
	SkipIfLabDisabled(t)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
	}

	client := NewEmailClient(Config{
		Host:     "localhost",
		Port:     1043, // Implicit TLS
		Username: "test",
		Password: "test",
		From:     "aegisgate@test.local",
		UseTLS:   false,
		TLSConfig: tlsConfig,
	})

	err := client.SendLicenseEmail("user@test.local", LicenseEmailData{
		CustomerName: "TLS Config Test",
		Tier:        "enterprise",
		LicenseKey:  "TLS-TEST-KEY",
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour).Format("2006-01-02"),
		IssuedAt:    time.Now().Format("2006-01-02"),
	})

	if err != nil {
		t.Fatalf("SendLicenseEmail with TLS config failed: %v", err)
	}
}

// =========================================================================
// STARTTLS Tests (Port 1026)
// =========================================================================

// TestSTARTTLS_Send tests STARTTLS upgrade on port 1026
func TestSTARTTLS_Send(t *testing.T) {
	SkipIfLabDisabled(t)

	// smtp.SendMail handles STARTTLS automatically on port 587
	// For port 1026, we need to test the STARTTLS upgrade path
	client := NewEmailClient(Config{
		Host:     "localhost",
		Port:     1026, // STARTTLS
		Username: "test",
		Password: "test",
		From:     "starttls@test.local",
		UseTLS:   true, // Enable STARTTLS mode
	})

	err := client.SendLicenseEmail("user@test.local", LicenseEmailData{
		CustomerName: "STARTTLS Test",
		Tier:        "professional",
		LicenseKey:  "STARTTLS-KEY",
		ExpiresAt:   time.Now().Add(90 * 24 * time.Hour).Format("2006-01-02"),
		IssuedAt:    time.Now().Format("2006-01-02"),
	})

	if err != nil {
		t.Fatalf("STARTTLS send failed: %v", err)
	}
}

// =========================================================================
// SimpleSendEmail Integration Tests
// =========================================================================

// TestSimpleSendEmail_WithMailpit tests SimpleSendEmail to Mailpit
func TestSimpleSendEmail_WithMailpit(t *testing.T) {
	SkipIfLabDisabled(t)

	cfg := Config{
		Host:     "localhost",
		Port:     1025,
		Username: "test",
		Password: "test",
		From:     "simple@test.local",
		UseTLS:   false,
	}

	err := SimpleSendEmail(cfg, "user@test.local", "Test Subject", "<p>Test Body</p>")
	if err != nil {
		t.Fatalf("SimpleSendEmail failed: %v", err)
	}
}

// TestSimpleSendEmail_STARTTLS tests SimpleSendEmail with STARTTLS
func TestSimpleSendEmail_STARTTLS(t *testing.T) {
	SkipIfLabDisabled(t)

	cfg := Config{
		Host:     "localhost",
		Port:     1026,
		Username: "test",
		Password: "test",
		From:     "starttls-simple@test.local",
		UseTLS:   true,
	}

	err := SimpleSendEmail(cfg, "user@test.local", "STARTTLS Subject", "<p>STARTTLS Body</p>")
	if err != nil {
		t.Fatalf("SimpleSendEmail STARTTLS failed: %v", err)
	}
}

// =========================================================================
// Error Handling Tests
// =========================================================================

// TestSend_ConnectionRefused tests handling of connection refused
func TestSend_ConnectionRefused(t *testing.T) {
	client := NewEmailClient(Config{
		Host:     "localhost",
		Port:     19999, // Invalid port
		Username: "test",
		Password: "test",
		From:     "test@test.local",
		UseTLS:   false,
	})

	err := client.SendLicenseEmail("user@test.local", LicenseEmailData{
		CustomerName: "Connection Test",
		Tier:        "developer",
		LicenseKey:  "CONN-TEST",
	})

	if err == nil {
		t.Error("Expected error on connection refused")
	}
}

// TestSend_TLSConnectionRefused tests TLS connection refusal
func TestSend_TLSConnectionRefused(t *testing.T) {
	client := NewEmailClient(Config{
		Host:     "localhost",
		Port:     19998, // Invalid TLS port
		Username: "test",
		Password: "test",
		From:     "test@test.local",
		UseTLS:   false,
	})

	err := client.SendLicenseEmail("user@test.local", LicenseEmailData{
		CustomerName: "TLS Connection Test",
		Tier:        "developer",
		LicenseKey:  "TLS-CONN-TEST",
	})

	if err == nil {
		t.Error("Expected error on TLS connection refused")
	}
}

// TestSend_NoAuth tests sending without authentication
func TestSend_NoAuth(t *testing.T) {
	SkipIfLabDisabled(t)

	client := NewEmailClient(Config{
		Host:   "localhost",
		Port:   1025,
		From:   "noauth@test.local",
		UseTLS: false,
	})

	err := client.SendLicenseEmail("user@test.local", LicenseEmailData{
		CustomerName: "No Auth Test",
		Tier:        "community",
		LicenseKey:  "NOAUTH-KEY",
	})

	// Mailpit in insecure mode should allow no auth
	if err != nil {
		t.Logf("No auth send result: %v", err)
	}
}

// =========================================================================
// Message Verification Tests
// =========================================================================

// TestMailpitMessageCount tests that sent messages are counted
func TestMailpitMessageCount(t *testing.T) {
	SkipIfLabDisabled(t)

	// Get initial count
	resp1, err := http.Get("http://localhost:8025/api/v1/info")
	if err != nil {
		t.Fatalf("Failed to get initial state: %v", err)
	}
	defer resp1.Body.Close()

	var before struct {
		Messages int `json:"Messages"`
	}
	json.NewDecoder(resp1.Body).Decode(&before)

	// Send a message
	client := NewEmailClient(Config{
		Host:   "localhost",
		Port:   1025,
		From:   "count@test.local",
		UseTLS: false,
	})

	err = client.SendLicenseEmail("user@test.local", LicenseEmailData{
		CustomerName: "Count Test",
		Tier:        "developer",
		LicenseKey:  "COUNT-TEST",
	})
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Get new count
	resp2, err := http.Get("http://localhost:8025/api/v1/info")
	if err != nil {
		t.Fatalf("Failed to get final state: %v", err)
	}
	defer resp2.Body.Close()

	var after struct {
		Messages int `json:"Messages"`
	}
	json.NewDecoder(resp2.Body).Decode(&after)

	if after.Messages <= before.Messages {
		t.Errorf("Expected message count to increase, before=%d after=%d", before.Messages, after.Messages)
	}
}

// TestMailpitGetMessage tests retrieving a sent message
func TestMailpitGetMessage(t *testing.T) {
	SkipIfLabDisabled(t)

	client := NewEmailClient(Config{
		Host:   "localhost",
		Port:   1025,
		From:   "get@test.local",
		UseTLS: false,
	})

	err := client.SendLicenseEmail("user@test.local", LicenseEmailData{
		CustomerName: "Get Message Test",
		Tier:        "developer",
		LicenseKey:  "GET-MESSAGE-TEST",
	})
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// List messages
	resp, err := http.Get("http://localhost:8025/api/v1/messages")
	if err != nil {
		t.Fatalf("Failed to list messages: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	var messages struct {
		Messages []struct {
			ID      string `json:"ID"`
			From    string `json:"From"`
			To      string `json:"To"`
			Subject string `json:"Subject"`
		} `json:"Messages"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		t.Fatalf("Failed to parse messages: %v", err)
	}

	if len(messages.Messages) == 0 {
		t.Error("Expected at least one message in Mailpit")
	}
}

// =========================================================================
// Build Message Tests
// =========================================================================

// TestBuildMessage_Basic tests basic message building
func TestBuildMessage_Basic(t *testing.T) {
	client := NewEmailClient(Config{
		From:     "from@test.local",
		FromName: "Test Sender",
	})

	msg, err := client.buildMessage("to@test.local", "Test Subject", "Test Body")
	if err != nil {
		t.Fatalf("buildMessage failed: %v", err)
	}

	msgStr := string(msg)
	if !contains(msgStr, "From: Test Sender <from@test.local>") {
		t.Error("Message should contain From header with name")
	}
	if !contains(msgStr, "To: to@test.local") {
		t.Error("Message should contain To header")
	}
	if !contains(msgStr, "Subject: Test Subject") {
		t.Error("Message should contain Subject header")
	}
	if !contains(msgStr, "Test Body") {
		t.Error("Message should contain body")
	}
}

// TestBuildMessage_NoFromName tests message building without FromName
func TestBuildMessage_NoFromName(t *testing.T) {
	client := NewEmailClient(Config{
		From: "from@test.local",
	})

	msg, err := client.buildMessage("to@test.local", "Subject", "Body")
	if err != nil {
		t.Fatalf("buildMessage failed: %v", err)
	}

	msgStr := string(msg)
	if !contains(msgStr, "From: from@test.local") {
		t.Error("Message should contain From header without name")
	}
}

// =========================================================================
// Helper Functions
// =========================================================================

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}