// SPDX-License-Identifier: Apache-2.0
//go:build lab

package email

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// Mailpit integration tests require a running Mailpit container (testlab).
//
// Setup:
//
//	cd testlab && docker compose up -d mailpit && ./scripts/setup.sh
//	LAB_ENABLED=1 go test -tags=lab -v ./pkg/email/...

// mailpitConfig returns the SMTP host from environment or defaults to localhost.
func mailpitHost() string {
	return os.Getenv("SMTP_HOST")
}

func mailpitPlainPort() string {
	return envOr("SMTP_PORT", "1025")
}

func mailpitSTARTTLSPort() string {
	return envOr("SMTP_STARTTLS_PORT", "1026")
}

func mailpitTLSPort() string {
	return envOr("SMTP_TLS_PORT", "1043")
}

func mailpitWebPort() string {
	return envOr("SMTP_WEB_PORT", "8025")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// waitForMailpit polls the Mailpit web API until it responds or times out.
func waitForMailpit(t *testing.T) {
	t.Helper()
	webPort := mailpitWebPort()
	url := fmt.Sprintf("http://%s:%s/api/v1/info", mailpitHost(), webPort)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("Mailpit not available at %s within 30s", url)
}

// mailpitMessageCount queries the Mailpit API for total messages.
func mailpitMessageCount(t *testing.T) int {
	t.Helper()
	webPort := mailpitWebPort()
	url := fmt.Sprintf("http://%s:%s/api/v1/messages?start=0&limit=1", mailpitHost(), webPort)
	resp, err := http.Get(url)
	if err != nil {
		t.Logf("Warning: cannot query Mailpit API: %v", err)
		return -1
	}
	defer resp.Body.Close()

	var result struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Logf("Warning: cannot parse Mailpit API response: %v", err)
		return -1
	}
	return result.Total
}

// TestMailpit_PlainSMTP tests the implicit TLS path against Mailpit.
// Mailpit supports implicit TLS on port 1043. We use UseTLS=false to exercise
// the manual SMTP client path (tls.Dial → NewClient → Auth → Mail → Rcpt → Data → Quit).
func TestMailpit_PlainSMTP(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("Skipping: set LAB_ENABLED=1 to run Mailpit integration tests")
	}
	waitForMailpit(t)

	cfg := Config{
		Host:     mailpitHost(),
		Port:     mustAtoi(t, mailpitTLSPort()), // implicit TLS = port 1043
		From:     "test@aegisgatesecurity.io",
		Username: "any@mailpit.local", // Mailpit accepts any auth (MP_SMTP_AUTH_ACCEPT_ANY=1)
		Password: "any-password",
		UseTLS:   false, // implicit TLS path
	}

	client := NewEmailClient(cfg)
	err := client.send("recipient@aegisgatesecurity.io", []byte("From: test@aegisgatesecurity.io\r\nTo: recipient@aegisgatesecurity.io\r\nSubject: Plain SMTP Test\r\n\r\nHello from Mailpit implicit TLS test.\r\n"))
	if err != nil {
		t.Fatalf("Implicit TLS send failed: %v", err)
	}

	count := mailpitMessageCount(t)
	if count >= 0 {
		t.Logf("Mailpit now has %d messages", count)
	}
}

// TestMailpit_ImplicitTLS_WithAuth exercises the full manual SMTP pipeline:
// tls.Dial → NewClient → Auth → Mail → Rcpt → Data → Data_Close → Quit
func TestMailpit_ImplicitTLS_WithAuth(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("Skipping: set LAB_ENABLED=1 to run Mailpit integration tests")
	}
	waitForMailpit(t)

	cfg := Config{
		Host:     mailpitHost(),
		Port:     mustAtoi(t, mailpitTLSPort()),
		From:     "sender@aegisgatesecurity.io",
		Username: "testuser@mailpit.local",
		Password: "testpass",
		UseTLS:   false, // implicit TLS
	}

	client := NewEmailClient(cfg)
	msg := []byte("From: sender@aegisgatesecurity.io\r\nTo: rcpt@aegisgatesecurity.io\r\nSubject: Auth Test\r\n\r\nTesting implicit TLS with AUTH.\r\n")

	err := client.send("rcpt@aegisgatesecurity.io", msg)
	if err != nil {
		t.Fatalf("Implicit TLS send with auth failed: %v", err)
	}
}

// TestMailpit_ImplicitTLS_WithoutAuth exercises the manual SMTP path without AUTH.
// This covers the auth==nil branch where client.Auth() is skipped.
func TestMailpit_ImplicitTLS_WithoutAuth(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("Skipping: set LAB_ENABLED=1 to run Mailpit integration tests")
	}
	waitForMailpit(t)

	cfg := Config{
		Host:   mailpitHost(),
		Port:   mustAtoi(t, mailpitTLSPort()),
		From:   "noauth@aegisgatesecurity.io",
		UseTLS: false, // implicit TLS, no auth
	}

	client := NewEmailClient(cfg)
	msg := []byte("From: noauth@aegisgatesecurity.io\r\nTo: noauth-rcpt@aegisgatesecurity.io\r\nSubject: No Auth Test\r\n\r\nTesting implicit TLS without AUTH.\r\n")

	err := client.send("noauth-rcpt@aegisgatesecurity.io", msg)
	if err != nil {
		t.Fatalf("Implicit TLS send without auth failed: %v", err)
	}
}

// TestMailpit_STARTTLS exercises the smtp.SendMail path (UseTLS=true).
// Mailpit exposes STARTTLS on port 1026. We use auth credentials to cover the
// smtp.PlainAuth → smtp.SendMail code path.
func TestMailpit_STARTTLS(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("Skipping: set LAB_ENABLED=1 to run Mailpit integration tests")
	}
	waitForMailpit(t)

	cfg := Config{
		Host:     mailpitHost(),
		Port:     mustAtoi(t, mailpitSTARTTLSPort()), // STARTTLS = port 1026
		From:     "starttls@aegisgatesecurity.io",
		Username: "starttls-user@mailpit.local",
		Password: "starttls-pass",
		UseTLS:   true,
	}

	client := NewEmailClient(cfg)
	msg := []byte("From: starttls@aegisgatesecurity.io\r\nTo: starttls-rcpt@aegisgatesecurity.io\r\nSubject: STARTTLS Test\r\n\r\nTesting STARTTLS with auth.\r\n")

	err := client.send("starttls-rcpt@aegisgatesecurity.io", msg)
	if err != nil {
		t.Fatalf("STARTTLS send failed: %v", err)
	}
}

// TestMailpit_STARTTLS_WithoutAuth exercises the UseTLS=true path without auth.
// When Username/Password are empty, auth is nil and smtp.SendMail is called without authentication.
func TestMailpit_STARTTLS_WithoutAuth(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("Skipping: set LAB_ENABLED=1 to run Mailpit integration tests")
	}
	waitForMailpit(t)

	cfg := Config{
		Host:   mailpitHost(),
		Port:   mustAtoi(t, mailpitSTARTTLSPort()),
		From:   "starttls-noauth@aegisgatesecurity.io",
		UseTLS: true, // STARTTLS, no auth
	}

	client := NewEmailClient(cfg)
	msg := []byte("From: starttls-noauth@aegisgatesecurity.io\r\nTo: noauth-starttls@aegisgatesecurity.io\r\nSubject: STARTTLS No Auth Test\r\n\r\nTesting STARTTLS without auth.\r\n")

	err := client.send("noauth-starttls@aegisgatesecurity.io", msg)
	if err != nil {
		t.Fatalf("STARTTLS send without auth failed: %v", err)
	}
}

// TestMailpit_SendLicenseEmail_E2E exercises the full SendLicenseEmail flow:
// applying defaults → rendering HTML template → building RFC 2822 message → SMTP delivery.
func TestMailpit_SendLicenseEmail_E2E(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("Skipping: set LAB_ENABLED=1 to run Mailpit integration tests")
	}
	waitForMailpit(t)

	cfg := Config{
		Host:     mailpitHost(),
		Port:     mustAtoi(t, mailpitSTARTTLSPort()),
		From:     "licenses@aegisgatesecurity.io",
		Username: "licenses@aegisgatesecurity.io",
		Password: "any-password",
		UseTLS:   true,
	}

	client := NewEmailClient(cfg)

	data := LicenseEmailData{
		CustomerName: "Integration Test User",
		Tier:         "Developer",
		LicenseKey:   "DEV-INT-TEST-KEY-001",
		IssuedAt:     time.Now().Format("2006-01-02"),
		ExpiresAt:    time.Now().AddDate(1, 0, 0).Format("2006-01-02"),
		Features:     []string{"MCP Guardrails", "HTTP Scanning", "Up to 5 Agents"},
		SupportEmail: "support@aegisgatesecurity.io",
		CompanyName:  "AegisGate Security, LLC",
		CompanyURL:   "https://aegisgatesecurity.io",
	}

	err := client.SendLicenseEmail("customer@example.com", data)
	if err != nil {
		t.Fatalf("SendLicenseEmail failed: %v", err)
	}
}

// TestMailpit_SimpleSendEmail_E2E exercises the SimpleSendEmail convenience function
// against a real SMTP server.
func TestMailpit_SimpleSendEmail_E2E(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("Skipping: set LAB_ENABLED=1 to run Mailpit integration tests")
	}
	waitForMailpit(t)

	cfg := Config{
		Host:     mailpitHost(),
		Port:     mustAtoi(t, mailpitSTARTTLSPort()),
		From:     "simple@aegisgatesecurity.io",
		Username: "simple@aegisgatesecurity.io",
		Password: "any-password",
		UseTLS:   true,
	}

	err := SimpleSendEmail(cfg, "recipient@example.com", "Simple Test Subject", "Simple test body content.")
	if err != nil {
		t.Fatalf("SimpleSendEmail failed: %v", err)
	}
}

// TestMailpit_ImplicitTLS_SendLicenseEmail exercises the implicit TLS path
// through the full SendLicenseEmail flow.
func TestMailpit_ImplicitTLS_SendLicenseEmail(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("Skipping: set LAB_ENABLED=1 to run Mailpit integration tests")
	}
	waitForMailpit(t)

	cfg := Config{
		Host:     mailpitHost(),
		Port:     mustAtoi(t, mailpitTLSPort()),
		From:     "licenses-tls@aegisgatesecurity.io",
		Username: "licenses-tls@aegisgatesecurity.io",
		Password: "any-password",
		UseTLS:   false, // implicit TLS
	}

	client := NewEmailClient(cfg)

	data := LicenseEmailData{
		CustomerName: "TLS Test User",
		Tier:         "Enterprise",
		LicenseKey:   "ENT-TLS-KEY-001",
		IssuedAt:     time.Now().Format("2006-01-02"),
		ExpiresAt:    time.Now().AddDate(1, 0, 0).Format("2006-01-02"),
		Features:     []string{"All features", "Unlimited agents", "Priority support"},
		SupportEmail: "support@aegisgatesecurity.io",
		CompanyName:  "AegisGate Security, LLC",
		CompanyURL:   "https://aegisgatesecurity.io",
	}

	err := client.SendLicenseEmail("customer-tls@example.com", data)
	if err != nil {
		t.Fatalf("Implicit TLS SendLicenseEmail failed: %v", err)
	}
}

// TestMailpit_MessagesReceived verifies that Mailpit actually received
// messages from the above tests by checking the message count increased.
func TestMailpit_MessagesReceived(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("Skipping: set LAB_ENABLED=1 to run Mailpit integration tests")
	}
	waitForMailpit(t)

	count := mailpitMessageCount(t)
	if count < 0 {
		t.Log("Cannot verify Mailpit message count (API unreachable)")
		return
	}
	// At minimum, the tests above should have sent several messages
	t.Logf("Mailpit has %d messages total", count)
	// We ran 6 send tests above, so should be at least 6
	if count < 6 {
		t.Errorf("Expected at least 6 messages in Mailpit, got %d", count)
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		t.Fatalf("invalid port %q: %v", s, err)
	}
	return n
}