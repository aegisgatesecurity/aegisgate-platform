// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Stripe Webhook Handler
// =========================================================================
//
// Handles Stripe webhook events for subscription management.
// Processes checkout.session.completed to generate and email license keys.
// =========================================================================

package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Server handles Stripe webhook HTTP requests
type Server struct {
	port         string
	secret       string
	licenseGen   LicenseGenerator
	emailService EmailService
	logger       *log.Logger
}

// LicenseGenerator interface for license key generation
type LicenseGenerator interface {
	GenerateLicense(customerID string, tier string, days int) (string, error)
	ActivateLicense(key string, email string) error
}

// EmailService interface for sending license emails
type EmailService interface {
	SendLicenseKey(email string, key string, tier string, expiresAt string) error
}

// WebhookPayload represents incoming Stripe webhook data
type WebhookPayload struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Created int64  `json:"created"`
	Data    struct {
		Object json.RawMessage `json:"object"`
	} `json:"data"`
}

// CheckoutSession represents Stripe checkout session data
type CheckoutSession struct {
	ID            string            `json:"id"`
	CustomerEmail string            `json:"customer_email"`
	Customer      string            `json:"customer"`
	Subscription  string            `json:"subscription"`
	PaymentStatus string            `json:"payment_status"`
	Status        string            `json:"status"`
	AmountTotal   int64             `json:"amount_total"`
	Currency      string            `json:"currency"`
	Metadata      map[string]string `json:"metadata"`
}

// Subscription represents Stripe subscription data
type Subscription struct {
	ID                 string `json:"id"`
	Customer           string `json:"customer"`
	Status             string `json:"status"`
	CurrentPeriodStart int64  `json:"current_period_start"`
	CurrentPeriodEnd   int64  `json:"current_period_end"`
	CancelAtPeriodEnd  bool   `json:"cancel_at_period_end"`
}

// Tier pricing map (cents)
var TierPrices = map[string]int64{
	"starter":      2900,
	"developer":    7900,
	"professional": 24900,
}

// NewWebhookServer creates a new webhook server
func NewWebhookServer(port string) *Server {
	// Webhook secret MUST come from environment variable for security
	// Never store real secrets in config files or code
	secret := os.Getenv("STRIPE_WEBHOOK_SECRET")

	return &Server{
		port:   port,
		secret: secret,
		logger: log.Default(),
	}
}

// WithLicenseGenerator sets the license generator
func (s *Server) WithLicenseGenerator(gen LicenseGenerator) *Server {
	s.licenseGen = gen
	return s
}

// WithEmailService sets the email service
func (s *Server) WithEmailService(svc EmailService) *Server {
	s.emailService = svc
	return s
}

// Start begins listening for webhook events
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/stripe", s.handleWebhook)
	mux.HandleFunc("/health", s.handleHealth)

	addr := ":" + s.port
	s.logger.Printf("Starting Stripe webhook server on %s", addr)
	return http.ListenAndServe(addr, mux)
}

// handleWebhook processes incoming Stripe webhook events
func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Printf("Failed to read body: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Only require signature when webhook secret is configured (production mode)
	sig := r.Header.Get("Stripe-Signature")
	if s.secret != "" && sig == "" {
		s.logger.Printf("Missing Stripe-Signature header")
		http.Error(w, "Missing signature", http.StatusBadRequest)
		return
	}

	if s.secret != "" && sig != "" {
		if err := s.verifySignature(body, sig); err != nil {
			s.logger.Printf("Invalid signature: %v", err)
			http.Error(w, "Invalid signature", http.StatusBadRequest)
			return
		}
	}

	var event WebhookPayload
	if err := json.Unmarshal(body, &event); err != nil {
		s.logger.Printf("Failed to parse event: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	s.logger.Printf("Received webhook: %s (ID: %s)", event.Type, event.ID)

	var processErr error
	switch event.Type {
	case "checkout.session.completed":
		processErr = s.handleCheckoutCompleted(event.Data.Object)
	case "customer.subscription.updated":
		processErr = s.handleSubscriptionUpdated(event.Data.Object)
	case "customer.subscription.deleted":
		processErr = s.handleSubscriptionDeleted(event.Data.Object)
	case "invoice.payment_succeeded":
		processErr = s.handleInvoicePaid(event.Data.Object)
	case "invoice.payment_failed":
		processErr = s.handleInvoiceFailed(event.Data.Object)
	default:
		s.logger.Printf("Unhandled event type: %s", event.Type)
	}

	if processErr != nil {
		s.logger.Printf("Error processing %s: %v", event.Type, processErr)
		http.Error(w, "Processing error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"received": true}`))
}

// verifySignature validates the Stripe webhook signature
func (s *Server) verifySignature(payload []byte, sig string) error {
	parts := strings.Split(sig, ",")
	var timestamp string
	var signatures []string

	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if kv[0] == "t" {
			timestamp = kv[1]
		} else if kv[0] == "v1" {
			signatures = append(signatures, kv[1])
		}
	}

	if timestamp == "" || len(signatures) == 0 {
		return fmt.Errorf("invalid signature format")
	}

	signedPayload := timestamp + "." + string(payload)
	mac := hmac.New(sha256.New, []byte(s.secret))
	mac.Write([]byte(signedPayload))
	expected := hex.EncodeToString(mac.Sum(nil))

	for _, sig := range signatures {
		if hmac.Equal([]byte(sig), []byte(expected)) {
			return nil
		}
	}

	return fmt.Errorf("signature mismatch")
}

// handleCheckoutCompleted processes successful checkout
func (s *Server) handleCheckoutCompleted(data json.RawMessage) error {
	var session CheckoutSession
	if err := json.Unmarshal(data, &session); err != nil {
		return fmt.Errorf("failed to parse checkout session: %w", err)
	}

	s.logger.Printf("Checkout completed: %s for %s", session.ID, session.CustomerEmail)

	if session.PaymentStatus != "paid" {
		s.logger.Printf("Skipping unpaid session: %s", session.ID)
		return nil
	}

	tier := session.Metadata["tier"]
	if tier == "" {
		tier = s.inferTierFromAmount(session.AmountTotal)
	}

	if s.licenseGen != nil {
		key, err := s.licenseGen.GenerateLicense(session.Customer, tier, 365)
		if err != nil {
			return fmt.Errorf("failed to generate license: %w", err)
		}

		if err := s.licenseGen.ActivateLicense(key, session.CustomerEmail); err != nil {
			s.logger.Printf("Warning: failed to activate license %s: %v", key, err)
		}

		if s.emailService != nil {
			expiresAt := time.Now().AddDate(1, 0, 0).Format("January 2, 2006")
			if err := s.emailService.SendLicenseKey(session.CustomerEmail, key, tier, expiresAt); err != nil {
				s.logger.Printf("Warning: failed to send license email: %v", err)
			}
		}

		s.logger.Printf("Generated license %s for %s (tier: %s)", key, session.CustomerEmail, tier)
	}

	return nil
}

// handleSubscriptionUpdated processes subscription updates
func (s *Server) handleSubscriptionUpdated(data json.RawMessage) error {
	var sub Subscription
	if err := json.Unmarshal(data, &sub); err != nil {
		return fmt.Errorf("failed to parse subscription: %w", err)
	}

	s.logger.Printf("Subscription updated: %s (status: %s)", sub.ID, sub.Status)

	switch sub.Status {
	case "past_due":
		s.logger.Printf("WARNING: Subscription past due: %s", sub.ID)
	case "active":
		s.logger.Printf("Subscription reactivated: %s", sub.ID)
	case "canceled":
		s.logger.Printf("Subscription canceled: %s", sub.ID)
	}

	return nil
}

// handleSubscriptionDeleted processes subscription cancellation
func (s *Server) handleSubscriptionDeleted(data json.RawMessage) error {
	var sub Subscription
	if err := json.Unmarshal(data, &sub); err != nil {
		return fmt.Errorf("failed to parse subscription: %w", err)
	}

	s.logger.Printf("Subscription deleted: %s", sub.ID)

	return nil
}

// handleInvoicePaid processes successful invoice payment
func (s *Server) handleInvoicePaid(data json.RawMessage) error {
	var invoice struct {
		ID             string `json:"id"`
		Customer       string `json:"customer"`
		AmountPaid     int64  `json:"amount_paid"`
		Currency       string `json:"currency"`
		Status         string `json:"status"`
		SubscriptionID string `json:"subscription"`
	}

	if err := json.Unmarshal(data, &invoice); err != nil {
		return fmt.Errorf("failed to parse invoice: %w", err)
	}

	s.logger.Printf("Invoice paid: %s (%d %s)", invoice.ID, invoice.AmountPaid/100, invoice.Currency)

	return nil
}

// handleInvoiceFailed processes failed invoice payment
func (s *Server) handleInvoiceFailed(data json.RawMessage) error {
	var invoice struct {
		ID        string `json:"id"`
		Customer  string `json:"customer"`
		AmountDue int64  `json:"amount_due"`
		Currency  string `json:"currency"`
	}

	if err := json.Unmarshal(data, &invoice); err != nil {
		return fmt.Errorf("failed to parse invoice: %w", err)
	}

	s.logger.Printf("Invoice payment failed: %s (%d %s)", invoice.ID, invoice.AmountDue/100, invoice.Currency)

	return nil
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := map[string]string{
		"status":  "healthy",
		"service": "stripe-webhook",
		"version": "1.0.0",
	}

	if s.secret == "" {
		status["webhook_secret"] = "not configured"
	} else {
		status["webhook_secret"] = "configured"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// inferTierFromAmount determines tier from payment amount (cents)
func (s *Server) inferTierFromAmount(amount int64) string {
	switch {
	case amount >= 24900:
		return "professional"
	case amount >= 7900:
		return "developer"
	case amount >= 2900:
		return "starter"
	default:
		return "developer"
	}
}

// CreateWebhookEndpoint creates the Stripe webhook endpoint URL
func CreateWebhookEndpoint(baseURL string) string {
	return strings.TrimSuffix(baseURL, "/") + "/webhook/stripe"
}

// GetWebhookSigningSecret returns the configured webhook secret
func GetWebhookSigningSecret() string {
	return os.Getenv("STRIPE_WEBHOOK_SECRET")
}

// SetWebhookSigningSecret sets the webhook secret (for testing)
func SetWebhookSigningSecret(secret string) {
	os.Setenv("STRIPE_WEBHOOK_SECRET", secret)
}

// MockLicenseGenerator is a mock implementation for development
type MockLicenseGenerator struct {
	keys map[string]string
}

// NewMockLicenseGenerator creates a mock license generator
func NewMockLicenseGenerator() *MockLicenseGenerator {
	return &MockLicenseGenerator{
		keys: make(map[string]string),
	}
}

// GenerateLicense generates a mock license key
func (m *MockLicenseGenerator) GenerateLicense(customerID string, tier string, days int) (string, error) {
	key := fmt.Sprintf("AG-%s-%d-%s", strings.ToUpper(tier), time.Now().Unix(), generateRandomString(16))
	m.keys[key] = customerID
	return key, nil
}

// ActivateLicense activates a mock license
func (m *MockLicenseGenerator) ActivateLicense(key string, email string) error {
	if _, exists := m.keys[key]; !exists {
		return fmt.Errorf("license not found: %s", key)
	}
	return nil
}

// MockEmailService is a mock implementation for development
type MockEmailService struct {
	sent []struct {
		to   string
		key  string
		tier string
	}
}

// NewMockEmailService creates a mock email service
func NewMockEmailService() *MockEmailService {
	return &MockEmailService{}
}

// SendLicenseKey sends a mock license email
func (m *MockEmailService) SendLicenseKey(to string, key string, tier string, expiresAt string) error {
	m.sent = append(m.sent, struct {
		to   string
		key  string
		tier string
	}{to, key, tier})
	log.Printf("[MOCK EMAIL] To: %s, Key: %s, Tier: %s", to, key, tier)
	return nil
}

// generateRandomString generates a random string for license keys
func generateRandomString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(result)
}
