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
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// Error code constants (v3.1.1)
const (
	ErrInvalidTier = "invalid_tier"
)

// ToS audit constants (v3.3.0 Phase 4)
//
// ToSAcceptanceVersion is the human-readable identifier of the Terms of
// Service that was published at aegisgatesecurity.io/legal/terms/ at the
// time of purchase. It is recorded in the audit log on every successful
// checkout so that the ToS version in effect at acceptance can be verified
// later (e.g., to defend a contract dispute, to enforce §1.2 amendment
// notice, or to identify the cohort of customers who accepted a given
// DRAFT during the v3.3.0 beta window).
//
// ToSAcceptanceHash is the SHA-256 of the canonical ToS file (the .md
// source published to the website) at the time the constant was set.
// A change to either constant signals a new ToS version; customers
// who accepted under the prior version are unaffected, per §1.2 of
// the ToS (existing subscriptions continue under the version they
// accepted).
const (
	ToSAcceptanceVersion = "2.0-v3.3.0-beta"
	ToSAcceptanceHash    = "9c0263647e96ef21a8bc396026f3f3207e530ccb9459175e327b60e3d234b3ec"
)

// Server handles Stripe webhook HTTP requests
type Server struct {
	port         string
	secret       string
	licenseGen   LicenseGenerator
	emailService EmailService
	logger       *log.Logger

	// processedEvents tracks Stripe event IDs that have been
	// successfully processed, preventing duplicate billing when
	// Stripe retries a webhook delivery. Entries expire after 30 days.
	processedEvents map[string]time.Time
	eventMu         sync.RWMutex
}

// LicenseGenerator interface for license key generation
type LicenseGenerator interface {
	GenerateLicense(customerID string, tier string, days int) (string, error)
	ActivateLicense(key string, email string) error
	// AddModules (v3.2.0 Phase 1.3) attaches billable compliance modules
	// to an existing license. priceCents is the amount the customer paid
	// at purchase time, captured here so future price changes don't affect
	// existing customers (locked decision Q2: "lock in at purchase price
	// forever"). tier and priceCents together form the audit trail.
	AddModules(licenseKey string, customerID string, modules []string, priceCents int64) error
}

// ErrInvalidModule is returned when a module name in the webhook payload
// is not a known billable module. v3.2.0 Phase 1.3.
var ErrInvalidModule = errors.New("invalid module")

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
	// SubscriptionItems (v3.2.0 Phase 1.3) is the modern Stripe shape for
	// multi-line-item checkouts. Each item has a Price with a lookup_key
	// like "module_hipaa". We use this to detect module purchases when
	// metadata.modules is not set.
	SubscriptionItems SubscriptionItemsWrapper `json:"subscription_items,omitempty"`
}

// SubscriptionItemsWrapper is the envelope for Stripe's subscription_items
// field on a checkout session. The actual line items are nested under
// .data[].price.lookup_key.
type SubscriptionItemsWrapper struct {
	Data []SubscriptionItem `json:"data"`
}

// SubscriptionItem is a single line item in a Stripe subscription.
type SubscriptionItem struct {
	ID    string                `json:"id"`
	Price SubscriptionItemPrice `json:"price"`
}

// SubscriptionItemPrice is the price sub-object of a subscription item.
type SubscriptionItemPrice struct {
	ID         string `json:"id"`
	LookupKey  string `json:"lookup_key"`
	UnitAmount int64  `json:"unit_amount"`
	Nickname   string `json:"nickname"`
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

	"developer":    7900,
	"professional": 24900,
}

// NewWebhookServer creates a new webhook server
func NewWebhookServer(port string) *Server {
	// Webhook secret MUST come from environment variable for security
	// Never store real secrets in config files or code
	//nolint:gosec G703 - environment variables are not user input
	secret := os.Getenv("STRIPE_WEBHOOK_SECRET")

	return &Server{
		port:            port,
		secret:          secret,
		logger:          log.Default(),
		processedEvents: make(map[string]time.Time),
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

	// HTTP server with timeouts to prevent slow-loris attacks (G114)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.logger.Printf("Server error: %v", err)
		return err
	}
	return nil
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

	// Idempotency check: if this event ID was already processed,
	// return 200 OK without re-processing. Stripe retries webhooks
	// on failure, so without this check duplicate events would
	// be processed (e.g., double billing for the same checkout).
	if event.ID != "" {
		s.eventMu.RLock()
		_, processed := s.processedEvents[event.ID]
		s.eventMu.RUnlock()
		if processed {
			s.logger.Printf("Duplicate event %s ignored (idempotent)", event.ID)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"received":true,"duplicate":true}`))
			return
		}
	}

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

	// Mark event as processed (idempotency).
	if event.ID != "" && s.processedEvents != nil {
		s.eventMu.Lock()
		s.processedEvents[event.ID] = time.Now()
		// Prune entries older than 30 days.
		cutoff := time.Now().Add(-30 * 24 * time.Hour)
		for id, ts := range s.processedEvents {
			if ts.Before(cutoff) {
				delete(s.processedEvents, id)
			}
		}
		s.eventMu.Unlock()
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"received": true}`)); err != nil {
		s.logger.Printf("failed to write response: %v", err)
	}
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
		switch kv[0] {
		case "t":
			timestamp = kv[1]
		case "v1":
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

// ModuleLookupKeyPrefix is the prefix Stripe uses in price.lookup_key
// for billable compliance modules. e.g., "module_hipaa", "module_pci".
// v3.2.0 Phase 1.3: the canonical modern shape for module line items.
const ModuleLookupKeyPrefix = "module_"

// MetadataModulesKey is the session.metadata key for the legacy CSV shape.
// v3.2.0 Phase 1.3: optional fallback for one-off add-ons or manual
// checkouts. Value is a comma-separated list of module names.
const MetadataModulesKey = "modules"

// moduleFromLookupKey extracts a module name from a Stripe price.lookup_key.
// Returns "" if the key is not a module key.
//
// Examples:
//
//	"module_hipaa"    -> "hipaa"
//	"module_pci"      -> "pci"
//	"module_iso42001" -> "iso42001"
//	"professional"    -> "" (not a module key)
//	""                -> ""
//	"module_"         -> "" (missing module name)
func moduleFromLookupKey(lookupKey string) string {
	if !strings.HasPrefix(lookupKey, ModuleLookupKeyPrefix) {
		return ""
	}
	name := strings.TrimPrefix(lookupKey, ModuleLookupKeyPrefix)
	if name == "" {
		return ""
	}
	return name
}

// parseModulesFromSession extracts the list of module names from a Stripe
// checkout session, handling all 3 supported input shapes.
//
// Priority (highest to lowest):
//  1. subscription_items.data[].price.lookup_key (modern Stripe shape)
//  2. metadata.modules (CSV, legacy/manual shape)
//  3. empty (no modules in this checkout)
//
// Returns the de-duplicated, validated list of module names. Unknown
// modules are rejected with an error (typo defense).
func (s *Server) parseModulesFromSession(session *CheckoutSession) ([]string, error) {
	seen := map[string]bool{}
	var modules []string

	// Shape 1: subscription_items.data[].price.lookup_key
	for _, item := range session.SubscriptionItems.Data {
		name := moduleFromLookupKey(item.Price.LookupKey)
		if name == "" {
			continue // not a module line item
		}
		if !license.IsValidModule(name) {
			return nil, fmt.Errorf("subscription line item has invalid module %q (lookup_key=%q): %w",
				name, item.Price.LookupKey, ErrInvalidModule)
		}
		if !seen[name] {
			seen[name] = true
			modules = append(modules, name)
		}
	}

	// Shape 2: metadata.modules (CSV)
	if csv, ok := session.Metadata[MetadataModulesKey]; ok && csv != "" {
		for _, raw := range strings.Split(csv, ",") {
			name := strings.TrimSpace(raw)
			if name == "" {
				continue
			}
			if !license.IsValidModule(name) {
				return nil, fmt.Errorf("metadata.%s contains invalid module %q: %w",
					MetadataModulesKey, name, ErrInvalidModule)
			}
			if !seen[name] {
				seen[name] = true
				modules = append(modules, name)
			}
		}
	}

	// Shape 3: empty (legacy single-tier, no modules). Return empty slice.
	return modules, nil
}

// moduleLineItemAmount returns the sum of unit_amounts for all module
// line items in the session. Used for the priceCents argument to
// AddModules (locked decision Q2: capture price at purchase time).
// Returns 0 if no module line items.
func (s *Server) moduleLineItemAmount(session *CheckoutSession, modules []string) int64 {
	if len(modules) == 0 {
		return 0
	}
	moduleSet := map[string]bool{}
	for _, m := range modules {
		moduleSet[m] = true
	}
	var total int64
	for _, item := range session.SubscriptionItems.Data {
		name := moduleFromLookupKey(item.Price.LookupKey)
		if name == "" || !moduleSet[name] {
			continue
		}
		total += item.Price.UnitAmount
	}
	return total
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

	// v3.3.0 Phase 4: record Terms-of-Service acceptance for this purchase.
	// The audit log entry captures the ToS version in effect at the time of
	// checkout (e.g., "2.0-v3.3.0-beta") and the SHA-256 of the canonical
	// ToS file published at /legal/terms/. This is the durable record of
	// the customer's acceptance under §1.4 of the ToS. The same data also
	// gets recorded again after license generation (below) so the audit
	// trail stays aligned even if license generation fails downstream.
	s.logger.Printf("ToS acceptance recorded: session=%s email=%s tos_version=%s tos_hash=%s",
		session.ID, session.CustomerEmail, ToSAcceptanceVersion, ToSAcceptanceHash)

	tierStr := session.Metadata["tier"]
	if tierStr == "" {
		tierStr = s.inferTierFromAmount(session.AmountTotal)
	}

	// v3.1.1: validate tier before passing to license generation.
	// Rejects unknown values with a structured error to surface
	// misconfiguration (e.g., typo in Stripe metadata, changed pricing
	// tier that inferTierFromAmount no longer recognizes). This also
	// normalizes alias inputs ("pro" -> "professional", "free" -> "community")
	// for consistent downstream logging and email.
	parsedTier, err := tier.ParseTier(tierStr)
	if err != nil {
		s.logger.Printf("ERROR: rejecting checkout %s: invalid tier %q (err=%v)",
			session.ID, tierStr, err)
		return fmt.Errorf("%s: %q: %w", ErrInvalidTier, tierStr, err)
	}

	// v3.2.0 Phase 1.3: parse module line items from the session.
	// 3 supported input shapes (see parseModulesFromSession):
	//   1. subscription_items.data[].price.lookup_key (modern Stripe)
	//   2. metadata.modules (CSV, legacy/manual)
	//   3. empty (legacy single-tier only — no modules)
	modules, err := s.parseModulesFromSession(&session)
	if err != nil {
		s.logger.Printf("ERROR: rejecting checkout %s: %v", session.ID, err)
		return err
	}
	modulePriceCents := s.moduleLineItemAmount(&session, modules)
	if len(modules) > 0 {
		s.logger.Printf("Checkout %s: %d module(s) attached: %v (price: %d cents)",
			session.ID, len(modules), modules, modulePriceCents)
	}

	if s.licenseGen != nil {
		key, err := s.licenseGen.GenerateLicense(session.Customer, parsedTier.String(), 365)
		if err != nil {
			return fmt.Errorf("failed to generate license: %w", err)
		}

		if err := s.licenseGen.ActivateLicense(key, session.CustomerEmail); err != nil {
			s.logger.Printf("Warning: failed to activate license %s: %v", key, err)
		}

		// v3.2.0 Phase 1.3: if modules were purchased, attach them to the
		// new license. AddModules records the price-at-purchase for Q2
		// (lock-in forever). This call is independent of tier generation
		// so it can also be used for adding modules to an existing license
		// in a future API endpoint.
		if len(modules) > 0 {
			if err := s.licenseGen.AddModules(key, session.Customer, modules, modulePriceCents); err != nil {
				return fmt.Errorf("failed to attach modules to license: %w", err)
			}
			s.logger.Printf("Attached %d module(s) to license %s at %d cents/mo",
				len(modules), key, modulePriceCents)
		}

		if s.emailService != nil {
			expiresAt := time.Now().AddDate(1, 0, 0).Format("January 2, 2006")
			if err := s.emailService.SendLicenseKey(session.CustomerEmail, key, parsedTier.String(), expiresAt); err != nil {
				s.logger.Printf("Warning: failed to send license email: %v", err)
			}
		}

		s.logger.Printf("Generated license %s for %s (tier: %s, tos_version: %s)", key, session.CustomerEmail, parsedTier.String(), ToSAcceptanceVersion)
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
	//nolint:errcheck - Health endpoint failures should not crash server
	if err := json.NewEncoder(w).Encode(status); err != nil {
		s.logger.Printf("health encoding error: %v", err)
	}
}

// inferTierFromAmount determines tier from payment amount (cents)
// v3.5.0: Starter tier removed. Community is free, Developer is first paid tier.
func (s *Server) inferTierFromAmount(amount int64) string {
	switch {
	case amount >= 49900: // Professional: $499/mo or $4,990/yr
		return "professional"
	case amount >= 7900: // Developer: $79/mo or $790/yr
		return "developer"
	default:
		return "developer" // Default fallback (Community is free, not paid)
	}
}

// CreateWebhookEndpoint creates the Stripe webhook endpoint URL
func CreateWebhookEndpoint(baseURL string) string {
	endpoint := strings.TrimSuffix(baseURL, "/") + "/webhook/stripe"
	// Validate endpoint is safe (basic URL validation)
	if strings.Contains(endpoint, "..") || strings.HasPrefix(endpoint, "//") {
		return ""
	}
	return endpoint
}

// GetWebhookSigningSecret returns the configured webhook secret
func GetWebhookSigningSecret() string {
	return os.Getenv("STRIPE_WEBHOOK_SECRET")
}

// SetWebhookSigningSecret sets the webhook secret (for testing)
//
//go:nosec G104
func SetWebhookSigningSecret(secret string) {
	if err := os.Setenv("STRIPE_WEBHOOK_SECRET", secret); err != nil {
		// In test environment, this is acceptable to fail silently
		return
	}
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

// AddModules (v3.2.0 Phase 1.3) is a no-op in the mock; the real
// implementation will update the LicensePayload.Modules field and
// persist the price-at-purchase (locked decision Q2: lock-in forever).
// We validate the key exists so tests catch missing-key bugs.
func (m *MockLicenseGenerator) AddModules(licenseKey string, customerID string, modules []string, priceCents int64) error {
	if _, exists := m.keys[licenseKey]; !exists {
		return fmt.Errorf("license not found: %s", licenseKey)
	}
	if len(modules) == 0 {
		return fmt.Errorf("no modules to add")
	}
	for _, name := range modules {
		if !license.IsValidModule(name) {
			return fmt.Errorf("invalid module: %s", name)
		}
	}
	// Mock: nothing to persist. Real impl will update LicensePayload.Modules.
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
