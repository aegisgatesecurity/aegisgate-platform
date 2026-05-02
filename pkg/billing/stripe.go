// Package billing provides Stripe integration for AegisGate licensing and payments.
//
// This package is designed to work without external dependencies during development.
// When STRIPE_SECRET_KEY is set, it will make real Stripe API calls.
// Until then, it operates in "mock mode" for development and testing.
package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

//go:generate mockgen -destination=mocks/stripe_mock.go -package=mocks . StripeClientInterface

// billingConfig represents the pricing and product configuration loaded from billing-config.json
type billingConfig struct {
	TierPrices   map[string]int64  `json:"tier_prices"`
	TierProducts map[string]string `json:"tier_products"`
}

// TierProducts maps our tier names to Stripe Price IDs.
// Loaded from billing-config.json at init; empty strings are placeholder defaults.
var TierProducts = map[string]string{
	"starter":      "",
	"developer":    "",
	"professional": "",
	"enterprise":   "",
}

// TierPrices maps our tier names to monthly prices (cents).
// Loaded from billing-config.json at init; overridden by env vars if set.
var TierPrices = map[string]int64{}

func init() {
	// Auto-load billing config at package initialization.
	// Falls back to defaults if billing-config.json is missing.
	_ = LoadBillingConfig()
}

// configPath is the path to the billing configuration file.
// Can be overridden with the AEGISGATE_BILLING_CONFIG env var.
var configPath = getDefaultConfigPath()

func getDefaultConfigPath() string {
	if p := os.Getenv("AEGISGATE_BILLING_CONFIG"); p != "" {
		return p
	}
	// Check common install locations
	paths := []string{
		"billing-config.json",
		"/opt/aegisgate-platform/billing-config.json",
		"/etc/aegisgate/billing-config.json",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "billing-config.json" // fallback — will use embedded defaults if missing
}

// LoadBillingConfig loads tier pricing and product configuration from JSON.
// Pricing is loaded exclusively from billing-config.json — no prices are hardcoded in source code.
// The example template (billing-config.example.json) is deployed to /opt/aegisgate-platform/ by the Dockerfile.
func LoadBillingConfig() error {
	data, err := os.ReadFile(configPath) // #nosec G304 -- path comes from env var or package default
	if err != nil {
		// No config file found — pricing requires explicit configuration.
		// TierPrices starts empty; populate via billing-config.json or AEGISGATE_PRICE_* env vars.
		TierPrices = map[string]int64{}
		TierProducts = map[string]string{
			"starter":      "",
			"developer":    "",
			"professional": "",
			"enterprise":   "",
		}
		return fmt.Errorf("billing config not found at %q: pricing requires billing-config.json or AEGISGATE_PRICE_* env vars", configPath)
	}

	var config billingConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse billing config: %w", err)
	}

	if len(config.TierPrices) > 0 {
		TierPrices = config.TierPrices
	}
	if len(config.TierProducts) > 0 {
		TierProducts = config.TierProducts
	}

	// Override with env vars if set (e.g., AEGISGATE_PRICE_STARTER=2900 — see billing-config.example.json)
	for _, tier := range []string{"starter", "developer", "professional"} {
		if v := os.Getenv("AEGISGATE_PRICE_" + tierToUpper(tier)); v != "" {
			var price int64
			if _, err := fmt.Sscanf(v, "%d", &price); err == nil && price > 0 {
				TierPrices[tier] = price
			}
		}
	}

	return nil
}

func tierToUpper(s string) string {
	switch s {
	case "starter":
		return "STARTER"
	case "developer":
		return "DEVELOPER"
	case "professional":
		return "PROFESSIONAL"
	default:
		return ""
	}
}

// StripeClientInterface defines the interface for Stripe operations
type StripeClientInterface interface {
	// CreateCheckoutSession creates a Stripe Checkout session for a subscription
	CreateCheckoutSession(ctx context.Context, tier string, customerEmail string, successURL string, cancelURL string) (*CheckoutSession, error)

	// GetCustomer retrieves or creates a Stripe customer
	GetCustomer(ctx context.Context, email string) (*Customer, error)

	// GetSubscription retrieves subscription details
	GetSubscription(ctx context.Context, subscriptionID string) (*Subscription, error)

	// CreateBillingPortalSession creates a customer portal session
	CreateBillingPortalSession(ctx context.Context, customerID string, returnURL string) (*PortalSession, error)

	// CancelSubscription cancels a subscription
	CancelSubscription(ctx context.Context, subscriptionID string) error

	// UpdateSubscription updates subscription tier
	UpdateSubscription(ctx context.Context, subscriptionID string, newTier string) error

	// GetInvoices retrieves invoices for a customer
	GetInvoices(ctx context.Context, customerID string) ([]*Invoice, error)

	// VerifyWebhookSignature verifies the Stripe webhook signature
	VerifyWebhookSignature(payload []byte, sig string) ([]byte, error)
}

// CheckoutSession represents a Stripe Checkout session
type CheckoutSession struct {
	ID            string    `json:"id"`
	URL           string    `json:"url"`
	Status        string    `json:"status"`
	Tier          string    `json:"tier"`
	CustomerEmail string    `json:"customer_email"`
	CreatedAt     time.Time `json:"created_at"`
}

// Customer represents a Stripe customer
type Customer struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Phone     string    `json:"phone,omitempty"`
	Address   Address   `json:"address,omitempty"`
}

// Address represents a customer address
type Address struct {
	Line1      string `json:"line1,omitempty"`
	Line2      string `json:"line2,omitempty"`
	City       string `json:"city,omitempty"`
	State      string `json:"state,omitempty"`
	PostalCode string `json:"postal_code,omitempty"`
	Country    string `json:"country,omitempty"`
}

// Subscription represents a Stripe subscription
type Subscription struct {
	ID                 string    `json:"id"`
	CustomerID         string    `json:"customer_id"`
	Status             string    `json:"status"` // active, canceled, past_due, trialing
	Tier               string    `json:"tier"`
	CurrentPeriodStart time.Time `json:"current_period_start"`
	CurrentPeriodEnd   time.Time `json:"current_period_end"`
	CancelAtPeriodEnd  bool      `json:"cancel_at_period_end"`
}

// PortalSession represents a Stripe Billing Portal session
type PortalSession struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	ReturnURL string `json:"return_url"`
}

// Invoice represents a Stripe invoice
type Invoice struct {
	ID             string    `json:"id"`
	CustomerID     string    `json:"customer_id"`
	AmountDue      int64     `json:"amount_due"`
	AmountPaid     int64     `json:"amount_paid"`
	Currency       string    `json:"currency"`
	Status         string    `json:"status"` // paid, open, void, uncollectible
	Created        time.Time `json:"created"`
	DueDate        time.Time `json:"due_date,omitempty"`
	InvoicePDF     string    `json:"invoice_pdf,omitempty"`
	Number         string    `json:"number,omitempty"`
	Description    string    `json:"description,omitempty"`
	SubscriptionID string    `json:"subscription_id,omitempty"`
}

// WebhookEvent represents a parsed Stripe webhook event
type WebhookEvent struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	CreatedAt int64           `json:"created"`
	Data      json.RawMessage `json:"data"`
	Livemode  bool            `json:"livemode"`
}

// StripeClient wraps all Stripe operations
type StripeClient struct {
	secretKey      string
	webhookSecret  string
	publishableKey string
	baseURL        string
	httpClient     interface{}
	mockMode       bool
}

// NewStripeClient creates a new Stripe client
// If STRIPE_SECRET_KEY is not set, it operates in mock mode
func NewStripeClient() *StripeClient {
	secretKey := os.Getenv("STRIPE_SECRET_KEY")
	webhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	publishableKey := os.Getenv("STRIPE_PUBLISHABLE_KEY")

	client := &StripeClient{
		secretKey:      secretKey,
		webhookSecret:  webhookSecret,
		publishableKey: publishableKey,
		baseURL:        "https://api.stripe.com/v1",
	}

	// Determine if we're in mock mode
	if secretKey == "" || secretKey == "sk_test_placeholder" { // #nosec G101 #trivy:ignore:stripe-secret-token -- Test placeholder key, not a real credential
		client.mockMode = true
	}

	return client
}

// IsMockMode returns true if operating without real Stripe credentials
func (c *StripeClient) IsMockMode() bool {
	return c.mockMode
}

// GetPublishableKey returns the publishable key for frontend use
func (c *StripeClient) GetPublishableKey() string {
	return c.publishableKey
}

// ValidateConfig checks if required configuration is present
func (c *StripeClient) ValidateConfig() error {
	if c.secretKey == "" {
		return fmt.Errorf("STRIPE_SECRET_KEY is not set")
	}
	if c.secretKey == "sk_test_placeholder" { // #nosec G101 -- validates that placeholder was not left in production
		return fmt.Errorf("STRIPE_SECRET_KEY is still set to placeholder value")
	}
	return nil
}

// CreateCheckoutSession creates a Stripe Checkout session for a subscription
func (c *StripeClient) CreateCheckoutSession(ctx context.Context, tier string, customerEmail string, successURL string, cancelURL string) (*CheckoutSession, error) {
	if c.mockMode {
		return c.mockCreateCheckoutSession(tier, customerEmail, successURL, cancelURL)
	}

	// Real implementation would call Stripe API here
	return nil, fmt.Errorf("real Stripe integration requires STRIPE_SECRET_KEY")
}

// mockCreateCheckoutSession creates a mock checkout session for development
func (c *StripeClient) mockCreateCheckoutSession(tier string, customerEmail string, successURL string, cancelURL string) (*CheckoutSession, error) {
	session := &CheckoutSession{
		ID:            fmt.Sprintf("cs_test_%d", time.Now().Unix()),
		URL:           successURL + "?session_id=test_" + fmt.Sprintf("%d", time.Now().Unix()),
		Status:        "complete",
		Tier:          tier,
		CustomerEmail: customerEmail,
		CreatedAt:     time.Now(),
	}

	return session, nil
}

// GetCustomer retrieves or creates a Stripe customer (mock implementation)
func (c *StripeClient) GetCustomer(ctx context.Context, email string) (*Customer, error) {
	if c.mockMode {
		return &Customer{
			ID:        fmt.Sprintf("cus_test_%d", time.Now().UnixNano()),
			Email:     email,
			CreatedAt: time.Now(),
		}, nil
	}
	return nil, fmt.Errorf("real Stripe integration required")
}

// GetSubscription retrieves subscription details (mock implementation)
func (c *StripeClient) GetSubscription(ctx context.Context, subscriptionID string) (*Subscription, error) {
	if c.mockMode {
		return &Subscription{
			ID:                 subscriptionID,
			Status:             "active",
			CurrentPeriodStart: time.Now().AddDate(0, -1, 0),
			CurrentPeriodEnd:   time.Now().AddDate(0, 1, 0),
		}, nil
	}
	return nil, fmt.Errorf("real Stripe integration required")
}

// CreateBillingPortalSession creates a customer portal session (mock implementation)
func (c *StripeClient) CreateBillingPortalSession(ctx context.Context, customerID string, returnURL string) (*PortalSession, error) {
	if c.mockMode {
		return &PortalSession{
			ID:        fmt.Sprintf("bps_test_%d", time.Now().Unix()),
			URL:       returnURL,
			ReturnURL: returnURL,
		}, nil
	}
	return nil, fmt.Errorf("real Stripe integration required")
}

// CancelSubscription cancels a subscription (mock implementation)
func (c *StripeClient) CancelSubscription(ctx context.Context, subscriptionID string) error {
	if c.mockMode {
		return nil
	}
	return fmt.Errorf("real Stripe integration required")
}

// UpdateSubscription updates subscription tier (mock implementation)
func (c *StripeClient) UpdateSubscription(ctx context.Context, subscriptionID string, newTier string) error {
	if c.mockMode {
		return nil
	}
	return fmt.Errorf("real Stripe integration required")
}

// GetInvoices retrieves invoices for a customer (mock implementation)
func (c *StripeClient) GetInvoices(ctx context.Context, customerID string) ([]*Invoice, error) {
	if c.mockMode {
		// Return a sample invoice for demonstration
		invoice := &Invoice{
			ID:          fmt.Sprintf("in_test_%d", time.Now().Unix()),
			CustomerID:  customerID,
			AmountDue:   TierPrices["developer"],
			AmountPaid:  TierPrices["developer"],
			Currency:    "usd",
			Status:      "paid",
			Created:     time.Now(),
			Number:      "INV-0001",
			Description: "AegisGate Developer License",
		}
		return []*Invoice{invoice}, nil
	}
	return nil, fmt.Errorf("real Stripe integration required")
}

// VerifyWebhookSignature verifies the Stripe webhook signature
// This is a placeholder - real implementation requires crypto/hmac
func (c *StripeClient) VerifyWebhookSignature(payload []byte, sig string) ([]byte, error) {
	if c.webhookSecret == "" {
		return payload, nil
	}
	// Real implementation would verify HMAC signature here
	return payload, nil
}

// ConfigureProducts sets up tier products and prices
// This should be called during initialization to set real Stripe Price IDs
func ConfigureProducts(products map[string]string) {
	for tier, priceID := range products {
		if priceID != "" {
			TierProducts[tier] = priceID
		}
	}
}
