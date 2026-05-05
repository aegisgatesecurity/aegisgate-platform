// Package webhook provides Stripe webhook event handling for AegisGate.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// EventHandler is the interface for handling Stripe webhook events
type EventHandler interface {
	HandleCheckoutSessionCompleted(ctx context.Context, event *StripeEvent) error
	HandleSubscriptionUpdated(ctx context.Context, event *StripeEvent) error
	HandleSubscriptionDeleted(ctx context.Context, event *StripeEvent) error
	HandleInvoicePaymentSucceeded(ctx context.Context, event *StripeEvent) error
	HandleInvoicePaymentFailed(ctx context.Context, event *StripeEvent) error
}

// StripeEvent represents a Stripe webhook event
type StripeEvent struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	CreatedAt int64           `json:"created"`
	Data      json.RawMessage `json:"data"`
	Livemode  bool            `json:"livemode"`
}

// CheckoutSessionData represents checkout.session data
type CheckoutSessionData struct {
	ID            string            `json:"id"`
	CustomerEmail string            `json:"customer_email"`
	CustomerID    string            `json:"customer"`
	Subscription  string            `json:"subscription"`
	PaymentStatus string            `json:"payment_status"`
	Status        string            `json:"status"`
	AmountTotal   int64             `json:"amount_total"`
	Currency      string            `json:"currency"`
	Metadata      map[string]string `json:"metadata"`
}

// SubscriptionData represents subscription data
type SubscriptionData struct {
	ID                 string    `json:"id"`
	CustomerID         string    `json:"customer"`
	Status             string    `json:"status"`
	Tier               string    `json:"tier"`
	CurrentPeriodStart time.Time `json:"current_period_start"`
	CurrentPeriodEnd   time.Time `json:"current_period_end"`
	CancelAtPeriodEnd  bool      `json:"cancel_at_period_end"`
	CancelAt           time.Time `json:"cancel_at,omitempty"`
	EndedAt            time.Time `json:"ended_at,omitempty"`
}

// InvoiceData represents invoice data
type InvoiceData struct {
	ID             string    `json:"id"`
	CustomerID     string    `json:"customer"`
	SubscriptionID string    `json:"subscription"`
	AmountDue      int64     `json:"amount_due"`
	AmountPaid     int64     `json:"amount_paid"`
	Currency       string    `json:"currency"`
	Status         string    `json:"status"`
	DueDate        time.Time `json:"due_date,omitempty"`
	Paid           bool      `json:"paid"`
	Number         string    `json:"number,omitempty"`
	Description    string    `json:"description,omitempty"`
}

// Handler processes Stripe webhook events
type Handler struct {
	licenseService LicenseServicer
	emailService   EmailServicer
	logger         *log.Logger
	webhookSecret  string
}

// LicenseServicer interface for license operations
type LicenseServicer interface {
	GenerateLicense(ctx context.Context, customerID string, tier string, durationDays int) (string, error)
	ActivateLicense(ctx context.Context, licenseKey string, customerEmail string) error
	DeactivateLicense(ctx context.Context, licenseKey string) error
	UpdateLicenseTier(ctx context.Context, licenseKey string, newTier string) error
}

// EmailServicer interface for email operations
type EmailServicer interface {
	SendLicenseEmail(ctx context.Context, to string, data EmailData) error
}

// EmailData contains data for license email
type EmailData struct {
	CustomerName string
	LicenseKey   string
	Tier         string
	ExpiresAt    string
}

// DefaultHandler creates a new webhook handler with default logger
func DefaultHandler(secret string) *Handler {
	return &Handler{
		logger:        log.Default(),
		webhookSecret: secret,
	}
}

// WithLicenseService sets the license service
func (h *Handler) WithLicenseService(svc LicenseServicer) *Handler {
	h.licenseService = svc
	return h
}

// WithEmailService sets the email service
func (h *Handler) WithEmailService(svc EmailServicer) *Handler {
	h.emailService = svc
	return h
}

// ProcessEvent processes a Stripe webhook event
func (h *Handler) ProcessEvent(ctx context.Context, payload []byte, sig string) error {
	// Parse the event
	var event StripeEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("failed to parse webhook event: %w", err)
	}

	// Log the event
	h.logger.Printf("Received webhook event: %s (ID: %s)", event.Type, event.ID)

	// Route to appropriate handler
	switch event.Type {
	case "checkout.session.completed":
		return h.handleCheckoutSessionCompleted(ctx, &event)
	case "customer.subscription.updated":
		return h.handleSubscriptionUpdated(ctx, &event)
	case "customer.subscription.deleted":
		return h.handleSubscriptionDeleted(ctx, &event)
	case "invoice.payment_succeeded":
		return h.handleInvoicePaymentSucceeded(ctx, &event)
	case "invoice.payment_failed":
		return h.handleInvoicePaymentFailed(ctx, &event)
	default:
		h.logger.Printf("Unhandled event type: %s", event.Type)
		return nil
	}
}

// handleCheckoutSessionCompleted processes successful checkout
func (h *Handler) handleCheckoutSessionCompleted(ctx context.Context, event *StripeEvent) error {
	var data CheckoutSessionData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return fmt.Errorf("failed to parse checkout session data: %w", err)
	}

	h.logger.Printf("Checkout completed for %s (session: %s)", data.CustomerEmail, data.ID)

	// Skip if not paid
	if data.PaymentStatus != "paid" {
		h.logger.Printf("Checkout not paid, skipping: %s", data.ID)
		return nil
	}

	// Get tier from metadata or default
	tier := data.Metadata["tier"]
	if tier == "" {
		tier = h.inferTierFromAmount(data.AmountTotal)
	}

	// Generate license
	if h.licenseService != nil {
		licenseKey, err := h.licenseService.GenerateLicense(ctx, data.CustomerID, tier, 365)
		if err != nil {
			return fmt.Errorf("failed to generate license: %w", err)
		}

		// Activate license
		if err := h.licenseService.ActivateLicense(ctx, licenseKey, data.CustomerEmail); err != nil {
			return fmt.Errorf("failed to activate license: %w", err)
		}

		// Send email
		if h.emailService != nil {
			expiresAt := time.Now().AddDate(1, 0, 0).Format("January 2, 2006")
			emailData := EmailData{
				CustomerName: data.CustomerEmail,
				LicenseKey:   licenseKey,
				Tier:         tier,
				ExpiresAt:    expiresAt,
			}
			if err := h.emailService.SendLicenseEmail(ctx, data.CustomerEmail, emailData); err != nil {
				h.logger.Printf("Failed to send license email: %v", err)
				// Don't fail the webhook for email errors
			}
		}
	}

	return nil
}

// handleSubscriptionUpdated processes subscription updates
func (h *Handler) handleSubscriptionUpdated(ctx context.Context, event *StripeEvent) error {
	var data SubscriptionData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return fmt.Errorf("failed to parse subscription data: %w", err)
	}

	h.logger.Printf("Subscription updated: %s (status: %s)", data.ID, data.Status)

	// Handle status changes
	switch data.Status {
	case "past_due":
		h.logger.Printf("Subscription past due: %s", data.ID)
		// Could send warning email here
	case "canceled":
		h.logger.Printf("Subscription canceled: %s", data.ID)
		// Deactivate license here if needed
	case "active":
		h.logger.Printf("Subscription reactivated: %s", data.ID)
	}

	return nil
}

// handleSubscriptionDeleted processes subscription cancellation
func (h *Handler) handleSubscriptionDeleted(ctx context.Context, event *StripeEvent) error {
	var data SubscriptionData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return fmt.Errorf("failed to parse subscription data: %w", err)
	}

	h.logger.Printf("Subscription deleted: %s", data.ID)

	// Deactivate any associated licenses
	if h.licenseService != nil {
		// Would need to look up license by customer ID
		h.logger.Printf("Would deactivate licenses for customer: %s", data.CustomerID)
	}

	return nil
}

// handleInvoicePaymentSucceeded processes successful payments
func (h *Handler) handleInvoicePaymentSucceeded(ctx context.Context, event *StripeEvent) error {
	var data InvoiceData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return fmt.Errorf("failed to parse invoice data: %w", err)
	}

	h.logger.Printf("Invoice payment succeeded: %s (amount: %d %s)", data.ID, data.AmountPaid, data.Currency)

	return nil
}

// handleInvoicePaymentFailed processes failed payments
func (h *Handler) handleInvoicePaymentFailed(ctx context.Context, event *StripeEvent) error {
	var data InvoiceData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return fmt.Errorf("failed to parse invoice data: %w", err)
	}

	h.logger.Printf("Invoice payment failed: %s (amount due: %d %s)", data.ID, data.AmountDue, data.Currency)

	// Could send dunning email here
	// Could notify customer of payment failure

	return nil
}

// inferTierFromAmount infers tier from payment amount (cents)
func (h *Handler) inferTierFromAmount(amount int64) string {
	switch {
	case amount >= 24900:
		return "professional"
	case amount >= 7900:
		return "developer"
	case amount >= 2900:
		return "starter"
	default:
		return "developer" // default fallback
	}
}

// HealthCheck returns the health status of the webhook handler
func (h *Handler) HealthCheck() error {
	if h.webhookSecret == "" {
		return fmt.Errorf("webhook secret not configured")
	}
	return nil
}
