// AegisGate Customer Portal API
// cmd/customer-portal/main.go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/billing"
)

// Config holds the customer portal configuration
type Config struct {
	Port           string        `yaml:"port"`
	SessionTimeout time.Duration `yaml:"session_timeout"`
	AllowedOrigins []string      `yaml:"allowed_origins"`
}

// APIResponse is the standard API response format
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// CustomerProfile represents the customer's organization
type CustomerProfile struct {
	CustomerID   string    `json:"customer_id"`
	Organization string    `json:"organization"`
	Email        string    `json:"email"`
	Plan         string    `json:"plan"`
	ActivatedAt  time.Time `json:"activated_at"`
	RenewalDate  time.Time `json:"renewal_date"`
	Status       string    `json:"status"`
}

// LicenseInfo represents the customer's current license
type LicenseInfo struct {
	LicenseID    string    `json:"license_id"`
	Tier         string    `json:"tier"`
	Features     []string  `json:"features"`
	MaxServers   int       `json:"max_servers"`
	MaxUsers     int       `json:"max_users"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Status       string    `json:"status"`
	SupportLevel string    `json:"support_level"`
}

// SubscriptionInfo represents the customer's subscription
type SubscriptionInfo struct {
	SubscriptionID  string    `json:"subscription_id"`
	Tier            string    `json:"tier"`
	Price           int64     `json:"price_cents"`
	Currency        string    `json:"currency"`
	BillingCycle    string    `json:"billing_cycle"`
	NextBillingDate time.Time `json:"next_billing_date"`
	Status          string    `json:"status"`
	PaymentMethod   string    `json:"payment_method"`
}

// UsageMetrics represents current usage statistics
type UsageMetrics struct {
	APIRequests    int64 `json:"api_requests"`
	APIRequestsCap int64 `json:"api_requests_cap"`
	MCPRequests    int64 `json:"mcp_requests"`
	MCPRequestsCap int64 `json:"mcp_requests_cap"`
	ActiveSessions int   `json:"active_sessions"`
	MaxSessions    int   `json:"max_sessions"`
	StorageUsedMB  int64 `json:"storage_used_mb"`
	StorageCapMB   int64 `json:"storage_cap_mb"`
}

// Invoice represents a billing invoice
type Invoice struct {
	InvoiceID     string    `json:"invoice_id"`
	InvoiceNumber string    `json:"invoice_number"`
	Amount        int64     `json:"amount_cents"`
	Currency      string    `json:"currency"`
	Status        string    `json:"status"`
	IssuedAt      time.Time `json:"issued_at"`
	DueAt         time.Time `json:"due_at"`
	PaidAt        time.Time `json:"paid_at,omitempty"`
	DownloadURL   string    `json:"download_url"`
}

// Document represents a legal document
type Document struct {
	DocumentID    string `json:"document_id"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	EffectiveDate string `json:"effective_date"`
	URL           string `json:"url"`
	Signed        bool   `json:"signed"`
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func main() {
	cfg := Config{Port: ":8081"}

	mux := http.NewServeMux()

	// Customer endpoints
	mux.HandleFunc("GET /api/v1/customer", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, CustomerProfile{
			CustomerID: "cust_example", Organization: "Example Corp",
			Email: "admin@example.com", Plan: "developer", Status: "active",
		})
	})
	mux.HandleFunc("GET /api/v1/customer/license", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, LicenseInfo{
			LicenseID: "lic_xxxx", Tier: "developer", Status: "active",
			Features: []string{"sso", "rbac", "compliance"},
		})
	})
	mux.HandleFunc("GET /api/v1/customer/subscription", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, SubscriptionInfo{
			SubscriptionID: "sub_xxxx", Tier: "developer", Price: billing.TierPrices["developer"], Currency: "USD",
		})
	})
	mux.HandleFunc("GET /api/v1/customer/usage", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, UsageMetrics{
			APIRequests: 45000, APIRequestsCap: 500000,
			MCPRequests: 12000, MCPRequestsCap: 250000,
		})
	})
	mux.HandleFunc("GET /api/v1/customer/invoices", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, []Invoice{
			{InvoiceID: "inv_001", InvoiceNumber: "AEGIS-2026-0001", Amount: billing.TierPrices["developer"]},
		})
	})
	mux.HandleFunc("GET /api/v1/customer/documents", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, []Document{
			{Name: "Business Associate Agreement (BAA)", URL: "/documents/baa.pdf"},
		})
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
	})

	log.Printf("Customer Portal starting on %s", cfg.Port)
	srv := &http.Server{
		Addr:         cfg.Port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
