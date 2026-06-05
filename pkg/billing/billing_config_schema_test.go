// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Billing config schema tests (v3.2.0 Phase 1.4)
//
// Tests the structure of billing-config.json and the example template.
// Pins the schema so that future changes (e.g., adding a 7th module,
// changing the price format) require an explicit test update.

package billing

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestBillingConfig_ValidJSON verifies the file parses as valid JSON.
func TestBillingConfig_ValidJSON(t *testing.T) {
	data, err := os.ReadFile("billing-config.json")
	if err != nil {
		t.Fatalf("ReadFile(billing-config.json): %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
}

// TestBillingConfigExample_ValidJSON verifies the example template parses.
func TestBillingConfigExample_ValidJSON(t *testing.T) {
	data, err := os.ReadFile("billing-config.example.json")
	if err != nil {
		t.Fatalf("ReadFile(billing-config.example.json): %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
}

// TestBillingConfig_TierPrices verifies all 6 expected tier price keys exist
// and have sensible values (positive cents, monthly < annual).
func TestBillingConfig_TierPrices(t *testing.T) {
	data, err := os.ReadFile("billing-config.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var v struct {
		TierPrices map[string]int `json:"tier_prices"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	expected := []string{
		"starter_monthly", "starter_annual",
		"developer_monthly", "developer_annual",
		"professional_monthly", "professional_annual",
	}
	for _, key := range expected {
		t.Run(key, func(t *testing.T) {
			cents, ok := v.TierPrices[key]
			if !ok {
				t.Fatalf("missing key: %s", key)
			}
			if cents <= 0 {
				t.Errorf("price %s = %d, want positive", key, cents)
			}
		})
	}

	// Sanity: annual should be > monthly for each tier (typically 10-12x).
	pairs := []struct {
		monthly, annual string
	}{
		{"starter_monthly", "starter_annual"},
		{"developer_monthly", "developer_annual"},
		{"professional_monthly", "professional_annual"},
	}
	for _, p := range pairs {
		t.Run(p.monthly+"_vs_"+p.annual, func(t *testing.T) {
			m := v.TierPrices[p.monthly]
			a := v.TierPrices[p.annual]
			if a < m*8 {
				t.Errorf("annual (%d) should be at least 8x monthly (%d)", a, m)
			}
			if a > m*15 {
				t.Errorf("annual (%d) should be at most 15x monthly (%d)", a, m)
			}
		})
	}
}

// TestBillingConfig_TierProducts verifies the new format with rich Price objects.
func TestBillingConfig_TierProducts(t *testing.T) {
	data, err := os.ReadFile("billing-config.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var v struct {
		TierProducts map[string]any `json:"tier_products"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// 6 paid tiers should have rich objects; enterprise can be "".
	richKeys := []string{
		"starter_monthly", "starter_annual",
		"developer_monthly", "developer_annual",
		"professional_monthly", "professional_annual",
	}
	for _, key := range richKeys {
		t.Run(key, func(t *testing.T) {
			val, ok := v.TierProducts[key]
			if !ok {
				t.Fatalf("missing key: %s", key)
			}
			obj, isObj := val.(map[string]any)
			if !isObj {
				t.Fatalf("tier_products.%s should be a rich object, got %T", key, val)
			}
			required := []string{"price_id", "product_id", "lookup_key", "buy_button_id"}
			for _, field := range required {
				if obj[field] == nil || obj[field] == "" {
					t.Errorf("tier_products.%s missing %q field", key, field)
				}
				// Verify price_id starts with "price_"
				if field == "price_id" {
					s, _ := obj[field].(string)
					if !strings.HasPrefix(s, "price_") {
						t.Errorf("tier_products.%s.price_id should start with 'price_', got %q", key, s)
					}
				}
			}
		})
	}

	// Enterprise can be empty string (custom pricing).
	ent, ok := v.TierProducts["enterprise"]
	if !ok {
		t.Error("missing 'enterprise' key in tier_products")
	}
	if s, isStr := ent.(string); !isStr || s != "" {
		t.Errorf("tier_products.enterprise should be empty string, got %T %v", ent, ent)
	}
}

// TestBillingConfig_ModuleProducts verifies the 6 module entries.
func TestBillingConfig_ModuleProducts(t *testing.T) {
	data, err := os.ReadFile("billing-config.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var v struct {
		ModuleProducts map[string]any `json:"module_products"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	expected := []string{"hipaa", "pci", "soc2", "iso42001", "fedramp", "fips"}
	if len(v.ModuleProducts) != len(expected) {
		t.Errorf("got %d module_products, want %d (the 6 locked modules)", len(v.ModuleProducts), len(expected))
	}
	for _, key := range expected {
		t.Run(key, func(t *testing.T) {
			val, ok := v.ModuleProducts[key]
			if !ok {
				t.Fatalf("missing module: %s", key)
			}
			obj, isObj := val.(map[string]any)
			if !isObj {
				t.Fatalf("module_products.%s should be an object, got %T", key, val)
			}
			// Required fields.
			for _, field := range []string{"lookup_key", "monthly_cents", "display_name", "required_tier"} {
				if obj[field] == nil {
					t.Errorf("module_products.%s missing %q", key, field)
				}
			}
			// lookup_key should match "module_<key>".
			if lk, _ := obj["lookup_key"].(string); lk != "module_"+key {
				t.Errorf("module_products.%s.lookup_key = %q, want \"module_%s\"", key, lk, key)
			}
			// Price ID can be a PLACEHOLDER_* for v3.2.0 Phase 1.4 (founder
			// is creating Stripe products in the background). Once the
			// founder fills in real IDs, this check should be tightened.
			if pid, _ := obj["price_id"].(string); pid != "" && !strings.HasPrefix(pid, "price_") && !strings.HasPrefix(pid, "PLACEHOLDER_") {
				t.Errorf("module_products.%s.price_id = %q, want \"price_*\" or \"PLACEHOLDER_*\"", key, pid)
			}
			// monthly_cents should be positive.
			if cents, ok := obj["monthly_cents"].(float64); ok && cents <= 0 {
				t.Errorf("module_products.%s.monthly_cents = %v, want positive", key, cents)
			}
		})
	}
}

// TestBillingConfig_ModulePricesMatchLockedTable pins the 6 module prices
// from the locked pricing table. If you change these values, you MUST
// update aegisgate-pricing-decisions-locked-2026-06-04.
func TestBillingConfig_ModulePricesMatchLockedTable(t *testing.T) {
	data, err := os.ReadFile("billing-config.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var v struct {
		ModuleProducts map[string]struct {
			MonthlyCents int `json:"monthly_cents"`
		} `json:"module_products"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	expected := map[string]int{
		"hipaa":    9900,  // $99/mo
		"pci":      9900,  // $99/mo
		"soc2":     14900, // $149/mo
		"iso42001": 7900,  // $79/mo
		"fedramp":  49900, // $499/mo
		"fips":     29900, // $299/mo
	}
	for module, wantCents := range expected {
		t.Run(module, func(t *testing.T) {
			got := v.ModuleProducts[module]
			if got.MonthlyCents != wantCents {
				t.Errorf("module %s: monthly_cents = %d, want %d ($%d/mo)",
					module, got.MonthlyCents, wantCents, wantCents/100)
			}
		})
	}
}

// TestBillingConfig_StarterConfig verifies the stripe_config section
// has the webhook endpoint and publishable key.
func TestBillingConfig_StarterConfig(t *testing.T) {
	data, err := os.ReadFile("billing-config.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var v struct {
		StripeConfig struct {
			WebhookEndpoint string `json:"webhook_endpoint"`
			PublishableKey  string `json:"publishable_key"`
		} `json:"stripe_config"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if v.StripeConfig.WebhookEndpoint == "" {
		t.Error("stripe_config.webhook_endpoint is empty")
	}
	if !strings.HasPrefix(v.StripeConfig.WebhookEndpoint, "https://") {
		t.Errorf("stripe_config.webhook_endpoint should be HTTPS, got %q", v.StripeConfig.WebhookEndpoint)
	}
	if v.StripeConfig.PublishableKey == "" {
		t.Error("stripe_config.publishable_key is empty")
	}
}
