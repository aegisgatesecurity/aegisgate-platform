// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Billing config schema tests (v3.2.0 Phase 1.4)
//
// Tests the structure of billing-config.json and the example template.
// Pins the schema so that future changes (e.g., adding a 7th module,
// changing the price format) require an explicit test update.
//
// In CI (where billing-config.json is gitignored), tests fall back to
// billing-config.example.json so the schema is always validated.

package billing

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// loadBillingConfig reads billing-config.json if present, otherwise falls
// back to billing-config.example.json. This allows CI to validate the
// schema structure without the real (gitignored) config.
func loadBillingConfig(t *testing.T) []byte {
	t.Helper()
	if data, err := os.ReadFile("billing-config.json"); err == nil {
		t.Log("using billing-config.json (live config)")
		return data
	}
	data, err := os.ReadFile("billing-config.example.json")
	if err != nil {
		t.Fatalf("cannot read billing-config.json or billing-config.example.json: %v", err)
	}
	t.Log("billing-config.json not found, falling back to billing-config.example.json")
	return data
}

// TestBillingConfig_ValidJSON verifies the file parses as valid JSON.
func TestBillingConfig_ValidJSON(t *testing.T) {
	data := loadBillingConfig(t)
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

// TestBillingConfig_TierPrices verifies all expected tier price keys exist
// and have sensible values (positive cents, monthly < annual).
func TestBillingConfig_TierPrices(t *testing.T) {
	data := loadBillingConfig(t)
	var v struct {
		TierPrices map[string]int `json:"tier_prices"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	expected := []string{
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
	data := loadBillingConfig(t)
	var v struct {
		TierProducts map[string]any `json:"tier_products"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	richKeys := []string{
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

// TestBillingConfig_ModuleProducts verifies the module entries.
func TestBillingConfig_ModuleProducts(t *testing.T) {
	data := loadBillingConfig(t)
	var v struct {
		ModuleProducts map[string]any `json:"module_products"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// The example config has 6 modules; the live config has 7 (eu_ai_act added in v3.3.0).
	// Accept either 6 or 7 so CI (example) and local (live) both pass.
	minModules := 6
	maxModules := 7
	if len(v.ModuleProducts) < minModules || len(v.ModuleProducts) > maxModules {
		t.Errorf("got %d module_products, want %d-%d", len(v.ModuleProducts), minModules, maxModules)
	}

	// Core 6 modules must always be present.
	core := []string{"hipaa", "pci", "soc2", "iso42001", "fedramp", "fips"}
	for _, key := range core {
		t.Run(key, func(t *testing.T) {
			val, ok := v.ModuleProducts[key]
			if !ok {
				t.Fatalf("missing module: %s", key)
			}
			obj, isObj := val.(map[string]any)
			if !isObj {
				t.Fatalf("module_products.%s should be an object, got %T", key, val)
			}
			for _, field := range []string{"price_id", "product_id", "lookup_key", "buy_button_id", "monthly_cents", "display_name", "required_tier"} {
				if obj[field] == nil {
					t.Errorf("module_products.%s missing %q", key, field)
				}
			}
			if lk, _ := obj["lookup_key"].(string); lk != "module_"+key {
				t.Errorf("module_products.%s.lookup_key = %q, want \"module_%s\"", key, lk, key)
			}
			if pid, _ := obj["price_id"].(string); !strings.HasPrefix(pid, "price_") {
				t.Errorf("module_products.%s.price_id = %q, want \"price_*\"", key, pid)
			}
			if bid, _ := obj["buy_button_id"].(string); !strings.HasPrefix(bid, "buy_btn_") {
				t.Errorf("module_products.%s.buy_button_id = %q, want \"buy_btn_*\"", key, bid)
			}
			if cents, ok := obj["monthly_cents"].(float64); ok && cents <= 0 {
				t.Errorf("module_products.%s.monthly_cents = %v, want positive", key, cents)
			}
		})
	}

	// eu_ai_act is optional (present in live config, not in example).
	if _, ok := v.ModuleProducts["eu_ai_act"]; ok {
		t.Run("eu_ai_act", func(t *testing.T) {
			val := v.ModuleProducts["eu_ai_act"]
			obj, isObj := val.(map[string]any)
			if !isObj {
				t.Fatalf("module_products.eu_ai_act should be an object, got %T", val)
			}
			if pid, _ := obj["price_id"].(string); !strings.HasPrefix(pid, "price_") {
				t.Errorf("module_products.eu_ai_act.price_id = %q, want \"price_*\"", pid)
			}
		})
	}
}

// TestBillingConfig_ModulePricesMatchLockedTable pins the 6 module prices
// from the locked pricing table.
func TestBillingConfig_ModulePricesMatchLockedTable(t *testing.T) {
	data := loadBillingConfig(t)
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
			got, ok := v.ModuleProducts[module]
			if !ok {
				t.Fatalf("missing module: %s", module)
			}
			if got.MonthlyCents != wantCents {
				t.Errorf("module %s: monthly_cents = %d, want %d ($%d/mo)",
					module, got.MonthlyCents, wantCents, wantCents/100)
			}
		})
	}
}

// TestBillingConfig_WebhookEndpoint verifies that the billing config
// has the webhook endpoint and publishable key.
func TestBillingConfig_WebhookEndpoint(t *testing.T) {
	data := loadBillingConfig(t)
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
	// The example config uses a placeholder for publishable_key; only
	// enforce non-empty if using the live config.
	if _, err := os.Stat("billing-config.json"); err == nil {
		if v.StripeConfig.PublishableKey == "" {
			t.Error("stripe_config.publishable_key is empty in live config")
		}
	}
}

// TestBillingConfig_NoPlaceholders pins that all module price_ids are
// real (not PLACEHOLDER_*).
func TestBillingConfig_NoPlaceholders(t *testing.T) {
	data := loadBillingConfig(t)
	var v struct {
		ModuleProducts map[string]struct {
			PriceID   string `json:"price_id"`
			ProductID string `json:"product_id"`
		} `json:"module_products"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// Accept 6 (example) or 7 (live with eu_ai_act).
	if len(v.ModuleProducts) < 6 || len(v.ModuleProducts) > 7 {
		t.Errorf("got %d module_products, want 6-7", len(v.ModuleProducts))
	}
	for name, m := range v.ModuleProducts {
		t.Run(name, func(t *testing.T) {
			if strings.HasPrefix(m.PriceID, "PLACEHOLDER") {
				t.Errorf("module %s: price_id is still PLACEHOLDER: %q", name, m.PriceID)
			}
			if strings.HasPrefix(m.ProductID, "PLACEHOLDER") {
				t.Errorf("module %s: product_id is still PLACEHOLDER: %q", name, m.ProductID)
			}
			if !strings.HasPrefix(m.PriceID, "price_") {
				t.Errorf("module %s: price_id should start with 'price_', got %q", name, m.PriceID)
			}
			if !strings.HasPrefix(m.ProductID, "prod_") {
				t.Errorf("module %s: product_id should start with 'prod_', got %q", name, m.ProductID)
			}
		})
	}
}

// TestBillingConfig_ProPriceIsLocked pins the Professional tier at $499/mo,
// $4990/yr per the v3.2.0 Phase 2 decision.
func TestBillingConfig_ProPriceIsLocked(t *testing.T) {
	data := loadBillingConfig(t)
	var v struct {
		TierPrices map[string]int `json:"tier_prices"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	cases := []struct {
		key  string
		want int
		desc string
	}{
		{"professional_monthly", 49900, "$499/mo"},
		{"professional_annual", 499000, "$4990/yr"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			got, ok := v.TierPrices[tc.key]
			if !ok {
				t.Fatalf("missing key %s", tc.key)
			}
			if got != tc.want {
				t.Errorf("%s = %d cents ($%.2f), want %d cents (%s)",
					tc.key, got, float64(got)/100, tc.want, tc.desc)
			}
		})
	}
}

// TestBillingConfig_ProPriceIDsAreCurrent pins the current Pro Stripe
// Price IDs. Update this test if the Stripe Prices are regenerated.
func TestBillingConfig_ProPriceIDsAreCurrent(t *testing.T) {
	data := loadBillingConfig(t)
	var tpRaw map[string]json.RawMessage
	{
		var top map[string]json.RawMessage
		if err := json.Unmarshal(data, &top); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		tp, ok := top["tier_products"]
		if !ok {
			t.Fatal("tier_products not found in config")
		}
		if err := json.Unmarshal(tp, &tpRaw); err != nil {
			t.Fatalf("Unmarshal tier_products: %v", err)
		}
	}
	cases := []struct {
		key        string
		wantPrice  string
		wantButton string
	}{
		{"professional_monthly", "price_1Tf6NWK2DQfk64XNNosvo3H6A", "buy_btn_1Tf6RqK2DQfk64XNJId23XtS"},
		{"professional_annual", "price_1Tf6NwK2DQfk64XNcsYRFodX", "buy_btn_1Tf6VcK2DQfk64XNyG8vnU5X"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			raw, ok := tpRaw[tc.key]
			if !ok {
				t.Fatalf("missing key %s", tc.key)
			}
			if len(raw) == 0 || raw[0] != '{' {
				t.Fatalf("tier_products.%s is not an object: %s", tc.key, string(raw))
			}
			var got struct {
				PriceID     string `json:"price_id"`
				BuyButtonID string `json:"buy_button_id"`
			}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("Unmarshal %s: %v", tc.key, err)
			}
			if got.PriceID != tc.wantPrice {
				t.Errorf("price_id = %q, want %q", got.PriceID, tc.wantPrice)
			}
			if got.BuyButtonID != tc.wantButton {
				t.Errorf("buy_button_id = %q, want %q", got.BuyButtonID, tc.wantButton)
			}
		})
	}
}
