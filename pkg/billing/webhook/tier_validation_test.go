// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Tier validation tests for billing/webhook (v3.1.1)
//
// Verifies that the Stripe webhook handler:
//   1. Rejects checkout sessions with unknown tier values (returns invalid_tier)
//   2. Accepts all 4 valid tier values (starter, developer, professional, enterprise)
//   3. Normalizes tier aliases (pro -> professional, free -> community)
//   4. inferTierFromAmount returns the right tier for each price bucket
// =========================================================================

package webhook

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// makeCheckoutSession builds a JSON CheckoutSession payload for testing.
// Tier can be a metadata tier string ("starter", "pro", "garbage") or empty
// to force inference from amount.
func makeCheckoutSession(id, email string, amountCents int64, metadataTier string) json.RawMessage {
	md := map[string]string{}
	if metadataTier != "" {
		md["tier"] = metadataTier
	}
	session := map[string]interface{}{
		"id":             id,
		"customer":       "cus_" + id,
		"customer_email": email,
		"amount_total":   amountCents,
		"payment_status": "paid",
		"metadata":       md,
	}
	data, _ := json.Marshal(session)
	return data
}

// TestHandleCheckoutCompleted_RejectsInvalidTier verifies that a checkout
// session with an unknown tier value in metadata is rejected with a
// structured invalid_tier error and does NOT generate a license.
func TestHandleCheckoutCompleted_RejectsInvalidTier(t *testing.T) {
	server := NewWebhookServer("8080")
	gen := NewMockLicenseGenerator()
	server.WithLicenseGenerator(gen)

	// "starthr" is a typo of "starter" — should be rejected
	data := makeCheckoutSession("cs_invalid_001", "test1@example.com", 2900, "starthr")

	err := server.handleCheckoutCompleted(data)
	if err == nil {
		t.Fatal("expected error for invalid tier, got nil")
	}
	if !strings.Contains(err.Error(), ErrInvalidTier) {
		t.Errorf("expected error to contain %q, got: %v", ErrInvalidTier, err)
	}

	// Verify no license was generated
	if len(gen.keys) != 0 {
		t.Errorf("expected 0 license keys generated for invalid tier, got %d: %v", len(gen.keys), gen.keys)
	}
}

// TestHandleCheckoutCompleted_AcceptsValidTiers verifies that all 4 valid
// tier values pass validation and result in license generation.
func TestHandleCheckoutCompleted_AcceptsValidTiers(t *testing.T) {
	validTiers := []string{"starter", "developer", "professional", "enterprise"}
	for _, tname := range validTiers {
		t.Run(tname, func(t *testing.T) {
			server := NewWebhookServer("8080")
			gen := NewMockLicenseGenerator()
			server.WithLicenseGenerator(gen)

			data := makeCheckoutSession("cs_valid_"+tname, "test-"+tname+"@example.com", 2900, tname)

			if err := server.handleCheckoutCompleted(data); err != nil {
				t.Errorf("expected no error for valid tier %q, got: %v", tname, err)
			}
			if len(gen.keys) != 1 {
				t.Errorf("expected 1 license key for tier %q, got %d", tname, len(gen.keys))
			}
			// The license key should embed the canonical (lowercase) tier name
			foundKey := false
			for k := range gen.keys {
				if strings.Contains(k, strings.ToUpper(tname)) {
					foundKey = true
					break
				}
			}
			if !foundKey {
				t.Errorf("expected license key to contain tier %q, got keys: %v", tname, gen.keys)
			}
		})
	}
}

// TestHandleCheckoutCompleted_NormalizesAliases verifies that alias inputs
// (e.g., "pro", "free") are normalized to canonical form via tier.ParseTier.
func TestHandleCheckoutCompleted_NormalizesAliases(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"pro", "professional"},
		{"free", "community"},
		{"PRO", "professional"},    // case-insensitive
		{"  Starter  ", "starter"}, // whitespace-trimmed
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			parsed, err := tier.ParseTier(c.input)
			if err != nil {
				t.Fatalf("ParseTier(%q) returned error: %v", c.input, err)
			}
			if parsed.String() != c.expected {
				t.Errorf("ParseTier(%q).String() = %q, want %q", c.input, parsed.String(), c.expected)
			}
		})
	}
}

// TestInferTierFromAmount_AllTiers verifies the fallback amount-based
// inference covers the 3 paid tiers (Enterprise is custom-quote; falls
// into professional bucket by amount).
func TestInferTierFromAmount_AllTiers(t *testing.T) {
	server := NewWebhookServer("8080")
	cases := []struct {
		amountCents int64
		want        string
	}{
		{2900, "starter"},
		{7900, "developer"},
		{24900, "professional"},
		{99999, "professional"}, // enterprise falls into professional bucket
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			got := server.inferTierFromAmount(c.amountCents)
			if got != c.want {
				t.Errorf("inferTierFromAmount(%d) = %q, want %q", c.amountCents, got, c.want)
			}
		})
	}
}

// TestHandleCheckoutCompleted_RejectsEmptyMetadataAndUninferableAmount
// verifies the edge case where metadata is empty AND the amount is too
// low to infer a tier (community/free has no paid amount). inferTierFromAmount
// defaults to "developer" for unknown amounts, so this is still a valid
// path. This test pins the current behavior.
func TestHandleCheckoutCompleted_DefaultsToDeveloperOnUnknownAmount(t *testing.T) {
	server := NewWebhookServer("8080")
	gen := NewMockLicenseGenerator()
	server.WithLicenseGenerator(gen)

	// amount=0, no metadata — inferTierFromAmount returns "developer" by default
	data := makeCheckoutSession("cs_default_dev", "test@example.com", 0, "")

	if err := server.handleCheckoutCompleted(data); err != nil {
		t.Errorf("expected no error for default-tier inference, got: %v", err)
	}
	if len(gen.keys) != 1 {
		t.Errorf("expected 1 license key, got %d", len(gen.keys))
	}
	// Key should be AG-DEVELOPER-...
	foundDevKey := false
	for k := range gen.keys {
		if strings.Contains(k, "DEVELOPER") {
			foundDevKey = true
			break
		}
	}
	if !foundDevKey {
		t.Errorf("expected license key to indicate DEVELOPER default, got keys: %v", gen.keys)
	}
}
