// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Vertical bundles (v3.7.0)
//
// bundle.go defines industry-specific accelerator packs that group compliance
// frameworks at a ~25-35% discount vs. buying them individually. A bundle
// sits ON TOP of a tier subscription — you can't buy a bundle without a tier,
// because the tier provides the platform capability (API, multi-tenancy, etc.)
// that the frameworks run on.
//
// Pricing model:
//
//	Tiers define PLATFORM capability + INCLUDED frameworks.
//	Accelerators add frameworks from higher tiers at a bundled price.
//	You never pay twice: frameworks included in your tier are free.
//
// Design principles:
//   - Grow as you need: start at a tier, add accelerators, upgrade when natural.
//   - No double-charging: tier-included frameworks are subtracted from accelerator cost.
//   - 9 line items on the pricing page (4 tiers + 5 accelerators).
//   - Simple enough to explain in 30 seconds, flexible enough for any org size.

package compliance

import (
	"fmt"
	"sort"
	"sync"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	tierpkg "github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// ---------------------------------------------------------------------------
// Tier-included frameworks (the "free with your tier" list)
// ---------------------------------------------------------------------------

// TierIncludedFrameworks returns the compliance frameworks included at no
// extra cost in the given tier. These are built into the platform — you
// don't need an accelerator or per-module purchase to access them.
//
// Community:    5 frameworks (privacy + AI safety basics)
// Developer:    +2 frameworks (SOC 2, ISO 27001 — audit-ready essentials)
// Professional: +8 frameworks (the deep compliance bench)
// Enterprise:   +3 frameworks (regulated-industry heavyweights)
func TierIncludedFrameworks(t tierpkg.Tier) []string {
	switch t {
	case tierpkg.TierCommunity:
		return []string{
			license.ModuleCCPA,
			"gdpr",
			"owasp_llm",
			"owasp_web",
			"atlas",
		}
	case tierpkg.TierDeveloper:
		return append(TierIncludedFrameworks(tierpkg.TierCommunity),
			license.ModuleSOC2,
			license.ModuleISO42001,
		)
	case tierpkg.TierProfessional:
		return append(TierIncludedFrameworks(tierpkg.TierDeveloper),
			license.ModuleHIPAA,
			license.ModulePCI,
			license.ModuleISO42001, // already in Developer; idempotent
			license.ModuleFIPS,
			license.ModuleEUAIAct,
			"nist_csf",
			"cis",
			license.ModuleCMMCL2,
			license.ModuleNIST800171,
		)
	case tierpkg.TierEnterprise:
		return append(TierIncludedFrameworks(tierpkg.TierProfessional),
			license.ModuleFedRAMP,
			license.ModuleHITRUST,
			license.ModuleTISAX,
		)
	default:
		return TierIncludedFrameworks(tierpkg.TierCommunity)
	}
}

// IsFrameworkIncludedInTier returns true if the framework is included in
// the given tier (no additional purchase needed).
func IsFrameworkIncludedInTier(framework string, t tierpkg.Tier) bool {
	for _, f := range TierIncludedFrameworks(t) {
		if f == framework {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Vertical accelerator bundles
// ---------------------------------------------------------------------------

// VerticalBundle groups compliance frameworks by industry vertical at a
// discounted price. Think of it as an "industry pack" that a CISO can buy
// instead of evaluating 15 individual module prices.
type VerticalBundle struct {
	// ID is the canonical bundle identifier (e.g., "healthcare").
	ID string `json:"id"`

	// DisplayName is the human-readable name (e.g., "Healthcare Accelerator").
	DisplayName string `json:"display_name"`

	// Description is a one-line pitch for the pricing page.
	Description string `json:"description"`

	// Frameworks lists the canonical module keys in this bundle.
	// These are the license module constants (e.g., "hipaa", "hitrust").
	Frameworks []string `json:"frameworks"`

	// RequiredTier is the minimum tier required to purchase this bundle.
	// (You need platform capability to run the frameworks.)
	RequiredTier tierpkg.Tier `json:"required_tier"`

	// BundlePriceCents is the price of the full bundle in cents/month.
	// This is already the discounted price.
	BundlePriceCents int `json:"bundle_price_cents"`

	// IndividualPriceCents is what these frameworks would cost if bought
	// individually (without bundling). Shown on pricing page as strikethrough.
	IndividualPriceCents int `json:"individual_price_cents"`

	// DiscountPercent is the savings percentage (for display on pricing page).
	DiscountPercent int `json:"discount_percent"`

	// Industry tags for the pricing page filtering.
	Industries []string `json:"industries"`
}

// verticalBundles is the canonical table of all accelerator bundles.
// Source of truth: aegisgate-pricing-decisions-locked-2026-06-04.
var verticalBundles = map[string]VerticalBundle{
	"healthcare": {
		ID:          "healthcare",
		DisplayName: "Healthcare Accelerator",
		Description: "HIPAA + HITRUST CSF — everything a healthcare org needs for compliance and certification.",
		Frameworks: []string{
			license.ModuleHIPAA,
			license.ModuleHITRUST,
		},
		RequiredTier:        tierpkg.TierEnterprise, // HITRUST requires Enterprise
		BundlePriceCents:   59900,                  // $599/mo
		IndividualPriceCents: 89800,                 // $99 + $799 = $898/mo individually
		DiscountPercent:     33,
		Industries:          []string{"healthcare", "medical", "pharma", "biotech"},
	},
	"defense": {
		ID:          "defense",
		DisplayName: "Defense Accelerator",
		Description: "CMMC L2 + NIST 800-171 + FedRAMP — the DoD contractor compliance stack.",
		Frameworks: []string{
			license.ModuleCMMCL2,
			license.ModuleNIST800171,
			license.ModuleFedRAMP,
		},
		RequiredTier:        tierpkg.TierProfessional,
		BundlePriceCents:   89900,                  // $899/mo
		IndividualPriceCents: 139700,                // $499 + $399 + $499 = $1,397/mo
		DiscountPercent:     36,
		Industries:          []string{"defense", "aerospace", "government", "contracting", "dod"},
	},
	"finance": {
		ID:          "finance",
		DisplayName: "Financial Services Accelerator",
		Description: "PCI-DSS + SOC 2 + ISO 27001 — the essential trio for fintech and banking.",
		Frameworks: []string{
			license.ModulePCI,
			license.ModuleSOC2,
			"iso27001",
		},
		RequiredTier:        tierpkg.TierDeveloper,
		BundlePriceCents:   24900,                   // $249/mo
		IndividualPriceCents: 32700,                  // $99 + $149 + $79 = $327/mo
		DiscountPercent:     24,
		Industries:          []string{"finance", "fintech", "banking", "insurance", "payments"},
	},
	"manufacturing": {
		ID:          "manufacturing",
		DisplayName: "Manufacturing & Automotive Accelerator",
		Description: "TISAX + ISO 27001 + ISO 42001 — the European industrial compliance standard.",
		Frameworks: []string{
			license.ModuleTISAX,
			"iso27001",
			license.ModuleISO42001,
		},
		RequiredTier:        tierpkg.TierEnterprise, // TISAX requires Enterprise
		BundlePriceCents:   49900,                   // $499/mo
		IndividualPriceCents: 75700,                   // $599 + $79 + $79 = $757/mo
		DiscountPercent:     34,
		Industries:          []string{"manufacturing", "automotive", "supply_chain", "industry"},
	},
	"privacy": {
		ID:          "privacy",
		DisplayName: "Privacy Pro Accelerator",
		Description: "GDPR + CCPA + ISO 27001 — privacy-first compliance for any org handling personal data.",
		Frameworks: []string{
			"gdpr",
			license.ModuleCCPA,
			"iso27001",
		},
		RequiredTier:        tierpkg.TierCommunity, // Privacy is for everyone
		BundlePriceCents:   4900,                    // $49/mo
		IndividualPriceCents: 7900,                   // $0 + $0 + $79 = $79/mo (GDPR + CCPA free, ISO 27001 $79)
		DiscountPercent:     38,
		Industries:          []string{"privacy", "saas", "ecommerce", "adtech", "data"},
	},
}

// once protects the bundle registration.
var bundleOnce sync.Once

// AllBundles returns all vertical accelerator bundles in display order
// (sorted by RequiredTier, then by BundlePriceCents ascending).
func AllBundles() []VerticalBundle {
	bundleOnce.Do(func() {
		// No-op: bundles are statically defined above.
		// This hook exists for future dynamic registration if needed.
	})
	out := make([]VerticalBundle, 0, len(verticalBundles))
	for _, b := range verticalBundles {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RequiredTier != out[j].RequiredTier {
			return out[i].RequiredTier < out[j].RequiredTier
		}
		return out[i].BundlePriceCents < out[j].BundlePriceCents
	})
	return out
}

// GetBundle returns a bundle by ID. Returns false if not found.
func GetBundle(id string) (VerticalBundle, bool) {
	b, ok := verticalBundles[id]
	return b, ok
}

// BundleCount returns the number of registered bundles.
func BundleCount() int {
	return len(verticalBundles)
}

// BundlesForIndustry returns all bundles tagged with the given industry.
func BundlesForIndustry(industry string) []VerticalBundle {
	var result []VerticalBundle
	for _, b := range verticalBundles {
		for _, ind := range b.Industries {
			if ind == industry {
				result = append(result, b)
				break
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].BundlePriceCents < result[j].BundlePriceCents
	})
	return result
}

// BundlesForTier returns all bundles available at the given tier.
// (The tier must meet the bundle's RequiredTier.)
func BundlesForTier(t tierpkg.Tier) []VerticalBundle {
	var result []VerticalBundle
	for _, b := range verticalBundles {
		if t >= b.RequiredTier {
			result = append(result, b)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].BundlePriceCents < result[j].BundlePriceCents
	})
	return result
}

// EffectiveBundlePrice calculates what a customer actually pays for a bundle
// given their current tier. Frameworks already included in the tier are
// subtracted from the bundle price. This prevents double-charging.
//
// Example: An Enterprise customer buying the Healthcare accelerator already
// has HITRUST included in their tier, so they only pay for HIPAA.
func EffectiveBundlePrice(bundleID string, customerTier tierpkg.Tier) (int, error) {
	b, ok := verticalBundles[bundleID]
	if !ok {
		return 0, fmt.Errorf("unknown bundle: %s", bundleID)
	}

	if customerTier < b.RequiredTier {
		return 0, fmt.Errorf("tier %s does not meet bundle %s minimum tier %s",
			customerTier, b.ID, b.RequiredTier)
	}

	// Count how many frameworks in this bundle are already included in the tier.
	included := TierIncludedFrameworks(customerTier)
	alreadyOwned := 0
	for _, fw := range b.Frameworks {
		for _, inc := range included {
			if fw == inc {
				alreadyOwned++
				break
			}
		}
	}

	// If all frameworks are already included, the bundle costs $0.
	if alreadyOwned == len(b.Frameworks) {
		return 0, nil
	}

	// Proportional discount: reduce price by the fraction already owned.
	// This ensures fairness — you don't pay for what you already have.
	if alreadyOwned > 0 {
		fractionOwned := float64(alreadyOwned) / float64(len(b.Frameworks))
		reduction := int(float64(b.BundlePriceCents) * fractionOwned)
		return b.BundlePriceCents - reduction, nil
	}

	return b.BundlePriceCents, nil
}

// BundleFrameworksMissing returns the list of frameworks in the bundle that
// are NOT already included in the customer's tier. These are the frameworks
// the customer actually gains from the bundle.
func BundleFrameworksMissing(bundleID string, customerTier tierpkg.Tier) ([]string, error) {
	b, ok := verticalBundles[bundleID]
	if !ok {
		return nil, fmt.Errorf("unknown bundle: %s", bundleID)
	}

	included := TierIncludedFrameworks(customerTier)
	var missing []string
	for _, fw := range b.Frameworks {
		found := false
		for _, inc := range included {
			if fw == inc {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, fw)
		}
	}
	return missing, nil
}

// UpgradePath returns a human-readable recommendation for the customer.
// If the customer's tier already includes some bundle frameworks, it
// explains what they'd gain and what they'd save.
func UpgradePath(bundleID string, customerTier tierpkg.Tier) (string, error) {
	b, ok := verticalBundles[bundleID]
	if !ok {
		return "", fmt.Errorf("unknown bundle: %s", bundleID)
	}

	included := TierIncludedFrameworks(customerTier)
	alreadyOwned := 0
	var gained []string
	for _, fw := range b.Frameworks {
		found := false
		for _, inc := range included {
			if fw == inc {
				found = true
				alreadyOwned++
				break
			}
		}
		if !found {
			gained = append(gained, fw)
		}
	}

	effectivePrice, _ := EffectiveBundlePrice(bundleID, customerTier)

	switch {
	case alreadyOwned == len(b.Frameworks):
		return fmt.Sprintf("All %s frameworks are already included in your %s tier. No additional purchase needed.",
			b.DisplayName, customerTier.DisplayName()), nil
	case alreadyOwned > 0:
		return fmt.Sprintf("%s adds %d frameworks (%v) not in your %s tier. %d of %d are already included. Effective price: $%d/mo (save %d%%).",
			b.DisplayName, len(gained), gained, customerTier.DisplayName(),
			alreadyOwned, len(b.Frameworks),
			effectivePrice/100, b.DiscountPercent), nil
	default:
		return fmt.Sprintf("%s adds %d frameworks to your %s tier. Bundle price: $%d/mo (save %d%% vs. individual purchase).",
			b.DisplayName, len(b.Frameworks), customerTier.DisplayName(),
			b.BundlePriceCents/100, b.DiscountPercent), nil
	}
}