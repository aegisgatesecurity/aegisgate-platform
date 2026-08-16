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
// v4.2.0: This function now DERIVES from gating.go (single source of truth).
// It queries AllModuleRequirements() and filters by tier. Manual list
// maintenance is eliminated.
//
// Community:    4 frameworks (OWASP LLM, OWASP Web, ATLAS, NIST AI RMF)
// Developer:    +6 frameworks (HIPAA, PCI, SOC 2, ISO 27001, CCPA, GDPR)
// Professional: +16 frameworks (industry-specific + security foundations)
// Enterprise:   +5 frameworks (FedRAMP, CMMC L2, NIST 800-171, HITRUST, TISAX)
func TierIncludedFrameworks(t tierpkg.Tier) []string {
	// v4.2.0: All frameworks are in gating.go (single source of truth).
	// No more communityBuiltIn list — Community tier frameworks are in
	// gating.go with RequiredTier: TierCommunity.
	var result []string

	for _, req := range AllModuleRequirements() {
		if t >= req.RequiredTier {
			result = append(result, req.Module)
		}
	}
	return result
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
// v4.2.0: 7 bundles per pricing unification plan.
var verticalBundles = map[string]VerticalBundle{
	"privacy": {
		ID:          "privacy",
		DisplayName: "Privacy & Data Protection Accelerator",
		Description: "GDPR + CCPA + ISO 27001 — privacy-first compliance for any org handling personal data.",
		Frameworks: []string{
			license.ModuleGDPR,
			license.ModuleCCPA,
			license.ModuleISO27001,
		},
		RequiredTier:         tierpkg.TierDeveloper,
		BundlePriceCents:     14900, // $149/mo
		IndividualPriceCents: 44700, // $149 + $149 + $149 = $447/mo
		DiscountPercent:      67,
		Industries:           []string{"privacy", "saas", "ecommerce", "adtech", "data"},
	},
	"saas_b2b": {
		ID:          "saas_b2b",
		DisplayName: "SaaS / B2B Technology Accelerator",
		Description: "SOC 2 + ISO 27001 + ISO 42001 — the essential stack for B2B SaaS companies selling to enterprise.",
		Frameworks: []string{
			license.ModuleSOC2,
			license.ModuleISO27001,
			license.ModuleISO42001,
		},
		RequiredTier:         tierpkg.TierDeveloper,
		BundlePriceCents:     19900, // $199/mo
		IndividualPriceCents: 49700, // $149 + $149 + $199 = $497/mo
		DiscountPercent:      60,
		Industries:           []string{"saas", "technology", "startup", "b2b", "software"},
	},
	"finance": {
		ID:          "finance",
		DisplayName: "Financial Services Accelerator",
		Description: "PCI-DSS + SOC 2 + ISO 27001 + GLBA + SOX + FFIEC — the complete banking and fintech compliance stack.",
		Frameworks: []string{
			license.ModulePCI,
			license.ModuleSOC2,
			license.ModuleISO27001,
			license.ModuleGLBA,
			license.ModuleSOX,
			license.ModuleFFIEC,
		},
		RequiredTier:         tierpkg.TierDeveloper,
		BundlePriceCents:     24900,  // $249/mo
		IndividualPriceCents: 104400, // $149 + $149 + $149 + $199 + $199 + $199 = $1,044/mo
		DiscountPercent:      76,
		Industries:           []string{"finance", "fintech", "banking", "insurance", "payments"},
	},
	"healthcare": {
		ID:          "healthcare",
		DisplayName: "Healthcare Accelerator",
		Description: "HIPAA + HITECH + HITRUST CSF — everything a healthcare org needs for compliance and certification.",
		Frameworks: []string{
			license.ModuleHIPAA,
			license.ModuleHITECH,
			license.ModuleHITRUST,
		},
		RequiredTier:         tierpkg.TierDeveloper,
		BundlePriceCents:     19900, // $199/mo
		IndividualPriceCents: 84700, // $149 + $199 + $499 = $847/mo
		DiscountPercent:      77,
		Industries:           []string{"healthcare", "medical", "pharma", "biotech", "hospital"},
	},
	"eu_compliance": {
		ID:          "eu_compliance",
		DisplayName: "EU Compliance Accelerator",
		Description: "EU AI Act + GDPR + ISO 42001 — compliance for any organization operating in the European Union.",
		Frameworks: []string{
			license.ModuleEUAIAct,
			license.ModuleGDPR,
			license.ModuleISO42001,
		},
		RequiredTier:         tierpkg.TierDeveloper, // Available at Developer — EU startups need this
		BundlePriceCents:     14900,                 // $149/mo
		IndividualPriceCents: 54700,                 // $199 + $149 + $199 = $547/mo
		DiscountPercent:      73,
		Industries:           []string{"eu", "europe", "privacy", "ai_governance"},
	},
	"energy": {
		ID:          "energy",
		DisplayName: "Energy & Critical Infrastructure Accelerator",
		Description: "NERC CIP + TSA SD + FIPS — compliance for utilities, energy, and critical infrastructure operators.",
		Frameworks: []string{
			license.ModuleNERCCIP,
			license.ModuleTSASD,
			license.ModuleFIPS,
		},
		RequiredTier:         tierpkg.TierProfessional,
		BundlePriceCents:     29900, // $299/mo
		IndividualPriceCents: 59700, // $199 + $199 + $199 = $597/mo
		DiscountPercent:      50,
		Industries:           []string{"energy", "utilities", "oil_gas", "pipeline", "critical_infrastructure", "power"},
	},
	"defense": {
		ID:          "defense",
		DisplayName: "Defense & Government Accelerator",
		Description: "CMMC L2 + NIST 800-171 + FedRAMP + CJIS + TSA SD — the complete DoD and government contractor compliance stack.",
		Frameworks: []string{
			license.ModuleCMMCL2,
			license.ModuleNIST800171,
			license.ModuleFedRAMP,
			license.ModuleCJIS,
			license.ModuleTSASD,
		},
		RequiredTier:         tierpkg.TierEnterprise, // Contains Enterprise-tier frameworks
		BundlePriceCents:     119900,                 // $1,199/mo
		IndividualPriceCents: 189500,                 // $499 + $499 + $499 + $199 + $199 = $1,895/mo
		DiscountPercent:      37,
		Industries:           []string{"defense", "aerospace", "government", "contracting", "dod", "law_enforcement"},
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
