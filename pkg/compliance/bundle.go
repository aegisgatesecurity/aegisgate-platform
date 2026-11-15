// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Vertical bundles (v3.7.0)
//
// bundle.go defines industry-specific accelerator packs that group compliance
// frameworks by vertical. A bundle sits ON TOP of a tier — it groups
// frameworks that an organization in a specific industry would typically
// need together.

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

// VerticalBundle groups compliance frameworks by industry vertical.
// Think of it as an "industry pack" that groups frameworks an organization
// in a specific sector would typically need.
type VerticalBundle struct {
	// ID is the canonical bundle identifier (e.g., "healthcare").
	ID string `json:"id"`

	// DisplayName is the human-readable name (e.g., "Healthcare Accelerator").
	DisplayName string `json:"display_name"`

	// Description is a one-line summary of the bundle.
	Description string `json:"description"`

	// Frameworks lists the canonical module keys in this bundle.
	// These are the license module constants (e.g., "hipaa", "hitrust").
	Frameworks []string `json:"frameworks"`

	// RequiredTier is the minimum tier required to use this bundle.
	// (You need platform capability to run the frameworks.)
	RequiredTier tierpkg.Tier `json:"required_tier"`

	// Industry tags for filtering.
	Industries []string `json:"industries"`
}

// verticalBundles is the canonical table of all accelerator bundles.
// v4.2.0: 7 bundles.
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
		RequiredTier: tierpkg.TierDeveloper,
		Industries:   []string{"privacy", "saas", "ecommerce", "adtech", "data"},
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
		RequiredTier: tierpkg.TierDeveloper,
		Industries:   []string{"saas", "technology", "startup", "b2b", "software"},
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
		RequiredTier: tierpkg.TierDeveloper,
		Industries:   []string{"finance", "fintech", "banking", "insurance", "payments"},
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
		RequiredTier: tierpkg.TierDeveloper,
		Industries:   []string{"healthcare", "medical", "pharma", "biotech", "hospital"},
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
		RequiredTier: tierpkg.TierDeveloper,
		Industries:   []string{"eu", "europe", "privacy", "ai_governance"},
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
		RequiredTier: tierpkg.TierProfessional,
		Industries:   []string{"energy", "utilities", "oil_gas", "pipeline", "critical_infrastructure", "power"},
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
		RequiredTier: tierpkg.TierEnterprise,
		Industries:   []string{"defense", "aerospace", "government", "contracting", "dod", "law_enforcement"},
	},
}

// once protects the bundle registration.
var bundleOnce sync.Once

// AllBundles returns all vertical accelerator bundles in display order
// (sorted by RequiredTier, then by ID alphabetically).
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
		return out[i].ID < out[j].ID
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
		return result[i].ID < result[j].ID
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
		return result[i].ID < result[j].ID
	})
	return result
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
// explains what they'd gain.
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

	switch {
	case alreadyOwned == len(b.Frameworks):
		return fmt.Sprintf("All %s frameworks are already included in your %s tier.",
			b.DisplayName, customerTier.DisplayName()), nil
	case alreadyOwned > 0:
		return fmt.Sprintf("%s adds %d frameworks (%v) not in your %s tier. %d of %d are already included.",
			b.DisplayName, len(gained), gained, customerTier.DisplayName(),
			alreadyOwned, len(b.Frameworks)), nil
	default:
		return fmt.Sprintf("%s adds %d frameworks to your %s tier.",
			b.DisplayName, len(b.Frameworks), customerTier.DisplayName()), nil
	}
}
