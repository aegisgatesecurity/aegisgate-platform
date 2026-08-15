// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance module gating (v3.2.0 Phase 1)
//
// gating.go provides the public API for asking "is this compliance
// framework currently enforced for this customer?" The answer depends on
// three things:
//
//  1. The license is valid (signed, not expired past grace).
//  2. The license's tier is high enough to own the module.
//  3. The license actually owns the module (it was purchased).
//
// This file is the single source of truth for module-to-tier mapping.
// Other packages (billing/webhook, compliance/scan_engine, audit log)
// import this and not the module-to-tier logic directly.
//
// v3.2.0 Phase 1.2.

package compliance

import (
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	tierpkg "github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// ModuleRequirement describes a single billable module: the minimum tier
// required to own it, and a human-readable name for audit logs.
type ModuleRequirement struct {
	Module            string       // canonical name (e.g., "hipaa")
	DisplayName       string       // human-readable (e.g., "HIPAA")
	RequiredTier      tierpkg.Tier // minimum tier required to own
	MinPriceCents     int          // locked list price in cents (for audit)
	HasImplementation bool         // true if a sub-package exists (e.g., pkg/compliance/hipaa)
}

// moduleRequirements is the canonical table mapping module name to its
// requirement. This is the SINGLE SOURCE OF TRUTH for all compliance
// module tier/pricing decisions. Other files (bundle.go, mcp_compliance.go,
// tier.go) DERIVE from this table — they do not maintain their own lists.
//
// v4.2.0: Unified to 31 modules (27 previously built + 4 new frameworks).
// All compliance tier decisions flow through this table.
//
// Tier mapping:
//   - Community (free):  CCPA, NIST AI RMF, OWASP Web (3 modules)
//   - Developer+:        HIPAA, PCI, SOC 2, ISO 27001 (4 modules)
//   - Professional+:     ISO 42001, FedRAMP, FIPS, EU AI Act, CMMC L2,
//                        NIST 800-171, Trust, SOX, GLBA, NERC CIP, CJIS,
//                        NIST CSF, CIS, CSA STAR, FERPA, NIST AI 600-1,
//                        HITECH, FFIEC, TSA SD, ISO 21434 (20 modules)
//   - Enterprise+:       HITRUST, TISAX (2 modules)
//   - Free (community-registered, not in gating): ATLAS, GDPR, OWASP LLM
var moduleRequirements = map[string]ModuleRequirement{
	license.ModuleHIPAA: {
		Module:            license.ModuleHIPAA,
		DisplayName:       "HIPAA",
		RequiredTier:      tierpkg.TierDeveloper,
		MinPriceCents:     9900, // $99/mo
		HasImplementation: true, // pkg/compliance/hipaa exists
	},
	license.ModulePCI: {
		Module:            license.ModulePCI,
		DisplayName:       "PCI-DSS",
		RequiredTier:      tierpkg.TierDeveloper,
		MinPriceCents:     9900, // $99/mo
		HasImplementation: true, // pkg/compliance/pci exists
	},
	license.ModuleSOC2: {
		Module:            license.ModuleSOC2,
		DisplayName:       "SOC 2",
		RequiredTier:      tierpkg.TierDeveloper,
		MinPriceCents:     14900, // $149/mo
		HasImplementation: true,  // pkg/compliance/soc2/ implemented (5 automated + 10 evidence-mapped)
	},
	license.ModuleISO42001: {
		Module:            license.ModuleISO42001,
		DisplayName:       "ISO 42001",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     7900, // $79/mo
		HasImplementation: true, // pkg/compliance/iso42001/ implemented (5 automated + 7 evidence-mapped)
	},
	license.ModuleFedRAMP: {
		Module:            license.ModuleFedRAMP,
		DisplayName:       "FedRAMP",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     49900, // $499/mo
		HasImplementation: true,  // pkg/compliance/fedramp/ implemented in v3.4.0+ (Path C: 60 in-scope controls across 11 NIST 800-53 families, 38 automated + 22 evidence-mapped)
	},
	license.ModuleFIPS: {
		Module:            license.ModuleFIPS,
		DisplayName:       "FIPS 140-2/140-3",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     29900, // $299/mo
		HasImplementation: true,  // pkg/compliance/fips/ implemented (8 automated + 2 manual)
	},
	// v3.3.0 Phase 1: EU AI Act (Regulation 2024/1689). 7th compliance framework.
	license.ModuleEUAIAct: {
		Module:            license.ModuleEUAIAct,
		DisplayName:       "EU AI Act",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     9900, // $99/mo (founder-locked 2026-06-06)
		HasImplementation: true, // pkg/compliance/eu-ai-act exists (v3.3.0)
	},
	// CMMC Level 2 (v3.6.0 M3). Professional+ tier, $499/mo.
	// CMMC L2 is required for DoD contractors handling CUI.
	license.ModuleCMMCL2: {
		Module:            license.ModuleCMMCL2,
		DisplayName:       "CMMC Level 2",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     49900, // $499/mo
		HasImplementation: true,  // pkg/compliance/cmmcl2/ (57 controls: 33 automated + 24 evidence-mapped)
	},
	// NIST SP 800-171 (v3.6.0 M3). Professional+ tier, $399/mo.
	// Required for protecting CUI in nonfederal systems.
	license.ModuleNIST800171: {
		Module:            license.ModuleNIST800171,
		DisplayName:       "NIST 800-171",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     39900, // $399/mo
		HasImplementation: true,  // pkg/compliance/nist800171/ (50 controls: 25 automated + 25 evidence-mapped)
	},
	// HITRUST CSF v11.2 (v3.6.0 M3). Enterprise tier, $799/mo.
	// Certifiable framework inheriting from HIPAA, NIST 800-53, ISO 27001.
	license.ModuleHITRUST: {
		Module:            license.ModuleHITRUST,
		DisplayName:       "HITRUST CSF",
		RequiredTier:      tierpkg.TierEnterprise,
		MinPriceCents:     79900, // $799/mo
		HasImplementation: true,  // pkg/compliance/hitrust/ (43 controls: 19 automated + 24 evidence-mapped)
	},
	// TISAX AL2 (v3.6.0 M3). Enterprise tier, $599/mo.
	// European automotive industry information security assessment.
	license.ModuleTISAX: {
		Module:            license.ModuleTISAX,
		DisplayName:       "TISAX AL2",
		RequiredTier:      tierpkg.TierEnterprise,
		MinPriceCents:     59900, // $599/mo
		HasImplementation: true,  // pkg/compliance/tisax/ (35 controls: 16 automated + 19 evidence-mapped)
	},
	// CCPA/CPRA (v3.6.0 M3). Community tier, free.
	// California Consumer Privacy Act — bundled with the platform.
	license.ModuleCCPA: {
		Module:            license.ModuleCCPA,
		DisplayName:       "CCPA/CPRA",
		RequiredTier:      tierpkg.TierCommunity,
		MinPriceCents:     0,    // Community tier, no add-on cost
		HasImplementation: true, // pkg/compliance/ccpa/ (12 controls: 8 automated + 4 evidence-mapped)
	},
	// NIST AI RMF 1.0 (v3.7.0). Community tier, free.
	// The foundational AI risk management framework — bundled with the platform.
	license.ModuleNISTAIRMF: {
		Module:            license.ModuleNISTAIRMF,
		DisplayName:       "NIST AI RMF 1.0",
		RequiredTier:      tierpkg.TierCommunity,
		MinPriceCents:     0,    // Community tier, no add-on cost
		HasImplementation: true, // pkg/compliance/nist_ai_rmf/ (20 controls: 15 automated + 5 evidence-mapped)
	},
	// Trust Framework (v4.2.0: now built and billable, not reserved).
	// 12,270 lines across 59 files — 5th architectural pillar.
	// Trust scoring, signed attestations, capability contracts, agent identity.
	license.ModuleTrust: {
		Module:            license.ModuleTrust,
		DisplayName:       "Trust Framework",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     9900,  // $99/mo
		HasImplementation: true,  // pkg/trust/ — fully built
	},
	// v4.2.0: ISO 27001 (previously built but not billable — now registered).
	license.ModuleISO27001: {
		Module:            license.ModuleISO27001,
		DisplayName:       "ISO 27001",
		RequiredTier:      tierpkg.TierDeveloper,
		MinPriceCents:     7900, // $79/mo
		HasImplementation: true, // pkg/compliance/iso27001/ exists
	},
	// v4.2.0: Previously orphaned frameworks — built but not billable.
	// Now registered with tier gates and pricing.
	license.ModuleSOX: {
		Module:            license.ModuleSOX,
		DisplayName:       "SOX (Sarbanes-Oxley)",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     19900, // $199/mo
		HasImplementation: true,  // pkg/compliance/sox/ exists
	},
	license.ModuleGLBA: {
		Module:            license.ModuleGLBA,
		DisplayName:       "GLBA (Gramm-Leach-Bliley)",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     14900, // $149/mo
		HasImplementation: true,  // pkg/compliance/glba/ exists
	},
	license.ModuleCJIS: {
		Module:            license.ModuleCJIS,
		DisplayName:       "CJIS Security Policy",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     29900, // $299/mo
		HasImplementation: true,  // pkg/compliance/cjis/ exists
	},
	license.ModuleNERCCIP: {
		Module:            license.ModuleNERCCIP,
		DisplayName:       "NERC CIP",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     29900, // $299/mo
		HasImplementation: true,  // pkg/compliance/nerc_cip/ exists
	},
	license.ModuleFERPA: {
		Module:            license.ModuleFERPA,
		DisplayName:       "FERPA",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     7900, // $79/mo
		HasImplementation: true, // pkg/compliance/ferpa/ exists
	},
	license.ModuleCSASTAR: {
		Module:            license.ModuleCSASTAR,
		DisplayName:       "CSA STAR",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     7900, // $79/mo
		HasImplementation: true, // pkg/compliance/csa_star/ exists
	},
	license.ModuleNISTCSF: {
		Module:            license.ModuleNISTCSF,
		DisplayName:       "NIST Cybersecurity Framework",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     9900, // $99/mo
		HasImplementation: true, // pkg/compliance/nist_csf/ exists
	},
	license.ModuleCIS: {
		Module:            license.ModuleCIS,
		DisplayName:       "CIS Critical Security Controls",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     9900, // $99/mo
		HasImplementation: true, // pkg/compliance/cis/ exists
	},
	license.ModuleNISTAI600: {
		Module:            license.ModuleNISTAI600,
		DisplayName:       "NIST AI 600-1",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     7900, // $79/mo
		HasImplementation: true, // pkg/compliance/nist_ai_600_1/ exists
	},
	license.ModuleOWASPWeb: {
		Module:            license.ModuleOWASPWeb,
		DisplayName:       "OWASP Web Top 10",
		RequiredTier:      tierpkg.TierCommunity,
		MinPriceCents:     0,    // Community tier, free
		HasImplementation: true, // pkg/compliance/owasp_web/ exists
	},
	// v4.2.0: New frameworks — built and integrated with cross-framework mapping.
	license.ModuleHITECH: {
		Module:            license.ModuleHITECH,
		DisplayName:       "HITECH Act",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     19900, // $199/mo
		HasImplementation: true,  // pkg/compliance/hitech/ (new)
	},
	license.ModuleFFIEC: {
		Module:            license.ModuleFFIEC,
		DisplayName:       "FFIEC Banking Guidance",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     29900, // $299/mo
		HasImplementation: true,  // pkg/compliance/ffiec/ (new)
	},
	license.ModuleTSASD: {
		Module:            license.ModuleTSASD,
		DisplayName:       "TSA Security Directive",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     24900, // $249/mo
		HasImplementation: true,  // pkg/compliance/tsa_sd/ (new)
	},
	license.ModuleISO21434: {
		Module:            license.ModuleISO21434,
		DisplayName:       "ISO 21434 (Automotive)",
		RequiredTier:      tierpkg.TierProfessional,
		MinPriceCents:     29900, // $299/mo
		HasImplementation: true,  // pkg/compliance/iso21434/ (new)
	},
}

// AllModuleRequirements returns a copy of the canonical module requirement
// table, in a deterministic order (sorted by RequiredTier then DisplayName).
// Useful for the compliance scan API's "list all available modules" call.
func AllModuleRequirements() []ModuleRequirement {
	// Build a stable-ordered slice: group by tier, then alphabetical within tier.
	// (We could use a heap or sort.Slice, but with 7 items, a 3-pass loop is fine.)
	byTier := map[tierpkg.Tier][]ModuleRequirement{}
	for _, r := range moduleRequirements {
		byTier[r.RequiredTier] = append(byTier[r.RequiredTier], r)
	}
	out := []ModuleRequirement{}
	// Emit in tier order: Community, Dev, Pro, Enterprise.
	for _, tier := range []tierpkg.Tier{tierpkg.TierCommunity, tierpkg.TierDeveloper, tierpkg.TierProfessional, tierpkg.TierEnterprise} {
		items := byTier[tier]
		// Simple insertion sort by DisplayName (7 items max, no need for sort.Slice).
		for i := 1; i < len(items); i++ {
			for j := i; j > 0 && items[j-1].DisplayName > items[j].DisplayName; j-- {
				items[j-1], items[j] = items[j], items[j-1]
			}
		}
		out = append(out, items...)
	}
	return out
}

// RequiredTierForModule returns the minimum tier required to own the given
// module. The second return value is false if the module name is unknown
// (typo, deprecated, or not yet billable).
func RequiredTierForModule(module string) (tierpkg.Tier, bool) {
	r, ok := moduleRequirements[module]
	if !ok {
		return 0, false
	}
	return r.RequiredTier, true
}

// GetModuleRequirement returns the full requirement record for a module.
// Returns false if the module is unknown.
func GetModuleRequirement(module string) (ModuleRequirement, bool) {
	r, ok := moduleRequirements[module]
	return r, ok
}

// GatingReason describes why a framework is or is not enforced.
// Used in GatingDecision.Reason for audit logs and the compliance scan API.
type GatingReason string

const (
	ReasonEnforced          GatingReason = "enforced"
	ReasonInvalidLicense    GatingReason = "invalid_license"
	ReasonTierTooLow        GatingReason = "tier_too_low"
	ReasonModuleNotOwned    GatingReason = "module_not_owned"
	ReasonUnknownFramework  GatingReason = "unknown_framework"
	ReasonReservedNoPrice   GatingReason = "module_reserved_no_price"
	ReasonImplementationGap GatingReason = "implementation_missing"
)

// GatingDecision is the result of evaluating "is this framework enforced
// for this license?". It includes the reason (for audit logs) and which
// requirements are missing (for the compliance scan API's "what do I need
// to upgrade to" prompt).
type GatingDecision struct {
	Enforced          bool         // true if the framework is enforced
	Framework         string       // the framework name queried (e.g., "hipaa")
	RequiredTier      tierpkg.Tier // minimum tier needed
	LicenseTier       tierpkg.Tier // license's actual tier (0 = invalid/none)
	ModuleOwned       bool         // does the license own the module?
	Reason            GatingReason // human-readable reason
	MissingUpgradeTo  string       // if not enforced, the DisplayName of the module to buy
	MissingTierTo     string       // if not enforced, the tier to upgrade to
	HasImplementation bool         // false = module is gated but no code exists yet
}

// IsFrameworkEnforced returns true if the given framework is currently
// enforced for the given license. A framework is enforced if:
//  1. The license is valid (or nil is acceptable for tier check).
//  2. The license's tier >= the module's required tier.
//  3. The license owns the module.
//
// Use EvaluateGating for a richer return value that explains why.
func IsFrameworkEnforced(framework string, lic *license.ValidationResult) bool {
	return EvaluateGating(framework, lic).Enforced
}

// EvaluateGating returns a GatingDecision describing whether the framework
// is enforced and, if not, what's missing. This is the richer version of
// IsFrameworkEnforced; use it when you need to show the user a "why not"
// message or write an audit log entry.
func EvaluateGating(framework string, lic *license.ValidationResult) GatingDecision {
	req, known := moduleRequirements[framework]
	if !known {
		return GatingDecision{
			Enforced:  false,
			Framework: framework,
			Reason:    ReasonUnknownFramework,
		}
	}

	// Note: implementation readiness (HasImplementation) is NOT checked
	// here. The gating API is the enforcement-policy layer; it reports
	// ownership status. Implementation readiness is a separate concern
	// (use IsImplementationReady(framework) for that) so the compliance
	// scan engine can show "coming soon" without confusing the gate
	// with "this customer is entitled but the code is missing".

	// License is required to be valid.
	if lic == nil || !lic.Valid {
		return GatingDecision{
			Enforced:          false,
			Framework:         framework,
			RequiredTier:      req.RequiredTier,
			Reason:            ReasonInvalidLicense,
			MissingUpgradeTo:  req.DisplayName,
			MissingTierTo:     req.RequiredTier.String(),
			HasImplementation: true,
		}
	}

	licenseTier := lic.Tier
	if licenseTier < req.RequiredTier {
		return GatingDecision{
			Enforced:          false,
			Framework:         framework,
			RequiredTier:      req.RequiredTier,
			LicenseTier:       licenseTier,
			Reason:            ReasonTierTooLow,
			MissingUpgradeTo:  req.DisplayName,
			MissingTierTo:     req.RequiredTier.String(),
			HasImplementation: true,
		}
	}

	// Tier is high enough; check module ownership.
	owned := false
	for _, m := range lic.Payload.Modules {
		if m == framework {
			owned = true
			break
		}
	}
	if !owned {
		return GatingDecision{
			Enforced:          false,
			Framework:         framework,
			RequiredTier:      req.RequiredTier,
			LicenseTier:       licenseTier,
			Reason:            ReasonModuleNotOwned,
			MissingUpgradeTo:  req.DisplayName,
			MissingTierTo:     req.RequiredTier.String(),
			HasImplementation: true,
		}
	}

	// All checks passed.
	return GatingDecision{
		Enforced:          true,
		Framework:         framework,
		RequiredTier:      req.RequiredTier,
		LicenseTier:       licenseTier,
		ModuleOwned:       true,
		Reason:            ReasonEnforced,
		HasImplementation: true,
	}
}

// TierMeetsRequirement returns true if the given tier is at or above the
// module's required tier. Convenience helper for callers that don't have
// a license yet (e.g., "can a Starter customer see HIPAA in the upgrade page?").
func TierMeetsRequirement(module string, tier tierpkg.Tier) bool {
	required, ok := RequiredTierForModule(module)
	if !ok {
		return false
	}
	return tier >= required
}

// IsImplementationReady returns true if the framework has an actual
// implementation (sub-package) shipped. Separated from IsFrameworkEnforced
// so the compliance scan engine can distinguish:
//
//	"HIPAA is enforced for this customer (they own it) but the sub-package
//	 isn't shipped yet"  →  IsFrameworkEnforced: true, IsImplementationReady: false
//
//	"HIPAA is not enforced (customer doesn't own it) and the sub-package
//	 IS shipped"        →  IsFrameworkEnforced: false, IsImplementationReady: true
//
// The compliance scan API uses this to show "Available" vs "Coming soon"
// badges without conflating ownership and implementation status.
func IsImplementationReady(framework string) bool {
	req, ok := moduleRequirements[framework]
	if !ok {
		return false
	}
	return req.HasImplementation
}

// ModuleRequirementCount returns the number of known modules in the
// requirements table. Used for sanity tests and metrics.
func ModuleRequirementCount() int {
	return len(moduleRequirements)
}
