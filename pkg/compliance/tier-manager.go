package compliance

import (
	"sync"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// Backward-compatible type aliases for tier constants.
// Existing code that references compliance.TierCommunity,
// compliance.TierDeveloper, etc. will work through these aliases.
type Tier = tier.Tier

const (
	TierCommunity    = tier.TierCommunity
	TierDeveloper    = tier.TierDeveloper
	TierProfessional = tier.TierProfessional
	TierEnterprise   = tier.TierEnterprise
)

// FrameworkTier holds tier assignment and metadata
type FrameworkTier struct {
	FrameworkID string
	Name        string
	Tier        tier.Tier
	Description string
	Features    []string
}

// TierManager manages framework access by tier
type TierManager struct {
	mu          sync.RWMutex
	tiers       map[string]FrameworkTier
	currentTier tier.Tier
}

// NewTierManager creates a new tier manager with Community as default
func NewTierManager() *TierManager {
	tm := &TierManager{
		tiers:       make(map[string]FrameworkTier),
		currentTier: tier.TierCommunity,
	}
	tm.initializeDefaults()
	return tm
}

// initializeDefaults sets up the default tier assignments for all
// registered compliance frameworks. Updated v3.7.0: all 20 frameworks
// now have tier assignments.
func (tm *TierManager) initializeDefaults() {
	// Community Tier - Free, open-source
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "atlas",
		Name:        "MITRE ATLAS",
		Tier:        tier.TierCommunity,
		Description: "MITRE ATLAS adversarial threat landscape for AI systems",
		Features: []string{
			"24 technique patterns",
			"Real-time scanning",
			"Basic reporting",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "owasp",
		Name:        "OWASP LLM Top 10",
		Tier:        tier.TierCommunity,
		Description: "OWASP Top 10 security risks for LLM applications",
		Features: []string{
			"10 risk categories",
			"Request/response scanning",
			"Risk scoring",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "nist_ai_rmf",
		Name:        "NIST AI Risk Management Framework",
		Tier:        tier.TierCommunity,
		Description: "NIST AI RMF 1.0 for AI system governance",
		Features: []string{
			"20 controls across 5 categories",
			"Compliance scoring",
			"Gap analysis",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "gdpr",
		Name:        "GDPR",
		Tier:        tier.TierCommunity,
		Description: "General Data Protection Regulation compliance",
		Features: []string{
			"6 core data protection requirements",
			"PII detection",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "cis",
		Name:        "CIS Critical Security Controls v8",
		Tier:        tier.TierCommunity,
		Description: "CIS Controls for enterprise security baseline",
		Features: []string{
			"15 controls across all CIS families",
			"100% automated",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "nist_csf",
		Name:        "NIST CSF 2.0",
		Tier:        tier.TierCommunity,
		Description: "NIST Cybersecurity Framework 2.0",
		Features: []string{
			"6 core functions",
			"100% automated",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "owasp_web",
		Name:        "OWASP Top 10 Web Application Security",
		Tier:        tier.TierCommunity,
		Description: "OWASP Top 10 web application security risks",
		Features: []string{
			"10 risk categories",
			"100% automated",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "csa_star",
		Name:        "CSA STAR Level 1",
		Tier:        tier.TierCommunity,
		Description: "Cloud Security Alliance Security, Trust, Assurance, and Risk",
		Features: []string{
			"16 CCM domains",
			"100% automated",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "nist_ai_600_1",
		Name:        "NIST AI 600-1 GenAI Profile",
		Tier:        tier.TierCommunity,
		Description: "NIST AI Risk Management Framework GenAI Profile",
		Features: []string{
			"12 GenAI risk categories",
			"100% automated",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "ccpa",
		Name:        "CCPA/CPRA",
		Tier:        tier.TierCommunity,
		Description: "California Consumer Privacy Act / California Privacy Rights Act",
		Features: []string{
			"12 controls (8 automated + 4 evidence-mapped)",
			"Data subject rights checks",
		},
	})

	// Developer Tier - Paid
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "hipaa",
		Name:        "HIPAA",
		Tier:        tier.TierDeveloper,
		Description: "Health Insurance Portability and Accountability Act Technical Safeguards",
		Features: []string{
			"15 in-scope controls (13 automated + 2 evidence-mapped)",
			"PHI detection",
			"Audit evidence generation",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "pci",
		Name:        "PCI-DSS v4.0",
		Tier:        tier.TierDeveloper,
		Description: "Payment Card Industry Data Security Standard",
		Features: []string{
			"50 in-scope requirements (42 automated + 6 evidence-mapped)",
			"CHD detection",
			"Encryption validation",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "soc2",
		Name:        "SOC 2 Type II",
		Tier:        tier.TierDeveloper,
		Description: "SOC 2 Type II controls for service organizations",
		Features: []string{
			"15 in-scope criteria (12 automated + 3 evidence-mapped)",
			"Trust Service Criteria CC6-CC9",
			"Audit evidence generation",
		},
	})

	// Professional Tier - Higher paid
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "iso42001",
		Name:        "ISO/IEC 42001:2023",
		Tier:        tier.TierProfessional,
		Description: "ISO/IEC 42001 AI Management System",
		Features: []string{
			"12 in-scope controls (9 automated + 3 evidence-mapped)",
			"AI management system controls",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "iso27001",
		Name:        "ISO/IEC 27001:2022",
		Tier:        tier.TierProfessional,
		Description: "ISO/IEC 27001 Information Security Management System",
		Features: []string{
			"67 Annex A controls, 100% automated",
			"Information security management",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "fedramp",
		Name:        "FedRAMP Moderate",
		Tier:        tier.TierProfessional,
		Description: "FedRAMP Moderate (NIST SP 800-53 Rev. 5)",
		Features: []string{
			"150 controls across 18 NIST 800-53 families (75 automated + 75 evidence-mapped)",
			"Hash-chain audit evidence",
			"Cross-framework mapping",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "fips",
		Name:        "FIPS 140-2/140-3",
		Tier:        tier.TierProfessional,
		Description: "FIPS 140 cryptographic module requirements",
		Features: []string{
			"12 security areas, 100% automated",
			"Cryptography validation",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "eu_ai_act",
		Name:        "EU AI Act",
		Tier:        tier.TierProfessional,
		Description: "EU AI Act (Regulation 2024/1689) compliance",
		Features: []string{
			"82 controls across 8 categories (17 automated + 65 evidence-mapped)",
			"AI risk classification",
			"Transparency checks",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "cmmcl2",
		Name:        "CMMC Level 2",
		Tier:        tier.TierProfessional,
		Description: "Cybersecurity Maturity Model Certification Level 2",
		Features: []string{
			"57 controls (33 automated + 24 evidence-mapped)",
			"DoD contractor requirements",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "nist800171",
		Name:        "NIST SP 800-171",
		Tier:        tier.TierProfessional,
		Description: "NIST SP 800-171 CUI protection requirements",
		Features: []string{
			"47 controls (28 automated + 19 evidence-mapped)",
			"Federal contractor requirements",
		},
	})

	// Enterprise Tier
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "hitrust",
		Name:        "HITRUST CSF v11.2",
		Tier:        tier.TierEnterprise,
		Description: "HITRUST Common Security Framework for healthcare",
		Features: []string{
			"43 controls (19 automated + 24 evidence-mapped)",
			"Healthcare certification",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "tisax",
		Name:        "TISAX AL2",
		Tier:        tier.TierEnterprise,
		Description: "Trusted Information Security Assessment Exchange for automotive",
		Features: []string{
			"35 controls (16 automated + 19 evidence-mapped)",
			"Automotive industry requirements",
		},
	})

	// Trust Framework (reserved, not yet billable)
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "trust",
		Name:        "Trust Framework (reserved)",
		Tier:        tier.TierProfessional,
		Description: "Reserved for future Trust Framework module (Phase 4)",
		Features:    []string{"Reserved"},
	})
}

// RegisterFramework registers a framework with its tier assignment
func (tm *TierManager) RegisterFramework(ft FrameworkTier) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.tiers[ft.FrameworkID] = ft
}

// GetFrameworkTier returns the tier assignment for a framework
func (tm *TierManager) GetFrameworkTier(frameworkID string) (FrameworkTier, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	ft, exists := tm.tiers[frameworkID]
	return ft, exists
}

// IsFrameworkAllowed checks if a framework is accessible at the current tier
func (tm *TierManager) IsFrameworkAllowed(frameworkID string) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	ft, exists := tm.tiers[frameworkID]
	if !exists {
		return false
	}

	return tm.isTierAllowed(tm.currentTier, ft.Tier)
}

// isTierAllowed checks if current tier allows access to the required tier
func (tm *TierManager) isTierAllowed(current, required tier.Tier) bool {
	// Higher tiers get access to lower tier features
	// Enterprise (3) > Professional (2) > Developer (1) > Community (0)
	return current >= required
}

// SetTier sets the current tier
func (tm *TierManager) SetTier(t tier.Tier) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.currentTier = t
}

// GetTier returns the current tier
func (tm *TierManager) GetTier() tier.Tier {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.currentTier
}

// GetAvailableFrameworks returns frameworks available at current tier
func (tm *TierManager) GetAvailableFrameworks() []FrameworkTier {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var available []FrameworkTier
	for _, ft := range tm.tiers {
		if tm.isTierAllowed(tm.currentTier, ft.Tier) {
			available = append(available, ft)
		}
	}
	return available
}

// GetAllFrameworks returns all registered frameworks
func (tm *TierManager) GetAllFrameworks() []FrameworkTier {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	all := make([]FrameworkTier, 0, len(tm.tiers))
	for _, ft := range tm.tiers {
		all = append(all, ft)
	}
	return all
}

// GetFrameworksByTier returns all frameworks in a specific tier
func (tm *TierManager) GetFrameworksByTier(t tier.Tier) []FrameworkTier {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var frameworks []FrameworkTier
	for _, ft := range tm.tiers {
		if ft.Tier == t {
			frameworks = append(frameworks, ft)
		}
	}
	return frameworks
}

// GetCommunityFrameworks returns Community-tier frameworks
func (tm *TierManager) GetCommunityFrameworks() []FrameworkTier {
	return tm.GetFrameworksByTier(tier.TierCommunity)
}

// GetDeveloperFrameworks returns Developer-tier frameworks
func (tm *TierManager) GetDeveloperFrameworks() []FrameworkTier {
	return tm.GetFrameworksByTier(tier.TierDeveloper)
}

// GetProfessionalFrameworks returns Professional-tier frameworks
func (tm *TierManager) GetProfessionalFrameworks() []FrameworkTier {
	return tm.GetFrameworksByTier(tier.TierProfessional)
}

// GetEnterpriseFrameworks returns Enterprise-tier frameworks
func (tm *TierManager) GetEnterpriseFrameworks() []FrameworkTier {
	return tm.GetFrameworksByTier(tier.TierEnterprise)
}