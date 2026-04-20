package compliance

import (
	"sync"
)

// Tier represents the license tier
type Tier int

const (
	TierCommunity  Tier = 0 // Free, open-source
	TierEnterprise Tier = 1 // Paid, commercial license
	TierPremium    Tier = 2 // Enterprise + premium modules
)

func (t Tier) String() string {
	switch t {
	case TierCommunity:
		return "community"
	case TierEnterprise:
		return "enterprise"
	case TierPremium:
		return "premium"
	default:
		return "unknown"
	}
}

// FrameworkTier holds tier assignment and metadata
type FrameworkTier struct {
	FrameworkID string
	Name        string
	Tier        Tier
	Description string
	Features    []string
}

// TierManager manages framework access by tier
type TierManager struct {
	mu          sync.RWMutex
	tiers       map[string]FrameworkTier
	currentTier Tier
}

// NewTierManager creates a new tier manager with Community as default
func NewTierManager() *TierManager {
	tm := &TierManager{
		tiers:       make(map[string]FrameworkTier),
		currentTier: TierCommunity,
	}
	tm.initializeDefaults()
	return tm
}

// initializeDefaults sets up the default tier assignments
func (tm *TierManager) initializeDefaults() {
	// Community Tier - Free, open-source
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "atlas",
		Name:        "MITRE ATLAS",
		Tier:        TierCommunity,
		Description: "MITRE ATLAS 18 threat techniques for AI security",
		Features: []string{
			"18 detection techniques",
			"60+ detection patterns",
			"Real-time scanning",
			"Basic reporting",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "owasp",
		Name:        "OWASP AI Top 10",
		Tier:        TierCommunity,
		Description: "OWASP Top 10 security risks for LLM applications",
		Features: []string{
			"10 OWASP categories",
			"40+ detection patterns",
			"Request/response scanning",
			"Risk scoring",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "gdpr",
		Name:        "GDPR",
		Tier:        TierCommunity,
		Description: "General Data Protection Regulation compliance",
		Features: []string{
			"6 core requirements",
			"Data protection checks",
			"PII detection",
		},
	})

	// Enterprise Tier - Paid
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "nist_ai_rmf",
		Name:        "NIST AI Risk Management Framework",
		Tier:        TierEnterprise,
		Description: "NIST AI RMF for AI system governance",
		Features: []string{
			"4 core functions (GV, MP, ME, RG)",
			"20+ controls",
			"Compliance scoring",
			"Gap analysis",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "nist_1500",
		Name:        "NIST SP 1500",
		Tier:        TierEnterprise,
		Description: "NITRD AI Risk Management Framework Controls",
		Features: []string{
			"10 control families",
			"50+ controls",
			"Comprehensive coverage",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "iso42001",
		Name:        "ISO/IEC 42001",
		Tier:        TierEnterprise,
		Description: "ISO/IEC 42001 AI Management System",
		Features: []string{
			"AI management system controls",
			"Risk assessment",
			"Performance evaluation",
		},
	})

	// Premium Tier - Enterprise + Specialized
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "soc2",
		Name:        "SOC 2",
		Tier:        TierPremium,
		Description: "SOC 2 Type II controls for service organizations",
		Features: []string{
			"5 Trust Service Criteria",
			"CC1-CC9 controls",
			"AI-specific controls",
			"Audit evidence generation",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "hipaa",
		Name:        "HIPAA",
		Tier:        TierPremium,
		Description: "Health Insurance Portability and Accountability Act",
		Features: []string{
			"PHI detection",
			"Security safeguards",
			"Breach notification checks",
		},
	})

	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "pci",
		Name:        "PCI DSS",
		Tier:        TierPremium,
		Description: "Payment Card Industry Data Security Standard",
		Features: []string{
			"CHD detection",
			"Encryption validation",
			"Network security checks",
		},
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
func (tm *TierManager) isTierAllowed(current, required Tier) bool {
	// Higher tiers get access to lower tier features
	// Premium (2) > Enterprise (1) > Community (0)
	return current >= required
}

// SetTier sets the current tier
func (tm *TierManager) SetTier(tier Tier) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.currentTier = tier
}

// GetTier returns the current tier
func (tm *TierManager) GetTier() Tier {
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
func (tm *TierManager) GetFrameworksByTier(tier Tier) []FrameworkTier {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var frameworks []FrameworkTier
	for _, ft := range tm.tiers {
		if ft.Tier == tier {
			frameworks = append(frameworks, ft)
		}
	}
	return frameworks
}

// GetCommunityFrameworks returns Community-tier frameworks
func (tm *TierManager) GetCommunityFrameworks() []FrameworkTier {
	return tm.GetFrameworksByTier(TierCommunity)
}

// GetEnterpriseFrameworks returns Enterprise-tier frameworks
func (tm *TierManager) GetEnterpriseFrameworks() []FrameworkTier {
	return tm.GetFrameworksByTier(TierEnterprise)
}

// GetPremiumFrameworks returns Premium-tier frameworks
func (tm *TierManager) GetPremiumFrameworks() []FrameworkTier {
	return tm.GetFrameworksByTier(TierPremium)
}

// ValidateLicense validates a license key for the given tier (stub)
func (tm *TierManager) ValidateLicense(licenseKey string, expectedTier Tier) bool {
	// Real implementation would:
	// 1. Parse license key
	// 2. Verify signature
	// 3. Check expiration
	// 4. Validate tier matches

	// Stub: always validate for Community, reject others
	if expectedTier == TierCommunity {
		return true
	}
	return licenseKey != "" // At least needs a key
}
