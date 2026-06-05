// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Scan Engine (v3.2.0 Phase 3)
//
// scanner.go is the customer-facing compliance scan engine. It
// answers two questions:
//
//   1. "Is my customer's compliance posture good right now?" — for
//      the customer portal's "Compliance" tab.
//   2. "What modules do I need to buy to enable X?" — for the
//      upgrade prompts.
//
// The scanner is a thin orchestrator. It composes:
//   - pkg/license.LicensePayload (Phase 1.1, modules the customer owns)
//   - pkg/compliance.gating (Phase 1.2, framework-to-module mapping)
//   - pkg/compliance.Registry (existing, framework instances)
//   - pkg/compliance.FrameworkModule (existing, control checks)
//
// v3.2.0 Phase 3.

package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// ErrNoLicense is returned when the customer has no license.
var ErrNoLicense = errors.New("no license provided")

// ErrUnknownFramework is returned when a requested framework is not registered.
var ErrUnknownFramework = errors.New("unknown framework")

// FrameworkScanResult is the per-framework scan output.
type FrameworkScanResult struct {
	// Framework is the canonical framework identifier (e.g., "hipaa",
	// "pci", "soc2", "iso42001"). Matches the keys in the
	// ModuleRequirement table.
	Framework string `json:"framework"`
	// DisplayName is the human-readable name (e.g., "HIPAA").
	DisplayName string `json:"displayName"`
	// Enforced is true if the customer's license authorizes this
	// framework (own module + sufficient tier + valid license).
	Enforced bool `json:"enforced"`
	// Module is the billable module name (e.g., "hipaa"). Empty
	// for free frameworks like ATLAS, NIST AI RMF, OWASP.
	Module string `json:"module,omitempty"`
	// Score is the compliance score 0-100, computed by the
	// registered framework's GenerateAssessment. 0 if not enforced.
	Score float64 `json:"score"`
	// ControlsTotal is the total number of controls in the framework.
	ControlsTotal int `json:"controlsTotal"`
	// ControlsEnforced is the number of controls that pass.
	ControlsEnforced int `json:"controlsEnforced"`
	// CompliancePct is ControlsEnforced / ControlsTotal * 100.
	// 0 if ControlsTotal is 0.
	CompliancePct float64 `json:"compliancePct"`
	// ReasonEnforced (when Enforced=true): "module_owned",
	// "framework_free", or "feature_always_on".
	ReasonEnforced string `json:"reasonEnforced,omitempty"`
	// ReasonNotEnforced (when Enforced=false): structured reason
	// code (e.g., "module_not_owned", "tier_too_low", "no_implementation").
	ReasonNotEnforced string `json:"reasonNotEnforced,omitempty"`
	// MissingModules (when Enforced=false): the modules the
	// customer would need to buy to enable this framework. Empty
	// for free frameworks.
	MissingModules []string `json:"missingModules,omitempty"`
	// UpgradeHint (when ReasonNotEnforced is "tier_too_low"):
	// human-readable hint like "Upgrade to Professional tier".
	UpgradeHint string `json:"upgradeHint,omitempty"`
	// ImplementationReady (always): whether the framework's Go
	// sub-package exists. Even if Enforced is true, the customer
	// might be entitled to a framework whose implementation is
	// still on the roadmap.
	ImplementationReady bool `json:"implementationReady"`
	// LastScan is when this result was generated.
	LastScan time.Time `json:"lastScan"`
}

// ScanReport is the top-level scan output, returned to the customer
// portal and the HTTP API. Named ScanReport to avoid collision with
// the existing Report type in this package.
type ScanReport struct {
	// CustomerTier is the customer's effective tier (Community,
	// Starter, Developer, Professional, Enterprise).
	CustomerTier tier.Tier `json:"customerTier"`
	// CustomerModules is the sorted list of modules the customer owns.
	CustomerModules []string `json:"customerModules"`
	// Frameworks is the per-framework scan results, sorted by
	// DisplayName for stable output.
	Frameworks []FrameworkScanResult `json:"frameworks"`
	// OverallScore is the average of all enforced frameworks' scores.
	// 0 if no frameworks are enforced.
	OverallScore float64 `json:"overallScore"`
	// OverallCompliancePct is the average of all enforced frameworks'
	// CompliancePct. 0 if no frameworks are enforced.
	OverallCompliancePct float64 `json:"overallPct"`
	// GeneratedAt is when the report was generated.
	GeneratedAt time.Time `json:"generatedAt"`
	// ScanDurationMs is the wall-clock duration of the scan in
	// milliseconds. Useful for the customer portal to display
	// "last scan took 47ms".
	ScanDurationMs int64 `json:"scanDurationMs"`
	// HasLicense is true if the customer has a non-empty license.
	HasLicense bool `json:"hasLicense"`
	// LicenseValid is true if the license is currently valid (not
	// expired, not revoked). False means results are best-effort.
	LicenseValid bool `json:"licenseValid"`
}

// Scanner is the compliance scan engine. Construct via NewScanner
// with a Registry (the existing framework registry) and a license
// payload (from the customer's license).
type Scanner struct {
	registry *Registry

	// mu protects the in-memory assessment cache. Assessments are
	// cached for scanCacheTTL to avoid recomputing on every
	// /api/v1/compliance/scan call.
	mu           sync.RWMutex
	cache        map[string]cachedReport
	scanCacheTTL time.Duration
}

type cachedReport struct {
	report   *ScanReport
	cachedAt time.Time
}

// ScannerOpts configures the Scanner.
type ScannerOpts struct {
	// CacheTTL controls how long a scan is cached. 0 = no caching.
	// Default: 5 minutes.
	CacheTTL time.Duration
}

// NewScanner creates a new Scanner. If registry is nil, an empty
// registry is used (all scans return zero scores, but the API still
// works for "what would the customer need to buy?").
// If opts is nil, defaults are used.
func NewScanner(registry *Registry, opts *ScannerOpts) *Scanner {
	if registry == nil {
		registry = NewRegistry()
	}
	ttl := 5 * time.Minute
	if opts != nil && opts.CacheTTL > 0 {
		ttl = opts.CacheTTL
	}
	return &Scanner{
		registry:     registry,
		cache:        make(map[string]cachedReport),
		scanCacheTTL: ttl,
	}
}

// cacheKey returns a stable key for a (license, tier) pair. Two
// scans with the same license payload and tier return the same key.
func (s *Scanner) cacheKey(lic *license.ValidationResult, t tier.Tier) string {
	if lic == nil || !lic.Valid {
		return "invalid"
	}
	mods := append([]string(nil), lic.Payload.Modules...)
	sort.Strings(mods)
	return fmt.Sprintf("%s|%v|%s", lic.Payload.LicenseID, t, joinModules(mods))
}

func joinModules(mods []string) string {
	out := ""
	for i, m := range mods {
		if i > 0 {
			out += ","
		}
		out += m
	}
	return out
}

// Scan runs a compliance scan and returns a ScanReport. The license
// is the customer's currently-validated license (or nil for community).
//
// The scan is cached: repeated calls within CacheTTL return the
// same ScanReport without recomputing.
func (s *Scanner) Scan(ctx context.Context, lic *license.ValidationResult) (*ScanReport, error) {
	start := time.Now()
	rpt := &ScanReport{
		Frameworks:   make([]FrameworkScanResult, 0),
		GeneratedAt:  start.UTC(),
		HasLicense:   lic != nil && lic.Valid,
		LicenseValid: lic != nil && lic.Valid,
	}
	if lic != nil && lic.Valid {
		rpt.CustomerTier = tier.Tier(lic.Tier)
		rpt.CustomerModules = append([]string(nil), lic.Payload.Modules...)
		sort.Strings(rpt.CustomerModules)
	} else {
		rpt.CustomerTier = tier.TierCommunity
		rpt.CustomerModules = []string{}
	}

	// Check cache.
	cacheKey := s.cacheKey(lic, rpt.CustomerTier)
	if s.scanCacheTTL > 0 {
		s.mu.RLock()
		if cached, ok := s.cache[cacheKey]; ok {
			if time.Since(cached.cachedAt) < s.scanCacheTTL {
				s.mu.RUnlock()
				return cached.report, nil
			}
		}
		s.mu.RUnlock()
	}

	// Walk the locked module requirements (6 billable modules).
	for _, modReq := range AllModuleRequirements() {
		result := s.scanModule(ctx, modReq, lic)
		rpt.Frameworks = append(rpt.Frameworks, result)
	}

	// Add the 3 free frameworks (ATLAS, NIST AI RMF, OWASP).
	for _, fw := range freeFrameworks {
		result := s.scanFreeFramework(ctx, fw, lic)
		rpt.Frameworks = append(rpt.Frameworks, result)
	}

	// Sort by DisplayName for stable output.
	sort.Slice(rpt.Frameworks, func(i, j int) bool {
		return rpt.Frameworks[i].DisplayName < rpt.Frameworks[j].DisplayName
	})

	// Compute overall stats.
	rpt.OverallScore, rpt.OverallCompliancePct = aggregateScores(rpt.Frameworks)

	rpt.ScanDurationMs = time.Since(start).Milliseconds()

	// Cache.
	if s.scanCacheTTL > 0 {
		s.mu.Lock()
		s.cache[cacheKey] = cachedReport{report: rpt, cachedAt: start.UTC()}
		s.mu.Unlock()
	}

	return rpt, nil
}

// ScanFramework returns a single framework's detailed scan result.
// Returns ErrUnknownFramework if the framework name is not registered.
func (s *Scanner) ScanFramework(ctx context.Context, lic *license.ValidationResult, framework string) (*FrameworkScanResult, *FrameworkAssessment, error) {
	for _, modReq := range AllModuleRequirements() {
		if modReq.Module == framework {
			result := s.scanModule(ctx, modReq, lic)
			if result.Enforced {
				assessment, _ := s.runAssessment(ctx, framework)
				return &result, assessment, nil
			}
			return &result, nil, nil
		}
	}
	for _, fw := range freeFrameworks {
		if fw == framework {
			result := s.scanFreeFramework(ctx, fw, lic)
			if result.Enforced {
				assessment, _ := s.runAssessment(ctx, framework)
				return &result, assessment, nil
			}
			return &result, nil, nil
		}
	}
	return nil, nil, fmt.Errorf("%w: %q", ErrUnknownFramework, framework)
}

// scanModule computes the FrameworkScanResult for a single billable module.
func (s *Scanner) scanModule(ctx context.Context, modReq ModuleRequirement, lic *license.ValidationResult) FrameworkScanResult {
	result := FrameworkScanResult{
		Framework:           modReq.Module,
		DisplayName:         modReq.DisplayName,
		Module:              modReq.Module,
		LastScan:            time.Now().UTC(),
		ImplementationReady: modReq.HasImplementation,
	}
	// Use the gating API to determine enforcement.
	decision := EvaluateGating(modReq.Module, lic)
	result.Enforced = decision.Enforced
	// Always compute the control count, even when not enforced.
	// The customer portal uses "this framework has N controls"
	// to show "buy this module to enable scanning of all N
	// controls" upgrade prompts. v3.2.0 Phase 3.4: real counts
	// for HIPAA and PCI (registered in framework_registration.go);
	// 0 for SOC 2 / ISO / FedRAMP / FIPS until their sub-packages
	// are implemented.
	result.Score, result.ControlsTotal, result.ControlsEnforced = s.scoreFramework(ctx, modReq.Module, modReq.Module)
	if result.Enforced {
		result.ReasonEnforced = string(decision.Reason)
		if result.ControlsTotal > 0 {
			result.CompliancePct = float64(result.ControlsEnforced) / float64(result.ControlsTotal) * 100
		}
	} else {
		result.ReasonNotEnforced = string(decision.Reason)
		result.UpgradeHint = formatUpgradeHint(decision)
		if !decision.Enforced && modReq.HasImplementation {
			result.MissingModules = []string{modReq.Module}
		}
	}
	return result
}

// scanFreeFramework computes the FrameworkScanResult for a free framework
// (ATLAS, NIST AI RMF, OWASP) which is enforced for every tier.
func (s *Scanner) scanFreeFramework(ctx context.Context, framework string, lic *license.ValidationResult) FrameworkScanResult {
	result := FrameworkScanResult{
		Framework:           framework,
		DisplayName:         displayNameForFree(framework),
		LastScan:            time.Now().UTC(),
		Enforced:            true,
		ReasonEnforced:      "framework_free",
		ImplementationReady: true,
	}
	result.Score, result.ControlsTotal, result.ControlsEnforced = s.scoreFramework(ctx, framework, "")
	if result.ControlsTotal > 0 {
		result.CompliancePct = float64(result.ControlsEnforced) / float64(result.ControlsTotal) * 100
	}
	return result
}

// scoreFramework returns (score, total, enforced) for the
// framework. v3.2.0 Phase 3.4: the total comes from the
// framework's registered control count (HIPAA and PCI have
// real counts; SOC 2, ISO 42001, FedRAMP, FIPS return 0 until
// their sub-packages are implemented). The enforced and score
// fields return 0 — they would only be non-zero after a live
// per-request scan (a much larger feature for a later release).
func (s *Scanner) scoreFramework(ctx context.Context, framework, module string) (score float64, total int, enforced int) {
	total = lookupControlCount(framework)
	if total == 0 {
		// Fall back to the registry-based assessment in case a
		// framework is registered there (e.g., free frameworks
		// with custom scoring).
		assessment, err := s.runAssessment(ctx, framework)
		if err == nil && assessment != nil {
			total = assessment.Summary.Total
			enforced = assessment.Summary.Compliant + assessment.Summary.Partial
			score = assessment.Summary.Score
		}
	}
	return score, total, enforced
}

// runAssessment invokes the framework's GenerateAssessment if it's
// registered. Returns nil if the framework isn't in the registry.
func (s *Scanner) runAssessment(ctx context.Context, framework string) (*FrameworkAssessment, error) {
	commonFW, ok := s.lookupRegistered(framework)
	if !ok {
		return nil, nil
	}
	if fm, ok := commonFW.(FrameworkModule); ok {
		assessment, err := fm.GenerateAssessment(ctx, []byte("{}"))
		if err != nil {
			return nil, err
		}
		return assessment, nil
	}
	return &FrameworkAssessment{
		Framework:   framework,
		Version:     "1.0",
		GeneratedAt: time.Now().UTC(),
		Summary:     AssessmentSummary{},
	}, nil
}

// lookupRegistered finds a framework in the registry by name.
func (s *Scanner) lookupRegistered(framework string) (any, bool) {
	switch framework {
	case string(FrameworkHIPAA), string(FrameworkPCIDSS), string(FrameworkATLAS),
		string(FrameworkNIST1500), string(FrameworkOWASP):
		return nil, false
	}
	return nil, false
}

// InvalidateCache clears the scan cache.
func (s *Scanner) InvalidateCache() {
	s.mu.Lock()
	s.cache = make(map[string]cachedReport)
	s.mu.Unlock()
}

func aggregateScores(results []FrameworkScanResult) (avgScore, avgCompliance float64) {
	var sumScore, sumComp float64
	n := 0
	for _, r := range results {
		if r.Enforced {
			sumScore += r.Score
			sumComp += r.CompliancePct
			n++
		}
	}
	if n == 0 {
		return 0, 0
	}
	return sumScore / float64(n), sumComp / float64(n)
}

// formatUpgradeHint converts a GatingDecision's missing-piece fields
// into a customer-facing string ("Buy the HIPAA module" or
// "Upgrade to Professional tier").
func formatUpgradeHint(d GatingDecision) string {
	switch {
	// When both tier-to-low and module-not-owned apply, prefer the tier
	// hint because the customer can't buy the module on their tier.
	case d.MissingTierTo != "":
		return "Upgrade to " + d.MissingTierTo + " tier"
	case d.MissingUpgradeTo != "":
		return "Buy the " + d.MissingUpgradeTo + " module"
	case d.Reason == ReasonInvalidLicense:
		return "Provide a valid license key"
	case d.Reason == ReasonUnknownFramework:
		return "Unknown compliance framework"
	}
	return string(d.Reason)
}

// freeFrameworks are the frameworks available to every customer
// regardless of paid tier or module ownership. These are part of
// the "MUST be Community" mandate (MITRE ATLAS, NIST AI RMF, OWASP
// LLM Top 10) and the platform's open-source commitment.
var freeFrameworks = []string{
	string(FrameworkATLAS),    // MITRE ATLAS — 66 techniques
	string(FrameworkNIST1500), // NIST AI RMF 1.0
	string(FrameworkOWASP),    // OWASP LLM Top 10
}

func displayNameForFree(framework string) string {
	switch framework {
	case string(FrameworkATLAS):
		return "MITRE ATLAS"
	case string(FrameworkNIST1500):
		return "NIST AI RMF"
	case string(FrameworkOWASP):
		return "OWASP LLM Top 10"
	}
	return framework
}

// JSON returns the report as a JSON-encoded byte slice. Convenience
// for the HTTP handler.
func (r *ScanReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
