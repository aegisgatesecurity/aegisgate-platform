// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// Compliance Framework Registry
// Unified interface for managing all compliance frameworks
// =========================================================================

package registry

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
)

// Registry manages all compliance frameworks for AegisGuard
type Registry struct {
	mu         sync.RWMutex
	frameworks map[string]common.Framework
	tier       string
}

// New creates a new compliance registry with the specified tier
func New(tier string) *Registry {
	return &Registry{
		frameworks: make(map[string]common.Framework),
		tier:       tier,
	}
}

// NewRegistry is an alias for New for backwards compatibility
// Deprecated: Use New() instead
func NewRegistry(tier string) *Registry {
	return New(tier)
}

// Register adds a framework to the registry
func (r *Registry) Register(framework common.Framework) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if framework == nil {
		return fmt.Errorf("%w: cannot register nil framework", ErrNilFramework)
	}

	id := framework.GetFrameworkID()
	if id == "" {
		return fmt.Errorf("%w: framework has no ID", ErrInvalidFramework)
	}

	// Check tier support
	if !framework.SupportsTier(r.tier) {
		return fmt.Errorf("%w: framework %s does not support tier %s", ErrTierNotSupported, id, r.tier)
	}

	r.frameworks[id] = framework
	return nil
}

// RegisterAll registers multiple frameworks at once
func (r *Registry) RegisterAll(frameworks []common.Framework) error {
	var errors []string
	for _, fw := range frameworks {
		if err := r.Register(fw); err != nil {
			errors = append(errors, err.Error())
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("%w: %s", ErrRegistrationFailed, strings.Join(errors, "; "))
	}
	return nil
}

// Unregister removes a framework from the registry
func (r *Registry) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.frameworks[id]; !ok {
		return fmt.Errorf("%w: %s", ErrFrameworkNotFound, id)
	}
	delete(r.frameworks, id)
	return nil
}

// Get retrieves a framework by ID
func (r *Registry) Get(id string) (common.Framework, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.frameworks[id]
	return f, ok
}

// List returns all registered frameworks
func (r *Registry) List() []common.Framework {
	r.mu.RLock()
	defer r.mu.RUnlock()

	frameworks := make([]common.Framework, 0, len(r.frameworks))
	for _, f := range r.frameworks {
		frameworks = append(frameworks, f)
	}
	return frameworks
}

// ListByTier returns frameworks supported by the current tier
func (r *Registry) ListByTier() []common.Framework {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var frameworks []common.Framework
	for _, f := range r.frameworks {
		if f.SupportsTier(r.tier) {
			frameworks = append(frameworks, f)
		}
	}
	return frameworks
}

// ListEnabled returns all enabled frameworks
func (r *Registry) ListEnabled() []common.Framework {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var frameworks []common.Framework
	for _, f := range r.frameworks {
		if f.IsEnabled() {
			frameworks = append(frameworks, f)
		}
	}
	return frameworks
}

// Count returns the number of registered frameworks
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.frameworks)
}

// CountEnabled returns the number of enabled frameworks
func (r *Registry) CountEnabled() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, f := range r.frameworks {
		if f.IsEnabled() {
			count++
		}
	}
	return count
}

// CheckAll runs checks against all registered frameworks
func (r *Registry) CheckAll(ctx context.Context, input common.CheckInput) (*AggregateResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check for context cancellation
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	result := &AggregateResult{
		Timestamp:     time.Now(),
		InputLength:   len(input.Content),
		OverallPassed: true,
		Frameworks:    make([]FrameworkResult, 0, len(r.frameworks)),
		Findings:      make([]common.Finding, 0),
	}

	for _, f := range r.frameworks {
		if !f.IsEnabled() {
			continue
		}

		frameworkResult, err := r.checkFramework(ctx, f, input)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("%s: %v", f.GetFrameworkID(), err).Error())
			continue
		}

		result.Frameworks = append(result.Frameworks, *frameworkResult)
		result.TotalPatterns += frameworkResult.TotalPatterns
		result.MatchedPatterns += frameworkResult.MatchedPatterns

		if !frameworkResult.Passed {
			result.OverallPassed = false
			result.Findings = append(result.Findings, frameworkResult.Findings...)
			result.CriticalFindings += countBySeverity(frameworkResult.Findings, common.SeverityCritical)
			result.HighFindings += countBySeverity(frameworkResult.Findings, common.SeverityHigh)
			result.MediumFindings += countBySeverity(frameworkResult.Findings, common.SeverityMedium)
			result.LowFindings += countBySeverity(frameworkResult.Findings, common.SeverityLow)
		}
	}

	return result, nil
}

// checkFramework runs a single framework check
func (r *Registry) checkFramework(ctx context.Context, f common.Framework, input common.CheckInput) (*FrameworkResult, error) {
	start := time.Now()
	checkResult, err := f.Check(ctx, input)
	duration := time.Since(start)

	frameworkResult := FrameworkResult{
		FrameworkID:   f.GetFrameworkID(),
		FrameworkName: f.GetName(),
		Duration:      duration,
		Findings:      []common.Finding{},
	}

	if err != nil {
		frameworkResult.Error = err.Error()
		frameworkResult.Passed = false
		return &frameworkResult, err
	}

	if checkResult != nil {
		frameworkResult.Passed = checkResult.Passed
		frameworkResult.Findings = checkResult.Findings
		frameworkResult.Duration = checkResult.Duration
		frameworkResult.TotalPatterns = checkResult.TotalPatterns
		frameworkResult.MatchedPatterns = checkResult.MatchedPatterns
	}

	return &frameworkResult, nil
}

// CheckAllRequests runs request checks against all frameworks
func (r *Registry) CheckAllRequests(ctx context.Context, req *common.HTTPRequest) (*AggregateResult, error) {
	if req == nil {
		return nil, fmt.Errorf("nil HTTP request")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	result := &AggregateResult{
		Timestamp:     time.Now(),
		OverallPassed: true,
		Frameworks:    make([]FrameworkResult, 0, len(r.frameworks)),
		Findings:      make([]common.Finding, 0),
	}

	// Build check input from request
	input := common.CheckInput{
		Content:   req.Body,
		Headers:   req.Headers,
		Metadata:  map[string]string{"url": req.URL, "method": req.Method},
		Timestamp: time.Now(),
	}

	for _, f := range r.frameworks {
		if !f.IsEnabled() {
			continue
		}

		frameworkResult, err := r.checkFramework(ctx, f, input)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", f.GetFrameworkID(), err))
			continue
		}

		result.Frameworks = append(result.Frameworks, *frameworkResult)

		if !frameworkResult.Passed {
			result.OverallPassed = false
			result.Findings = append(result.Findings, frameworkResult.Findings...)
		}
	}

	return result, nil
}

// CheckAllResponses runs response checks against all frameworks
func (r *Registry) CheckAllResponses(ctx context.Context, resp *common.HTTPResponse) (*AggregateResult, error) {
	if resp == nil {
		return nil, fmt.Errorf("nil HTTP response")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	result := &AggregateResult{
		Timestamp:     time.Now(),
		OverallPassed: true,
		Frameworks:    make([]FrameworkResult, 0, len(r.frameworks)),
		Findings:      make([]common.Finding, 0),
	}

	// Build check input from response
	input := common.CheckInput{
		Content:   resp.Body,
		Headers:   resp.Headers,
		Metadata:  map[string]string{"status_code": fmt.Sprintf("%d", resp.StatusCode)},
		Timestamp: time.Now(),
	}

	for _, f := range r.frameworks {
		if !f.IsEnabled() {
			continue
		}

		frameworkResult, err := r.checkFramework(ctx, f, input)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", f.GetFrameworkID(), err))
			continue
		}

		result.Frameworks = append(result.Frameworks, *frameworkResult)

		if !frameworkResult.Passed {
			result.OverallPassed = false
			result.Findings = append(result.Findings, frameworkResult.Findings...)
		}
	}

	return result, nil
}

// CheckByFramework runs a check using a specific framework
func (r *Registry) CheckByFramework(ctx context.Context, frameworkID string, input common.CheckInput) (*FrameworkResult, error) {
	r.mu.RLock()
	f, ok := r.frameworks[frameworkID]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrFrameworkNotFound, frameworkID)
	}

	return r.checkFramework(ctx, f, input)
}

// CheckByFrameworks runs checks using specific frameworks
func (r *Registry) CheckByFrameworks(ctx context.Context, frameworkIDs []string, input common.CheckInput) (*AggregateResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := &AggregateResult{
		Timestamp:     time.Now(),
		InputLength:   len(input.Content),
		OverallPassed: true,
		Frameworks:    make([]FrameworkResult, 0, len(frameworkIDs)),
		Findings:      make([]common.Finding, 0),
	}

	for _, id := range frameworkIDs {
		f, ok := r.frameworks[id]
		if !ok {
			result.Errors = append(result.Errors, fmt.Errorf("%s: %w", id, ErrFrameworkNotFound).Error())
			continue
		}

		if !f.IsEnabled() {
			continue
		}

		frameworkResult, err := r.checkFramework(ctx, f, input)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", id, err))
			continue
		}

		result.Frameworks = append(result.Frameworks, *frameworkResult)

		if !frameworkResult.Passed {
			result.OverallPassed = false
			result.Findings = append(result.Findings, frameworkResult.Findings...)
		}
	}

	return result, nil
}

// SetTier changes the current tier and validates all frameworks
func (r *Registry) SetTier(tier string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.tier = tier

	// Check if all frameworks support the new tier
	for id, f := range r.frameworks {
		if !f.SupportsTier(tier) {
			return fmt.Errorf("%w: framework %s does not support tier %s", ErrTierNotSupported, id, tier)
		}
	}

	return nil
}

// GetTier returns the current tier
func (r *Registry) GetTier() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tier
}

// GetStats returns statistics about the registry
func (r *Registry) GetStats() RegistryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := RegistryStats{
		Tier:            r.tier,
		TotalFrameworks: len(r.frameworks),
		EnabledCount:    0,
		TotalPatterns:   0,
		Frameworks:      make([]FrameworkStats, 0, len(r.frameworks)),
	}

	for _, f := range r.frameworks {
		frameworkStats := FrameworkStats{
			ID:             f.GetFrameworkID(),
			Name:           f.GetName(),
			Version:        f.GetVersion(),
			Enabled:        f.IsEnabled(),
			PatternCount:   f.GetPatternCount(),
			SeverityLevels: f.GetSeverityLevels(),
		}
		stats.Frameworks = append(stats.Frameworks, frameworkStats)
		stats.TotalPatterns += f.GetPatternCount()
		if f.IsEnabled() {
			stats.EnabledCount++
		}
	}

	return stats
}

// Enable enables a specific framework
func (r *Registry) Enable(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	f, ok := r.frameworks[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrFrameworkNotFound, id)
	}
	f.Enable()
	return nil
}

// Disable disables a specific framework
func (r *Registry) Disable(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	f, ok := r.frameworks[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrFrameworkNotFound, id)
	}
	f.Disable()
	return nil
}

// EnableAll enables all registered frameworks
func (r *Registry) EnableAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.frameworks {
		f.Enable()
	}
}

// DisableAll disables all registered frameworks
func (r *Registry) DisableAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.frameworks {
		f.Disable()
	}
}

// Configure applies configuration to a specific framework
func (r *Registry) Configure(id string, config map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	f, ok := r.frameworks[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrFrameworkNotFound, id)
	}
	return f.Configure(config)
}

// IsRegistered checks if a framework is registered
func (r *Registry) IsRegistered(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.frameworks[id]
	return ok
}

// IsEnabled checks if a framework is enabled
func (r *Registry) IsEnabled(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.frameworks[id]
	return ok && f.IsEnabled()
}

// ============================================================================
// RESULT TYPES
// ============================================================================

// AggregateResult represents the combined results from all frameworks
type AggregateResult struct {
	Timestamp        time.Time
	InputLength      int
	OverallPassed    bool
	Frameworks       []FrameworkResult
	Findings         []common.Finding
	TotalPatterns    int
	MatchedPatterns  int
	CriticalFindings int
	HighFindings     int
	MediumFindings   int
	LowFindings      int
	Errors           []string
}

// FrameworkResult represents the result from a single framework
type FrameworkResult struct {
	FrameworkID     string
	FrameworkName   string
	Passed          bool
	Findings        []common.Finding
	Duration        time.Duration
	TotalPatterns   int
	MatchedPatterns int
	Error           string
}

// RegistryStats represents statistics about the registry
type RegistryStats struct {
	Tier            string
	TotalFrameworks int
	EnabledCount    int
	TotalPatterns   int
	Frameworks      []FrameworkStats
}

// FrameworkStats represents statistics for a single framework
type FrameworkStats struct {
	ID             string
	Name           string
	Version        string
	Enabled        bool
	PatternCount   int
	SeverityLevels []common.Severity
}

// ============================================================================
// ERRORS
// ============================================================================

// Registry errors
var (
	ErrNilFramework       = fmt.Errorf("nil framework")
	ErrInvalidFramework   = fmt.Errorf("invalid framework")
	ErrTierNotSupported   = fmt.Errorf("tier not supported")
	ErrFrameworkNotFound  = fmt.Errorf("framework not found")
	ErrRegistrationFailed = fmt.Errorf("registration failed")
)

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// countBySeverity counts findings by severity level
func countBySeverity(findings []common.Finding, severity common.Severity) int {
	count := 0
	for _, f := range findings {
		if f.Severity == severity {
			count++
		}
	}
	return count
}
