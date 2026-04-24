// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package compliance provides the compliance module infrastructure for AegisGate.
// Each compliance framework is implemented as a separate, independently licensable module.
package compliance

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// ControlCheckStatus represents the compliance status of a control check.
type ControlCheckStatus string

const (
	StatusCompliant     ControlCheckStatus = "compliant"
	StatusNonCompliant  ControlCheckStatus = "non_compliant"
	StatusPartial       ControlCheckStatus = "partial"
	StatusNotApplicable ControlCheckStatus = "not_applicable"
	StatusUnknown       ControlCheckStatus = "unknown"
)

// ControlCheckResult represents the result of a compliance control check.
type ControlCheckResult struct {
	Framework   string             `json:"framework"`
	ControlID   string             `json:"control_id"`
	ControlName string             `json:"control_name"`
	Status      ControlCheckStatus `json:"status"`
	Severity    ControlSeverity    `json:"severity,omitempty"`
	Message     string             `json:"message"`
	Details     string             `json:"details,omitempty"`
	Remediation string             `json:"remediation,omitempty"`
	Evidence    []string           `json:"evidence,omitempty"`
	Timestamp   time.Time          `json:"timestamp"`
	References  []string           `json:"references,omitempty"`
}

// ControlDefinition represents a compliance control definition.
type ControlDefinition struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    string          `json:"category,omitempty"`
	Severity    ControlSeverity `json:"severity,omitempty"`
	Remediation string          `json:"remediation,omitempty"`
	References  []string        `json:"references,omitempty"`
	Automated   bool            `json:"automated"`
	CheckFunc   CheckFunc       `json:"-"`
}

// CheckFunc is the function signature for control check implementations.
type CheckFunc func(ctx context.Context, input []byte) (*ControlCheckResult, error)

// FrameworkModule defines the interface for compliance framework modules.
type FrameworkModule interface {
	core.Module

	// Framework returns the framework identifier.
	Framework() string

	// Version returns the framework version.
	Version() string

	// Controls returns all registered controls.
	Controls() []ControlDefinition

	// CheckControl performs a specific control check.
	CheckControl(ctx context.Context, controlID string, input []byte) (*ControlCheckResult, error)

	// CheckAll performs all automated control checks.
	CheckAll(ctx context.Context, input []byte) ([]*ControlCheckResult, error)

	// GenerateAssessment generates a compliance assessment report.
	GenerateAssessment(ctx context.Context, input []byte) (*FrameworkAssessment, error)
}

// FrameworkAssessment represents a comprehensive assessment for a framework.
type FrameworkAssessment struct {
	Framework    string                `json:"framework"`
	Version      string                `json:"version"`
	GeneratedAt  time.Time             `json:"generated_at"`
	Results      []*ControlCheckResult `json:"results"`
	Summary      AssessmentSummary     `json:"summary"`
	Remediations []string              `json:"remediations,omitempty"`
}

// AssessmentSummary provides summary statistics for an assessment.
type AssessmentSummary struct {
	Total         int     `json:"total"`
	Compliant     int     `json:"compliant"`
	NonCompliant  int     `json:"non_compliant"`
	Partial       int     `json:"partial"`
	NotApplicable int     `json:"not_applicable"`
	Score         float64 `json:"score"`
}

// BaseComplianceModule provides a base implementation for compliance modules.
type BaseComplianceModule struct {
	*core.BaseModule
	framework string
	version   string
	controls  []ControlDefinition
	mu        sync.RWMutex
}

// NewBaseComplianceModule creates a new base compliance module.
func NewBaseComplianceModule(framework, version string, tier core.Tier) *BaseComplianceModule {
	return &BaseComplianceModule{
		BaseModule: core.NewBaseModule(core.ModuleMetadata{
			ID:          framework,
			Name:        fmt.Sprintf("%s Compliance Module", framework),
			Version:     version,
			Description: fmt.Sprintf("%s compliance controls as a licensed add-on module", framework),
			Category:    core.CategoryCompliance,
			Tier:        tier,
			Tags:        []string{"compliance", framework},
		}),
		framework: framework,
		version:   version,
		controls:  make([]ControlDefinition, 0),
	}
}

// Framework returns the framework identifier.
func (m *BaseComplianceModule) Framework() string {
	return m.framework
}

// Version returns the framework version.
func (m *BaseComplianceModule) Version() string {
	return m.version
}

// Controls returns all registered controls.
func (m *BaseComplianceModule) Controls() []ControlDefinition {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]ControlDefinition(nil), m.controls...)
}

// RegisterControl adds a control to the module.
func (m *BaseComplianceModule) RegisterControl(control ControlDefinition) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.controls = append(m.controls, control)
}

// CheckControl performs a specific control check.
func (m *BaseComplianceModule) CheckControl(ctx context.Context, controlID string, input []byte) (*ControlCheckResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, control := range m.controls {
		if control.ID == controlID {
			if control.CheckFunc == nil {
				return &ControlCheckResult{
					Framework:   m.framework,
					ControlID:   control.ID,
					ControlName: control.Name,
					Status:      StatusNotApplicable,
					Message:     "Control check is not automated",
					Timestamp:   time.Now(),
				}, nil
			}
			return control.CheckFunc(ctx, input)
		}
	}

	return nil, fmt.Errorf("control %q not found", controlID)
}

// CheckAll performs all automated control checks.
func (m *BaseComplianceModule) CheckAll(ctx context.Context, input []byte) ([]*ControlCheckResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make([]*ControlCheckResult, 0, len(m.controls))

	for _, control := range m.controls {
		if control.CheckFunc != nil {
			result, err := control.CheckFunc(ctx, input)
			if err != nil {
				result = &ControlCheckResult{
					Framework:   m.framework,
					ControlID:   control.ID,
					ControlName: control.Name,
					Status:      StatusUnknown,
					Message:     fmt.Sprintf("Check failed: %v", err),
					Timestamp:   time.Now(),
				}
			}
			results = append(results, result)
		}
	}

	return results, nil
}

// GenerateAssessment generates a comprehensive compliance assessment.
func (m *BaseComplianceModule) GenerateAssessment(ctx context.Context, input []byte) (*FrameworkAssessment, error) {
	results, err := m.CheckAll(ctx, input)
	if err != nil {
		return nil, err
	}

	summary := AssessmentSummary{
		Total: len(results),
	}

	remediations := make([]string, 0)

	for _, result := range results {
		switch result.Status {
		case StatusCompliant:
			summary.Compliant++
		case StatusNonCompliant:
			summary.NonCompliant++
			if result.Remediation != "" {
				remediations = append(remediations, result.Remediation)
			}
		case StatusPartial:
			summary.Partial++
			if result.Remediation != "" {
				remediations = append(remediations, result.Remediation)
			}
		case StatusNotApplicable:
			summary.NotApplicable++
		}
	}

	if summary.Total > 0 {
		summary.Score = float64(summary.Compliant) / float64(summary.Total) * 100
	}

	return &FrameworkAssessment{
		Framework:    m.framework,
		Version:      m.version,
		GeneratedAt:  time.Now(),
		Results:      results,
		Summary:      summary,
		Remediations: remediations,
	}, nil
}

// OptionalDependencies returns optional modules.
func (m *BaseComplianceModule) OptionalDependencies() []string {
	return []string{"scanner", "metrics"}
}

// Provides returns module capabilities.
func (m *BaseComplianceModule) Provides() []string {
	return []string{"compliance", m.framework + "_compliance"}
}
