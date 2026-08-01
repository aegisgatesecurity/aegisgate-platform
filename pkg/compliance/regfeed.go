// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Regulatory Change Feed — Track Regulatory and Framework Changes
// =========================================================================
//
// This module provides a regulatory change feed that tracks updates to
// compliance frameworks (EU AI Act enforcement dates, NIST AI RMF updates,
// ISO 42001 publications, etc.). GRC auditors and legal teams need to know
// when the rules change — this module gives them a queryable, exportable
// record of regulatory changes affecting their AI deployments.
// =========================================================================

package compliance

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ChangeType describes the type of regulatory change.
type RegulatoryChangeType string

const (
	ChangeAmendment       RegulatoryChangeType = "amendment"
	ChangeNewRelease      RegulatoryChangeType = "new_release"
	ChangeWithdrawal      RegulatoryChangeType = "withdrawal"
	ChangeGuidanceUpdate  RegulatoryChangeType = "guidance_update"
	ChangeEnforcementDate RegulatoryChangeType = "enforcement_date"
)

// RegulatoryChange represents a single regulatory or framework change.
type RegulatoryChange struct {
	ID               string               `json:"id"`
	Framework        Framework            `json:"framework"`
	ChangeType       RegulatoryChangeType `json:"change_type"`
	Title            string               `json:"title"`
	Description      string               `json:"description"`
	EffectiveDate    time.Time            `json:"effective_date"`
	Source           string               `json:"source"`
	Severity         string               `json:"severity"` // "critical", "important", "informational"
	AffectedControls []string             `json:"affected_controls,omitempty"`
	DetectedAt       time.Time            `json:"detected_at"`
}

// FeedStats provides summary statistics about the change feed.
type FeedStats struct {
	TotalChanges int                    `json:"total_changes"`
	ByFramework  map[string]int         `json:"by_framework"`
	BySeverity   map[string]int         `json:"by_severity"`
	ByChangeType map[string]int         `json:"by_change_type"`
	Earliest     time.Time              `json:"earliest"`
	Latest       time.Time              `json:"latest"`
}

// RegulatoryChangeFeed tracks regulatory changes with query and export capability.
type RegulatoryChangeFeed struct {
	changes []RegulatoryChange
	mu      sync.RWMutex
	version string
}

// NewRegulatoryChangeFeed creates a new empty regulatory change feed.
func NewRegulatoryChangeFeed() *RegulatoryChangeFeed {
	return &RegulatoryChangeFeed{
		changes: make([]RegulatoryChange, 0),
		version: "3.6.0",
	}
}

// AddChange adds a regulatory change to the feed after validation.
func (f *RegulatoryChangeFeed) AddChange(change RegulatoryChange) error {
	if change.ID == "" {
		return fmt.Errorf("regulatory change ID is required")
	}
	if change.Title == "" {
		return fmt.Errorf("regulatory change title is required")
	}
	if change.Framework == "" {
		return fmt.Errorf("regulatory change framework is required")
	}
	if change.ChangeType == "" {
		return fmt.Errorf("regulatory change type is required")
	}
	if change.EffectiveDate.IsZero() {
		return fmt.Errorf("regulatory change effective date is required")
	}

	if change.DetectedAt.IsZero() {
		change.DetectedAt = time.Now().UTC()
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.changes = append(f.changes, change)
	return nil
}

// GetChanges returns changes matching the given criteria.
func (f *RegulatoryChangeFeed) GetChanges(since time.Time, framework Framework) []RegulatoryChange {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var results []RegulatoryChange
	for _, c := range f.changes {
		if !since.IsZero() && c.EffectiveDate.Before(since) {
			continue
		}
		if framework != "" && c.Framework != framework {
			continue
		}
		results = append(results, c)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].EffectiveDate.After(results[j].EffectiveDate)
	})

	return results
}

// GetLatest returns the n most recent changes.
func (f *RegulatoryChangeFeed) GetLatest(n int) []RegulatoryChange {
	f.mu.RLock()
	defer f.mu.RUnlock()

	sorted := make([]RegulatoryChange, len(f.changes))
	copy(sorted, f.changes)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].EffectiveDate.After(sorted[j].EffectiveDate)
	})

	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[:n]
}

// GetBySeverity returns changes matching a severity level.
func (f *RegulatoryChangeFeed) GetBySeverity(severity string) []RegulatoryChange {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var results []RegulatoryChange
	for _, c := range f.changes {
		if c.Severity == severity {
			results = append(results, c)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].EffectiveDate.After(results[j].EffectiveDate)
	})
	return results
}

// GetByChangeType returns changes matching a change type.
func (f *RegulatoryChangeFeed) GetByChangeType(changeType RegulatoryChangeType) []RegulatoryChange {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var results []RegulatoryChange
	for _, c := range f.changes {
		if c.ChangeType == changeType {
			results = append(results, c)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].EffectiveDate.After(results[j].EffectiveDate)
	})
	return results
}

// ExportJSON exports all changes as JSON.
func (f *RegulatoryChangeFeed) ExportJSON() ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	data, err := json.MarshalIndent(f.changes, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal regulatory changes: %w", err)
	}
	return data, nil
}

// Stats returns summary statistics about the change feed.
func (f *RegulatoryChangeFeed) Stats() FeedStats {
	f.mu.RLock()
	defer f.mu.RUnlock()

	stats := FeedStats{
		TotalChanges: len(f.changes),
		ByFramework:  make(map[string]int),
		BySeverity:   make(map[string]int),
		ByChangeType: make(map[string]int),
	}

	for _, c := range f.changes {
		stats.ByFramework[string(c.Framework)]++
		stats.BySeverity[c.Severity]++
		stats.ByChangeType[string(c.ChangeType)]++

		if stats.Earliest.IsZero() || c.EffectiveDate.Before(stats.Earliest) {
			stats.Earliest = c.EffectiveDate
		}
		if stats.Latest.IsZero() || c.EffectiveDate.After(stats.Latest) {
			stats.Latest = c.EffectiveDate
		}
	}

	return stats
}

// SeedDefaultChanges pre-populates the feed with known recent regulatory
// changes affecting AI governance and security.
func (f *RegulatoryChangeFeed) SeedDefaultChanges() {
	changes := []RegulatoryChange{
		{
			ID:            "REG-2025-001",
			Framework:     "eu_ai_act",
			ChangeType:    ChangeEnforcementDate,
			Title:         "EU AI Act — Prohibited AI Practices Enter Force",
			Description:   "Article 5 prohibited AI practices (social scoring, real-time biometric identification) become enforceable. Organizations deploying AI systems in the EU must verify compliance.",
			EffectiveDate: time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC),
			Source:         "https://eur-lex.europa.eu/eli/reg/2024/1689",
			Severity:      "critical",
			AffectedControls: []string{"Art.5", "Art.7", "Art.9"},
			DetectedAt:    time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:            "REG-2025-002",
			Framework:     "eu_ai_act",
			ChangeType:    ChangeEnforcementDate,
			Title:         "EU AI Act — General-Purpose AI Obligations Enter Force",
			Description:   "Obligations for providers of general-purpose AI models (transparency, copyright, technical documentation) become enforceable.",
			EffectiveDate: time.Date(2025, 8, 2, 0, 0, 0, 0, time.UTC),
			Source:         "https://eur-lex.europa.eu/eli/reg/2024/1689",
			Severity:      "critical",
			AffectedControls: []string{"Art.53", "Art.54", "Art.55"},
			DetectedAt:    time.Date(2025, 8, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:            "REG-2025-003",
			Framework:     "nist_ai_rmf",
			ChangeType:    ChangeGuidanceUpdate,
			Title:         "NIST AI RMF 1.0 — Updated Companion Guide Released",
			Description:   "NIST released an updated companion guide for the AI Risk Management Framework with new implementation examples for generative AI systems.",
			EffectiveDate: time.Date(2025, 3, 15, 0, 0, 0, 0, time.UTC),
			Source:         "https://www.nist.gov/artificial-intelligence/ai-risk-management-framework",
			Severity:      "important",
			AffectedControls: []string{"GV.1.1", "RM.1.1", "MS.2.1"},
			DetectedAt:    time.Date(2025, 3, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:            "REG-2024-001",
			Framework:     "iso42001",
			ChangeType:    ChangeNewRelease,
			Title:         "ISO/IEC 42001:2023 — AI Management System Standard Published",
			Description:   "ISO published the first international standard for AI management systems. Provides requirements for establishing, implementing, and improving an AI management system.",
			EffectiveDate: time.Date(2023, 12, 19, 0, 0, 0, 0, time.UTC),
			Source:         "https://www.iso.org/standard/81230.html",
			Severity:      "critical",
			AffectedControls: []string{"4.1", "4.2", "5.1", "6.1", "7.1"},
			DetectedAt:    time.Date(2023, 12, 19, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:            "REG-2024-002",
			Framework:     "owasp",
			ChangeType:    ChangeNewRelease,
			Title:         "OWASP LLM Top 10 2025 — Updated List Published",
			Description:   "OWASP published the 2025 update to the LLM Top 10, adding new categories for agentic AI risks and updating existing entries based on evolving threat landscape.",
			EffectiveDate: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
			Source:         "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			Severity:      "important",
			AffectedControls: []string{"LLM01", "LLM02", "LLM05", "LLM06"},
			DetectedAt:    time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:            "REG-2025-004",
			Framework:     "atlas",
			ChangeType:    ChangeAmendment,
			Title:         "MITRE ATLAS — New Technique T0046 (Agentic Autonomy Exploitation)",
			Description:   "MITRE added T0046 to the ATLAS matrix covering adversarial exploitation of AI agent autonomy boundaries. Relevant for multi-agent and tool-calling systems.",
			EffectiveDate: time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC),
			Source:         "https://atlas.mitre.org/",
			Severity:      "important",
			AffectedControls: []string{"T0046", "T0043", "T0040"},
			DetectedAt:    time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:            "REG-2025-005",
			Framework:     "ccpa",
			ChangeType:    ChangeAmendment,
			Title:         "CCPA/CPRA — Updated AI Profiling Regulations",
			Description:   "California updated CPRA regulations regarding automated decision-making and AI profiling. New opt-out requirements for AI-driven profiling take effect.",
			EffectiveDate: time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC),
			Source:         "https://oag.ca.gov/privacy/ccpa",
			Severity:      "important",
			AffectedControls: []string{"1798.100", "1798.140", "1798.185"},
			DetectedAt:    time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:            "REG-2025-006",
			Framework:     "nist_ai_600_1",
			ChangeType:    ChangeGuidanceUpdate,
			Title:         "NIST AI 600-1 — AI Risk Management Profile for Generative AI",
			Description:   "NIST published AI 600-1, a cross-sectoral profile for managing risks in generative AI systems. Includes new controls for LLM deployment, content provenance, and hallucination management.",
			EffectiveDate: time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC),
			Source:         "https://www.nist.gov/artificial-intelligence",
			Severity:      "important",
			AffectedControls: []string{"MS.2.4", "GV.1.4", "RM.2.1"},
			DetectedAt:    time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:            "REG-2025-007",
			Framework:     "soc2",
			ChangeType:    ChangeGuidanceUpdate,
			Title:         "SOC 2 — AI Supplemental Criteria Published",
			Description:   "AICPA published supplemental SOC 2 criteria for AI system controls, addressing LLM security, training data governance, and model monitoring requirements.",
			EffectiveDate: time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			Source:         "https://www.aicpa-cima.com/topic/audit-assurance",
			Severity:      "important",
			AffectedControls: []string{"CC6.1", "CC6.3", "CC7.1", "CC7.2"},
			DetectedAt:    time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:            "REG-2025-008",
			Framework:     "fedramp",
			ChangeType:    ChangeAmendment,
			Title:         "FedRAMP — AI System Authorization Pathway Updated",
			Description:   "FedRAMP released updated guidance for AI system authorization, including new security controls for LLM providers and requirements for AI-specific vulnerability assessments.",
			EffectiveDate: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
			Source:         "https://www.fedramp.gov/",
			Severity:      "critical",
			AffectedControls: []string{"AC-2", "SC-8", "SI-3", "RA-5"},
			DetectedAt:    time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, c := range changes {
		_ = f.AddChange(c) // seeded changes are pre-validated
	}
}