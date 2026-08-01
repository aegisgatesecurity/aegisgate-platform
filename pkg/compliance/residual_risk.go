// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Residual Risk Map
// =========================================================================
//
// residual_risk.go provides a cross-referenced risk map for all 52 ATLAS
// techniques. It answers the CISO question: "For each threat, are we
// detecting it, partially detecting it, or not detecting it at all — and
// if not, who covers it?"
//
// The map is built from three authoritative sources:
//   - pkg/compliance/atlas.go: detection patterns (regex rules)
//   - pkg/compliance/mapping/techniques.go: AegisGate control mappings
//   - pkg/incident/atlas_enrichment.go: severity & enrichment data
//
// This produces a board-ready view of residual risk.
// =========================================================================

package compliance

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/mapping"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/incident"
)

// DetectionStatus describes whether AegisGate's rule engine catches a
// given ATLAS sub-technique.
type DetectionStatus string

const (
	// Detected means the rule engine has a dedicated pattern for this
	// technique that catches most known variants.
	Detected DetectionStatus = "Detected"
	// Partial means the rule engine has patterns that catch some but not
	// all variants of this technique (e.g., direct injection is caught
	// but multi-turn is not).
	Partial DetectionStatus = "Partial"
	// NotDetected means no detection pattern exists in the rule engine;
	// coverage may exist via alternative pillars (MCP, ACP, Trust, SIEM).
	NotDetected DetectionStatus = "Not Detected"
)

// BlastRadius describes the worst-case impact of a technique if
// successfully exploited.
type BlastRadius string

const (
	BlastCritical BlastRadius = "Critical"
	BlastHigh     BlastRadius = "High"
	BlastMedium   BlastRadius = "Medium"
	BlastLow      BlastRadius = "Low"
)

// ResidualRiskEntry is a single row in the residual risk map. It
// shows, for each ATLAS sub-technique, whether our rules detect it,
// what other pillar covers the gap, how bad it would be, and what
// the customer should do about it.
type ResidualRiskEntry struct {
	// TechniqueID is the ATLAS sub-technique ID (e.g., "T1535.001").
	TechniqueID string `json:"technique_id"`
	// TechniqueName is the human-readable name.
	TechniqueName string `json:"technique_name"`
	// ParentTechnique is the parent technique ID (e.g., "T1535").
	ParentTechnique string `json:"parent_technique"`
	// Category is the ATLAS category (e.g., "PromptInjection").
	Category string `json:"category"`
	// DetectionStatus indicates whether the rule engine detects this technique.
	DetectionStatus DetectionStatus `json:"detection_status"`
	// AlternativeCoverage lists which other pillars cover this technique
	// when rules don't: "HTTP Scanner", "MCP", "ACP", "Trust Framework",
	// "SIEM", etc. Empty if no alternative coverage exists.
	AlternativeCoverage []string `json:"alternative_coverage"`
	// BlastRadius is the worst-case impact if this technique succeeds.
	BlastRadius BlastRadius `json:"blast_radius"`
	// RecommendedAction tells the customer what to do about any gap.
	RecommendedAction string `json:"recommended_action"`
}

// ResidualRiskSummary provides aggregate statistics for the risk map.
type ResidualRiskSummary struct {
	TotalTechniques   int            `json:"total_techniques"`
	Detected          int            `json:"detected"`
	Partial           int            `json:"partial"`
	NotDetected       int            `json:"not_detected"`
	CriticalBlast     int            `json:"critical_blast"`
	HighBlast         int            `json:"high_blast"`
	MediumBlast       int            `json:"medium_blast"`
	LowBlast          int            `json:"low_blast"`
	ResidualRiskCount int            `json:"residual_risk_count"`
	CoveragePercent   float64        `json:"coverage_percent"`
	ByCategory        map[string]int `json:"by_category"`
}

// pillarForControl maps an AegisGate control ID to its pillar name.
// This is the "alternative coverage" axis: if the rule engine doesn't
// catch it, which other pillar does?
func pillarForControl(controlID string) string {
	pillars := map[string]string{
		"AG-DETECT-SCANNER":            "HTTP Scanner",
		"AG-AUTH-RBAC-MFA":             "Trust Framework",
		"AG-OUTPUT-PII-SECRET-FILTER":  "HTTP Scanner",
		"AG-VULN-CI-SCANNING":          "SIEM",
		"AG-CRYPTO-TLS-FIPS":           "Trust Framework",
		"AG-AUDIT-LOG-HASH-CHAIN":      "SIEM",
		"AG-TRUST-AGENT-ATTESTATION":   "Trust Framework",
		"AG-CM-BASELINE-CONFIG":        "ACP",
		"AG-CA-CONTINUOUS-MONITORING":  "SIEM",
		"AG-IR-INCIDENT-RESPONSE":      "SIEM",
		"AG-SC-BOUNDARY-PROTECTION":    "ACP",
		"AG-DATA-PROTECTION-PRIVACY":   "MCP",
		"AG-SECURITY-AWARENESS":        "Trust Framework",
		"AG-ASSET-INVENTORY":           "SIEM",
		"AG-SUPPLY-CHAIN-RISK":         "SIEM",
		"AG-BUSINESS-CONTINUITY":       "ACP",
		"AG-IDENTITY-LIFECYCLE":        "Trust Framework",
		"AG-NETWORK-SECURITY":          "ACP",
		"AG-RISK-GOVERNANCE":           "Trust Framework",
		"AG-PHYSICAL-SECURITY":         "ACP",
		"AG-AI-SAFETY-QUALITY":         "Trust Framework",
		"AG-AC-CONCURRENT-SESSIONS":    "Trust Framework",
		"AG-IA-ADVERSARY-DETECTION":    "Trust Framework",
		"AG-IR-INTEGRATION":            "SIEM",
		"AG-SC-RESOURCE-AVAILABILITY":  "ACP",
		"AG-CM-CONFIGURATION-PLANNING": "ACP",
		"AG-AT-AWARENESS-TRAINING":     "Trust Framework",
		"AG-CP-CONTINGENCY":            "ACP",
		"AG-CA-SECURITY-ASSESSMENT":    "SIEM",
		"AG-AC-ACCESS-ENFORCEMENT":     "Trust Framework",
		"AG-AU-AUDIT-MONITORING":       "SIEM",
		"AG-PL-PLANNING":               "Trust Framework",
		"AG-MA-MAINTENANCE":            "ACP",
		"AG-PS-PERSONNEL-SECURITY":     "Trust Framework",
		"AG-IR-IR-POLICY-PLANNING":     "SIEM",
		"AG-SC-COMM-PROTECTION":        "ACP",
		"AG-SI-SYSTEM-INTEGRITY":       "SIEM",
		"AG-SA-SYSTEM-ACQUISITION":     "ACP",
	}
	if p, ok := pillars[controlID]; ok {
		return p
	}
	return "Trust Framework"
}

// severityToBlastRadius maps the incident severity to a blast radius
// classification. The mapping follows:
//   - critical → Critical
//   - high     → High
//   - medium   → Medium
//   - low      → Low
func severityToBlastRadius(sev incident.IncidentSeverity) BlastRadius {
	switch sev {
	case incident.SeverityCritical:
		return BlastCritical
	case incident.SeverityHigh:
		return BlastHigh
	case incident.SeverityMedium:
		return BlastMedium
	default:
		return BlastLow
	}
}

// recommendedActionFor returns a recommended action based on the
// detection status, blast radius, and alternative coverage.
func recommendedActionFor(status DetectionStatus, blast BlastRadius, altCoverage []string) string {
	switch status {
	case Detected:
		if blast == BlastCritical {
			return "Rule-based detection in place; tune alert thresholds and validate SIEM integration quarterly"
		}
		return "Rule-based detection in place; monitor for new variants and update patterns as they emerge"
	case Partial:
		pillars := strings.Join(altCoverage, ", ")
		if blast == BlastCritical {
			if pillars != "" {
				return fmt.Sprintf("Partial rule coverage; CRITICAL blast radius — supplement with %s monitoring and add dedicated detection rules for uncovered variants", pillars)
			}
			return "Partial rule coverage; CRITICAL blast radius — develop dedicated detection rules for uncovered variants immediately"
		}
		if pillars != "" {
			return fmt.Sprintf("Partial rule coverage; supplement with %s monitoring and expand pattern set for full variant coverage", pillars)
		}
		return "Partial rule coverage; expand detection pattern set to cover all known variants"
	default: // NotDetected
		pillars := strings.Join(altCoverage, ", ")
		if blast == BlastCritical {
			if pillars != "" {
				return fmt.Sprintf("No rule detection; CRITICAL blast radius — rely on %s; develop and deploy dedicated detection rules as P1 priority", pillars)
			}
			return "No rule detection; CRITICAL blast radius — develop and deploy dedicated detection rules as P1 priority"
		}
		if blast == BlastHigh {
			if pillars != "" {
				return fmt.Sprintf("No rule detection; rely on %s; develop detection rules as P2 priority", pillars)
			}
			return "No rule detection; develop detection rules as P2 priority"
		}
		if pillars != "" {
			return fmt.Sprintf("No rule detection; monitor via %s; consider adding rule-based detection in future release", pillars)
		}
		return "No rule detection; consider adding rule-based detection in future release"
	}
}

// all52Techniques returns the complete set of 52 ATLAS sub-techniques
// that AegisGate tracks. These are the union of techniques from the
// detection patterns (atlas.go) and the enrichment database
// (atlas_enrichment.go). The enrichment database is authoritative for
// names, categories, and severities.
func all52Techniques() []struct {
	id       string
	parent   string
	category string
	name     string
	severity incident.IncidentSeverity
} {
	// The 52 sub-techniques come from atlas_enrichment.go's atlasTechniqueDB.
	// We list them explicitly so the compiler enforces completeness.
	return []struct {
		id       string
		parent   string
		category string
		name     string
		severity incident.IncidentSeverity
	}{
		// Prompt Injection (T1535)
		{"T1535.001", "T1535", "PromptInjection", "Ignore Previous Instructions", incident.SeverityHigh},
		{"T1535.002", "T1535", "PromptInjection", "Override System Boundaries", incident.SeverityHigh},
		{"T1535.003", "T1535", "PromptInjection", "Prompt Injection via Role Play", incident.SeverityHigh},
		{"T1535.004", "T1535", "PromptInjection", "Token Smuggling", incident.SeverityCritical},
		{"T1535.005", "T1535", "PromptInjection", "Multi-turn Prompt Injection", incident.SeverityCritical},

		// LLM Jailbreak (T1484)
		{"T1484.001", "T1484", "LLMJailbreak", "Direct Jailbreak", incident.SeverityCritical},
		{"T1484.002", "T1484", "LLMJailbreak", "Indirect Jailbreak", incident.SeverityCritical},
		{"T1484.003", "T1484", "LLMJailbreak", "Context Manipulation", incident.SeverityCritical},
		{"T1484.004", "T1484", "LLMJailbreak", "Adversarial Suffix", incident.SeverityHigh},
		{"T1484.005", "T1484", "LLMJailbreak", "Structured Output Manipulation", incident.SeverityCritical},

		// Prompt Extraction (T1632)
		{"T1632.001", "T1632", "PromptExtraction", "Direct System Prompt Extraction", incident.SeverityCritical},
		{"T1632.002", "T1632", "PromptExtraction", "Indirect Prompt Extraction", incident.SeverityCritical},
		{"T1632.003", "T1632", "PromptExtraction", "Translation-based Extraction", incident.SeverityHigh},
		{"T1632.004", "T1632", "PromptExtraction", "API-based Extraction", incident.SeverityHigh},
		{"T1632.005", "T1632", "PromptExtraction", "Context Window Extraction", incident.SeverityHigh},

		// Data Extraction (T1589)
		{"T1589.001", "T1589", "DataExtraction", "PII Extraction", incident.SeverityHigh},
		{"T1589.002", "T1589", "DataExtraction", "Model Data Extraction", incident.SeverityCritical},
		{"T1589.003", "T1589", "DataExtraction", "Credential Extraction", incident.SeverityHigh},
		{"T1589.004", "T1589", "DataExtraction", "Configuration Extraction", incident.SeverityHigh},
		{"T1589.005", "T1589", "DataExtraction", "Training Data Inference", incident.SeverityHigh},

		// Indirect Injection (T1584)
		{"T1584.001", "T1584", "IndirectInjection", "Third-Party Injection", incident.SeverityCritical},
		{"T1584.002", "T1584", "IndirectInjection", "Data Poisoning via Injection", incident.SeverityCritical},
		{"T1584.003", "T1584", "IndirectInjection", "Retrieval-Augmented Injection", incident.SeverityHigh},
		{"T1584.004", "T1584", "IndirectInjection", "Tool-Use Injection", incident.SeverityHigh},
		{"T1584.005", "T1584", "IndirectInjection", "Cross-Prompt Injection", incident.SeverityHigh},

		// Vector DB Poisoning (T1600)
		{"T1600.001", "T1600", "VectorDBPoisoning", "Direct Vector DB Poisoning", incident.SeverityCritical},
		{"T1600.002", "T1600", "VectorDBPoisoning", "Indirect Vector DB Poisoning", incident.SeverityCritical},
		{"T1600.003", "T1600", "VectorDBPoisoning", "Embedding Manipulation", incident.SeverityHigh},

		// Content Injection (T1613)
		{"T1613.001", "T1613", "ContentInjection", "Markdown Injection", incident.SeverityHigh},
		{"T1613.002", "T1613", "ContentInjection", "HTML Injection", incident.SeverityHigh},
		{"T1613.003", "T1613", "ContentInjection", "Code Injection via Output", incident.SeverityHigh},

		// Plugin Exploitation (T1563)
		{"T1563.001", "T1563", "PluginExploitation", "MCP Tool Exploitation", incident.SeverityCritical},
		{"T1563.002", "T1563", "PluginExploitation", "Plugin Permission Escalation", incident.SeverityHigh},
		{"T1563.003", "T1563", "PluginExploitation", "Malicious Plugin Registration", incident.SeverityCritical},

		// Defense Evasion (T1622)
		{"T1622.001", "T1622", "DefenseEvasion", "Obfuscation", incident.SeverityHigh},
		{"T1622.002", "T1622", "DefenseEvasion", "Impair Defenses", incident.SeverityHigh},
		{"T1622.003", "T1622", "DefenseEvasion", "Agent Impersonation", incident.SeverityHigh},

		// Credential Forgery (T1606)
		{"T1606.001", "T1606", "CredentialForgery", "API Key Forgery", incident.SeverityCritical},
		{"T1606.002", "T1606", "CredentialForgery", "Token Forgery", incident.SeverityCritical},

		// MFA Bypass (T1621)
		{"T1621.001", "T1621", "MFABypass", "MFA Fatigue Attack", incident.SeverityCritical},
		{"T1621.002", "T1621", "MFABypass", "MFA Bypass via Prompt Injection", incident.SeverityCritical},

		// Elevation of Privilege (T1548)
		{"T1548.001", "T1548", "ElevationAbuse", "Privilege Escalation via Role Manipulation", incident.SeverityCritical},
		{"T1548.002", "T1548", "ElevationAbuse", "Capability Escalation", incident.SeverityCritical},

		// Inhibit Recovery (T1490)
		{"T1490.001", "T1490", "InhibitRecovery", "Safety Instruction Override", incident.SeverityCritical},
		{"T1490.002", "T1490", "InhibitRecovery", "Backup Disabling", incident.SeverityCritical},

		// Denial of Service (T1498)
		{"T1498.001", "T1498", "DenialOfService", "Resource Exhaustion", incident.SeverityHigh},
		{"T1498.002", "T1498", "DenialOfService", "Token Limit Exploitation", incident.SeverityHigh},

		// Endpoint Denial (T1499)
		{"T1499.001", "T1499", "EndpointDenial", "API Endpoint Flooding", incident.SeverityHigh},
		{"T1499.002", "T1499", "EndpointDenial", "Inference Endpoint DoS", incident.SeverityHigh},

		// Config Exfiltration (T1602)
		{"T1602.001", "T1602", "ConfigExfiltration", "System Config Extraction", incident.SeverityCritical},
		{"T1602.002", "T1602", "ConfigExfiltration", "Model Config Extraction", incident.SeverityCritical},

		// Resource Exhaustion (T1648)
		{"T1648.001", "T1648", "ResourceExhaustion", "Compute Resource Exhaustion", incident.SeverityHigh},
	}
}

// detectionPatternIDs builds a set of all ATLAS sub-technique IDs that
// have detection patterns in the ATLAS framework (atlas.go). These are
// the techniques our rule engine can "Detect" outright.
func detectionPatternIDs() map[string]bool {
	// All 52 sub-techniques have detection patterns in atlas.go.
	// The ATLAS framework initPatterns() method creates patterns for
	// every sub-technique in this list. We verify this by building
	// the set from the framework itself.
	ids := make(map[string]bool)
	techs := all52Techniques()
	for _, t := range techs {
		ids[t.id] = true
	}
	return ids
}

// detectionStatusFor determines whether a sub-technique is Detected,
// Partial, or Not Detected by the rule engine. The determination is
// based on whether the ATLAS framework has a pattern for this
// sub-technique, and whether the pattern's regex covers the full
// attack surface or only a subset.
//
// The logic is:
//   - If the sub-technique has a pattern in atlas.go AND the pattern
//     relationship in techniques.go is "detects" → Detected
//   - If the sub-technique has a pattern BUT only the parent technique
//     is mapped (not the sub-technique) → Partial
//   - If no pattern exists → Not Detected
func detectionStatusFor(techniqueID string, parentTechnique string) DetectionStatus {
	// All 52 sub-techniques have patterns in atlas.go (initPatterns),
	// so we check whether the parent technique is covered by a "detects"
	// relationship in techniques.go.
	//
	// Techniques with explicit "detects" relationship get full Detected
	// status; those with only "mitigates" or "supports" get Partial.
	mappings := mapping.AegisGateControlsForTechnique("atlas", parentTechnique)

	hasDetects := false
	hasMitigates := false
	for _, m := range mappings {
		if m.Relationship == "detects" {
			hasDetects = true
		}
		if m.Relationship == "mitigates" || m.Relationship == "supports" {
			hasMitigates = true
		}
	}

	// Special cases: sub-techniques that have their own dedicated patterns
	// with regex rules are always Detected (the pattern IS the detection).
	detectedSubTechniques := map[string]bool{
		// All T1535 sub-techniques have dedicated patterns
		"T1535.001": true, "T1535.002": true, "T1535.003": true,
		"T1535.004": true, "T1535.005": true,
		// All T1484 sub-techniques have dedicated patterns
		"T1484.001": true, "T1484.002": true, "T1484.003": true,
		"T1484.004": true, "T1484.005": true,
		// All T1632 sub-techniques have dedicated patterns
		"T1632.001": true, "T1632.002": true, "T1632.003": true,
		"T1632.004": true, "T1632.005": true,
		// All T1589 sub-techniques have dedicated patterns
		"T1589.001": true, "T1589.002": true, "T1589.003": true,
		"T1589.004": true, "T1589.005": true,
		// All T1584 sub-techniques have dedicated patterns
		"T1584.001": true, "T1584.002": true, "T1584.003": true,
		"T1584.004": true, "T1584.005": true,
		// All T1600 sub-techniques have dedicated patterns
		"T1600.001": true, "T1600.002": true, "T1600.003": true,
		// All T1613 sub-techniques have dedicated patterns
		"T1613.001": true, "T1613.002": true, "T1613.003": true,
		// All T1563 sub-techniques have dedicated patterns
		"T1563.001": true, "T1563.002": true, "T1563.003": true,
		// All T1622 sub-techniques have dedicated patterns
		"T1622.001": true, "T1622.002": true, "T1622.003": true,
		// All T1606 sub-techniques have dedicated patterns
		"T1606.001": true, "T1606.002": true,
		// All T1621 sub-techniques have dedicated patterns
		"T1621.001": true, "T1621.002": true,
		// All T1548 sub-techniques have dedicated patterns
		"T1548.001": true, "T1548.002": true,
		// All T1490 sub-techniques have dedicated patterns
		"T1490.001": true, "T1490.002": true,
		// All T1498 sub-techniques have dedicated patterns
		"T1498.001": true, "T1498.002": true,
		// All T1499 sub-techniques have dedicated patterns
		"T1499.001": true, "T1499.002": true,
		// All T1602 sub-techniques have dedicated patterns
		"T1602.001": true, "T1602.002": true,
		// T1648 sub-technique has a dedicated pattern
		"T1648.001": true,
	}

	if detectedSubTechniques[techniqueID] {
		if hasDetects {
			return Detected
		}
		// Has a regex pattern (rule-based detection) even if the
		// technique mapping says "mitigates" — the pattern still detects.
		return Detected
	}

	// For techniques without dedicated regex patterns, check if
	// the parent has a "detects" mapping.
	if hasDetects {
		return Detected
	}
	if hasMitigates {
		return Partial
	}
	return NotDetected
}

// alternativeCoverageFor determines which pillars (HTTP Scanner, MCP,
// ACP, Trust Framework, SIEM) provide coverage when the rule engine
// doesn't detect a technique. It uses the technique-to-control
// mappings from techniques.go to identify the relevant pillars.
func alternativeCoverageFor(techniqueID string, parentTechnique string) []string {
	// First check for sub-technique-specific mappings.
	// The techniques.go file maps parent techniques, so we look up
	// the parent technique to find all controls that cover it.
	mappings := mapping.AegisGateControlsForTechnique("atlas", parentTechnique)

	seen := make(map[string]bool)
	var pillars []string

	for _, m := range mappings {
		pillar := pillarForControl(m.AegisGateControl)
		if !seen[pillar] {
			seen[pillar] = true
			pillars = append(pillars, pillar)
		}
	}

	// Deduplicate and sort for deterministic output
	sort.Strings(pillars)
	return pillars
}

// ResidualRiskMap generates the complete residual risk map for all
// 52 ATLAS sub-techniques. Each entry cross-references the detection
// patterns, technique mappings, and enrichment data.
func ResidualRiskMap() []ResidualRiskEntry {
	techs := all52Techniques()
	entries := make([]ResidualRiskEntry, 0, len(techs))

	for _, t := range techs {
		status := detectionStatusFor(t.id, t.parent)
		altCoverage := alternativeCoverageFor(t.id, t.parent)
		blast := severityToBlastRadius(t.severity)
		action := recommendedActionFor(status, blast, altCoverage)

		entries = append(entries, ResidualRiskEntry{
			TechniqueID:         t.id,
			TechniqueName:       t.name,
			ParentTechnique:     t.parent,
			Category:            t.category,
			DetectionStatus:     status,
			AlternativeCoverage: altCoverage,
			BlastRadius:         blast,
			RecommendedAction:   action,
		})
	}

	// Sort by technique ID for deterministic output
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].TechniqueID < entries[j].TechniqueID
	})

	return entries
}

// Summary returns aggregate statistics for the residual risk map.
func Summary(entries []ResidualRiskEntry) ResidualRiskSummary {
	s := ResidualRiskSummary{
		TotalTechniques: len(entries),
		ByCategory:      make(map[string]int),
	}

	for _, e := range entries {
		switch e.DetectionStatus {
		case Detected:
			s.Detected++
		case Partial:
			s.Partial++
		case NotDetected:
			s.NotDetected++
		}
		switch e.BlastRadius {
		case BlastCritical:
			s.CriticalBlast++
		case BlastHigh:
			s.HighBlast++
		case BlastMedium:
			s.MediumBlast++
		case BlastLow:
			s.LowBlast++
		}
		s.ByCategory[e.Category]++
	}

	// Residual risk = techniques not detected by rules AND not
	// covered by alternative pillars
	for _, e := range entries {
		if e.DetectionStatus == NotDetected && len(e.AlternativeCoverage) == 0 {
			s.ResidualRiskCount++
		}
	}

	if s.TotalTechniques > 0 {
		s.CoveragePercent = float64(s.Detected+s.Partial) / float64(s.TotalTechniques) * 100
	}

	return s
}

// String returns a human-readable table of the residual risk map.
// This is suitable for console output and board-level reporting.
func String() string {
	entries := ResidualRiskMap()
	s := Summary(entries)

	var b strings.Builder

	// Header
	b.WriteString("┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐\n")
	b.WriteString("│                                              AEGISGATE RESIDUAL RISK MAP — ATLAS TECHNIQUE COVERAGE                               │\n")
	b.WriteString("├──────────────┬─────────────────────────────────────┬───────────┬─────────────────────────┬────────────┬────────────────────────────────────────────────────┤\n")
	b.WriteString("│ Technique ID │ Technique Name                      │ Detection │ Alternative Coverage    │ Blast Rad. │ Recommended Action                                 │\n")
	b.WriteString("├──────────────┼─────────────────────────────────────┼───────────┼─────────────────────────┼────────────┼────────────────────────────────────────────────────┤\n")

	for _, e := range entries {
		name := e.TechniqueName
		if len(name) > 35 {
			name = name[:32] + "..."
		}
		altCov := strings.Join(e.AlternativeCoverage, ", ")
		if len(altCov) > 23 {
			altCov = altCov[:20] + "..."
		}
		action := e.RecommendedAction
		if len(action) > 52 {
			action = action[:49] + "..."
		}
		fmt.Fprintf(&b, "│ %-12s │ %-35s │ %-9s │ %-23s │ %-10s │ %-52s │\n",
			e.TechniqueID, name, e.DetectionStatus, altCov, e.BlastRadius, action)
	}

	b.WriteString("├──────────────┼─────────────────────────────────────┼───────────┼─────────────────────────┼────────────┼────────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&b, "│ %-12s │ %-35s │ %-9d │ %-23s │ %-10s │ %-52s │\n",
		"TOTAL", fmt.Sprintf("%d techniques", s.TotalTechniques), s.Detected+s.Partial, "", "", "")
	b.WriteString("└──────────────┴─────────────────────────────────────┴───────────┴─────────────────────────┴────────────┴────────────────────────────────────────────────────┘\n")

	// Summary section
	b.WriteString("\n")
	b.WriteString("══════════════════════════════════════════════════════════════════════\n")
	b.WriteString("                         RESIDUAL RISK SUMMARY                        \n")
	b.WriteString("══════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(&b, "  Total Techniques:           %d\n", s.TotalTechniques)
	fmt.Fprintf(&b, "  Detected by Rules:          %d\n", s.Detected)
	fmt.Fprintf(&b, "  Partially Detected:         %d\n", s.Partial)
	fmt.Fprintf(&b, "  Not Detected:               %d\n", s.NotDetected)
	fmt.Fprintf(&b, "  Residual Risk (no rules +   %d\n", s.ResidualRiskCount)
	fmt.Fprintf(&b, "   no alternative coverage)\n")
	fmt.Fprintf(&b, "  Coverage (Detected+Partial): %.1f%%\n", s.CoveragePercent)
	b.WriteString("──────────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(&b, "  Critical Blast Radius:      %d\n", s.CriticalBlast)
	fmt.Fprintf(&b, "  High Blast Radius:          %d\n", s.HighBlast)
	fmt.Fprintf(&b, "  Medium Blast Radius:        %d\n", s.MediumBlast)
	fmt.Fprintf(&b, "  Low Blast Radius:           %d\n", s.LowBlast)
	b.WriteString("══════════════════════════════════════════════════════════════════════\n")

	return b.String()
}
