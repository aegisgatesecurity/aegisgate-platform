// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Compliance Mapping Helpers
// =========================================================================
//
// compliance_mapping.go provides helpers for mapping incidents to
// compliance controls. The mapping is based on:
//   - The correlation patterns that triggered the incident
//   - The incident source (correlation, SOC, auto-rule, API)
//   - The incident severity
//
// Supported frameworks:
//   - FedRAMP (NIST SP 800-53 Rev. 5) — IR family
//   - SOC 2 (AICPA Trust Services Criteria) — CC family
//   - NIST SP 800-171 — IR family
//   - ISO 27001 — A.16 (Information Security Incident Management)
//
// v3.8 incident response automation.
// =========================================================================

package incident

// MapToCompliance maps an incident's source and patterns to compliance
// controls. It uses the built-in pattern-to-control mappings for
// FedRAMP, SOC2, NIST 800-171, and ISO 27001.
//
// If no patterns match, it returns a generic mapping based on the
// incident source.
func MapToCompliance(source IncidentSource, patterns []string) []ComplianceMapping {
	mappings := make([]ComplianceMapping, 0)

	seen := make(map[string]bool)

	for _, pattern := range patterns {
		if m, ok := fedrampIRMappings[pattern]; ok {
			key := m.Framework + ":" + m.ControlID
			if !seen[key] {
				mappings = append(mappings, m)
				seen[key] = true
			}
		}
		if m, ok := soc2Mappings[pattern]; ok {
			key := m.Framework + ":" + m.ControlID
			if !seen[key] {
				mappings = append(mappings, m)
				seen[key] = true
			}
		}
		if m, ok := nist171Mappings[pattern]; ok {
			key := m.Framework + ":" + m.ControlID
			if !seen[key] {
				mappings = append(mappings, m)
				seen[key] = true
			}
		}
		if m, ok := iso27001Mappings[pattern]; ok {
			key := m.Framework + ":" + m.ControlID
			if !seen[key] {
				mappings = append(mappings, m)
				seen[key] = true
			}
		}
	}

	// If no pattern-specific mappings, add a generic mapping
	// based on the incident source.
	if len(mappings) == 0 {
		mappings = append(mappings, defaultMappingForSource(source))
	}

	return mappings
}

// defaultMappingForSource returns a generic compliance mapping based
// on the incident source.
func defaultMappingForSource(source IncidentSource) ComplianceMapping {
	switch source {
	case SourceCorrelation:
		return ComplianceMapping{
			Framework:   "FedRAMP",
			ControlID:  "IR-4",
			ControlName: "Incident Handling",
			Relevance:   "Correlation engine detected threat pattern",
		}
	case SourceAutoRule:
		return ComplianceMapping{
			Framework:   "FedRAMP",
			ControlID:  "IR-5",
			ControlName: "Incident Monitoring",
			Relevance:   "Automated detection rule triggered",
		}
	case SourceSOC:
		return ComplianceMapping{
			Framework:   "SOC2",
			ControlID:  "CC6.1",
			ControlName: "Security Incident Response",
			Relevance:   "SOC analyst created incident",
		}
	default:
		return ComplianceMapping{
			Framework:   "FedRAMP",
			ControlID:  "IR-4",
			ControlName: "Incident Handling",
			Relevance:   "External incident report",
		}
	}
}

// =====================================================================
// FedRAMP IR Family Mappings
// =====================================================================

var fedrampIRMappings = map[string]ComplianceMapping{
	"mcp_error_injection": {
		Framework:   "FedRAMP",
		ControlID:  "IR-4",
		ControlName: "Incident Handling",
		Relevance:   "MCP error injection triggers incident handling",
	},
	"task_hijacking": {
		Framework:   "FedRAMP",
		ControlID:  "IR-4",
		ControlName: "Incident Handling",
		Relevance:   "Task hijacking requires immediate containment",
	},
	"browser_escalation": {
		Framework:   "FedRAMP",
		ControlID:  "IR-4",
		ControlName: "Incident Handling",
		Relevance:   "Browser escalation requires containment",
	},
	"rate_anomaly": {
		Framework:   "FedRAMP",
		ControlID:  "IR-5",
		ControlName: "Incident Monitoring",
		Relevance:   "Rate anomaly triggers monitoring procedures",
	},
	"capability_creep": {
		Framework:   "FedRAMP",
		ControlID:  "IR-6",
		ControlName: "Incident Reporting",
		Relevance:   "Capability creep requires reporting",
	},
}

// =====================================================================
// SOC 2 Mappings
// =====================================================================

var soc2Mappings = map[string]ComplianceMapping{
	"mcp_error_injection": {
		Framework:   "SOC2",
		ControlID:  "CC6.1",
		ControlName: "Security Incident Response",
		Relevance:   "Cross-protocol attack requires security incident response",
	},
	"task_hijacking": {
		Framework:   "SOC2",
		ControlID:  "CC6.1",
		ControlName: "Security Incident Response",
		Relevance:   "Task hijacking is a high-severity security incident",
	},
	"browser_escalation": {
		Framework:   "SOC2",
		ControlID:  "CC6.1",
		ControlName: "Security Incident Response",
		Relevance:   "Privilege escalation is a critical security incident",
	},
	"rate_anomaly": {
		Framework:   "SOC2",
		ControlID:  "CC6.3",
		ControlName: "Security Event Monitoring",
		Relevance:   "Rate anomaly triggers event monitoring",
	},
	"capability_creep": {
		Framework:   "SOC2",
		ControlID:  "CC6.3",
		ControlName: "Security Event Monitoring",
		Relevance:   "Capability creep triggers access monitoring",
	},
}

// =====================================================================
// NIST SP 800-171 Mappings
// =====================================================================

var nist171Mappings = map[string]ComplianceMapping{
	"mcp_error_injection": {
		Framework:   "NIST-800-171",
		ControlID:  "IR.1",
		ControlName: "Incident Response",
		Relevance:   "MCP error injection triggers incident response",
	},
	"task_hijacking": {
		Framework:   "NIST-800-171",
		ControlID:  "IR.1",
		ControlName: "Incident Response",
		Relevance:   "Task hijacking requires incident response",
	},
	"browser_escalation": {
		Framework:   "NIST-800-171",
		ControlID:  "IR.1",
		ControlName: "Incident Response",
		Relevance:   "Privilege escalation triggers incident response",
	},
	"rate_anomaly": {
		Framework:   "NIST-800-171",
		ControlID:  "IR.2",
		ControlName: "Incident Response Training",
		Relevance:   "Rate anomaly informs incident response procedures",
	},
	"capability_creep": {
		Framework:   "NIST-800-171",
		ControlID:  "IR.1",
		ControlName: "Incident Response",
		Relevance:   "Capability creep triggers incident response review",
	},
}

// =====================================================================
// ISO 27001 Mappings
// =====================================================================

var iso27001Mappings = map[string]ComplianceMapping{
	"mcp_error_injection": {
		Framework:   "ISO27001",
		ControlID:  "A.16.1.1",
		ControlName: "Responsibilities and Procedures",
		Relevance:   "MCP error injection triggers incident management",
	},
	"task_hijacking": {
		Framework:   "ISO27001",
		ControlID:  "A.16.1.1",
		ControlName: "Responsibilities and Procedures",
		Relevance:   "Task hijacking triggers incident management",
	},
	"browser_escalation": {
		Framework:   "ISO27001",
		ControlID:  "A.16.1.2",
		ControlName: "Reporting Information Security Events",
		Relevance:   "Browser escalation requires immediate reporting",
	},
	"rate_anomaly": {
		Framework:   "ISO27001",
		ControlID:  "A.16.1.4",
		ControlName: "Assessment of Information Security Events",
		Relevance:   "Rate anomaly triggers event assessment",
	},
	"capability_creep": {
		Framework:   "ISO27001",
		ControlID:  "A.16.1.7",
		ControlName: "Collection of Evidence",
		Relevance:   "Capability creep requires evidence collection",
	},
}