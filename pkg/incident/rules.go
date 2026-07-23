// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Built-In Detection Rules
// =========================================================================
//
// rules.go defines default detection rules that map correlation
// patterns to incidents. These rules are registered at engine
// startup and provide out-of-the-box automated detection.
//
// Each rule maps a correlation pattern to:
//   - An incident severity
//   - A compliance framework mapping
//   - An optional playbook for automated response
//
// The rules reference pattern IDs from pkg/correlation/engine.go:
//   - mcp_error_injection (MCP error followed by A2A request)
//   - task_hijacking (A2A message triggers ANP task creation)
//   - browser_escalation (ANP task enables browser control)
//   - rate_anomaly (coordinated attack across protocols)
//   - capability_creep (agent uses more capabilities over time)
//
// v3.8 incident response automation.
// =========================================================================

package incident

// DefaultDetectionRules returns the built-in detection rules. These
// map correlation engine patterns to incident types and compliance
// controls.
func DefaultDetectionRules() []*DetectionRule {
	return []*DetectionRule{
		MCPErrorInjectionRule(),
		TaskHijackingRule(),
		BrowserEscalationRule(),
		RateAnomalyRule(),
		CapabilityCreepRule(),
	}
}

// MCPErrorInjectionRule detects MCP error injection patterns.
// Maps to FedRAMP IR-4 (Incident Handling) and SOC2 CC6.1.
func MCPErrorInjectionRule() *DetectionRule {
	return &DetectionRule{
		ID:          "rule_mcp_error_injection",
		Name:        "MCP Error Injection",
		Description: "MCP error followed by A2A request — indicates " +
			"potential prompt injection or error manipulation " +
			"attack across MCP and A2A protocol boundaries.",
		Enabled:     true,
		Source:       SourceCorrelation,
		Severity:     SeverityHigh,
		Patterns:     []string{"mcp_error_injection"},
		EventTypes:   []string{"error", "request"},
		MinEvents:    1,
		TimeWindow:   30 * 1e9, // 30 seconds (in nanoseconds for Duration)
		PlaybookID:   "pb_fedramp_ir4",
		AutoCreate:  true,
		AutoExecute: false, // requires human approval for block step
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "FedRAMP",
				ControlID:  "IR-4",
				ControlName: "Incident Handling",
				Relevance:  "MCP error injection triggers incident handling procedures",
			},
			{
				Framework:   "SOC2",
				ControlID:  "CC6.1",
				ControlName: "Security Incident Response",
				Relevance:  "Cross-protocol attack requires security incident response",
			},
		},
	}
}

// TaskHijackingRule detects task hijacking patterns where an A2A
// message triggers ANP task creation. Maps to FedRAMP IR-4 and
// SOC2 CC6.1.
func TaskHijackingRule() *DetectionRule {
	return &DetectionRule{
		ID:          "rule_task_hijacking",
		Name:        "Task Hijacking",
		Description: "A2A message triggers ANP task creation — " +
			"indicates potential task hijacking where an agent " +
			"delegates unauthorized actions through the A2A protocol.",
		Enabled:     true,
		Source:       SourceCorrelation,
		Severity:     SeverityCritical,
		Patterns:     []string{"task_hijacking"},
		EventTypes:   []string{"message", "task_create"},
		MinEvents:    1,
		TimeWindow:   60 * 1e9, // 1 minute
		PlaybookID:   "pb_soc2_cc61",
		AutoCreate:  true,
		AutoExecute: true, // critical severity auto-executes
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "FedRAMP",
				ControlID:  "IR-4",
				ControlName: "Incident Handling",
				Relevance:  "Task hijacking requires immediate containment",
			},
			{
				Framework:   "SOC2",
				ControlID:  "CC6.1",
				ControlName: "Security Incident Response",
				Relevance:  "Task hijacking is a high-severity security incident",
			},
		},
	}
}

// BrowserEscalationRule detects browser escalation patterns where
// ANP task enables browser control. Maps to FedRAMP IR-4, SOC2
// CC6.1, and NIST 800-171 IR.1.
func BrowserEscalationRule() *DetectionRule {
	return &DetectionRule{
		ID:          "rule_browser_escalation",
		Name:        "Browser Escalation",
		Description: "ANP task enables browser control — indicates " +
			"potential privilege escalation from ANP task creation " +
			"to computer-use capabilities.",
		Enabled:     true,
		Source:       SourceCorrelation,
		Severity:     SeverityCritical,
		Patterns:     []string{"browser_escalation"},
		EventTypes:   []string{"task", "computer_use"},
		MinEvents:    1,
		TimeWindow:   120 * 1e9, // 2 minutes
		PlaybookID:   "pb_soc2_cc61",
		AutoCreate:  true,
		AutoExecute: true, // critical severity auto-executes
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "FedRAMP",
				ControlID:  "IR-4",
				ControlName: "Incident Handling",
				Relevance:  "Browser escalation requires immediate containment",
			},
			{
				Framework:   "SOC2",
				ControlID:  "CC6.1",
				ControlName: "Security Incident Response",
				Relevance:  "Privilege escalation is a critical security incident",
			},
			{
				Framework:   "NIST-800-171",
				ControlID:  "IR.1",
				ControlName: "Incident Response",
				Relevance:  "Privilege escalation triggers incident response procedures",
			},
		},
	}
}

// RateAnomalyRule detects coordinated attacks across protocols.
// Maps to FedRAMP IR-5 (Incident Monitoring).
func RateAnomalyRule() *DetectionRule {
	return &DetectionRule{
		ID:          "rule_rate_anomaly",
		Name:        "Rate Anomaly",
		Description: "Coordinated attack across protocols — unusual " +
			"rate of events from a single agent indicates potential " +
			"reconnaissance or brute-force activity.",
		Enabled:     true,
		Source:       SourceCorrelation,
		Severity:     SeverityHigh,
		Patterns:     []string{"rate_anomaly"},
		EventTypes:   []string{"request", "error", "block"},
		MinEvents:    3,
		TimeWindow:   60 * 1e9, // 1 minute
		PlaybookID:   "pb_fedramp_ir5",
		AutoCreate:  true,
		AutoExecute: true, // monitoring playbook is safe to auto-execute
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "FedRAMP",
				ControlID:  "IR-5",
				ControlName: "Incident Monitoring",
				Relevance:  "Rate anomaly triggers monitoring and observation procedures",
			},
		},
	}
}

// CapabilityCreepRule detects agents using more capabilities over
// time. Maps to NIST 800-171 IR.1 (Incident Response).
func CapabilityCreepRule() *DetectionRule {
	return &DetectionRule{
		ID:          "rule_capability_creep",
		Name:        "Capability Creep",
		Description: "Agent uses more capabilities over time — " +
			"indicates gradual privilege escalation or compromised " +
			"agent expanding its access.",
		Enabled:     true,
		Source:       SourceCorrelation,
		Severity:     SeverityMedium,
		Patterns:     []string{"capability_creep"},
		EventTypes:   []string{"capability_change"},
		MinEvents:    2,
		TimeWindow:   600 * 1e9, // 10 minutes
		PlaybookID:   "pb_nist800171_ir1",
		AutoCreate:  true,
		AutoExecute: false, // medium severity, needs triage first
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "NIST-800-171",
				ControlID:  "IR.1",
				ControlName: "Incident Response",
				Relevance:  "Capability creep triggers incident response review",
			},
		},
	}
}