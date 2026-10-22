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
//   - artex_rapid_recon (rapid multi-endpoint reconnaissance)
//   - artex_credential_spray (credential spraying via API credentials)
//   - artex_multi_agent_coord (multi-agent attack coordination)
//   - artex_ai_accelerated (AI-accelerated lateral movement)
//   - artex_graph_anomaly (Microsoft Graph API anomalies)
//
// v3.8 incident response automation.
// v4.8.0 ARTEX behavioral detection (Black October 2026).
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
		// ARTEX behavioral rules (Black October 2026)
		ARTEXRapidReconRule(),
		ARTEXCredentialSprayRule(),
		ARTEXMultiAgentCoordRule(),
		ARTEXAIAcceleratedRule(),
		ARTEXGraphAnomalyRule(),
	}
}

// MCPErrorInjectionRule detects MCP error injection patterns.
// Maps to FedRAMP IR-4 (Incident Handling) and SOC2 CC6.1.
func MCPErrorInjectionRule() *DetectionRule {
	return &DetectionRule{
		ID:   "rule_mcp_error_injection",
		Name: "MCP Error Injection",
		Description: "MCP error followed by A2A request — indicates " +
			"potential prompt injection or error manipulation " +
			"attack across MCP and A2A protocol boundaries.",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityHigh,
		Patterns:    []string{"mcp_error_injection"},
		EventTypes:  []string{"error", "request"},
		MinEvents:   1,
		TimeWindow:  30 * 1e9, // 30 seconds (in nanoseconds for Duration)
		PlaybookID:  "pb_fedramp_ir4",
		AutoCreate:  true,
		AutoExecute: false, // requires human approval for block step
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "FedRAMP",
				ControlID:   "IR-4",
				ControlName: "Incident Handling",
				Relevance:   "MCP error injection triggers incident handling procedures",
			},
			{
				Framework:   "SOC2",
				ControlID:   "CC6.1",
				ControlName: "Security Incident Response",
				Relevance:   "Cross-protocol attack requires security incident response",
			},
		},
	}
}

// TaskHijackingRule detects task hijacking patterns where an A2A
// message triggers ANP task creation. Maps to FedRAMP IR-4 and
// SOC2 CC6.1.
func TaskHijackingRule() *DetectionRule {
	return &DetectionRule{
		ID:   "rule_task_hijacking",
		Name: "Task Hijacking",
		Description: "A2A message triggers ANP task creation — " +
			"indicates potential task hijacking where an agent " +
			"delegates unauthorized actions through the A2A protocol.",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityCritical,
		Patterns:    []string{"task_hijacking"},
		EventTypes:  []string{"message", "task_create"},
		MinEvents:   1,
		TimeWindow:  60 * 1e9, // 1 minute
		PlaybookID:  "pb_soc2_cc61",
		AutoCreate:  true,
		AutoExecute: true, // critical severity auto-executes
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "FedRAMP",
				ControlID:   "IR-4",
				ControlName: "Incident Handling",
				Relevance:   "Task hijacking requires immediate containment",
			},
			{
				Framework:   "SOC2",
				ControlID:   "CC6.1",
				ControlName: "Security Incident Response",
				Relevance:   "Task hijacking is a high-severity security incident",
			},
		},
	}
}

// BrowserEscalationRule detects browser escalation patterns where
// ANP task enables browser control. Maps to FedRAMP IR-4, SOC2
// CC6.1, and NIST 800-171 IR.1.
func BrowserEscalationRule() *DetectionRule {
	return &DetectionRule{
		ID:   "rule_browser_escalation",
		Name: "Browser Escalation",
		Description: "ANP task enables browser control — indicates " +
			"potential privilege escalation from ANP task creation " +
			"to computer-use capabilities.",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityCritical,
		Patterns:    []string{"browser_escalation"},
		EventTypes:  []string{"task", "computer_use"},
		MinEvents:   1,
		TimeWindow:  120 * 1e9, // 2 minutes
		PlaybookID:  "pb_soc2_cc61",
		AutoCreate:  true,
		AutoExecute: true, // critical severity auto-executes
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "FedRAMP",
				ControlID:   "IR-4",
				ControlName: "Incident Handling",
				Relevance:   "Browser escalation requires immediate containment",
			},
			{
				Framework:   "SOC2",
				ControlID:   "CC6.1",
				ControlName: "Security Incident Response",
				Relevance:   "Privilege escalation is a critical security incident",
			},
			{
				Framework:   "NIST-800-171",
				ControlID:   "IR.1",
				ControlName: "Incident Response",
				Relevance:   "Privilege escalation triggers incident response procedures",
			},
		},
	}
}

// RateAnomalyRule detects coordinated attacks across protocols.
// Maps to FedRAMP IR-5 (Incident Monitoring).
func RateAnomalyRule() *DetectionRule {
	return &DetectionRule{
		ID:   "rule_rate_anomaly",
		Name: "Rate Anomaly",
		Description: "Coordinated attack across protocols — unusual " +
			"rate of events from a single agent indicates potential " +
			"reconnaissance or brute-force activity.",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityHigh,
		Patterns:    []string{"rate_anomaly"},
		EventTypes:  []string{"request", "error", "block"},
		MinEvents:   3,
		TimeWindow:  60 * 1e9, // 1 minute
		PlaybookID:  "pb_fedramp_ir5",
		AutoCreate:  true,
		AutoExecute: true, // monitoring playbook is safe to auto-execute
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "FedRAMP",
				ControlID:   "IR-5",
				ControlName: "Incident Monitoring",
				Relevance:   "Rate anomaly triggers monitoring and observation procedures",
			},
		},
	}
}

// CapabilityCreepRule detects agents using more capabilities over
// time. Maps to NIST 800-171 IR.1 (Incident Response).
func CapabilityCreepRule() *DetectionRule {
	return &DetectionRule{
		ID:   "rule_capability_creep",
		Name: "Capability Creep",
		Description: "Agent uses more capabilities over time — " +
			"indicates gradual privilege escalation or compromised " +
			"agent expanding its access.",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityMedium,
		Patterns:    []string{"capability_creep"},
		EventTypes:  []string{"capability_change"},
		MinEvents:   2,
		TimeWindow:  600 * 1e9, // 10 minutes
		PlaybookID:  "pb_nist800171_ir1",
		AutoCreate:  true,
		AutoExecute: false, // medium severity, needs triage first
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "NIST-800-171",
				ControlID:   "IR.1",
				ControlName: "Incident Response",
				Relevance:   "Capability creep triggers incident response review",
			},
		},
	}
}

// ============================================================================
// ARTEX BEHAVIORAL DETECTION RULES (Black October 2026)
//
// These rules map ARTEX-specific correlation patterns to incidents.
// Source: Zscaler ThreatLabz + Microsoft Threat Intelligence (Oct 2026)
//
// ARTEX is an open-source AI autonomous pentesting framework (Go + Next.js)
// used by Storm-0940 and multiple threat groups. It automates reconnaissance,
// credential attacks, and lateral movement via multi-agent LLM coordination.
//
// These rules detect ARTEX-like behavioral patterns in Platform's
// correlation engine, triggering incident response and compliance mappings.
// ============================================================================

// ARTEXRapidReconRule detects rapid multi-endpoint reconnaissance
// consistent with ARTEX framework usage. Storm-0940 hit 2,900 auth
// attempts/minute across 327 accounts in 8 organizations.
// Maps to NIST CSF DE.AE-2 (Detection Processes) and MITRE ATLAS T0029.
func ARTEXRapidReconRule() *DetectionRule {
	return &DetectionRule{
		ID:   "rule_artex_rapid_recon",
		Name: "ARTEX Rapid Reconnaissance",
		Description: "Rapid multi-endpoint probing detected — " +
			"AI-accelerated reconnaissance pattern consistent with " +
			"ARTEX autonomous pentesting framework.",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityHigh,
		Patterns:    []string{"artex_rapid_recon"},
		EventTypes:  []string{"request", "probe", "scan"},
		MinEvents:   2,
		TimeWindow:  60 * 1e9, // 60 seconds
		PlaybookID:  "pb_fedramp_ir5",
		AutoCreate:  true,
		AutoExecute: false, // needs triage — could be legitimate load testing
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "NIST-CSF",
				ControlID:   "DE.AE-2",
				ControlName: "Detection Processes",
				Relevance:   "Rapid reconnaissance triggers detection and analysis processes",
			},
			{
				Framework:   "MITRE-ATLAS",
				ControlID:   "T0029",
				ControlName: "Reconnaissance",
				Relevance:   "ARTEX automates ML model reconnaissance per ATLAS T0029",
			},
		},
	}
}

// ARTEXCredentialSprayRule detects credential spraying via API
// credentials. Storm-0940 observed 151,000+ failed sign-in attempts.
// Maps to FedRAMP IR-4, SOC2 CC6.1, and NIST CSF DE.AE-3.
func ARTEXCredentialSprayRule() *DetectionRule {
	return &DetectionRule{
		ID:   "rule_artex_credential_spray",
		Name: "ARTEX Credential Spraying",
		Description: "Automated credential spraying via application " +
			"credentials — password attack pattern consistent with " +
			"ARTEX framework and Storm-0940 campaign.",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityCritical,
		Patterns:    []string{"artex_credential_spray"},
		EventTypes:  []string{"auth_failure", "credential_attack", "error"},
		MinEvents:   2,
		TimeWindow:  300 * 1e9, // 5 minutes
		PlaybookID:  "pb_soc2_cc61",
		AutoCreate:  true,
		AutoExecute: true, // critical — auto-block the attacking agent
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "FedRAMP",
				ControlID:   "IR-4",
				ControlName: "Incident Handling",
				Relevance:   "Credential spraying requires immediate containment",
			},
			{
				Framework:   "SOC2",
				ControlID:   "CC6.1",
				ControlName: "Security Incident Response",
				Relevance:   "Automated credential attack is a critical security incident",
			},
			{
				Framework:   "NIST-CSF",
				ControlID:   "DE.AE-3",
				ControlName: "Detection Processes",
				Relevance:   "Credential spraying triggers intrusion detection and analysis",
			},
		},
	}
}

// ARTEXMultiAgentCoordRule detects multi-agent coordination where
// multiple agents perform different attack phases (recon, exploit,
// data access). Zscaler confirmed GLM reviewed DeepSeek's subagent work.
// Maps to NIST CSF DE.AE-2 and MITRE ATLAS T0050.
func ARTEXMultiAgentCoordRule() *DetectionRule {
	return &DetectionRule{
		ID:   "rule_artex_multi_agent_coord",
		Name: "ARTEX Multi-Agent Coordination",
		Description: "Multiple agents coordinating attack phases across " +
			"protocols — reconnaissance, exploitation, and data access " +
			"consistent with ARTEX multi-agent LLM framework.",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityHigh,
		Patterns:    []string{"artex_multi_agent_coord"},
		EventTypes:  []string{"coordination", "handoff", "message"},
		MinEvents:   2,
		TimeWindow:  600 * 1e9, // 10 minutes
		PlaybookID:  "pb_soc2_cc61",
		AutoCreate:  true,
		AutoExecute: false, // needs triage — could be legitimate multi-agent workflow
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "NIST-CSF",
				ControlID:   "DE.AE-2",
				ControlName: "Detection Processes",
				Relevance:   "Multi-agent coordination triggers detection analysis",
			},
			{
				Framework:   "MITRE-ATLAS",
				ControlID:   "T0050",
				ControlName: "ML Attack Staging",
				Relevance:   "Multi-agent coordination for attack staging per ATLAS T0050",
			},
		},
	}
}

// ARTEXAIAcceleratedRule detects AI-accelerated attack progression.
// Storm-0940 went from initial targeting to privileged cloud access
// in under 3 hours — impossibly fast for human-operated attacks.
// Maps to NIST CSF DE.AE-4 and FedRAMP IR-5.
func ARTEXAIAcceleratedRule() *DetectionRule {
	return &DetectionRule{
		ID:   "rule_artex_ai_accelerated",
		Name: "ARTEX AI-Accelerated Attack",
		Description: "Rapid lateral movement and privilege escalation " +
			"— attack progression faster than human-operated, " +
			"consistent with AI-accelerated ARTEX framework.",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityMedium,
		Patterns:    []string{"artex_ai_accelerated"},
		EventTypes:  []string{"lateral_movement", "privilege_escalation"},
		MinEvents:   2,
		TimeWindow:  10800 * 1e9, // 3 hours
		PlaybookID:  "pb_fedramp_ir5",
		AutoCreate:  true,
		AutoExecute: false, // medium — needs investigation to confirm AI acceleration
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "NIST-CSF",
				ControlID:   "DE.AE-4",
				ControlName: "Detection Processes",
				Relevance:   "AI-accelerated attack triggers behavioral anomaly detection",
			},
			{
				Framework:   "FedRAMP",
				ControlID:   "IR-5",
				ControlName: "Incident Monitoring",
				Relevance:   "Rapid lateral movement triggers enhanced monitoring",
			},
		},
	}
}

// ARTEXGraphAnomalyRule detects Microsoft Graph API anomalies —
// reconnaissance queries, OAuth app registrations, and credential
// changes in close succession. Storm-0940 used these techniques
// against M365 tenants.
// Maps to NIST CSF DE.AE-2 and SOC2 CC6.1.
func ARTEXGraphAnomalyRule() *DetectionRule {
	return &DetectionRule{
		ID:   "rule_artex_graph_anomaly",
		Name: "ARTEX Graph API Anomaly",
		Description: "Microsoft Graph API anomalies — reconnaissance " +
			"queries followed by OAuth app registration or credential " +
			"changes, consistent with Storm-0940 / ARTEX campaign.",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityHigh,
		Patterns:    []string{"artex_graph_anomaly"},
		EventTypes:  []string{"graph_recon", "oauth_registration", "credential_change"},
		MinEvents:   2,
		TimeWindow:  1800 * 1e9, // 30 minutes
		PlaybookID:  "pb_soc2_cc61",
		AutoCreate:  true,
		AutoExecute: false, // needs triage — could be legitimate admin activity
		ComplianceMappings: []ComplianceMapping{
			{
				Framework:   "NIST-CSF",
				ControlID:   "DE.AE-2",
				ControlName: "Detection Processes",
				Relevance:   "Graph API anomalies trigger detection and analysis",
			},
			{
				Framework:   "SOC2",
				ControlID:   "CC6.1",
				ControlName: "Security Incident Response",
				Relevance:   "OAuth registration after recon is a high-severity security incident",
			},
		},
	}
}
