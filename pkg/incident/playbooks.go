// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Built-In Playbook Templates
// =========================================================================
//
// playbooks.go defines default incident response playbooks that map to
// compliance controls. These playbooks are registered at engine startup
// and provide out-of-the-box automated response capabilities.
//
// Each playbook follows a compliance framework's incident response
// requirements:
//
//   - FedRAMP IR-4: Incident Handling (4-step containment)
//   - FedRAMP IR-5: Incident Monitoring (observation + audit)
//   - SOC2 CC6.1: Security Incident Response (5-step containment)
//   - NIST 800-171 IR.1: Incident Response (4-step containment)
//
// v3.8 incident response automation.
// =========================================================================

package incident

import "time"

// DefaultPlaybooks returns the built-in playbook templates. These are
// registered at engine startup and can be overridden or extended by
// the user.
func DefaultPlaybooks() []*Playbook {
	return []*Playbook{
		FedRAMPIR4Playbook(),
		FedRAMPIR5Playbook(),
		SOC2CC61Playbook(),
		NIST800171IR1Playbook(),
	}
}

// FedRAMPIR4Playbook returns the FedRAMP IR-4 (Incident Handling)
// playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Collects evidence for audit
//  3. Blocks the offending agent
//  4. Creates an attestation envelope
func FedRAMPIR4Playbook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_fedramp_ir4",
		Name: "FedRAMP IR-4 Incident Handling",
		Description: "Automated incident response per FedRAMP IR-4 " +
			"control. Handles containment, evidence collection, and " +
			"attestation.",
		Severity:    SeverityHigh,
		Source:      SourceCorrelation,
		Tags:        []string{"fedramp", "ir-4", "incident-handling"},
		AutoExecute: false, // requires human approval for block
		Steps: []*PlaybookStep{
			{
				ID:   "ir4_step1_notify",
				Name: "Notify Security Team",
				Description: "Send notification to the security team " +
					"about the detected incident.",
				Action: "notify",
				Parameters: map[string]string{
					"recipients": "security@example.com",
					"priority":   "high",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "ir4_step2_evidence",
				Name: "Collect Evidence",
				Description: "Gather all evidence related to the " +
					"incident for forensic analysis and compliance " +
					"audit.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "ir4_step3_block",
				Name: "Block Agent",
				Description: "Block the offending agent to prevent " +
					"further damage.",
				Action:     "block_agent",
				Parameters: map[string]string{},
				OnFailure:  "stop", // stop if we can't block
				Timeout:    1 * time.Minute,
				Required:   true,
			},
			{
				ID:   "ir4_step4_attestation",
				Name: "Create Attestation",
				Description: "Create a signed attestation envelope " +
					"linking the incident to the audit trail.",
				Action: "create_attestation",
				Parameters: map[string]string{
					"framework": "FedRAMP",
					"control":   "IR-4",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  false,
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// FedRAMPIR5Playbook returns the FedRAMP IR-5 (Incident Monitoring)
// playbook. This is an observation + audit playbook that:
//  1. Notifies the monitoring team
//  2. Collects evidence
//  3. Runs a compliance check
func FedRAMPIR5Playbook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_fedramp_ir5",
		Name: "FedRAMP IR-5 Incident Monitoring",
		Description: "Automated incident monitoring per FedRAMP IR-5 " +
			"control. Observes, collects evidence, and validates " +
			"compliance controls.",
		Severity:    SeverityMedium,
		Source:      SourceCorrelation,
		Tags:        []string{"fedramp", "ir-5", "incident-monitoring"},
		AutoExecute: true, // safe to auto-execute (no blocking)
		Steps: []*PlaybookStep{
			{
				ID:   "ir5_step1_notify",
				Name: "Notify Monitoring Team",
				Description: "Send notification to the monitoring " +
					"team about the detected anomaly.",
				Action: "notify",
				Parameters: map[string]string{
					"recipients": "monitoring@example.com",
					"priority":   "medium",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "ir5_step2_evidence",
				Name: "Collect Evidence",
				Description: "Gather evidence for monitoring and " +
					"trend analysis.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "ir5_step3_compliance",
				Name: "Run Compliance Check",
				Description: "Validate compliance controls " +
					"affected by the incident.",
				Action: "run_compliance_check",
				Parameters: map[string]string{
					"framework": "FedRAMP",
					"control":   "IR-5",
				},
				OnFailure: "continue",
				Timeout:   1 * time.Minute,
				Required:  false,
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// SOC2CC61Playbook returns the SOC2 CC6.1 (Security Incident Response)
// playbook. This is a 5-step containment playbook that:
//  1. Notifies the security team
//  2. Isolates the session
//  3. Collects evidence
//  4. Creates an attestation
//  5. Escalates if needed
func SOC2CC61Playbook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_soc2_cc61",
		Name: "SOC2 CC6.1 Security Incident Response",
		Description: "Automated incident response per SOC2 CC6.1 " +
			"control. Handles isolation, evidence collection, " +
			"attestation, and escalation.",
		Severity:    SeverityHigh,
		Source:      SourceCorrelation,
		Tags:        []string{"soc2", "cc6.1", "security-incident"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:          "cc61_step1_notify",
				Name:        "Notify Security Team",
				Description: "Send high-priority notification.",
				Action:      "notify",
				Parameters: map[string]string{
					"recipients": "security@example.com",
					"priority":   "high",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "cc61_step2_isolate",
				Name: "Isolate Session",
				Description: "Isolate the affected session to " +
					"prevent lateral movement.",
				Action:     "isolate_session",
				Parameters: map[string]string{},
				OnFailure:  "stop",
				Timeout:    1 * time.Minute,
				Required:   true,
			},
			{
				ID:          "cc61_step3_evidence",
				Name:        "Collect Evidence",
				Description: "Gather forensic evidence.",
				Action:      "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "cc61_step4_attestation",
				Name: "Create Attestation",
				Description: "Create a signed attestation " +
					"envelope for SOC 2 audit.",
				Action: "create_attestation",
				Parameters: map[string]string{
					"framework": "SOC2",
					"control":   "CC6.1",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  false,
			},
			{
				ID:   "cc61_step5_escalate",
				Name: "Escalate",
				Description: "Escalate to senior security if " +
					"containment is not confirmed.",
				Action: "escalate",
				Parameters: map[string]string{
					"policy_id": "policy_soc2_cc61",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  false,
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// NIST800171IR1Playbook returns the NIST 800-171 IR.1 (Incident
// Response) playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Collects evidence
//  3. Blocks the offending agent
//  4. Creates an attestation envelope
func NIST800171IR1Playbook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_nist800171_ir1",
		Name: "NIST 800-171 IR.1 Incident Response",
		Description: "Automated incident response per NIST 800-171 " +
			"IR.1 control. Handles containment, evidence " +
			"collection, and attestation.",
		Severity:    SeverityMedium,
		Source:      SourceCorrelation,
		Tags:        []string{"nist", "800-171", "ir-1", "incident-response"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:   "ir1_step1_notify",
				Name: "Notify Security Team",
				Description: "Send notification about the detected " +
					"incident.",
				Action: "notify",
				Parameters: map[string]string{
					"recipients": "security@example.com",
					"priority":   "medium",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "ir1_step2_evidence",
				Name: "Collect Evidence",
				Description: "Gather evidence for incident " +
					"documentation.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:          "ir1_step3_block",
				Name:        "Block Agent",
				Description: "Block the offending agent.",
				Action:      "block_agent",
				Parameters:  map[string]string{},
				OnFailure:   "stop",
				Timeout:     1 * time.Minute,
				Required:    true,
			},
			{
				ID:   "ir1_step4_attestation",
				Name: "Create Attestation",
				Description: "Create a signed attestation " +
					"envelope.",
				Action: "create_attestation",
				Parameters: map[string]string{
					"framework": "NIST-800-171",
					"control":   "IR.1",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  false,
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}
