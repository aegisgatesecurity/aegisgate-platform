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
		ATLASPromptInjectionPlaybook(),
		ATLASLLMJailbreakPlaybook(),
		ATLASPromptExtractionPlaybook(),
		ATLASDataExtractionPlaybook(),
		ATLASIndirectInjectionPlaybook(),
		ATLASVectorDBPoisoningPlaybook(),
		ATLASContentInjectionPlaybook(),
		ATLASPluginExploitationPlaybook(),
		ATLASDefenseEvasionPlaybook(),
		ATLASElevationAbusePlaybook(),
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

// =====================================================================
// ATLAS Playbooks — MITRE ATLAS (Adversarial Threat Landscape
// for AI Systems) technique-to-response mapping playbooks.
// Each playbook maps to an ATLAS technique category and provides
// incident response procedures appropriate for AI-specific attacks.
// =====================================================================

// ATLASPromptInjectionPlaybook returns the ATLAS T1535 (Prompt
// Injection) playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Collects evidence
//  3. Blocks the offending agent
//  4. Creates an attestation envelope
func ATLASPromptInjectionPlaybook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_atlas_prompt_injection",
		Name: "ATLAS T1535 Prompt Injection Response",
		Description: "Automated incident response for ATLAS T1535 " +
			"Prompt Injection attacks. Handles notification, " +
			"evidence collection, agent blocking, and attestation.",
		Severity:    SeverityCritical,
		Source:      SourceCorrelation,
		Tags:        []string{"atlas", "T1535", "prompt-injection"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:   "atlas_t1535_step1_notify",
				Name: "Notify Security Team",
				Description: "Send critical-priority notification " +
					"about the detected prompt injection attack.",
				Action: "notify",
				Parameters: map[string]string{
					"recipients": "security@example.com",
					"priority":   "critical",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "atlas_t1535_step2_evidence",
				Name: "Collect Evidence",
				Description: "Gather forensic evidence of the " +
					"prompt injection attempt including full " +
					"request context.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "atlas_t1535_step3_block",
				Name: "Block Agent",
				Description: "Block the offending agent to prevent " +
					"further prompt injection attempts.",
				Action:     "block_agent",
				Parameters: map[string]string{},
				OnFailure:  "stop",
				Timeout:    1 * time.Minute,
				Required:   true,
			},
			{
				ID:   "atlas_t1535_step4_attestation",
				Name: "Create Attestation",
				Description: "Create a signed attestation envelope " +
					"linking the incident to the ATLAS audit trail.",
				Action: "create_attestation",
				Parameters: map[string]string{
					"framework": "ATLAS",
					"control":   "T1535",
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

// ATLASLLMJailbreakPlaybook returns the ATLAS T1484 (LLM Jailbreak)
// playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Collects evidence
//  3. Blocks the offending agent
//  4. Creates an attestation envelope
func ATLASLLMJailbreakPlaybook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_atlas_llm_jailbreak",
		Name: "ATLAS T1484 LLM Jailbreak Response",
		Description: "Automated incident response for ATLAS T1484 " +
			"LLM Jailbreak attacks. Handles notification, " +
			"evidence collection, agent blocking, and attestation.",
		Severity:    SeverityCritical,
		Source:      SourceCorrelation,
		Tags:        []string{"atlas", "T1484", "llm-jailbreak"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:   "atlas_t1484_step1_notify",
				Name: "Notify Security Team",
				Description: "Send critical-priority notification " +
					"about the detected LLM jailbreak attempt.",
				Action: "notify",
				Parameters: map[string]string{
					"recipients": "security@example.com",
					"priority":   "critical",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "atlas_t1484_step2_evidence",
				Name: "Collect Evidence",
				Description: "Gather forensic evidence of the " +
					"jailbreak attempt including conversation " +
					"context and adversarial patterns.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "atlas_t1484_step3_block",
				Name: "Block Agent",
				Description: "Block the offending agent to prevent " +
					"further jailbreak attempts.",
				Action:     "block_agent",
				Parameters: map[string]string{},
				OnFailure:  "stop",
				Timeout:    1 * time.Minute,
				Required:   true,
			},
			{
				ID:   "atlas_t1484_step4_attestation",
				Name: "Create Attestation",
				Description: "Create a signed attestation envelope " +
					"linking the incident to the ATLAS audit trail.",
				Action: "create_attestation",
				Parameters: map[string]string{
					"framework": "ATLAS",
					"control":   "T1484",
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

// ATLASPromptExtractionPlaybook returns the ATLAS T1632 (Prompt
// Extraction) playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Isolates the session
//  3. Collects evidence
//  4. Escalates for review
func ATLASPromptExtractionPlaybook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_atlas_prompt_extraction",
		Name: "ATLAS T1632 Prompt Extraction Response",
		Description: "Automated incident response for ATLAS T1632 " +
			"Prompt Extraction attacks. Handles notification, " +
			"session isolation, evidence collection, and escalation.",
		Severity:    SeverityCritical,
		Source:      SourceCorrelation,
		Tags:        []string{"atlas", "T1632", "prompt-extraction"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:   "atlas_t1632_step1_notify",
				Name: "Notify Security Team",
				Description: "Send critical-priority notification " +
					"about the detected prompt extraction attempt.",
				Action: "notify",
				Parameters: map[string]string{
					"recipients": "security@example.com",
					"priority":   "critical",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "atlas_t1632_step2_isolate",
				Name: "Isolate Session",
				Description: "Isolate the affected session to " +
					"prevent further prompt exfiltration.",
				Action:     "isolate_session",
				Parameters: map[string]string{},
				OnFailure:  "stop",
				Timeout:    1 * time.Minute,
				Required:   true,
			},
			{
				ID:   "atlas_t1632_step3_evidence",
				Name: "Collect Evidence",
				Description: "Gather forensic evidence of the " +
					"prompt extraction attempt including " +
					"exfiltration patterns.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "atlas_t1632_step4_escalate",
				Name: "Escalate",
				Description: "Escalate to senior security for " +
					"review of prompt extraction attack.",
				Action: "escalate",
				Parameters: map[string]string{
					"policy_id": "policy_atlas_t1632",
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

// ATLASDataExtractionPlaybook returns the ATLAS T1589 (Data
// Extraction) playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Isolates the session
//  3. Collects evidence
//  4. Escalates for review
func ATLASDataExtractionPlaybook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_atlas_data_extraction",
		Name: "ATLAS T1589 Data Extraction Response",
		Description: "Automated incident response for ATLAS T1589 " +
			"Data Extraction attacks. Handles notification, " +
			"session isolation, evidence collection, and escalation.",
		Severity:    SeverityCritical,
		Source:      SourceCorrelation,
		Tags:        []string{"atlas", "T1589", "data-extraction"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:   "atlas_t1589_step1_notify",
				Name: "Notify Security Team",
				Description: "Send critical-priority notification " +
					"about the detected data extraction attempt.",
				Action: "notify",
				Parameters: map[string]string{
					"recipients": "security@example.com",
					"priority":   "critical",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "atlas_t1589_step2_isolate",
				Name: "Isolate Session",
				Description: "Isolate the affected session to " +
					"prevent further data exfiltration.",
				Action:     "isolate_session",
				Parameters: map[string]string{},
				OnFailure:  "stop",
				Timeout:    1 * time.Minute,
				Required:   true,
			},
			{
				ID:   "atlas_t1589_step3_evidence",
				Name: "Collect Evidence",
				Description: "Gather forensic evidence of the " +
					"data extraction attempt including " +
					"exfiltration patterns.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "atlas_t1589_step4_escalate",
				Name: "Escalate",
				Description: "Escalate to senior security for " +
					"review of data extraction attack.",
				Action: "escalate",
				Parameters: map[string]string{
					"policy_id": "policy_atlas_t1589",
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

// ATLASIndirectInjectionPlaybook returns the ATLAS T1584 (Indirect
// Prompt Injection) playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Collects evidence
//  3. Blocks the offending agent
//  4. Creates an attestation envelope
func ATLASIndirectInjectionPlaybook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_atlas_indirect_injection",
		Name: "ATLAS T1584 Indirect Prompt Injection Response",
		Description: "Automated incident response for ATLAS T1584 " +
			"Indirect Prompt Injection attacks. Handles " +
			"notification, evidence collection, agent blocking, " +
			"and attestation.",
		Severity:    SeverityCritical,
		Source:      SourceCorrelation,
		Tags:        []string{"atlas", "T1584", "indirect-injection"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:   "atlas_t1584_step1_notify",
				Name: "Notify Security Team",
				Description: "Send critical-priority notification " +
					"about the detected indirect injection attack.",
				Action: "notify",
				Parameters: map[string]string{
					"recipients": "security@example.com",
					"priority":   "critical",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "atlas_t1584_step2_evidence",
				Name: "Collect Evidence",
				Description: "Gather forensic evidence of the " +
					"indirect injection attempt including " +
					"third-party source context.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "atlas_t1584_step3_block",
				Name: "Block Agent",
				Description: "Block the offending agent to prevent " +
					"further indirect injection attempts.",
				Action:     "block_agent",
				Parameters: map[string]string{},
				OnFailure:  "stop",
				Timeout:    1 * time.Minute,
				Required:   true,
			},
			{
				ID:   "atlas_t1584_step4_attestation",
				Name: "Create Attestation",
				Description: "Create a signed attestation envelope " +
					"linking the incident to the ATLAS audit trail.",
				Action: "create_attestation",
				Parameters: map[string]string{
					"framework": "ATLAS",
					"control":   "T1584",
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

// ATLASVectorDBPoisoningPlaybook returns the ATLAS T1600 (Vector DB
// Poisoning) playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Isolates the session
//  3. Collects evidence
//  4. Escalates for review
func ATLASVectorDBPoisoningPlaybook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_atlas_vector_db_poisoning",
		Name: "ATLAS T1600 Vector DB Poisoning Response",
		Description: "Automated incident response for ATLAS T1600 " +
			"Vector DB Poisoning attacks. Handles notification, " +
			"session isolation, evidence collection, and escalation.",
		Severity:    SeverityCritical,
		Source:      SourceCorrelation,
		Tags:        []string{"atlas", "T1600", "vector-db-poisoning"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:   "atlas_t1600_step1_notify",
				Name: "Notify Security Team",
				Description: "Send critical-priority notification " +
					"about the detected vector DB poisoning attack.",
				Action: "notify",
				Parameters: map[string]string{
					"recipients": "security@example.com",
					"priority":   "critical",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "atlas_t1600_step2_isolate",
				Name: "Isolate Session",
				Description: "Isolate the affected session to " +
					"prevent further knowledge base contamination.",
				Action:     "isolate_session",
				Parameters: map[string]string{},
				OnFailure:  "stop",
				Timeout:    1 * time.Minute,
				Required:   true,
			},
			{
				ID:   "atlas_t1600_step3_evidence",
				Name: "Collect Evidence",
				Description: "Gather forensic evidence of the " +
					"vector DB poisoning attempt including " +
					"RAG context and retrieval patterns.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "atlas_t1600_step4_escalate",
				Name: "Escalate",
				Description: "Escalate to senior security for " +
					"review of vector DB poisoning attack.",
				Action: "escalate",
				Parameters: map[string]string{
					"policy_id": "policy_atlas_t1600",
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

// ATLASContentInjectionPlaybook returns the ATLAS T1613 (Content
// Injection) playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Collects evidence
//  3. Runs a compliance check
//  4. Escalates if needed
func ATLASContentInjectionPlaybook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_atlas_content_injection",
		Name: "ATLAS T1613 Content Injection Response",
		Description: "Automated incident response for ATLAS T1613 " +
			"Content Injection attacks. Handles notification, " +
			"evidence collection, compliance check, and escalation.",
		Severity:    SeverityHigh,
		Source:      SourceCorrelation,
		Tags:        []string{"atlas", "T1613", "content-injection"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:   "atlas_t1613_step1_notify",
				Name: "Notify Security Team",
				Description: "Send high-priority notification " +
					"about the detected content injection attack.",
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
				ID:   "atlas_t1613_step2_evidence",
				Name: "Collect Evidence",
				Description: "Gather forensic evidence of the " +
					"content injection attempt including " +
					"output manipulation patterns.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "atlas_t1613_step3_compliance",
				Name: "Run Compliance Check",
				Description: "Validate ATLAS compliance controls " +
					"affected by the content injection.",
				Action: "run_compliance_check",
				Parameters: map[string]string{
					"framework": "ATLAS",
					"control":   "T1613",
				},
				OnFailure: "continue",
				Timeout:   1 * time.Minute,
				Required:  false,
			},
			{
				ID:   "atlas_t1613_step4_escalate",
				Name: "Escalate",
				Description: "Escalate to senior security for " +
					"review of content injection attack.",
				Action: "escalate",
				Parameters: map[string]string{
					"policy_id": "policy_atlas_t1613",
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

// ATLASPluginExploitationPlaybook returns the ATLAS T1563 (Plugin
// Exploitation) playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Collects evidence
//  3. Blocks the offending agent
//  4. Creates an attestation envelope
func ATLASPluginExploitationPlaybook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_atlas_plugin_exploitation",
		Name: "ATLAS T1563 Plugin Exploitation Response",
		Description: "Automated incident response for ATLAS T1563 " +
			"Plugin Exploitation attacks. Handles notification, " +
			"evidence collection, agent blocking, and attestation.",
		Severity:    SeverityCritical,
		Source:      SourceCorrelation,
		Tags:        []string{"atlas", "T1563", "plugin-exploitation"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:   "atlas_t1563_step1_notify",
				Name: "Notify Security Team",
				Description: "Send critical-priority notification " +
					"about the detected plugin exploitation attack.",
				Action: "notify",
				Parameters: map[string]string{
					"recipients": "security@example.com",
					"priority":   "critical",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "atlas_t1563_step2_evidence",
				Name: "Collect Evidence",
				Description: "Gather forensic evidence of the " +
					"plugin exploitation attempt including " +
					"plugin command logs.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "atlas_t1563_step3_block",
				Name: "Block Agent",
				Description: "Block the offending agent to prevent " +
					"further plugin exploitation attempts.",
				Action:     "block_agent",
				Parameters: map[string]string{},
				OnFailure:  "stop",
				Timeout:    1 * time.Minute,
				Required:   true,
			},
			{
				ID:   "atlas_t1563_step4_attestation",
				Name: "Create Attestation",
				Description: "Create a signed attestation envelope " +
					"linking the incident to the ATLAS audit trail.",
				Action: "create_attestation",
				Parameters: map[string]string{
					"framework": "ATLAS",
					"control":   "T1563",
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

// ATLASDefenseEvasionPlaybook returns the ATLAS T1622 (Defense
// Evasion) playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Collects evidence
//  3. Runs a compliance check
//  4. Escalates if needed
func ATLASDefenseEvasionPlaybook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_atlas_defense_evasion",
		Name: "ATLAS T1622 Defense Evasion Response",
		Description: "Automated incident response for ATLAS T1622 " +
			"Defense Evasion attacks. Handles notification, " +
			"evidence collection, compliance check, and escalation.",
		Severity:    SeverityHigh,
		Source:      SourceCorrelation,
		Tags:        []string{"atlas", "T1622", "defense-evasion"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:   "atlas_t1622_step1_notify",
				Name: "Notify Security Team",
				Description: "Send high-priority notification " +
					"about the detected defense evasion attack.",
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
				ID:   "atlas_t1622_step2_evidence",
				Name: "Collect Evidence",
				Description: "Gather forensic evidence of the " +
					"defense evasion attempt including " +
					"obfuscation patterns.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "atlas_t1622_step3_compliance",
				Name: "Run Compliance Check",
				Description: "Validate ATLAS compliance controls " +
					"affected by the defense evasion.",
				Action: "run_compliance_check",
				Parameters: map[string]string{
					"framework": "ATLAS",
					"control":   "T1622",
				},
				OnFailure: "continue",
				Timeout:   1 * time.Minute,
				Required:  false,
			},
			{
				ID:   "atlas_t1622_step4_escalate",
				Name: "Escalate",
				Description: "Escalate to senior security for " +
					"review of defense evasion attack.",
				Action: "escalate",
				Parameters: map[string]string{
					"policy_id": "policy_atlas_t1622",
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

// ATLASElevationAbusePlaybook returns the ATLAS T1548 (Elevation
// Abuse) playbook. This is a 4-step containment playbook that:
//  1. Notifies the security team
//  2. Collects evidence
//  3. Blocks the offending agent
//  4. Creates an attestation envelope
func ATLASElevationAbusePlaybook() *Playbook {
	now := time.Now().UTC()
	return &Playbook{
		ID:   "pb_atlas_elevation_abuse",
		Name: "ATLAS T1548 Elevation Abuse Response",
		Description: "Automated incident response for ATLAS T1548 " +
			"Elevation Abuse attacks. Handles notification, " +
			"evidence collection, agent blocking, and attestation.",
		Severity:    SeverityCritical,
		Source:      SourceCorrelation,
		Tags:        []string{"atlas", "T1548", "elevation-abuse"},
		AutoExecute: false,
		Steps: []*PlaybookStep{
			{
				ID:   "atlas_t1548_step1_notify",
				Name: "Notify Security Team",
				Description: "Send critical-priority notification " +
					"about the detected elevation abuse attack.",
				Action: "notify",
				Parameters: map[string]string{
					"recipients": "security@example.com",
					"priority":   "critical",
				},
				OnFailure: "continue",
				Timeout:   30 * time.Second,
				Required:  true,
			},
			{
				ID:   "atlas_t1548_step2_evidence",
				Name: "Collect Evidence",
				Description: "Gather forensic evidence of the " +
					"elevation abuse attempt including " +
					"privilege escalation patterns.",
				Action: "collect_evidence",
				Parameters: map[string]string{
					"include_timeline": "true",
				},
				OnFailure: "continue",
				Timeout:   2 * time.Minute,
				Required:  true,
			},
			{
				ID:   "atlas_t1548_step3_block",
				Name: "Block Agent",
				Description: "Block the offending agent to prevent " +
					"further elevation abuse attempts.",
				Action:     "block_agent",
				Parameters: map[string]string{},
				OnFailure:  "stop",
				Timeout:    1 * time.Minute,
				Required:   true,
			},
			{
				ID:   "atlas_t1548_step4_attestation",
				Name: "Create Attestation",
				Description: "Create a signed attestation envelope " +
					"linking the incident to the ATLAS audit trail.",
				Action: "create_attestation",
				Parameters: map[string]string{
					"framework": "ATLAS",
					"control":   "T1548",
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
