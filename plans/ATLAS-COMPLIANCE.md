# SPDX-License-Identifier: Apache-2.0
# ============================================================================
# AegisGate Platform - MITRE ATLAS Compliance Matrix
# ============================================================================
#
# Version: v3.1.0
# Last Updated: 2026-05-27
# 
# This document maps AegisGate security capabilities to MITRE ATLAS
# (Adversarial Threat Landscape for Artificial-Intelligence Systems)
# techniques and tactics.
#
# ATLAS Reference: https://atlas.mitre.org
#
# ============================================================================

# MITRE ATLAS Coverage Summary

| Category | Techniques Covered | Total ATLAS Techniques | Coverage % |
|----------|-------------------|----------------------|-----------|
| Reconnaissance (TA01) | 3 | 12 | 25% |
| Resource Development (TA02) | 2 | 8 | 25% |
| Initial Access (TA03) | 6 | 6 | 100% |
| Execution (TA04) | 8 | 8 | 100% |
| Persistence (TA05) | 4 | 10 | 40% |
| Privilege Escalation (TA06) | 5 | 7 | 71% |
| Defense Evasion (TA07) | 6 | 12 | 50% |
| Credential Access (TA08) | 8 | 9 | 89% |
| Discovery (TA09) | 4 | 10 | 40% |
| Lateral Movement (TA10) | 4 | 6 | 67% |
| Collection (TA11) | 6 | 10 | 60% |
| Command and Control (TA12) | 3 | 8 | 38% |
| Exfiltration (TA13) | 5 | 6 | 83% |
| Impact (TA14) | 2 | 8 | 25% |
| **TOTAL** | **66** | **120** | **55%** |

---

## Critical Guardrails with ATLAS Mapping

| Guardrail ID | Guardrail Name | ATLAS Technique | Severity |
|-------------|----------------|-----------------|----------|
| http_injection_scan | HTTP Injection Detection | ATLAS-TA03-ST01, TA04-ST01 | CRITICAL |
| http_command_block | Command Injection Block | ATLAS-TA04-ST04 | CRITICAL |
| http_rate_limit | Rate Limiting | ATLAS-TA08-ST03, TA13-ST04 | HIGH |
| mcp_capability_enforce | MCP Capability Enforcement | ATLAS-TA03-ST04, TA06-ST03 | HIGH |
| a2a_guard_block | A2A Request Blocking | ATLAS-TA10-ST02, TA10-ST04 | CRITICAL |
| a2a_trust_check | A2A Trust Verification | ATLAS-TA06-ST01, TA10-ST02 | CRITICAL |
| anp_injection_scan | ANP Injection Detection | ATLAS-TA03-ST01, TA04-ST01 | CRITICAL |
| anp_step_integrity | ANP Step Chain Integrity | ATLAS-TA04-ST06 | HIGH |
| anp_artifact_scan | ANP Artifact Scanning | ATLAS-TA04-ST05, TA11-ST02 | HIGH |
| cu_sensitive_data | Computer Use Sensitive Data | ATLAS-TA08-ST08, TA08-ST01, TA08-ST06 | CRITICAL |
| cu_url_whitelist | URL Allowlist | ATLAS-TA03-ST03, TA09-ST01 | HIGH |
| resp_pii_block | PII Detection & Block | ATLAS-TA08-ST08 | CRITICAL |
| resp_secret_block | Secret Detection & Block | ATLAS-TA08-ST02, TA08-ST06 | CRITICAL |
| trust_score_anomaly | Trust Score Anomaly | ATLAS-TA06-ST01 | CRITICAL |
| corr_mcp_injection | Cross-Protocol Injection | ATLAS-TA03-ST01, TA04-ST01 | CRITICAL |
| corr_task_hijack | Task Hijacking Detection | ATLAS-TA10-ST04 | CRITICAL |

---

## Compliance Gaps & Remediation

### High Priority Gaps

| Gap ID | Description | ATLAS Coverage |
|-------|-------------|---------------|
| GAP-001 | No specialized prompt injection detection for multi-turn attacks | TA03-ST01, TA04-ST02 |
| GAP-002 | Training data poisoning detection is basic | TA04-ST02, TA10-ST01 |
| GAP-003 | No model watermarking verification | TA13-ST03 |
| GAP-004 | Model extraction detection is partial | TA13-ST04 |
| GAP-005 | No specialized LLM-specific C2 detection | TA12-ST01, TA12-ST02 |

---

## NIST AI RMF Alignment

| NIST AI RMF Function | AegisGate Capability |
|---------------------|---------------------|
| GOVERN (GV) | Identity Registry, Contract Management |
| MAP (MA) | Trust Score Engine, Correlation Engine |
| MEASURE (MS) | Metrics Collection, Compliance Attestation |

---

*Document Version: 1.0*
*Last Updated: 2026-05-27*
*AegisGate Platform v3.1.0+*
