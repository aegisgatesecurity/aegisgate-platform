# AICM v1.1 Control Mapping Reference Implementation
## AegisGate Security Platform → Cloud Security Alliance AI Controls Matrix

**Contributor:** AegisGate Security, LLC  
**Platform Version:** v4.4.1  
**Date:** September 2026  
**AICM Version:** v1.1.1 (generated 2026-07-22)  
**License:** Apache 2.0 (open-source platform)  
**Status:** Draft for CSA AI Safety Working Group review

### Methodology

Mapping was performed by extracting all 247 AICM v1.1.1 controls from the official CSA Excel spreadsheet and evaluating each against AegisGate's source code (Go, 401K LOC across 60+ packages). Controls were classified as **Full** (AegisGate directly implements the control's requirements), **Partial** (AegisGate contributes to but does not fully satisfy the control), or **Not Applicable** (organizational/physical controls outside software scope). Each mapping includes specific package paths and function references as implementation evidence.

---

## 1. Executive Summary

This document maps the Cloud Security Alliance's AI Controls Matrix (AICM) v1.1 — 247 controls across 18 domains — to the AegisGate Security Platform, an open-source AI security gateway proxy. AegisGate inspects, detects, and governs AI traffic across five protocols (MCP, A2A, ACP, ANP, HTTP) using a three-layer detection pipeline (regex, ATLAS, machine learning) and a comprehensive response guard (PII, secrets, toxicity, hallucination, token limiting).

**Mapping Results:**

| Relevance | Count | Percentage | Description |
|-----------|-------|------------|-------------|
| Full | 66 | 27% | AegisGate directly implements the control |
| Partial | 77 | 31% | AegisGate contributes to the control |
| Not Applicable | 104 | 42% | Organizational/physical controls outside software scope |
| **Total Relevant** | **143** | **58%** | **Full + Partial** |

Of the 143 relevant controls (those applicable to a software-based AI security proxy), AegisGate fully addresses 66 and partially addresses 77.

## 2. AegisGate Platform Overview

AegisGate is an AI security gateway that sits between AI applications and AI model providers, inspecting all traffic in transit. It is NOT a cloud infrastructure provider, HR system, physical security tool, or endpoint management solution — so controls in those domains are marked "Not Applicable."

### Core Capabilities

| Capability | Implementation | AICM Domains Addressed |
|------------|---------------|----------------------|
| **3-Layer Detection Pipeline** | L1: 216 regex patterns; L2: MITRE ATLAS threat detection; L3: CharCNN-BiLSTM ML classifier (ONNX, 2-5M parameters, <1ms CPU inference) | AIS, DSP, MDS, TVM, LOG |
| **Response Guard** | PII scanner, secret detector, toxicity filter, hallucination detector, token limiter, redactor | AIS, DSP, LOG |
| **Multi-Protocol Inspection** | MCP, A2A, ACP, ANP, HTTP — all with dedicated guards | AIS, IPY, LOG |
| **Agent RBAC** | 4 agent roles (restricted→admin), 4 user roles (viewer→admin), tool authorization risk matrix with approval workflow | IAM, AIS, GRC |
| **Guardrails** | Rate limiting, session limits, tool limits, stdio validation, parameter constraints | AIS, GRC, TVM |
| **Compliance Engine** | 31 frameworks with automated cross-mapping (73KB framework mapping engine), OPA policy engine, compliance gating | GRC, A&A |
| **Audit & Evidence** | RFC 5424 syslog, SOC 2 audit automation, tamper-evident attestation envelopes, legal hold | LOG, A&A, SEF |
| **AI Bill of Materials (AIBOM)** | CycloneDX 1.6 SBOM extended for AI: models, RAG corpora, MCP servers, A2A agents, ACP capabilities, ANP tasks. Fully implemented generator, signing (ECDSA P-256), and verification. v0.1 requires explicit struct population; auto-discovery from live config planned for v0.2 | STA, DSP, MDS |
| **Incident Management** | Incident engine with playbooks, rules, ATLAS enrichment, SOAR integration | SEF, TVM |
| **Anomaly Detection** | Entropy analysis, frequency analysis, tokenizer, anomaly scoring | LOG, TVM, MDS |
| **Model Security** | Adversarial robustness testing (PGD/FGSM), evasion resistance, drift detection, signature verification | MDS, TVM |
| **SSO & Authentication** | SAML 2.0, OIDC, JWKS key rotation, session management | IAM |
| **Data Privacy** | DSAR (GDPR), PII redaction, data provenance via AIBOM | DSP |
| **Vendor Risk** | Vendor risk assessment module, supply chain security via AIBOM | STA |

## 3. Domain-by-Domain Mapping Summary

### High Relevance Domains (AegisGate core strength)

| Domain | Controls | Full | Partial | N/A | Key AegisGate Features |
|--------|----------|------|---------|-----|----------------------|
| **Logging & Monitoring (LOG)** | 16 | 12 | 3 | 1 | RFC 5424 syslog, audit trail, anomaly detection, input/output monitoring |
| **Model Security (MDS)** | 13 | 8 | 5 | 0 | Adversarial testing, AIBOM, attestation, drift detection, signature verification |
| **Identity & Access Mgmt (IAM)** | 18 | 10 | 7 | 1 | 4 agent + 4 user roles, tool auth matrix, SSO (SAML/OIDC), agent access restriction |
| **Threat & Vuln Mgmt (TVM)** | 13 | 6 | 7 | 0 | 216 patterns + ATLAS + ML, guardrails, CVE feed, incident response with ATLAS enrichment |
| **Data Security & Privacy (DSP)** | 24 | 8 | 12 | 4 | PII scanner, secret detector, redactor, AIBOM data provenance, DSAR, data poisoning detection |
| **Application & Interface (AIS)** | 15 | 7 | 7 | 1 | Input/output validation, agent security boundaries, API security, prompt differentiation |

### Medium Relevance Domains

| Domain | Controls | Full | Partial | N/A | Key AegisGate Features |
|--------|----------|------|---------|-----|----------------------|
| **Supply Chain Mgmt (STA)** | 16 | 3 | 7 | 6 | AIBOM (AI Bill of Materials), vendor risk module, supply chain inventory |
| **Security Incident (SEF)** | 10 | 4 | 4 | 2 | Incident engine, playbooks, SOAR, ATLAS enrichment, legal hold |
| **Governance, Risk & Compliance (GRC)** | 15 | 4 | 7 | 4 | 31 compliance frameworks, regulatory mapping, AI impact assessment, human supervision |
| **Audit & Assurance (A&A)** | 6 | 1 | 5 | 0 | Compliance verification, SOC 2 audit automation, evidence collection |
| **Change Control (CCC)** | 9 | 1 | 4 | 4 | Baseline deviation detection, anomaly detection, ML drift |
| **Infrastructure Security (I&S)** | 9 | 1 | 3 | 5 | Multi-tenancy segmentation, network defense for AI traffic |
| **Interoperability (IPY)** | 4 | 1 | 1 | 2 | 5 protocol support, signature verification, attestation |

### Not Applicable Domains (Organizational/Physical)

| Domain | Controls | N/A | Reason |
|--------|----------|-----|--------|
| **Datacenter Security (DCS)** | 18 | 18 | Physical security — AegisGate is software |
| **Human Resources (HRS)** | 15 | 15 | HR controls — background checks, training, NDAs |
| **Business Continuity (BCR)** | 11 | 11 | BCP/DR — organizational resilience planning |
| **Universal Endpoint Mgmt (UEM)** | 14 | 13 | Endpoint management — OS-level controls |
| **Cryptography & Key Mgmt (CEK)** | 21 | 17 | KMS/HSM — key lifecycle management (4 partial for data protection/monitoring) |

## 4. AI-Specific Control Coverage

AICM v1.1 introduces 32 **AI-Specific** controls (vs. "Cloud & AI Related" or "Cloud-Specific"). AegisGate addresses all 32:

| Control ID | Title | Relevance | AegisGate Implementation |
|------------|-------|-----------|------------------------|
| AIS-11 | Agents Security Boundaries | **Full** | 4 agent roles + tool auth risk matrix + guardrails |
| AIS-13 | AI Sandboxing | **Partial** | MCP guardrails (session/tool/rate limits), prompt cache isolation |
| AIS-14 | AI Cache Protection | **Partial** | Prompt cache verification, response guard prevents cache poisoning |
| AIS-15 | Prompt Differentiation | **Full** | L1/L2/L3 detection pipeline distinguishes legitimate from adversarial prompts |
| DSP-21 | Data Poisoning Prevention & Detection | **Full** | L1 regex (atlas_poison) detects poisoning instructions in prompts; L2 ATLAS detects poisoning techniques (T1584); L3 ML includes poisoning vocabulary; incident enrichment categorizes vector DB poisoning — inference-time detection, not training-dataset inspection |
| DSP-22 | Privacy Enhancing Technologies | **Partial** | PII redaction, token limiting, prompt cache normalization |
| DSP-23 | Data Integrity Check | **Full** | Attestation envelopes, MCP signature verification, AIBOM signing |
| DSP-24 | Data Differentiation and Relevance | **Full** | Multi-layer detection pipeline + response guard filter |
| GRC-09 | Acceptable Use of the AI Service | **Full** | Guardrails enforce usage policies, RBAC restricts capabilities |
| GRC-10 | AI Impact Assessment | **Full** | Detection pipeline + AI-specific compliance frameworks (NIST AI RMF, ISO 42001, EU AI Act) |
| GRC-11 | Bias and Fairness Assessment | **Partial** | Ingress: L1 (atlas_bias_injection) detects bias injection attacks; L3 ML trained on bias injection samples. Compliance: 5+ frameworks (EU AI Act, HITRUST, FFIEC, SOC 2, NIST) include bias controls. Egress: no dedicated bias/fairness output detector |
| GRC-12 | Ethics Committee | **N/A** | Organizational governance structure |
| GRC-13 | Explainability Requirement | **Partial** | Every security decision records matched pattern, threat type, severity, block reason. FrameworkRefCache cross-references detections to ATLAS, NIST AI RMF, OWASP LLM, CWE, CVE. Explains proxy decisions, not AI model reasoning |
| GRC-14 | Explainability Evaluation | **Partial** | Evidence packages include per-control pass/fail, reason, remediation, references. Implements explainability controls for TSA-SD, FFIEC, EU AI Act. Evaluates proxy decisions, not AI model reasoning |
| GRC-15 | Human Supervision | **Full** | Tool auth requires human approval for high-risk operations |
| HRS-14 | AI Competency Training | **N/A** | Organizational training control |
| HRS-15 | AI Acceptable Use | **N/A** | Organizational HR policy |
| LOG-15 | Input Monitoring | **Full** | L1 (216 regex) + L2 (ATLAS) + L3 (ML) monitor all AI inputs |
| LOG-16 | Output Monitoring | **Full** | Response guard (PII/secrets/toxicity/hallucination) monitors all AI outputs |
| MDS-02 | Model Artifact Scanning | **Full** | AIBOM + signature verification |
| MDS-03 | Model Documentation | **Full** | AIBOM generates CycloneDX 1.6-compliant model documentation (provider, model ID, version). v0.1: operator-supplied; v0.2 auto-discovers |
| MDS-04 | Model Documentation Requirements | **Full** | AIBOM includes model type, provider, version, SHA-256 hashes for prompts and RAG corpora. v0.1: explicit registration; v0.2 wires to live config |
| MDS-05 | Model Documentation Validation | **Partial** | Attestation envelopes verify documentation integrity |
| MDS-06 | Adversarial Attack Analysis | **Full** | PGD/FGSM testing, ATLAS, detection patterns |
| MDS-07 | Robustness Against Adversarial Attack | **Full** | Adversarial robustness + evasion resistance testing |
| MDS-08 | Model Integrity Checks | **Full** | Attestation envelopes (tamper-evident, ECDSA P-256), AIBOM signing (pkg/aibom/sign.go), MCP signature verification |
| MDS-09 | Model Signing/Ownership Verification | **Full** | Attestation envelopes sign with ECDSA P-256; AIBOM includes ownership metadata (issuer, key ID); verify.go validates identity |
| MDS-11 | Model Failure | **Partial** | Anomaly detection, incident engine, SOAR |
| MDS-12 | Open Model Risk Assessment | **Partial** | Detection pipeline + AIBOM provenance |
| STA-09 | Service Bill of Material (BOM) | **Full** | AIBOM = CycloneDX 1.6 SBOM extended for AI. Generator, signer, verifier all implemented. v0.1: explicit struct population; v0.2: auto-discovery |
| TVM-04 | Threat Analysis and Modelling | **Full** | MITRE ATLAS implementation |
| TVM-13 | Guardrails | **Full** | Comprehensive guardrail system (rate/session/tool limits, RBAC, tool auth, response guard) |

**AI-Specific control score: 20 Full, 9 Partial, 3 N/A = 29 of 32 directly relevant.**

## 5. Implementation Patterns Relevant to the Community

The following patterns from AegisGate's mapping may be useful to other organizations implementing AICM controls. These are shared as reference patterns, not as the only valid approach:

1. **AI Bill of Materials (AIBOM) Pattern** — CycloneDX 1.6 SBOM extended for AI components (STA-08, STA-09, MDS-03/04). Generator (pkg/aibom/generator.go, 18 functions), cryptographic signing (pkg/aibom/sign.go), and verification (pkg/aibom/verify.go). v0.1 requires explicit struct population; auto-discovery from live config planned for v0.2. Organizations implementing AI supply chain transparency may find this CycloneDX extension useful as a starting point.

2. **Multi-Protocol Inspection Pattern** — 5 AI protocols (MCP, A2A, ACP, ANP, HTTP) with dedicated guards (IPY-02, AIS-08). As AI protocols proliferate beyond HTTP, organizations may need to inspect non-HTTP AI traffic — this pattern demonstrates per-protocol guard architecture.

3. **Agent-Specific RBAC Pattern** — Role-based access control designed for AI agents, not just human users (IAM-18, AIS-11). 4 agent roles with tool authorization risk matrix. Organizations adopting AI agents may find this pattern useful for controlling agent capabilities.

4. **AI-Specific Threat Modeling Pattern** — MITRE ATLAS implementation (TVM-04) with 216 detection patterns. Organizations building AI threat detection can use ATLAS as a structured threat model, as we did.

5. **Adversarial Robustness Testing Pattern** — PGD/FGSM testing (MDS-06/07) validates that detection models resist adversarial evasion. This pattern may be useful for organizations that need to validate their own AI security tooling against adversarial attacks.

6. **Data Poisoning Detection Pattern** — Multi-layer pipeline (L1/L2/L3) for inference-time data poisoning detection (DSP-21). This approach may help organizations that need to detect poisoning attempts without inspecting training datasets.

7. **Prompt Differentiation Pattern** — Defense-in-depth pipeline distinguishes legitimate from adversarial prompts (AIS-15). This pattern may be useful for organizations that need to differentiate between benign and malicious AI inputs.

8. **Model Drift Monitoring Pattern** — Continuous ML drift detection (MDS-10) identifies model degradation. Organizations deploying ML-based detection may find this pattern useful for maintaining detection accuracy over time.

## 6. Cross-Reference to Existing Framework Mappings

AegisGate already maps to 31 compliance frameworks. The AICM mapping is particularly strong where it overlaps with these existing mappings:

| Existing Framework | AegisGate Module | AICM Domain Overlap |
|-------------------|-----------------|---------------------|
| NIST AI RMF | `pkg/compliance/nist_ai_rmf` | GRC, MDS, TVM, DSP |
| ISO 42001 | `pkg/compliance/iso42001` | GRC, A&A, MDS |
| EU AI Act | `pkg/compliance/eu_ai_act` | GRC, DSP, MDS |
| SOC 2 | `pkg/compliance/soc2` | A&A, LOG, SEF |
| NIST CSF | `pkg/compliance/nist_csf` | TVM, LOG, IAM, I&S |
| ISO 27001 | `pkg/compliance/iso27001` | IAM, LOG, I&S, CEK |
| HIPAA | `pkg/compliance/hipaa` | DSP, LOG, SEF |
| PCI DSS | `pkg/compliance/pci` | DSP, LOG, IAM |
| GDPR | `pkg/compliance/community/gdpr` | DSP, GRC |
| CCPA | `pkg/compliance/ccpa` | DSP, GRC |
| CSA STAR (CCM v4) | `pkg/compliance/csa_star` | All 16 CCM domains |

The AICM mapping extends the existing CSA STAR (CCM v4) module by adding AI-specific controls not present in the original CCM.

### AICM Scope Applicability Overlap

The AICM v1.1 spreadsheet includes a "Scope Applicability" tab that maps AICM controls to five external frameworks: AIUC-1, BSI AI C4, EU AI Act, ISO 42001, and NIST AI RMF. AegisGate already implements three of these five frameworks (EU AI Act, ISO 42001, NIST AI RMF) as compliance modules with automated `CheckFunc` implementations. This means the AICM-to-AegisGate mapping is reinforced by existing framework-to-framework mappings — controls that the AICM itself cross-references to these frameworks are already covered by AegisGate's compliance engine.

## 7. Gaps and Limitations

AegisGate does **not** address the following AICM controls (marked N/A):

- **Physical/Datacenter Security (DCS, 18 controls):** AegisGate is software-only
- **Human Resources (HRS, 15 controls):** Background checks, NDAs, training are organizational
- **Business Continuity (BCR, 11 controls):** BCP/DR planning is organizational
- **Endpoint Management (UEM, 13 controls):** OS-level device management
- **Key Management (CEK, 17 of 21 controls):** KMS/HSM lifecycle management
- **Organizational Governance (4 GRC controls):** Ethics committee, policy reviews, special interest groups
- **Contractual Controls (4 STA controls):** Service agreements, contract reviews

These gaps are inherent to AegisGate's scope as an AI security proxy — they would be addressed by the deploying organization's broader security program, not by a single tool.

## 8. Recommendation for CSA AI Safety WG

This mapping demonstrates that a purpose-built AI security gateway can address a significant portion of the AICM (143 of 247 controls, 58%) — including 20 of 32 AI-specific controls fully (29 of 32 relevant). The remaining 104 N/A controls are organizational/physical and require broader security program coverage.

**Context:** A review of the public ecosystem found framework-to-framework crosswalks (AICM → ISO 42001, NIST SP 800-53, AIUC-1) and domain-level mappings, but no per-control vendor-product-to-AICM mappings. This appears to be the first public, per-control product mapping. If others exist, we welcome pointers to compare methodologies.

**Suggested contributions to the CSA AI Safety Working Group:**

1. **Crosswalk spreadsheet** (`aicm-aegisgate-crosswalk.csv`) — complete 247-control mapping with implementation evidence
2. **Reference implementation patterns** — how a proxy-based architecture addresses AI-specific controls (AIS-11, AIS-15, DSP-21, TVM-13)
3. **AIBOM as STA-08/STA-09 implementation** — CycloneDX extension for AI supply chain transparency
4. **Agent RBAC pattern for IAM-18** — role-based access control designed for AI agents
5. **Guardrail taxonomy for TVM-13** — multi-layer guardrail approach (rate limiting, tool auth, response guard)

---

*This document and the accompanying crosswalk CSV are open-source (Apache 2.0) and available for community use. The AegisGate platform source code is at https://github.com/aegisgatesecurity/aegisgate-platform.*