# SPDX-License-Identifier: Apache-2.0
# =========================================================================
# AegisGate Platform - EU AI Act Control Mapping (v3.3.0 Phase 1.2)
# =========================================================================
#
# Version: 1.0 (v3.3.0)
# Last Updated: 2026-06-06
# Authoritative Source: Regulation (EU) 2024/1689 of the European Parliament
# and of the Council (the 'EU AI Act')
#
# This document is the internal 'we are experts' mapping of AegisGate's
# EU AI Act compliance coverage. It complements the customer-facing
# 1-pager at docs/compliance/eu-ai-act.md.
#
# Per-control entries are ordered by category, then by control ID. Each
# row contains: control ID, name, category, severity, Article reference,
# whether AegisGate can auto-check it, the Go check function name (if any),
# and the evidence type a customer/auditor would supply.
#
# AegisGate module metadata (founder-locked 2026-06-06):
#   - Framework ID:  eu_ai_act
#   - Version:       1.0
#   - Required tier: Professional+
#   - Monthly price: $99/mo
#   - Module:        pkg/compliance/eu-ai-act/
#
# =========================================================================

## Summary

| Category | Article | Controls | Automated | Manual |
|----------|---------|---------:|----------:|-------:|
| Prohibited Practices | various | 8 | 0 | 8 |
| Risk Management | various | 10 | 1 | 9 |
| Data Governance | various | 8 | 0 | 8 |
| Technical Documentation | various | 5 | 1 | 4 |
| Record Keeping | various | 5 | 1 | 4 |
| Transparency | various | 8 | 1 | 7 |
| Human Oversight | various | 6 | 1 | 5 |
| Accuracy and Robustness | various | 12 | 2 | 10 |
| GPAI Models | various | 10 | 0 | 10 |
| AI Controls | various | 10 | 1 | 9 |
| **Total** | | **82** | **8** | **74** |

---

## Per-Control Mapping

> Each control is implemented in `pkg/compliance/eu-ai-act/controls.go`
> via a `m.RegisterControl(compliance.ControlDefinition{...})` call. Automated
> controls have a `CheckFunc` pointing at a `checkXxx` method in
> `eu_ai_act.go`; manual controls are auditor-verified.

| Control ID | Name | Category | Severity | Article | Automated | Check Function |
|------------|------|----------|----------|---------|-----------|----------------|
| EUAIAct-Art5-001 | Subliminal Manipulation Techniques | Prohibited Practices | Critical | 5(1)(a) | No | manual review |
| EUAIAct-Art5-002 | Exploitation of Vulnerabilities | Prohibited Practices | Critical | 5(1)(b) | No | manual review |
| EUAIAct-Art5-003 | Social Scoring by Public Authorities | Prohibited Practices | Critical | 5(1)(c) | No | manual review |
| EUAIAct-Art5-004 | Real-Time Remote Biometric Identification | Prohibited Practices | Critical | 5(1)(h) | No | manual review |
| EUAIAct-Art5-005 | Predictive Policing Individual Risk | Prohibited Practices | Critical | 5(1)(d) | No | manual review |
| EUAIAct-Art5-006 | Untargeted Scraping of Facial Images | Prohibited Practices | Critical | 5(1)(e) | No | manual review |
| EUAIAct-Art5-007 | Emotion Recognition in Workplace/Education | Prohibited Practices | Critical | 5(1)(f) | No | manual review |
| EUAIAct-Art5-008 | Biometric Categorization of Sensitive Attributes | Prohibited Practices | Critical | 5(1)(g) | No | manual review |
| EUAIAct-Art9-001 | Risk Management System Established | Risk Management | Critical | 9(1) | Yes | `checkRiskManagement` |
| EUAIAct-Art9-002 | Risk Identification and Analysis | Risk Management | Critical | 9(2)(a) | No | manual review |
| EUAIAct-Art9-003 | Risk Estimation and Evaluation | Risk Management | Critical | 9(2)(b) | No | manual review |
| EUAIAct-Art9-004 | Risk Mitigation Measures | Risk Management | Critical | 9(2)(c) | No | manual review |
| EUAIAct-Art9-005 | Testing Procedures for Mitigation | Risk Management | Critical | 9(2)(d) | No | manual review |
| EUAIAct-Art9-006 | Continuous Monitoring and Review | Risk Management | Critical | 9(2)(e) | No | manual review |
| EUAIAct-Art9-007 | Iteration Throughout Lifecycle | Risk Management | Critical | 9(3) | No | manual review |
| EUAIAct-Art9-008 | Integration with Quality Management | Risk Management | Critical | 9(4) | No | manual review |
| EUAIAct-Art9-009 | Documentation of Known Risks | Risk Management | Critical | 9(5) | No | manual review |
| EUAIAct-Art9-010 | Residual Risk Acceptability | Risk Management | Critical | 9(6) | No | manual review |
| EUAIAct-Art10-001 | Training Data Quality and Relevance | Data Governance | High | 10(1) | No | manual review |
| EUAIAct-Art10-002 | Data Governance and Management | Data Governance | High | 10(2) | No | manual review |
| EUAIAct-Art10-003 | Bias Examination and Mitigation | Data Governance | High | 10(2)(a) | No | manual review |
| EUAIAct-Art10-004 | Data Preparation and Processing | Data Governance | High | 10(2)(b) | No | manual review |
| EUAIAct-Art10-005 | Dataset Representativeness | Data Governance | High | 10(3) | No | manual review |
| EUAIAct-Art10-006 | Statistical Properties of Datasets | Data Governance | High | 10(4) | No | manual review |
| EUAIAct-Art10-007 | Possible Biases Identification | Data Governance | High | 10(5) | No | manual review |
| EUAIAct-Art10-008 | Data Provenance and Lineage | Data Governance | High | 10(6) | No | manual review |
| EUAIAct-Art11-001 | Technical Documentation Before Market | Technical Documentation | High | 11(1) | Yes | `checkTechnicalDocumentation` |
| EUAIAct-Art11-002 | System Characteristics Documentation | Technical Documentation | High | 11(1)(a) | No | manual review |
| EUAIAct-Art11-003 | Design Specifications | Technical Documentation | High | 11(1)(b) | No | manual review |
| EUAIAct-Art11-004 | Development Process Documentation | Technical Documentation | High | 11(1)(c) | No | manual review |
| EUAIAct-Art11-005 | Intended Purpose Documentation | Technical Documentation | High | 11(1)(d) | No | manual review |
| EUAIAct-Art12-001 | Automatic Logging Capabilities | Record Keeping | High | 12(1) | Yes | `checkRecordKeeping` |
| EUAIAct-Art12-002 | Log Traceability | Record Keeping | High | 12(2) | No | manual review |
| EUAIAct-Art12-003 | Log Retention Period | Record Keeping | High | 12(3) | No | manual review |
| EUAIAct-Art12-004 | Log Integrity and Tamper Evidence | Record Keeping | High | 12(4) | No | manual review |
| EUAIAct-Art12-005 | Log Accessibility for Authorities | Record Keeping | High | 12(5) | No | manual review |
| EUAIAct-Art13-001 | System Designed for Transparency | Transparency | High | 13(1) | Yes | `checkTransparency` |
| EUAIAct-Art13-002 | Instructions for Use Provided | Transparency | High | 13(2) | No | manual review |
| EUAIAct-Art13-003 | System Capabilities Disclosure | Transparency | High | 13(3)(a) | No | manual review |
| EUAIAct-Art13-004 | System Limitations Disclosure | Transparency | High | 13(3)(b) | No | manual review |
| EUAIAct-Art13-005 | Intended Purpose Disclosure | Transparency | High | 13(3)(c) | No | manual review |
| EUAIAct-Art13-006 | Accuracy Levels Disclosure | Transparency | High | 13(3)(d) | No | manual review |
| EUAIAct-Art13-007 | Robustness Disclosure | Transparency | High | 13(3)(e) | No | manual review |
| EUAIAct-Art13-008 | Cybersecurity Measures Disclosure | Transparency | High | 13(3)(f) | No | manual review |
| EUAIAct-Art14-001 | Human Oversight Designed In | Human Oversight | High | 14(1) | Yes | `checkHumanOversight` |
| EUAIAct-Art14-002 | Oversight Measures Effective | Human Oversight | High | 14(2) | No | manual review |
| EUAIAct-Art14-003 | Human Reviewers Can Intervene | Human Oversight | High | 14(3) | No | manual review |
| EUAIAct-Art14-004 | Kill Switch / Abort Capability | Human Oversight | High | 14(4) | No | manual review |
| EUAIAct-Art14-005 | Bias Monitoring by Humans | Human Oversight | High | 14(5) | No | manual review |
| EUAIAct-Art14-006 | Override Capability | Human Oversight | High | 14(6) | No | manual review |
| EUAIAct-Art15-001 | Accuracy Level Appropriate | Accuracy and Robustness | Critical | 15(1) | Yes | `checkAccuracyRobustness` |
| EUAIAct-Art15-002 | Robustness Measures | Accuracy and Robustness | Critical | 15(2) | No | manual review |
| EUAIAct-Art15-003 | Resilience to Errors and Faults | Accuracy and Robustness | Critical | 15(3) | No | manual review |
| EUAIAct-Art15-004 | Performance Monitoring in Operation | Accuracy and Robustness | Critical | 15(4) | No | manual review |
| EUAIAct-Art15-005 | Cybersecurity Measures | Accuracy and Robustness | Critical | 15(5) | No | manual review |
| EUAIAct-Art15-006 | Protection vs Unauthorized Access | Accuracy and Robustness | Critical | 15(5)(a) | No | manual review |
| EUAIAct-Art15-007 | Data Poisoning Mitigation | Accuracy and Robustness | Critical | 15(5)(b) | Yes | `checkCybersecurity` |
| EUAIAct-Art15-008 | Model Poisoning Mitigation | Accuracy and Robustness | Critical | 15(5)(c) | No | manual review |
| EUAIAct-Art15-009 | Adversarial Attack Mitigation | Accuracy and Robustness | Critical | 15(5)(d) | No | manual review |
| EUAIAct-Art15-010 | Training Data Confidentiality | Accuracy and Robustness | Critical | 15(5)(e) | No | manual review |
| EUAIAct-Art15-011 | Model Parameter Integrity | Accuracy and Robustness | Critical | 15(5)(f) | No | manual review |
| EUAIAct-Art15-012 | System Service Availability | Accuracy and Robustness | Critical | 15(5)(g) | No | manual review |
| EUAIAct-Art51-001 | Technical Documentation for GPAI | GPAI Models | High | 51(1)(a) | No | manual review |
| EUAIAct-Art51-002 | Downstream Provider Information | GPAI Models | High | 51(1)(b) | No | manual review |
| EUAIAct-Art51-003 | Copyright Compliance Policy | GPAI Models | High | 51(1)(c) | No | manual review |
| EUAIAct-Art51-004 | Training Data Summary Disclosure | GPAI Models | High | 51(1)(d) | No | manual review |
| EUAIAct-Art52-001 | AI Office Request Compliance | GPAI Models | High | 52(1) | No | manual review |
| EUAIAct-Art53-001 | Systemic Risk Classification | GPAI Models | High | 53(1) | No | manual review |
| EUAIAct-Art53-002 | State-of-the-Art Evaluation | GPAI Models | High | 53(1)(a) | No | manual review |
| EUAIAct-Art53-003 | Systemic Risk Assessment | GPAI Models | High | 53(1)(b) | No | manual review |
| EUAIAct-Art55-001 | Code of Conduct Adherence | GPAI Models | High | 55(1) | No | manual review |
| EUAIAct-Art55-002 | Voluntary Commitments | GPAI Models | High | 55(2) | No | manual review |
| EUAIAct-AI-001 | Prompt Injection Protection | AI Controls | Medium | AegisGate extension | Yes | `checkPromptInjectionProtection` |
| EUAIAct-AI-002 | Training Data Sanitization | AI Controls | Medium | AegisGate extension | No | manual review |
| EUAIAct-AI-003 | AI System Output Filtering | AI Controls | Medium | AegisGate extension | No | manual review |
| EUAIAct-AI-004 | AI Model Bias Detection | AI Controls | Medium | AegisGate extension | No | manual review |
| EUAIAct-AI-005 | AI Model Hallucination Detection | AI Controls | Medium | AegisGate extension | No | manual review |
| EUAIAct-AI-006 | AI Agent Capability Attestation | AI Controls | Medium | AegisGate extension | No | manual review |
| EUAIAct-AI-007 | AI Model Versioning and Lineage | AI Controls | Medium | AegisGate extension | No | manual review |
| EUAIAct-AI-008 | AI Model Red Team Testing | AI Controls | Medium | AegisGate extension | No | manual review |
| EUAIAct-AI-009 | AI Model Interpretability and Explainability | AI Controls | Medium | AegisGate extension | No | manual review |
| EUAIAct-AI-010 | AI System Kill Switch and Rollback | AI Controls | Medium | AegisGate extension | No | manual review |

---

## Per-Control Evidence & References

Detailed evidence requirements and references for each control, organized by category.

### Prohibited Practices

- **EUAIAct-Art5-001 - Subliminal Manipulation Techniques** (Article 5(1)(a), Critical)
  - Automated: No (manual review)
  - Evidence: Article 5 prohibits AI that deploys subliminal techniques beyond a person's consciousness to materially distort behavior. Evidence: policy/code review confirms no dark-pattern or below-threshold manipulation. AegisGate can detect manipulation patterns in proxy traffic via the dedicated checkProhibitedPractices method (also covers 5-002, 5-004, 5-006).
- **EUAIAct-Art5-002 - Exploitation of Vulnerabilities** (Article 5(1)(b), Critical)
  - Automated: No (manual review)
  - Evidence: Article 5 prohibits exploiting vulnerabilities of natural persons due to age, disability, or social/economic situation. Evidence: design review and DPIA. AegisGate manipulation-pattern detection (checkProhibitedPractices) flags vulnerable-population targeting language.
- **EUAIAct-Art5-003 - Social Scoring by Public Authorities** (Article 5(1)(c), Critical)
  - Automated: No (manual review)
  - Evidence: Article 5 prohibits social scoring of natural persons by public authorities (or on their behalf) leading to detrimental treatment unrelated to context. Evidence: design review confirms no social-scoring use case. Out of scope for typical private-sector deployment.
- **EUAIAct-Art5-004 - Real-Time Remote Biometric Identification** (Article 5(1)(h), Critical)
  - Automated: No (manual review)
  - Evidence: Article 5 prohibits real-time remote biometric identification in publicly accessible spaces for law enforcement purposes (limited exceptions apply). Evidence: deployment review confirms no public-space biometric system. AegisGate biometric-pattern detection (checkProhibitedPractices) flags public real-time biometric usage.
- **EUAIAct-Art5-005 - Predictive Policing Individual Risk** (Article 5(1)(d), Critical)
  - Automated: No (manual review)
  - Evidence: Article 5 prohibits AI for predicting risk of natural persons committing criminal offences based solely on profiling or personality traits. Evidence: use-case review. AegisGate code/policy review via compliance scan.
- **EUAIAct-Art5-006 - Untargeted Scraping of Facial Images** (Article 5(1)(e), Critical)
  - Automated: No (manual review)
  - Evidence: Article 5 prohibits untargeted scraping of facial images from the internet or CCTV to create or expand facial-recognition databases. Evidence: data-procurement review.
- **EUAIAct-Art5-007 - Emotion Recognition in Workplace/Education** (Article 5(1)(f), Critical)
  - Automated: No (manual review)
  - Evidence: Article 5 prohibits emotion-recognition AI in workplace and educational institutions (medical/safety exceptions). Evidence: deployment review. AegisGate has dedicated emotion-recognition policy support in proxy configuration.
- **EUAIAct-Art5-008 - Biometric Categorization of Sensitive Attributes** (Article 5(1)(g), Critical)
  - Automated: No (manual review)
  - Evidence: Article 5 prohibits biometric categorization inferring race, political opinions, trade union membership, religious beliefs, sex life, or sexual orientation. Evidence: feature review.

### Risk Management

- **EUAIAct-Art9-001 - Risk Management System Established** (Article 9(1), Critical)
  - Automated: Yes (`checkRiskManagement`)
  - Evidence: Article 9 requires a continuous, iterative risk-management process run throughout the high-risk AI lifecycle. Automated check looks for `risk_management`/`risk_assessment` and `risk_documentation`/`risk_register` markers in the customer's input payload (e.g., a configuration dump). Partial credit if process or documentation is missing.
- **EUAIAct-Art9-002 - Risk Identification and Analysis** (Article 9(2)(a), Critical)
  - Automated: No (manual review)
  - Evidence: Article 9(2)(a) requires identifying and analyzing known and reasonably foreseeable risks to health, safety, and fundamental rights. Evidence: risk register, threat model document.
- **EUAIAct-Art9-003 - Risk Estimation and Evaluation** (Article 9(2)(b), Critical)
  - Automated: No (manual review)
  - Evidence: Article 9(2)(b) requires estimating and evaluating risks that may emerge during use. Evidence: risk-acceptance criteria, severity matrix.
- **EUAIAct-Art9-004 - Risk Mitigation Measures** (Article 9(2)(c), Critical)
  - Automated: No (manual review)
  - Evidence: Article 9(2)(c) requires adopting risk-mitigation measures (design changes, guardrails, information). Evidence: design documents, control inventory. AegisGate: many of these mitigations are platform features (prompt injection, secret scanning).
- **EUAIAct-Art9-005 - Testing Procedures for Mitigation** (Article 9(2)(d), Critical)
  - Automated: No (manual review)
  - Evidence: Article 9(2)(d) requires testing procedures to ensure mitigation is effective. Evidence: test plans, regression suite, red-team reports. AegisGate proxy logs provide test-traffic evidence.
- **EUAIAct-Art9-006 - Continuous Monitoring and Review** (Article 9(2)(e), Critical)
  - Automated: No (manual review)
  - Evidence: Article 9(2)(e) requires continuous monitoring and review. Evidence: monitoring dashboards, incident logs. AegisGate metrics, audit logging (Community-tier) provide the audit trail.
- **EUAIAct-Art9-007 - Iteration Throughout Lifecycle** (Article 9(3), Critical)
  - Automated: No (manual review)
  - Evidence: Article 9(3) requires the risk-management system to be iterated throughout the lifecycle, with periodic review. Evidence: change-management records.
- **EUAIAct-Art9-008 - Integration with Quality Management** (Article 9(4), Critical)
  - Automated: No (manual review)
  - Evidence: Article 9(4) requires integration with the provider's quality management system (QMS). Evidence: QMS documentation referencing AI risk process.
- **EUAIAct-Art9-009 - Documentation of Known Risks** (Article 9(5), Critical)
  - Automated: No (manual review)
  - Evidence: Article 9(5) requires documentation of known and foreseeable risks. Evidence: risk register, residual-risk assessment. AegisGate: control scanning produces a risk inventory.
- **EUAIAct-Art9-010 - Residual Risk Acceptability** (Article 9(6), Critical)
  - Automated: No (manual review)
  - Evidence: Article 9(6) requires informing users of residual risk. Evidence: user-facing disclosures, in-product warnings.

### Data Governance

- **EUAIAct-Art10-001 - Training Data Quality and Relevance** (Article 10(1), High)
  - Automated: No (manual review)
  - Evidence: Article 10(1): high-risk AI training/validation/test datasets must be relevant, representative, and free of errors to the intended purpose. Evidence: data-card, Datasheets-for-Datasets.
- **EUAIAct-Art10-002 - Data Governance and Management** (Article 10(2), High)
  - Automated: No (manual review)
  - Evidence: Article 10(2): data governance and management practices for training/validation/test data. Evidence: data-governance policy, line-of-responsibility.
- **EUAIAct-Art10-003 - Bias Examination and Mitigation** (Article 10(2)(a), High)
  - Automated: No (manual review)
  - Evidence: Article 10(2)(a): examination of datasets for possible biases. Evidence: bias audit reports, fairness metrics. AegisGate AI-004 bias detection provides automated evidence.
- **EUAIAct-Art10-004 - Data Preparation and Processing** (Article 10(2)(b), High)
  - Automated: No (manual review)
  - Evidence: Article 10(2)(b): data preparation and processing operations (annotation, cleaning, augmentation). Evidence: preprocessing pipeline documentation.
- **EUAIAct-Art10-005 - Dataset Representativeness** (Article 10(3), High)
  - Automated: No (manual review)
  - Evidence: Article 10(3): datasets must be sufficiently representative of the intended use population. Evidence: population analysis, sampling strategy.
- **EUAIAct-Art10-006 - Statistical Properties of Datasets** (Article 10(4), High)
  - Automated: No (manual review)
  - Evidence: Article 10(4): datasets must have appropriate statistical properties. Evidence: dataset statistics, distribution plots.
- **EUAIAct-Art10-007 - Possible Biases Identification** (Article 10(5), High)
  - Automated: No (manual review)
  - Evidence: Article 10(5): identify possible biases and gaps. Evidence: bias register, gap analysis.
- **EUAIAct-Art10-008 - Data Provenance and Lineage** (Article 10(6), High)
  - Automated: No (manual review)
  - Evidence: Article 10(6): data provenance and lineage. Evidence: dataset card with source attribution. AegisGate AI-007 model lineage complements this.

### Technical Documentation

- **EUAIAct-Art11-001 - Technical Documentation Before Market** (Article 11(1), High)
  - Automated: Yes (`checkTechnicalDocumentation`)
  - Evidence: Article 11(1) requires technical documentation per Annex IV before market placement. Automated check: looks for `technical_documentation`/`model_documentation` markers in input.
- **EUAIAct-Art11-002 - System Characteristics Documentation** (Article 11(1)(a), High)
  - Automated: No (manual review)
  - Evidence: Article 11(1)(a): general description of the AI system. Evidence: system card, model card, README.
- **EUAIAct-Art11-003 - Design Specifications** (Article 11(1)(b), High)
  - Automated: No (manual review)
  - Evidence: Article 11(1)(b): design specifications including algorithmic choices. Evidence: architecture diagrams, design specs.
- **EUAIAct-Art11-004 - Development Process Documentation** (Article 11(1)(c), High)
  - Automated: No (manual review)
  - Evidence: Article 11(1)(c): documentation of the development process. Evidence: SDLC docs, training pipeline.
- **EUAIAct-Art11-005 - Intended Purpose Documentation** (Article 11(1)(d), High)
  - Automated: No (manual review)
  - Evidence: Article 11(1)(d): intended purpose per Article 6(3). Evidence: intended-purpose statement, use-case spec.

### Record Keeping

- **EUAIAct-Art12-001 - Automatic Logging Capabilities** (Article 12(1), High)
  - Automated: Yes (`checkRecordKeeping`)
  - Evidence: Article 12(1) requires automatic logging over the lifecycle. Automated check: looks for `audit_log`/`audit_enabled`/`log_integrity`/`signed_logs`/`tamper_evident` markers. AegisGate audit logging (Community-tier Feature) directly satisfies this.
- **EUAIAct-Art12-002 - Log Traceability** (Article 12(2), High)
  - Automated: No (manual review)
  - Evidence: Article 12(2): logs must enable traceability of system functioning. Evidence: log schema, correlation IDs. AegisGate request_logging feature.
- **EUAIAct-Art12-003 - Log Retention Period** (Article 12(3), High)
  - Automated: No (manual review)
  - Evidence: Article 12(3): logs retained for an appropriate period consistent with intended purpose. Evidence: retention policy. AegisGate retention_policies (Professional+).
- **EUAIAct-Art12-004 - Log Integrity and Tamper Evidence** (Article 12(4), High)
  - Automated: No (manual review)
  - Evidence: Article 12(4): logs must be tamper-evident. Evidence: append-only storage, hash chain, WORM. AegisGate SBOM + signed audit log features.
- **EUAIAct-Art12-005 - Log Accessibility for Authorities** (Article 12(5), High)
  - Automated: No (manual review)
  - Evidence: Article 12(5): logs must be accessible on request to competent authorities. Evidence: export/audit-trail API.

### Transparency

- **EUAIAct-Art13-001 - System Designed for Transparency** (Article 13(1), High)
  - Automated: Yes (`checkTransparency`)
  - Evidence: Article 13(1): high-risk AI must be designed to allow deployers to interpret outputs and use appropriately. Automated check: looks for `model_card`/`system_card`/`instructions_for_use`/`transparency_notice` markers.
- **EUAIAct-Art13-002 - Instructions for Use Provided** (Article 13(2), High)
  - Automated: No (manual review)
  - Evidence: Article 13(2): provider must supply instructions for use including the Annex IV info. Evidence: deployment guide, user manual.
- **EUAIAct-Art13-003 - System Capabilities Disclosure** (Article 13(3)(a), High)
  - Automated: No (manual review)
  - Evidence: Article 13(3)(a): disclosure of system capabilities and limitations. Evidence: capability disclosure doc.
- **EUAIAct-Art13-004 - System Limitations Disclosure** (Article 13(3)(b), High)
  - Automated: No (manual review)
  - Evidence: Article 13(3)(b): known limitations, foreseeable misuse. Evidence: limitations doc, advisory.
- **EUAIAct-Art13-005 - Intended Purpose Disclosure** (Article 13(3)(c), High)
  - Automated: No (manual review)
  - Evidence: Article 13(3)(c): intended purpose and prohibited use cases. Evidence: use-case doc.
- **EUAIAct-Art13-006 - Accuracy Levels Disclosure** (Article 13(3)(d), High)
  - Automated: No (manual review)
  - Evidence: Article 13(3)(d): accuracy level and relevant metrics. Evidence: accuracy report.
- **EUAIAct-Art13-007 - Robustness Disclosure** (Article 13(3)(e), High)
  - Automated: No (manual review)
  - Evidence: Article 13(3)(e): robustness and cybersecurity measures. Evidence: security/robustness doc.
- **EUAIAct-Art13-008 - Cybersecurity Measures Disclosure** (Article 13(3)(f), High)
  - Automated: No (manual review)
  - Evidence: Article 13(3)(f): cybersecurity measures expected of deployer. Evidence: deployer security guide.

### Human Oversight

- **EUAIAct-Art14-001 - Human Oversight Designed In** (Article 14(1), High)
  - Automated: Yes (`checkHumanOversight`)
  - Evidence: Article 14(1): high-risk AI must be designed to allow effective human oversight. Automated check: looks for `human_review`/`human_oversight`/`human_in_the_loop`/`kill_switch`/`abort`/`manual_review`/`override` markers.
- **EUAIAct-Art14-002 - Oversight Measures Effective** (Article 14(2), High)
  - Automated: No (manual review)
  - Evidence: Article 14(2): oversight measures must be appropriate to the system. Evidence: oversight design doc, training material for reviewers.
- **EUAIAct-Art14-003 - Human Reviewers Can Intervene** (Article 14(3), High)
  - Automated: No (manual review)
  - Evidence: Article 14(3): persons assigned to oversight must be able to correctly understand the system. Evidence: training records, decision logs.
- **EUAIAct-Art14-004 - Kill Switch / Abort Capability** (Article 14(4), High)
  - Automated: No (manual review)
  - Evidence: Article 14(4): persons assigned to oversight must be able to decide not to use / disregard / reverse the output. Evidence: abort button, rollback procedure. AegisGate AI-010 kill-switch.
- **EUAIAct-Art14-005 - Bias Monitoring by Humans** (Article 14(5), High)
  - Automated: No (manual review)
  - Evidence: Article 14(5): oversight must include bias monitoring in operation. Evidence: bias monitoring dashboard.
- **EUAIAct-Art14-006 - Override Capability** (Article 14(6), High)
  - Automated: No (manual review)
  - Evidence: Article 14(6): override or reverse the AI output. Evidence: override procedures, decision-audit logs.

### Accuracy and Robustness

- **EUAIAct-Art15-001 - Accuracy Level Appropriate** (Article 15(1), Critical)
  - Automated: Yes (`checkAccuracyRobustness`)
  - Evidence: Article 15(1): accuracy and robustness appropriate to intended purpose. Automated check: looks for `accuracy_testing`/`benchmark_results` AND `robustness_testing`/`red_team`/`adversarial_testing` markers. Partial credit if only one is present.
- **EUAIAct-Art15-002 - Robustness Measures** (Article 15(2), Critical)
  - Automated: No (manual review)
  - Evidence: Article 15(2): robustness to errors/faults. Evidence: fault-injection test reports. AegisGate circuit_breaker feature.
- **EUAIAct-Art15-003 - Resilience to Errors and Faults** (Article 15(3), Critical)
  - Automated: No (manual review)
  - Evidence: Article 15(3): resilience to errors/faults. Evidence: chaos-engineering reports.
- **EUAIAct-Art15-004 - Performance Monitoring in Operation** (Article 15(4), Critical)
  - Automated: No (manual review)
  - Evidence: Article 15(4): performance monitoring. Evidence: monitoring dashboards, drift detection. AegisGate ml_traffic_pattern (Community), ml_behavioral (Professional).
- **EUAIAct-Art15-005 - Cybersecurity Measures** (Article 15(5), Critical)
  - Automated: No (manual review)
  - Evidence: Article 15(5): cybersecurity measures appropriate to the system. Evidence: threat model, pen-test reports, security review.
- **EUAIAct-Art15-006 - Protection vs Unauthorized Access** (Article 15(5)(a), Critical)
  - Automated: No (manual review)
  - Evidence: Article 15(5)(a): protection against unauthorized access. Evidence: authentication/authorization design, mTLS, OAuth/OIDC. AegisGate mTLS (Developer+), OAuthSSO (Developer+).
- **EUAIAct-Art15-007 - Data Poisoning Mitigation** (Article 15(5)(b), Critical)
  - Automated: Yes (`checkCybersecurity`)
  - Evidence: Article 15(5)(b): protection against data/model poisoning. Automated check: detects `data_poisoning`/`training_data_poison`/`backdoor_trigger` patterns; partial credit if `adversarial_mitigation`/`input_sanitization` markers present.
- **EUAIAct-Art15-008 - Model Poisoning Mitigation** (Article 15(5)(c), Critical)
  - Automated: No (manual review)
  - Evidence: Article 15(5)(c): model poisoning mitigation. Evidence: training pipeline hardening, signed model artifacts. AegisGate SBOM tracking.
- **EUAIAct-Art15-009 - Adversarial Attack Mitigation** (Article 15(5)(d), Critical)
  - Automated: No (manual review)
  - Evidence: Article 15(5)(d): adversarial attack mitigation. Evidence: adversarial input detection, hardened prompts. AegisGate AI-001 prompt injection detection.
- **EUAIAct-Art15-010 - Training Data Confidentiality** (Article 15(5)(e), Critical)
  - Automated: No (manual review)
  - Evidence: Article 15(5)(e): confidentiality of training data. Evidence: encryption at rest, key management. AegisGate data_encryption (Developer+), vault_secrets (Professional+).
- **EUAIAct-Art15-011 - Model Parameter Integrity** (Article 15(5)(f), Critical)
  - Automated: No (manual review)
  - Evidence: Article 15(5)(f): integrity of model parameters. Evidence: signed model weights, attestations. AegisGate trust_pillar (Professional+).
- **EUAIAct-Art15-012 - System Service Availability** (Article 15(5)(g), Critical)
  - Automated: No (manual review)
  - Evidence: Article 15(5)(g): availability of system services. Evidence: HA, autoscaling. AegisGate deploy_ha (Enterprise).

### GPAI Models

- **EUAIAct-Art51-001 - Technical Documentation for GPAI** (Article 51(1)(a), High)
  - Automated: No (manual review)
  - Evidence: Article 51(1)(a): GPAI providers must draw up and keep up-to-date technical documentation including training process and evaluation. Evidence: model card, training recipe.
- **EUAIAct-Art51-002 - Downstream Provider Information** (Article 51(1)(b), High)
  - Automated: No (manual review)
  - Evidence: Article 51(1)(b): information for downstream providers on capabilities, limitations, permitted/prohibited uses. Evidence: provider-facing doc, API terms.
- **EUAIAct-Art51-003 - Copyright Compliance Policy** (Article 51(1)(c), High)
  - Automated: No (manual review)
  - Evidence: Article 51(1)(c): copyright compliance policy. Evidence: copyright policy, opt-out mechanism.
- **EUAIAct-Art51-004 - Training Data Summary Disclosure** (Article 51(1)(d), High)
  - Automated: No (manual review)
  - Evidence: Article 51(1)(d): training data summary public disclosure. Evidence: data summary doc, model card training data section.
- **EUAIAct-Art52-001 - AI Office Request Compliance** (Article 52(1), High)
  - Automated: No (manual review)
  - Evidence: Article 52(1): GPAI providers must provide information/documents on request to the AI Office and national authorities. Evidence: response procedure.
- **EUAIAct-Art53-001 - Systemic Risk Classification** (Article 53(1), High)
  - Automated: No (manual review)
  - Evidence: Article 53(1): GPAI models with systemic risk must perform model evaluation, adversarial testing, and risk mitigation. Evidence: classification rationale.
- **EUAIAct-Art53-002 - State-of-the-Art Evaluation** (Article 53(1)(a), High)
  - Automated: No (manual review)
  - Evidence: Article 53(1)(a): evaluation of the model with state-of-the-art protocols. Evidence: benchmark reports.
- **EUAIAct-Art53-003 - Systemic Risk Assessment** (Article 53(1)(b), High)
  - Automated: No (manual review)
  - Evidence: Article 53(1)(b): assessment and mitigation of systemic risk at Union level. Evidence: systemic risk assessment report.
- **EUAIAct-Art55-001 - Code of Conduct Adherence** (Article 55(1), High)
  - Automated: No (manual review)
  - Evidence: Article 55(1): voluntary codes of conduct for AI governance. Evidence: code-of-conduct compliance statement.
- **EUAIAct-Art55-002 - Voluntary Commitments** (Article 55(2), High)
  - Automated: No (manual review)
  - Evidence: Article 55(2): voluntary commitments on AI governance beyond regulatory requirements. Evidence: commitments doc.

### AI Controls

- **EUAIAct-AI-001 - Prompt Injection Protection** (Article AegisGate extension, Medium)
  - Automated: Yes (`checkPromptInjectionProtection`)
  - Evidence: AegisGate extension. Automated check: detects `prompt_injection`/`jailbreak`/`ignore_previous` patterns. Partial credit if `prompt_injection_detector`/`input_filter`/`system_prompt_hardening` mitigation is present. Sourced from internal security research and MITRE ATLAS TA03/TA04.
- **EUAIAct-AI-002 - Training Data Sanitization** (Article AegisGate extension, Medium)
  - Automated: No (manual review)
  - Evidence: AegisGate extension. Evidence: preprocessing pipeline docs, secret/PII scrubbing config. AegisGate secret_scanning (Community) and pii_scanning (Community) features directly support this.
- **EUAIAct-AI-003 - AI System Output Filtering** (Article AegisGate extension, Medium)
  - Automated: No (manual review)
  - Evidence: AegisGate extension. Evidence: response-side secret/PII/injection filters. AegisGate bidirectional_inspection (Community) implements this end-to-end.
- **EUAIAct-AI-004 - AI Model Bias Detection** (Article AegisGate extension, Medium)
  - Automated: No (manual review)
  - Evidence: AegisGate extension. Evidence: bias-mitigation reports, fairness metrics. AegisGate ml_behavioral (Professional) and ml_threat_detection (Professional) support detection.
- **EUAIAct-AI-005 - AI Model Hallucination Detection** (Article AegisGate extension, Medium)
  - Automated: No (manual review)
  - Evidence: AegisGate extension. Evidence: fact-checking pipeline, hallucination scoring. AegisGate response-side content scanning (resp_pii_block, resp_secret_block) is a starting point.
- **EUAIAct-AI-006 - AI Agent Capability Attestation** (Article AegisGate extension, Medium)
  - Automated: No (manual review)
  - Evidence: AegisGate extension. Evidence: signed capability manifests for AI agents. AegisGate trust_pillar (Professional+) provides Ed25519/ECDSA attestation primitives; mcp_basic_rbac (Community) implements session-level capability enforcement.
- **EUAIAct-AI-007 - AI Model Versioning and Lineage** (Article AegisGate extension, Medium)
  - Automated: No (manual review)
  - Evidence: AegisGate extension. Evidence: model registry with versioning. AegisGate sbom_tracking (Community) is the analog for software models.
- **EUAIAct-AI-008 - AI Model Red Team Testing** (Article AegisGate extension, Medium)
  - Automated: No (manual review)
  - Evidence: AegisGate extension. Evidence: red-team reports. AegisGate's red-team scenario library is referenced from the prompt-injection detection patterns.
- **EUAIAct-AI-009 - AI Model Interpretability and Explainability** (Article AegisGate extension, Medium)
  - Automated: No (manual review)
  - Evidence: AegisGate extension. Evidence: SHAP/LIME or other explainability reports, attribution. AegisGate proxy request_logging provides the per-request evidence trail.
- **EUAIAct-AI-010 - AI System Kill Switch and Rollback** (Article AegisGate extension, Medium)
  - Automated: No (manual review)
  - Evidence: AegisGate extension. Evidence: documented kill-switch + rollback procedure. AegisGate circuit_breaker (Community) is a partial implementation; full kill-switch is part of the v3.3.0+ roadmap.

---

## Source-of-Truth Cross-Reference

- Go source of truth: `pkg/compliance/eu-ai-act/controls.go` (82 `RegisterControl` calls)
- Test coverage: `pkg/compliance/eu-ai-act/eu_ai_act_test.go` (13 tests)
- Gating: `pkg/compliance/gating.go` `license.ModuleEUAIAct` entry (`TierProfessional`, $99/mo)
- Module registration: `pkg/compliance/framework_registration.go` (RegisterBuiltinFrameworks)
- Tier feature: `pkg/tier/tier.go` `FeatureEUAIActModule` (Professional)
- Billing: `pkg/billing/billing-config.json` `module_eu_ai_act` entry
- Customer 1-pager: `docs/compliance/eu-ai-act.md`
- Plan: `plans/V3.3.0-ROADMAP.md` Phase 1 (lines 225-260)

---

*Document Version: 1.0*
*Last Updated: 2026-06-06*
*AegisGate Platform v3.3.0+*
*Source: Regulation (EU) 2024/1689 + AegisGate implementation*