# UNITED STATES PROVISIONAL PATENT APPLICATION

**Title:** SYSTEMS AND METHODS FOR MAPPING ARTIFICIAL INTELLIGENCE SECURITY DETECTIONS TO COMPLIANCE FRAMEWORK CONTROLS

**Inventor:** [INVENTOR NAME — FILL IN BEFORE FILING]
**Entity Status:** Micro Entity (under 37 CFR 1.29)
**Related Applications:** None
**Filing Date:** [FILL IN WHEN FILED]

---

## TECHNICAL FIELD

The present disclosure relates generally to compliance and cybersecurity and, more specifically, to systems and methods for mapping real-time artificial intelligence (AI) security detections to compliance framework controls and generating audit-ready compliance reports from AI traffic analysis.

## BACKGROUND

Organizations face an increasing regulatory burden related to AI usage. Multiple compliance frameworks now include AI-specific controls, including: HIPAA (healthcare data privacy), PCI DSS 4.0 (payment card security), SOC 2 (security and availability), ISO 42001 (AI management systems), NIST AI Risk Management Framework, EU AI Act, and others. Additionally, AI-specific threat taxonomies such as MITRE ATLAS and OWASP LLM Top 10 define adversarial techniques targeting AI systems.

Existing compliance tools (e.g., Vanta, Drata, Secureframe) map organizational infrastructure and policies to compliance controls. They do not detect AI-specific security events or generate compliance reports from AI traffic analysis. Existing AI security tools (e.g., Lakera Guard, Prompt Security) detect AI threats but do not map detections to compliance frameworks or generate audit-ready reports.

What is needed is a system that: (1) detects AI-specific security events (data exfiltration, prompt injection, unauthorized access, etc.), (2) maps each detection to relevant compliance framework controls in real-time, (3) generates audit-ready compliance reports from AI traffic analysis, and (4) supports multiple compliance frameworks simultaneously with a unified detection-to-control mapping.

## SUMMARY OF THE INVENTION

The present disclosure describes systems and methods for mapping AI security detections to compliance framework controls. The system comprises: a detection module configured to detect AI security events from intercepted AI traffic; a control mapping module configured to map each detected event to relevant compliance framework controls; a report generation module configured to generate audit-ready compliance reports from accumulated detections; and a framework registry configured to store and manage mappings for multiple compliance frameworks.

In one embodiment, the system supports at least 33 compliance frameworks simultaneously, including: HIPAA, PCI DSS 4.0, SOC 2 Type I/II, ISO 27001, ISO 42001, NIST AI RMF, NIST 800-53, EU AI Act, MITRE ATLAS, OWASP LLM Top 10, OWASP Top 10, FedRAMP, GDPR, CCPA, FIPS 140-2/140-3, GLBA, SOX, and others.

In another embodiment, the control mapping module maintains a mapping table associating each detection pattern with one or more compliance framework control identifiers, wherein a single detection event may map to controls in multiple frameworks simultaneously.

In another embodiment, the report generation module produces compliance reports for a specified time period, framework, and scope, including: detected events, mapped control identifiers, severity classifications, remediation status, and evidence artifacts.

## DETAILED DESCRIPTION

### 1. System Architecture

The compliance mapping system operates as a module within an AI security gateway. It receives detected security events from the detection pipeline and produces compliance-mapped audit reports.

### 1.1 Detection Module

The detection module identifies AI-specific security events including:

1. **Data Exfiltration Events:** Detection of PII, credentials, secrets, or sensitive organizational data in AI prompts or agent communications.
2. **Prompt Injection Events:** Detection of adversarial prompts designed to manipulate AI behavior, mapped to MITRE ATLAS techniques.
3. **Unauthorized Access Events:** Detection of AI agents attempting to access resources beyond their authorization scope.
4. **Compliance Violation Events:** Detection of content that violates specific regulatory requirements (e.g., PHI in a non-HIPAA-compliant context, cardholder data in a non-PCI-compliant context).

Each detected event includes: an event identifier, timestamp, source (user/agent), detection layer (regex/compliance/ML), matched pattern or ML score, severity classification, and raw content (stored securely for audit purposes).

### 1.2 Framework Registry

The framework registry stores compliance framework definitions, each comprising:

- **Framework Identifier:** Unique code (e.g., "HIPAA", "PCI_DSS_4", "SOC2", "EU_AI_ACT").
- **Framework Version:** Semantic version (e.g., "4.0.1" for PCI DSS 4.0).
- **Framework Name:** Full legal name.
- **Control Catalog:** A set of control definitions, each comprising: control identifier (e.g., "HIPAA-164.312(a)(1)"), control description, control category, control severity (critical/high/medium/low), and control mapping hints (keywords or detection pattern associations).
- **Applicable Scopes:** The organizational contexts in which the framework applies (e.g., healthcare, financial, federal).

### 1.3 Control Mapping Module

The control mapping module maps each detected event to relevant compliance framework controls using a mapping table. The mapping table associates each detection pattern identifier with one or more compliance framework control identifiers.

For example, detection of a Social Security number in an AI prompt maps to:
- HIPAA §164.312(a)(1) — Access Control (if the SSN may be PHI)
- PCI DSS 3.3.1 — Concealment of PAN (if in a payment context)
- SOC 2 CC6.1 — Logical and Physical Access Controls
- GDPR Article 32 — Security of Processing (if the data subject is in the EU)
- NIST AI RMF 2.4 — Characterize and Secure

A single detection event may map to controls in multiple frameworks simultaneously. The mapping is performed in real-time as events are detected.

The mapping table is configurable and may be extended by security administrators to support additional frameworks or custom control mappings. Each mapping entry includes:

- **Detection Pattern ID:** The identifier of the detection pattern that triggered the event.
- **Framework ID:** The compliance framework identifier.
- **Control ID:** The specific control within the framework.
- **Mapping Confidence:** A confidence score (0.0-1.0) indicating the strength of the association.
- **Mapping Rationale:** A textual description of why the detection maps to this control.

### 1.4 Report Generation Module

The report generation module produces audit-ready compliance reports from accumulated detection events and their control mappings. Reports include:

1. **Executive Summary:** High-level overview of compliance posture, including total events detected, frameworks with violations, and overall compliance score.

2. **Framework-Specific Reports:** For each supported framework, a detailed report including:
   - Total events detected and mapped to this framework.
   - Control-level breakdown: which controls had violations, how many, and severity.
   - Timeline of events for each control.
   - Remediation status (open, in progress, resolved).
   - Evidence artifacts (event logs, blocked content hashes, detection details).

3. **Cross-Framework Matrix:** A matrix showing which detection events map to which frameworks, enabling compliance teams to understand the overlap and prioritize remediation.

4. **Trend Analysis:** Historical trends showing event frequency, severity, and framework coverage over time.

5. **Export Formats:** Reports may be exported in: PDF (human-readable), JSON (machine-readable), CSV (spreadsheet), and SIEM-compatible formats (CEF, LEEF, RFC 5424 Syslog) for integration with external GRC tools.

### 1.5 EU AI Act Specific Controls

For the EU AI Act, the system maps detections to the 82 controls across 9 categories:

1. **Risk Management System** (Article 9): Events related to AI system risk assessment and mitigation.
2. **Data and Data Governance** (Article 10): Events related to training data quality and bias detection.
3. **Technical Documentation** (Article 11): Events generating documentation artifacts for AI system records.
4. **Record-Keeping** (Article 12): Attestation logs and detection events contributing to AI system audit trails.
5. **Transparency** (Article 13): Events related to AI system transparency and user information.
6. **Human Oversight** (Article 14): Events triggering human review requirements.
7. **Accuracy, Robustness, Cybersecurity** (Article 15): Events related to AI system security vulnerabilities.
8. **Post-Market Monitoring** (Article 72): Events indicating AI system degradation or emerging risks.
9. **Serious Incident Reporting** (Article 73): Events meeting the threshold for regulatory reporting.

### 1.6 HIPAA Specific Controls

For HIPAA, the system maps PII and PHI detections to Security Rule controls:

- §164.312(a)(1) Access Control: Detection of unauthorized access to PHI in AI prompts.
- §164.312(b) Audit Controls: Generation of audit logs for all AI interactions involving PHI.
- §164.312(c)(1) Integrity: Detection of PHI modification or corruption in AI processing.
- §164.312(d) Person or Entity Authentication: Verification of agent identity before PHI access.
- §164.312(e)(1) Transmission Security: Blocking of PHI transmission to non-compliant AI services.

### 1.7 PCI DSS 4.0 Specific Controls

For PCI DSS 4.0, the system maps payment data detections to:

- Requirement 3.3.1: Concealment of PAN when displayed or transmitted.
- Requirement 4.2.1: Strong cryptography for PAN transmission.
- Requirement 7.2.1: Access control for cardholder data.
- Requirement 10.2.1: Audit logging for individual user access to cardholder data.

## CLAIMS

1. A system for mapping artificial intelligence security detections to compliance framework controls, comprising: a detection module configured to detect AI security events from intercepted AI traffic; a framework registry configured to store definitions for a plurality of compliance frameworks including AI-specific frameworks; a control mapping module configured to map each detected event to relevant compliance framework controls in real-time; and a report generation module configured to generate audit-ready compliance reports.

2. The system of claim 1, wherein the framework registry supports at least 33 compliance frameworks simultaneously.

3. The system of claim 1, wherein a single detected event maps to controls in multiple compliance frameworks simultaneously.

4. The system of claim 1, wherein the report generation module produces framework-specific reports including control-level breakdowns, timeline of events, and remediation status.

5. The system of claim 1, wherein the compliance frameworks include at least HIPAA, PCI DSS, SOC 2, ISO 42001, NIST AI RMF, EU AI Act, MITRE ATLAS, and OWASP LLM Top 10.

6. The system of claim 1, wherein the control mapping module uses a configurable mapping table associating detection pattern identifiers with compliance framework control identifiers.

7. The system of claim 1, wherein the report generation module exports reports in PDF, JSON, CSV, and SIEM-compatible formats.

8. The system of claim 1, wherein the AI-specific security events include data exfiltration, prompt injection, and unauthorized access events.

9. The system of claim 1, wherein the detection events include a severity classification and evidence artifacts for audit purposes.

10. The system of claim 1, wherein the report generation module produces a cross-framework matrix showing which detection events map to which frameworks.

---

**Note:** Replace [INVENTOR NAME] with the full legal name of the inventor before filing. File at https://patentscenter.uspto.gov using "Provisional" application type. Select "Micro Entity" for reduced fees ($65).