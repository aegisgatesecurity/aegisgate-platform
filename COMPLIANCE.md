# AegisGate Compliance Posture

AegisGate Security, LLC maintains self-assessment documentation against industry-standard cybersecurity and privacy frameworks.

## Self-Assessments

All self-assessment documents are published on the AegisGate website:

| Framework | Document | Scope |
|-----------|----------|-------|
| HIPAA Security Rule | [aegisgatesecurity.io/compliance/hipaa/](https://aegisgatesecurity.io/compliance/hipaa/) | 45 C.F.R. §§ 164.302–318 |
| NIST CSF 2.0 | [aegisgatesecurity.io/compliance/nist-csf/](https://aegisgatesecurity.io/compliance/nist-csf/) | Six core functions (GV, ID, PR, DE, RS, RC) |
| SOC 2 Type 1 Readiness | [aegisgatesecurity.io/compliance/soc2/](https://aegisgatesecurity.io/compliance/soc2/) | Trust Services Criteria (Security, Availability) |
| CIS Controls v8 IG1 | [aegisgatesecurity.io/compliance/cis/](https://aegisgatesecurity.io/compliance/cis/) | 56 baseline safeguards |
| EU AI Act | [aegisgatesecurity.io/compliance/eu-ai-act/](https://aegisgatesecurity.io/compliance/eu-ai-act/) | Regulation 2024/1689 |
| PCI-DSS SAQ A | See `legal-docs/20-PCI-DSS-Self-Assessment-SAQ-A.md` | Self-Assessment Questionnaire A |

**Important:** These are self-assessments, not third-party certifications. They document how AegisGate's controls map to each framework's requirements based on our product architecture and development practices.

## Automated Compliance Engine

AegisGate's compliance posture is reinforced at runtime by the automated compliance engine in `pkg/compliance/`:

- **24 frameworks** with 857+ automated CheckFuncs
- **153+ detection patterns** for real-time threat scanning
- **Hash-chained audit logs** for tamper-evident compliance records

See the [compliance registry](pkg/compliance/framework-registry.go) and [framework mapping](pkg/compliance/framework_mapping.go) for implementation details.

## Legal Documents

Legal documents (ToS, Privacy Policy, BAA, DPA, etc.) are published at [aegisgatesecurity.io/legal/](https://aegisgatesecurity.io/legal/).

## Review Cycle

Self-assessments are reviewed quarterly and updated annually, or ad hoc in response to material changes.