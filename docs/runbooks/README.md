# SOC Runbooks — AegisGate Platform

## Purpose

These runbooks provide **actionable investigation workflows** for SOC analysts when AegisGate detects a threat. Each runbook answers:

1. **What triggered this?** — Pattern explanation
2. **Is this always bad?** — Context matters
3. **What's the investigation workflow?** — Step-by-step
4. **What's the remediation?** — Block, educate, ignore
5. **What's the compliance impact?** — HIPAA, PCI, SOX, etc.

## Philosophy

> AegisGate is built for **SOC practitioners**, not compliance checklists.
> 
> These runbooks reflect real-world investigation workflows — not theoretical "best practices" from a GRC consultant.

## Runbook Index

| ID | Title | Sector | Severity |
|----|-------|--------|----------|
| [RUNBOOK-001](./RUNBOOK-001-PII-DETECTION.md) | PII Detection (SSN, MRN, Passport) | All | High |
| [RUNBOOK-002](./RUNBOOK-002-SECRETS-CREDENTIALS.md) | Secrets & Credentials (AWS, API Keys) | All | Critical |
| [RUNBOOK-003](./RUNBOOK-003-FINANCIAL-CODES.md) | Financial Codes (SWIFT, Credit Cards, Routing) | Banking/Finance | High |
| [RUNBOOK-004](./RUNBOOK-004-HEALTHCARE-CODES.md) | Healthcare Codes (CPT, HCPCS, ICD-10) | Healthcare | Medium |
| [RUNBOOK-005](./RUNBOOK-005-OT-PROTOCOLS.md) | OT Protocol Manipulation (Modbus, DNP3, OPC-UA) | Manufacturing/Energy | High |

## How to Use

### For SOC Analysts

1. **Alert fires** → Note the `category` and `severity` from AegisGate
2. **Open relevant runbook** → Follow the investigation workflow
3. **Make escalation decision** → Use the severity matrix
4. **Document findings** → Update incident ticket with runbook reference

### For GRC/Compliance

1. **Audit request** → Identify relevant framework (HIPAA, PCI, SOX)
2. **Map to runbooks** → Each runbook lists compliance impacts
3. **Export evidence** → AegisGate logs + incident tickets = audit trail

## Integration

Each AegisGate detection event includes:
- `category` → Maps to runbook (e.g., `pii_ssn` → RUNBOOK-001)
- `severity` → Determines escalation path
- `runbook_url` → Direct link to relevant runbook (Platform UI)

## Contributing

These runbooks evolve with real SOC experience. If you encounter a false positive, edge case, or new attack pattern:

1. **Document it** → Add to the relevant runbook's "Edge Cases" section
2. **Share it** → Submit a PR to the AegisGate repo
3. **Validate it** → Test with the community

---

**Version:** 1.0  
**Last Updated:** 2026-08-14  
**Maintainer:** AegisGate Security, LLC
