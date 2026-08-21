# Compliance Overview

AegisGate provides automated compliance mapping across **31 security and AI governance frameworks** — 4 Community, 6 Developer, 16 Professional, 5 Enterprise. Every framework has a full Go implementation with automated control checking, evidence generation, and cross-framework mapping.

## Control Counts

| Metric | Count | Percentage |
|--------|-------|------------|
| **Total controls** | 2,043 | 100% |
| **Automated controls** | 1,457 | 71.3% |
| **Manual controls** | 586 | 28.7% |

Manual controls are genuinely human-process controls: organizational policies, legal agreements, physical security, HR training, governance, supply chain management, and external audit procedures.

## 4 Automation Methods

1. **Config State Verification** — reads running configuration and validates it against framework requirements (e.g., TLS enabled, audit logging on, rate limits configured)
2. **Audit Trail Evidence** — examines audit logs for required evidence artifacts (access logged, data retention enforced, incident response tracked)
3. **Detection Engine State** — checks that detection rules and scanners are active and covering required patterns (PII detection running, prompt injection blocking, secret scanning enabled)
4. **Cross-Framework Mapping** — maps evidence from one framework to satisfy another's requirements (HIPAA access logging → SOC 2 CC6.1, GDPR PII protection → ISO 27001 A.8.12)

## Framework List by Tier

### Community (4 frameworks, free)

| Framework | Package | Controls |
|-----------|---------|----------|
| OWASP LLM Top 10 | `pkg/compliance/community/owasp/` | 49 patterns |
| OWASP Web Top 10 | `pkg/compliance/owasp_web/` | 10 categories |
| MITRE ATLAS | `pkg/compliance/community/atlas/` | 66 techniques |
| NIST AI RMF 1.0 | `pkg/compliance/nist_ai_rmf/` | 50 controls |

### Developer (6 frameworks, $79/mo)

| Framework | Package | Controls |
|-----------|---------|----------|
| HIPAA | `pkg/compliance/hipaa/` | 54 controls |
| PCI-DSS v4.0 | `pkg/compliance/pci/` | 152 controls |
| SOC 2 Type II | `pkg/compliance/soc2/` | 64 controls |
| ISO/IEC 27001:2022 | `pkg/compliance/iso27001/` | 116 controls |
| CCPA/CPRA | `pkg/compliance/ccpa/` | 26 controls |
| GDPR | `pkg/compliance/community/gdpr/` | 99 controls |

### Professional (16 frameworks, $499/mo)

| Framework | Package |
|-----------|---------|
| ISO/IEC 42001:2023 | `pkg/compliance/iso42001/` |
| EU AI Act | `pkg/compliance/eu-ai-act/` |
| FIPS 140-2/140-3 | `pkg/compliance/fips/` |
| CIS Critical Security Controls | `pkg/compliance/cis/` |
| NIST Cybersecurity Framework | `pkg/compliance/nist_csf/` |
| CSA STAR | `pkg/compliance/csa_star/` |
| NIST AI 600-1 | `pkg/compliance/nist_ai_600_1/` |
| SOX | `pkg/compliance/sox/` |
| GLBA | `pkg/compliance/glba/` |
| CJIS Security Policy | `pkg/compliance/cjis/` |
| NERC CIP | `pkg/compliance/nerc_cip/` |
| FERPA | `pkg/compliance/ferpa/` |
| HITECH Act | `pkg/compliance/hitech/` |
| FFIEC Banking Guidance | `pkg/compliance/ffiec/` |
| TSA Security Directive | `pkg/compliance/tsa_sd/` |
| ISO 21434 (Automotive) | `pkg/compliance/iso21434/` |

### Enterprise (5 frameworks, custom)

| Framework | Package |
|-----------|---------|
| FedRAMP | `pkg/compliance/fedramp/` |
| CMMC Level 2 | `pkg/compliance/cmmcl2/` |
| NIST 800-171 | `pkg/compliance/nist800171/` |
| HITRUST CSF | `pkg/compliance/hitrust/` |
| TISAX AL2 | `pkg/compliance/tisax/` |

## Architecture

### Module Registration

Each framework is registered in `pkg/compliance/framework_registration.go` and tier-gated in `pkg/compliance/gating.go`. The `moduleRequirements` map in `gating.go` is the single source of truth for which tier unlocks each framework.

### Control Pattern

Each framework module follows the `BaseComplianceModule` pattern with `RegisterControl`:

```go
module := &BaseComplianceModule{
    FrameworkID:   "hipaa",
    FrameworkName: "HIPAA",
    Tier:          tierpkg.TierDeveloper,
}

module.RegisterControl(ComplianceControl{
    ID:        "HIPAA-AS-001",
    Title:     "Access Control",
    Category:  "Administrative Safeguards",
    Automated: true,
    CheckFunc: func(ctx context.Context, state *SystemState) ComplianceResult {
        // Check that RBAC is enabled
        if !state.RBACEnabled {
            return ComplianceResult{Status: NonCompliant, Evidence: "RBAC not enabled"}
        }
        return ComplianceResult{Status: Compliant}
    },
})
```

### Tier Gating

Tier enforcement flows through `pkg/compliance/gating.go`:

- Community tier modules: always enforced (free, regardless of license)
- Developer+ modules: enforced when license tier ≥ module's `RequiredTier`
- Unlicensed paid modules: return `ErrEnterpriseOnly` / `codes.Unimplemented`

### Cross-Framework Mapping

Cross-framework mapping is implemented in `pkg/compliance/mapping/`. It allows evidence from one framework to satisfy another's requirements:

```
HIPAA §164.308(a)(1)(ii)(A) Risk Analysis → SOC 2 CC3.2 Risk Assessment
HIPAA §164.312(b) Audit Controls → SOC 2 CC7.2 System Monitoring
GDPR Art. 32 Security of Processing → ISO 27001 A.8.1 Information Security Policy
```

### Evidence Generation

Evidence packages include:
- Config state snapshots
- Audit log excerpts (hash-chained)
- Detection engine status
- Cross-framework mapping references
- RFC 3161 timestamped attestations (Professional+)

## Guided Setup for Compliance

Use deploy profiles to get compliance-ready quickly:

```bash
# High-security profile for HIPAA, SOC 2, EU AI Act
./aegisgate-platform --profile high-security --embedded-mcp

# Air-gapped profile for FedRAMP, CMMC, HITRUST
./aegisgate-platform --profile air-gapped --embedded-mcp

# Validate compliance config
./aegisgate-platform config validate aegisgate-platform.yaml

# Generate compliance report
./aegisgate-platform report --framework hipaa --format json
```

See also: `glossary.md`, `cli-reference.md`, `getting-started.md`