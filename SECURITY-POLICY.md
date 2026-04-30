# AegisGate Security Policy

**Version:** 1.0  
**Effective Date:** April 29, 2026  
**Review Date:** October 29, 2026  
**Contact:** security@aegisgatesecurity.io

---

## 1. Introduction

AegisGate Security ("AegisGate," "we," "our," or "us") is committed to ensuring the security of our platform and our customers' data. This Security Policy outlines our security practices, vulnerability disclosure process, and compliance posture.

This policy applies to:
- The AegisGate Security Platform (all tiers)
- All hosted services and infrastructure
- Customer data processed by AegisGate

---

## 2. Security Architecture

### 2.1 Platform Security Controls

| Control | Implementation | Coverage |
|---------|---------------|----------|
| **License Enforcement** | ECDSA P-256 digital signatures | 100% |
| **RBAC** | 5-tier role-based access | 93.9% |
| **Tool Authorization** | Risk matrix enforcement | 96.2% |
| **MCP Guardrails** | 8 active security guards | 100% |
| **Compliance Registry** | 13 frameworks | 100% |
| **Rate Limiting** | Per-client RPM enforcement | 100% |
| **Audit Logging** | File-backed compliance logs | 100% |
| **Network Isolation** | Kubernetes NetworkPolicy | 100% |

### 2.2 Deployment Security

- **Container Images:** Signed with cosign (keyless via GitHub OIDC)
- **Binary Releases:** Signed with cosign
- **SBOM:** Generated via Syft (CycloneDX + SPDX)
- **SBOM Attestation:** Stored with container image
- **Provenance:** Full supply chain attestation

### 2.3 CI/CD Security

| Scan | Tool | Frequency |
|------|------|-----------|
| Vulnerability Database | govulncheck | Every push |
| Static Analysis | gosec | Every push |
| Secret Scanning | trufflehog | Every push |
| Container Scanning | trivy | Weekly + every push |
| Dependency Review | dependency-review | Every push |
| SBOM Generation | syft + anchore | Every release |

---

## 3. Vulnerability Disclosure

### 3.1 Coordinated Disclosure Process

We follow a coordinated vulnerability disclosure process:

1. **Report:** Send details to security@aegisgatesecurity.io
2. **Acknowledgment:** We respond within 48 hours
3. **Assessment:** We triage and assign severity within 7 days
4. **Remediation:** We aim to fix within 90 days
5. **Disclosure:** Public announcement after fix release

### 3.2 Severity Ratings

| Severity | Description | Response Time |
|----------|-------------|---------------|
| **Critical** | Remote code execution, data breach | 24 hours |
| **High** | Privilege escalation, denial of service | 7 days |
| **Medium** | Information disclosure, bypass | 30 days |
| **Low** | Minor issues, non-exploitable | 90 days |

### 3.3 Safe Harbor

We authorize and appreciate security research on our systems, provided researchers:
- Do not exceed the scope of authorized testing
- Do not access more data than necessary
- Report vulnerabilities privately and promptly
- Allow reasonable time for remediation before public disclosure
- Do not engage in social engineering or physical attacks

### 3.4 Out of Scope

The following are outside the scope of our vulnerability disclosure program:
- Social engineering attacks
- Physical security testing
- Denial of service attacks on production systems
- Automated scanning that impacts availability
- Issues on third-party services not controlled by AegisGate

---

## 4. Compliance Frameworks

### 4.1 Supported Frameworks

| Framework | Coverage | Developer Tier | Professional Tier | Enterprise |
|-----------|----------|:--------------:|:-----------------:|:----------:|
| MITRE ATLAS | 100% | ✅ | ✅ | ✅ |
| NIST AI RMF | 100% | ✅ | ✅ | ✅ |
| OWASP LLM Top 10 | 100% | ✅ | ✅ | ✅ |
| ISO 27001 | 100% | ✅ | ✅ | ✅ |
| GDPR | 100% | ❌ | ✅ | ✅ |
| HIPAA | 100% | ❌ | ✅ (BAA) | ✅ |
| PCI-DSS | 100% | ❌ | ✅ (Agreement) | ✅ |
| SOC 2 Type II | In Progress | ❌ | ❌ | ✅ |
| ISO 42001 (AI) | 100% | ❌ | ❌ | ✅ |

### 4.2 Data Processing

For GDPR and HIPAA compliance, AegisGate offers:
- **Data Processing Agreement (DPA):** Available upon request
- **Business Associate Agreement (BAA):** Required for HIPAA customers
- **Data Retention Schedule:** Documented per tier

---

## 5. Incident Response

### 5.1 Incident Types

| Type | Definition | Example |
|------|------------|---------|
| **Security Incident** | Unauthorized access to systems | Brute force attack detected |
| **Data Breach** | Unauthorized access to customer data | PII exposure |
| **Compliance Violation** | Failure of security controls | RBAC bypass |

### 5.2 Response Procedure

1. **Detection:** Automated alerting + manual reporting
2. **Triage:** Severity assessment within 4 hours
3. **Containment:** Isolate affected systems
4. **Investigation:** Root cause analysis
5. **Notification:** Customer notification per legal requirements
6. **Remediation:** Fix vulnerabilities
7. **Post-Incident:** Lessons learned, control improvements

### 5.3 Notification Timeline

| Regulation | Notification Requirement |
|------------|-------------------------|
| HIPAA | 60 days to HHS (breach of PHI) |
| GDPR | 72 hours to supervisory authority |
| SOC 2 | No specific timeline, but timely |

---

## 6. Infrastructure Security

### 6.1 Cloud Infrastructure

- **Provider:** Multi-cloud capable (AWS, GCP, Azure)
- **Container Orchestration:** Kubernetes (Helm + K8s manifests)
- **Network Policies:** Restrictive ingress/egress
- **Secrets Management:** Kubernetes Secrets
- **Monitoring:** Prometheus + Grafana

### 6.2 Container Security

- **Base Image:** Minimal Alpine Linux
- **Image Scanning:** Trivy (every build)
- **Image Signing:** cosign (keyless via GitHub OIDC)
- **SBOM:** Generated and attested per release

---

## 7. Customer Responsibilities

### 7.1 License Management

- Keep license keys secure (do not commit to git)
- Rotate keys regularly
- Report suspected compromise immediately

### 7.2 Configuration

- Follow security hardening guides in documentation
- Enable all available security controls
- Use SSO where possible

### 7.3 Compliance

- Review and sign required agreements (BAA, DPA)
- Complete required security questionnaires
- Provide audit access as required

---

## 8. Contact Information

| Contact | Purpose | Response Time |
|---------|---------|---------------|
| **security@aegisgatesecurity.io** | Vulnerability reports | 24-48 hours |
| **support@aegisgatesecurity.io** | General support | 24-48 hours |
| **legal@aegisgatesecurity.io** | Legal/compliance | 5 business days |

---

## 9. Policy Updates

This policy is reviewed quarterly and updated as needed. Material changes will be communicated via:
- Email to registered contacts
- Security advisories on GitHub
- Version bump in this document

**Last Updated:** April 29, 2026  
**Next Review:** October 29, 2026
