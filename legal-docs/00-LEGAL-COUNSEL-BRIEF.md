# LEGAL COUNSEL BRIEF
## AegisGate Security Platform — For Attorney Review

**Prepared:** April 29, 2026  
**Version:** 1.0 DRAFT

---

## PURPOSE

This brief provides the context needed for legal counsel to review, finalize, and where necessary draft the legal documents for AegisGate Security, LLC's commercial launch.

**Goal:** Launch commercial tiers (Starter, Developer, Professional, Enterprise) with appropriate legal framework.

---

## COMPANY INFORMATION

| Item | Details |
|------|---------|
| **Company Name** | AegisGate Security, LLC |
| **Type** | Limited Liability Company |
| **Jurisdiction** | [STATE] |
| **Address** | [TO BE COMPLETED] |
| **Email** | support@aegisgatesecurity.io |
| **Website** | https://aegisgatesecurity.io |

---

## PRODUCT DESCRIPTION

### What AegisGate Does

AegisGate Security Platform is a cloud-based AI infrastructure security gateway that:

1. **Scans API traffic** between AI clients and backend services
2. **Protects MCP (Model Context Protocol) servers** with 8 security guardrails
3. **Enforces compliance frameworks** (HIPAA, PCI-DSS, GDPR, SOC2, etc.)
4. **Provides RBAC and SSO** for enterprise authentication
5. **Generates audit logs and compliance reports**

### How It Works

```
AI Client (Claude/GPT) ──▶ AegisGate Proxy ──▶ API/MCP Server
                              │
                              ▼
                    ┌─────────────────┐
                    │ Threat Detection│
                    │ Compliance Check│
                    │ Rate Limiting    │
                    │ RBAC Enforcement│
                    └─────────────────┘
```

### Key Technical Features

| Feature | Description |
|---------|-------------|
| **License Enforcement** | ECDSA P-256 signed keys, 7-day grace period |
| **MCP Guardrails** | 8 guardrails: auth, session limits, tool calls, memory, timeouts, STDIO |
| **Compliance Registry** | 13 frameworks (ATLAS, NIST, OWASP, HIPAA, PCI-DSS, GDPR, etc.) |
| **Rate Limiting** | Per-tier RPM (requests per minute) enforcement |
| **Audit Logging** | Event logging with configurable retention |
| **SSO Integration** | OIDC/SAML support for enterprise identity providers |

---

## SUBSCRIPTION TIERS

### Overview

| Tier | Price | Key Features |
|------|-------|--------------|
| **Community** | Free | Basic protection, 120 RPM, open source (Apache 2.0) |
| **Starter** | $29/mo | Core protection, 150 RPM |
| **Developer** | $79/mo | SSO + RBAC, 500 RPM |
| **Professional** | $249/mo | HIPAA + BAA, PCI-DSS, GDPR, 2,500 RPM |
| **Enterprise** | Custom | Unlimited, SOC2, dedicated SLA |

### Compliance Needs by Tier

| Tier | Compliance Modules | Legal Documents Needed |
|------|-------------------|------------------------|
| Community | ATLAS, NIST, OWASP | None (Apache 2.0) |
| Starter | Same as Community + 150 RPM | Standard SaaS ToS |
| Developer | Same + SSO/RBAC | Standard SaaS ToS |
| Professional | HIPAA, PCI-DSS, GDPR | **BAA, DPA, PCI-DSS Agreement** |
| Enterprise | All of above + SOC2 | All above + MSA addendum |

---

## DATA HANDLING

### What We Process

| Data Type | Examples | Retention |
|-----------|----------|-----------|
| **API metadata** | Endpoints called, response codes | 7 days (Community) - 1 year (Enterprise) |
| **Audit logs** | Security events, access logs | Tier-dependent |
| **Threat data** | Detected patterns, alerts | 7-90 days |
| **License info** | Customer email, tier, expiration | Duration + 90 days |
| **Usage metrics** | RPM counts, session counts | Aggregated, non-identifying |

### What We Do NOT Process

- **PHI (Protected Health Information)** — Unless customer is using our service to scan PHI-containing traffic
- **Cardholder Data** — We do not process payment cards
- **SSN/Government IDs** — Not collected
- **Biometric Data** — Not collected

### Data Storage

| Item | Details |
|------|---------|
| **Hosting** | Cloud-based (AWS/GCP/Azure) |
| **Encryption** | TLS 1.3 in transit, AES-256 at rest |
| **Location** | US-based (primary); EU available for Enterprise |

### Sub-processors

**Current sub-processors:** None at this time.

*Note: Our DPA and Subprocessor List document the process for approving future sub-processors.*

---

## CUSTOMER BASE

### Target Customers

| Segment | Description |
|---------|-------------|
| **Developers** | Individual developers using AI in their applications |
| **Startups** | Small teams building AI-powered products |
| **Healthcare** | Companies handling PHI who need HIPAA compliance |
| **Financial Services** | Fintech companies needing PCI-DSS compliance |
| **Enterprises** | Large organizations needing SOC2 and custom SLA |

### Intended Markets

| Market | Primary Regions |
|--------|-----------------|
| **Primary** | United States |
| **Secondary** | European Union (GDPR considerations) |
| **Tertiary** | United Kingdom (UK GDPR) |

---

## DELIVERABLES FOR LEGAL COUNSEL

### Documents We Have Drafted (Attached)

| # | Document | Status | Notes |
|---|----------|--------|-------|
| 1 | Business Associate Agreement | DRAFT | Needs review for HIPAA customers |
| 2 | Data Processing Agreement | DRAFT | GDPR Article 28 compliant |
| 3 | PCI-DSS Vendor Agreement | DRAFT | Service provider obligations |
| 4 | Master Service Agreement | DRAFT | General terms + SLA Exhibit |
| 5 | Mutual NDA | DRAFT | For sales discussions |
| 6 | Cookie Policy | DRAFT | GDPR/CCPA compliant |
| 7 | Acceptable Use Policy | DRAFT | Complements ToS |
| 8 | Subprocessor List | DRAFT | Start with "none" |
| 9 | Security Addendum | DRAFT | Enterprise security requirements |
| 10 | Data Retention Schedule | DRAFT | GDPR/HIPAA retention periods |
| 11 | Incident Response Template | DRAFT | Breach notification procedures |

### Website Legal Pages (Already Live)

| Document | Status | Notes |
|----------|--------|-------|
| Terms of Service | ✅ DRAFT COMPLETE | See legal-docs/12-Terms-of-Service.md |
| Privacy Policy | ✅ DRAFT COMPLETE | See legal-docs/13-Privacy-Policy.md |
| End-User License Agreement | ✅ DRAFT COMPLETE | See legal-docs/14-End-User-License-Agreement.md |

### Documents Needed From Counsel

| Document | Priority | Notes |
|----------|----------|-------|
| Final ToS | 🔴 CRITICAL | Draft complete - needs review |
| Final Privacy Policy | 🔴 CRITICAL | Draft complete - needs review |
| Final EULA | 🔴 CRITICAL | Draft complete - needs review |
| BAA (final) | 🟠 HIGH | Ready for review |
| DPA (final) | 🟠 HIGH | Ready for review |
| PCI-DSS Agreement (final) | 🟠 HIGH | Ready for review |

---

## SPECIFIC QUESTIONS FOR LEGAL COUNSEL

### 1. BAA Specifics
- [ ] Does our BAA draft meet HIPAA requirements?
- [ ] Should we offer BAAs to Developer tier customers who may handle PHI?
- [ ] What insurance requirements should we include?

### 2. International Considerations
- [ ] Does our DPA meet GDPR Article 28 requirements?
- [ ] Should we add UK GDPR provisions?
- [ ] Do we need a California-specific Privacy Notice (CCPA)?

### 3. Liability and Indemnification
- [ ] Are our liability caps reasonable for SaaS security software?
- [ ] Should we add specific indemnification for IP infringement?
- [ ] Do we need professional liability/E&O insurance?

### 4. Export Compliance
- [ ] Do we need to address export controls (EAR/ITAR)?
- [ ] Should we restrict service to certain jurisdictions?

### 5. Pricing and Billing
- [ ] Are our pricing and refund terms acceptable?
- [ ] Should we require annual pre-pay for any tiers?
- [ ] Do we need specific terms for custom Enterprise pricing?

---

## ATTACHMENTS

Please review the following drafts alongside your review:

1. `/legal-docs/12-Terms-of-Service.md` ← **NEW - Needs review**
2. `/legal-docs/13-Privacy-Policy.md` ← **NEW - Needs review**
3. `/legal-docs/14-End-User-License-Agreement.md` ← **NEW - Needs review**
4. `/legal-docs/01-BAA-Business-Associate-Agreement.md`
5. `/legal-docs/02-DPA-Data-Processing-Agreement.md`
6. `/legal-docs/03-PCI-DSS-Vendor-Agreement.md`
7. `/legal-docs/04-Mutual-NDA.md`
8. `/legal-docs/05-Master-Service-Agreement.md`
9. `/legal-docs/06-Cookie-Policy.md`
10. `/legal-docs/07-Acceptable-Use-Policy.md`
11. `/legal-docs/08-Subprocessor-List.md`
12. `/legal-docs/09-Security-Addendum.md`
13. `/legal-docs/10-Data-Retention-Schedule.md`
14. `/legal-docs/11-Incident-Response-Template.md`

Website legal pages:
- `https://aegisgatesecurity.io/legal/terms.html`
- `https://aegisgatesecurity.io/legal/privacy.html`
- `https://aegisgatesecurity.io/legal/eula.html`

---

## ESTIMATED ATTORNEY TIME

| Item | Estimated Time |
|------|----------------|
| ToS finalization | 1 hour |
| Privacy Policy finalization | 1 hour |
| EULA finalization | 30 min |
| BAA review and finalization | 1 hour |
| DPA review | 30 min |
| General review and Q&A | 1 hour |
| **Total estimated** | **5 hours** |

---

## CONTACT

**Primary Contact:** [YOUR NAME]  
**Email:** support@aegisgatesecurity.io  
**Phone:** [YOUR PHONE]  

**Available for questions:** Monday-Friday, 9am-5pm [TIMEZONE]

---

*This brief is provided to assist legal counsel in reviewing our documentation. All documents are drafts and should not be used as binding agreements until reviewed and approved by qualified legal counsel.*
