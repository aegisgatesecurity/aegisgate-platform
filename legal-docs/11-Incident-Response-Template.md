# INCIDENT RESPONSE RUNBOOK

**Document Version:** 1.0 DRAFT  
**Effective Date:** June 1, 2026

---

## INTRODUCTION

This Incident Response Runbook outlines the procedures for AegisGate Security, LLC ("Company," "we," or "us") to respond to security incidents affecting customer data. This document supports compliance with:
- HIPAA Breach Notification Rule (45 C.F.R. § 164.400)
- GDPR Article 33/34 (72-hour notification)
- PCI-DSS Requirement 12.10

---

## 1. INCIDENT CLASSIFICATION

### 1.1 Severity Levels

| Level | Definition | Examples | Response Time |
|-------|------------|-----------|----------------|
| **Critical (P1)** | Active breach, data exfiltration, systemic compromise | PHI exposed, credentials stolen, ransomware | 1 hour |
| **High (P2)** | Confirmed security event, limited scope | Unauthorized access, malware detected | 4 hours |
| **Medium (P3)** | Suspected compromise, investigation needed | Anomalous behavior, failed attacks | 24 hours |
| **Low (P4)** | Informational, no immediate threat | Failed login attempts, policy violations | 7 days |

### 1.2 Incident Categories

| Category | Description | Examples |
|----------|-------------|----------|
| **Data Breach** | Unauthorized access to data | PHI exposure, PII leak |
| **System Compromise** | Unauthorized system access | Account takeover, backdoor |
| **Denial of Service** | Service availability impact | DDoS, resource exhaustion |
| **Malware** | Malicious software | Ransomware, trojans |
| **Social Engineering** | Human-targeted attacks | Phishing, impersonation |
| **Insider Threat** | Internal actor misconduct | Malicious employee, negligence |
| **Physical Security** | Physical access incident | Stolen laptop, unauthorized facility access |

---

## 2. INCIDENT RESPONSE TEAM

### 2.1 Team Composition

| Role | Responsibilities |
|------|------------------|
| **Incident Commander (IC)** | Overall coordination, decision-making |
| **Security Lead** | Technical investigation, containment |
| **Communications Lead** | Internal/external communications |
| **Legal Counsel** | Legal obligations, breach assessment |
| **Engineering Lead** | System remediation, recovery |

### 2.2 Contact Information

| Role | Primary | Backup |
|------|---------|--------|
| Incident Commander | security-ic@aegisgatesecurity.io | [PRIVATE] |
| Security Lead | security-ops@aegisgatesecurity.io | [PRIVATE] |
| Communications | comms@aegisgatesecurity.io | support@aegisgatesecurity.io |
| Legal Counsel | support@aegisgatesecurity.io | [PRIVATE] |

---

## 3. RESPONSE PROCEDURES

### 3.1 Initial Detection (0-30 minutes)

**Step 1: Triage**
```
□ Receive incident alert (automated or manual)
□ Classify severity (P1-P4)
□ Assign incident ID (format: INC-YYYYMMDD-###)
□ Page Incident Commander for P1/P2
□ Open incident channel (#incident-YYYYMMDD-###)
```

**Step 2: Initial Assessment**
```
□ What systems/data are affected?
□ Is the incident ongoing or contained?
□ What is the scope (customers, data, systems)?
□ Are there regulatory implications (HIPAA, GDPR)?
□ Document initial findings in incident log
```

### 3.2 Containment (30 minutes - 2 hours)

**Immediate Containment (P1/P2)**
```
□ Isolate affected systems (network isolation, account disable)
□ Preserve evidence (disk images, memory dumps, logs)
□ Block malicious IPs/domains at firewall
□ Revoke compromised credentials
□ Enable enhanced monitoring on affected systems
```

**Evidence Preservation**
```
□ Timestamp all actions taken
□ Preserve logs (syslog, application, access)
□ Create disk images for forensics
□ Document chain of custody
□ Secure evidence storage location
```

### 3.3 Investigation (2-24 hours)

**Technical Investigation**
```
□ Identify attack vector and timeline
□ Determine scope of compromise
□ Identify affected data and customers
□ Assess data exposure (what, how many, how long)
□ Review relevant logs for patterns
□ Conduct malware analysis (if applicable)
```

**Customer Assessment**
```
□ Identify affected customers
□ Determine customer impact
□ Review customer-specific data exposure
□ Prepare customer-specific findings
```

### 3.4 Notification (Per Regulations)

**Internal Notification (within 1 hour of P1/P2)**
```
□ Notify C-suite/management
□ Notify Legal Counsel
□ Notify PR/Communications (if public incident)
□ Notify engineering team (if not already involved)
□ Brief executive team
```

**Regulatory Notification**

| Regulation | Notification Deadline | Recipient |
|------------|---------------------|----------|
| HIPAA | 60 days of discovery ( HHS) | HHS OCR |
| HIPAA | Immediate if >500 individuals | Media (for large breaches) |
| GDPR | 72 hours of discovery | Supervisory authority |
| State Laws | Per state requirement | State Attorney General |
| PCI-DSS | Immediate | Card brands, acquiring bank |

**Customer Notification**

| Tier | Notification Timeline | Method |
|------|----------------------|--------|
| Community/Starter | Within 72 hours | Email + portal |
| Developer | Within 48 hours | Email + portal + call (P1) |
| Professional | Within 24 hours | Email + portal + call |
| Enterprise | Within 4 hours | Email + portal + dedicated call |

**Notification Template (See Exhibit B)**

### 3.5 Remediation (24-72 hours)

**Root Cause Analysis**
```
□ Complete attack timeline
□ Identify root cause
□ Document vulnerabilities exploited
□ Review control failures
□ Prepare RCA report
```

**Remediation Actions**
```
□ Patch/fix vulnerabilities
□ Rotate credentials/keys
□ Rebuild compromised systems
□ Update security controls
□ Implement additional monitoring
□ Conduct penetration test (if warranted)
```

### 3.6 Recovery (72 hours - 2 weeks)

**System Recovery**
```
□ Restore from known-good backups
□ Verify system integrity
□ Re-enable services (staged rollout)
□ Conduct security testing
□ Monitor for recurrence
```

**Post-Incident Review**
```
□ Conduct lessons learned session
□ Update incident response procedures
□ Identify process improvements
□ Update training materials
□ Schedule follow-up review (30 days)
```

---

## 4. DOCUMENTATION

### 4.1 Incident Log

All incidents must be documented with:
- Incident ID and classification
- Discovery date/time
- Containment date/time
- Resolution date/time
- Root cause
- Impact assessment
- Actions taken
- Lessons learned

### 4.02 Evidence Retention

| Evidence Type | Retention Period |
|---------------|-----------------|
| System logs | 3 years |
| Disk images | 1 year |
| Network captures | 1 year |
| Incident documentation | 5 years |
| Customer notifications | 5 years |

---

## 5. COMMUNICATION TEMPLATES

### 5.1 Initial Customer Notification

```
Subject: [ACTION REQUIRED] Security Incident Notification - AegisGate Platform

Dear [Customer Name],

[Date] — We are contacting you regarding a security incident that may affect your data processed through the AegisGate Security Platform.

INCIDENT SUMMARY
─────────────────
Incident ID: [INC-YYYYMMDD-###]
Discovered: [Date/Time]
Affected Systems: [Description]
Data Affected: [Types of data]

WHAT HAPPENED
─────────────────
[Brief, factual description of the incident]

WHAT WE ARE DOING
─────────────────
[Steps taken to investigate, contain, and remediate]

WHAT YOU SHOULD DO
─────────────────
[Recommended actions for the customer]

FOR MORE INFORMATION
─────────────────
Contact: security@aegisgatesecurity.io
Support Portal: https://aegisgatesecurity.io/support

We sincerely apologize for this incident and are committed to protecting your data.

Sincerely,
AegisGate Security Team
```

### 5.2 Regulatory Notification (HIPAA)

```
To: Secretary, U.S. Department of Health and Human Services
Re: Breach of Unsecured Protected Health Information

Breach Notification ID: [INC-YYYYMMDD-###]
Date of Discovery: [Date]
Date of Breach (if known): [Date]
Discovery Method: [How we learned of the breach]
Affected Individuals: [Count]
Data Types: [Types of PHI]
Location of Breached Information: [Description]

[Detailed description of breach circumstances and steps taken]
```

---

## 6. POST-INCIDENT REVIEW

### 6.1 Lessons Learned Agenda

1. **Incident Overview** — What happened?
2. **Timeline** — When did each event occur?
3. **Response Effectiveness** — What worked? What didn't?
4. **Root Cause Analysis** — Why did it happen?
5. **Control Gaps** — What controls failed?
6. **Remediation Status** — What has been fixed?
7. **Process Improvements** — What should change?
8. **Action Items** — Who does what by when?

### 6.2 Review Meeting

- **Timing:** Within 2 weeks of incident closure
- **Attendees:** IRT members, engineering, management
- **Output:** Updated procedures, action items with owners/due dates

---

## 7. EXHIBIT A: CONTACT LIST

| Contact | Role | Contact Info |
|---------|------|-------------|
| [PRIVATE] | Incident Commander | [PRIVATE] |
| [PRIVATE] | Security Lead | [PRIVATE] |
| [PRIVATE] | Legal Counsel | [PRIVATE] |
| [PRIVATE] | VP Engineering | [PRIVATE] |
| [PRIVATE] | CEO | [PRIVATE] |

**External Contacts:**
- FBI Cyber Division: cy.fbi.gov
- CISA: cisa.gov/report
- [State] Attorney General: [Contact info]

---

*DRAFT - For discussion purposes only. Subject to legal review.*
