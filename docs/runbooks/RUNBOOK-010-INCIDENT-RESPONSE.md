# RUNBOOK-010: Incident Response for AI Security (Meta-Runbook, Escalation Paths, Evidence Preservation)

**Sector:** All  
**Severity:** N/A (Meta-runbook — guides response to all other runbooks)  
**Patterns:** N/A (Process documentation, not detection patterns)

---

## Purpose

This is the **meta-runbook** for AI security incident response. It provides:

1. **Overall IR workflow** — How to respond to any AI security incident
2. **Escalation paths** — Who to notify and when
3. **Evidence preservation** — What to collect and how
4. **Regulatory notification** — When and how to notify authorities
5. **Post-incident activities** — Lessons learned, remediation, reporting

**Use this runbook in conjunction with specific detection runbooks:**
- RUNBOOK-001 through RUNBOOK-009: Specific threat detection
- RUNBOOK-010: Overall incident response process
- RUNBOOK-011 through RUNBOOK-012: Specialized scenarios

---

## Incident Response Workflow (NIST SP 800-61)

### Phase 1: Preparation (Before Incident)

**Organizational Readiness:**

| Activity | Owner | Frequency |
|----------|-------|-----------|
| **IR Plan Development** | CISO | Annually |
| **AI Security Policy** | CISO + Legal | Annually |
| **Runbook Training** | Security Team | Quarterly |
| **Tabletop Exercises** | Security Team | Semi-annually |
| **Tool Validation** | Security Engineering | Quarterly |
| **Contact List Updates** | Security Operations | Monthly |

**Technical Readiness:**

| Control | Status | Verification |
|---------|--------|--------------|
| **AegisGate Platform deployed** | ✅ Required | Health check daily |
| **Detection rules updated** | ✅ Required | Version check weekly |
| **Log aggregation configured** | ✅ Required | Log flow verification daily |
| **Alerting channels tested** | ✅ Required | Monthly test alert |
| **Evidence storage secured** | ✅ Required | Access review quarterly |
| **Backup procedures tested** | ✅ Required | Semi-annual restore test |

---

### Phase 2: Identification (Detection → Triage)

**Step 1: Alert Received**

| Source | Action |
|--------|--------|
| **AegisGate automatic detection** | Alert created in Platform UI |
| **User report** | Create ticket in incident management system |
| **SIEM correlation** | Escalate to SOC analyst |
| **External notification** | Log and validate |

**Step 2: Initial Triage (Within 15 Minutes)**

**Triage Checklist:**

- [ ] **Categorize the incident** — Which runbook applies?
- [ ] **Assess severity** — Low, Medium, High, Critical
- [ ] **Identify affected systems** — Which AI services, users, data?
- [ ] **Determine scope** — Single user, department, organization-wide?
- [ ] **Check for active threat** — Is the attack ongoing?

**Severity Classification:**

| Severity | Criteria | Response Time | Escalation |
|----------|----------|---------------|------------|
| **Low** | Single occurrence, educational context, no data exposure | 24-48 hours | SOC Analyst |
| **Medium** | Repeated occurrences, unclear intent, potential policy violation | 4-8 hours | SOC Lead |
| **High** | Confirmed policy violation, sensitive data exposure, malicious intent | 1-2 hours | Security Manager |
| **Critical** | Active attack, critical data exposure, regulatory impact, media risk | Immediate | CISO + Legal |

**Step 3: Declare Incident (If High/Critical)**

**Incident Declaration Criteria:**

- ✅ Confirmed malicious activity
- ✅ Sensitive data exposure (PII, PHI, IP, financial)
- ✅ Regulatory impact (HIPAA, PCI, GDPR, EU AI Act)
- ✅ Business impact (service disruption, financial loss, reputational risk)
- ✅ Media/PR risk (customer-facing incident, high-profile target)

**Incident Declaration Template:**

```
INCIDENT DECLARATION

Incident ID: INC-YYYY-NNNNN
Date/Time: YYYY-MM-DD HH:MM UTC
Declared By: [Name, Title]

Summary: [2-3 sentence description]

Severity: [Low/Medium/High/Critical]
Category: [PII Exposure / Secrets / Adversarial AI / etc.]

Affected Systems: [List AI services, applications, users]
Data Impact: [Type and volume of data potentially exposed]

Business Impact: [Operational, financial, reputational impact]

Regulatory Impact: [HIPAA, PCI, GDPR, etc. if applicable]

Immediate Actions Taken: [List containment steps]

Next Steps: [Investigation, remediation, notification plans]
```

---

### Phase 3: Containment (Stop the Bleeding)

**Short-Term Containment (Immediate):**

| Action | When | Owner |
|--------|------|-------|
| **Block malicious prompts** | Automatic (AegisGate) | Platform |
| **Disable user access** | Confirmed malicious activity | IAM Team |
| **Isolate affected systems** | Active attack | Infrastructure |
| **Preserve volatile evidence** | Before any system changes | Forensics |
| **Notify stakeholders** | High/Critical severity | Communications |

**Long-Term Containment (24-48 Hours):**

| Action | When | Owner |
|--------|------|-------|
| **Credential rotation** | If secrets exposed | Infrastructure |
| **System hardening** | If vulnerability exploited | Security Engineering |
| **Access review** | If insider threat suspected | IAM Team |
| **Enhanced monitoring** | For related activity | SOC |
| **Temporary service suspension** | If ongoing risk | Business Owner |

---

### Phase 4: Eradication (Remove the Threat)

**Eradication Activities:**

| Activity | Description | Owner |
|----------|-------------|-------|
| **Malware removal** | Remove any malicious code | Security Engineering |
| **Vulnerability patching** | Fix exploited vulnerabilities | Infrastructure |
| **Account remediation** | Reset passwords, revoke sessions | IAM Team |
| **Data sanitization** | Remove exposed data from AI service logs | Legal + Vendor Mgmt |
| **Policy updates** | Close gaps that enabled incident | Security + Legal |

**Verification:**

- [ ] **Threat removed** — No indicators of continued compromise
- [ ] **Vulnerabilities fixed** — Patching verified
- [ ] **Access revoked** — Compromised credentials invalidated
- [ ] **Monitoring enhanced** — Detection for similar activity

---

### Phase 5: Recovery (Return to Normal)

**Recovery Activities:**

| Activity | Description | Owner |
|----------|-------------|-------|
| **System restoration** | Restore from clean backups if needed | Infrastructure |
| **Service restoration** | Bring services back online | Operations |
| **User communication** | Notify affected users | Communications |
| **Enhanced monitoring** | Watch for recurrence | SOC |
| **Business validation** | Confirm normal operations | Business Owner |

**Recovery Criteria:**

- ✅ Threat fully eradicated
- ✅ Systems verified clean
- ✅ Monitoring in place
- ✅ Users notified (if required)
- ✅ Business approval to resume

---

### Phase 6: Lessons Learned (Continuous Improvement)

**Post-Incident Review (Within 2 Weeks):**

**Attendees:**
- Incident Response Lead
- SOC Analyst(s) involved
- Security Engineering
- Legal/Compliance (if regulatory impact)
- Business Owner (if business impact)
- Communications (if external notification)

**Review Agenda:**

1. **Timeline review** — What happened when?
2. **Detection effectiveness** — Did AegisGate catch it in time?
3. **Response effectiveness** — What went well? What didn't?
4. **Root cause analysis** — Why did this happen?
5. **Remediation status** — Are all fixes in place?
6. **Process improvements** — What should we change?

**Post-Incident Report Template:**

```
POST-INCIDENT REPORT

Incident ID: INC-YYYY-NNNNN
Report Date: YYYY-MM-DD
Report Author: [Name, Title]

EXECUTIVE SUMMARY
[High-level overview for leadership]

INCIDENT TIMELINE
[Detailed timeline from detection to recovery]

DETECTION ANALYSIS
- How was the incident detected?
- Time from occurrence to detection
- Detection effectiveness rating

RESPONSE ANALYSIS
- Response timeline
- What worked well
- What didn't work well
- Gaps identified

ROOT CAUSE
[5 Whys analysis or similar]

IMPACT ASSESSMENT
- Data impact (type, volume, sensitivity)
- Business impact (downtime, financial, reputational)
- Regulatory impact (notifications required)

REMEDIATION STATUS
[All fixes implemented or planned with dates]

LESSONS LEARNED
[Key takeaways]

RECOMMENDATIONS
[Specific actions to prevent recurrence]

METRICS
- Time to detect: X hours
- Time to contain: X hours
- Time to eradicate: X hours
- Time to recover: X hours
- Total incident duration: X hours
```

---

## Escalation Paths

### Internal Escalation

| Severity | Primary Contact | Backup | Escalation Timeline |
|----------|-----------------|--------|---------------------|
| **Low** | SOC Analyst | SOC Lead | 24-48 hours |
| **Medium** | SOC Lead | Security Manager | 4-8 hours |
| **High** | Security Manager | CISO | 1-2 hours |
| **Critical** | CISO | CEO/Board | Immediate |

### External Escalation

| Scenario | Authority | Timeline | Contact |
|----------|-----------|----------|---------|
| **HIPAA breach (500+ individuals)** | HHS OCR | 60 days | https://ocrportal.hhs.gov |
| **HIPAA breach (<500 individuals)** | HHS OCR | 60 days (annual log) | https://ocrportal.hhs.gov |
| **PCI-DSS cardholder data breach** | Card Brands | Immediate | Via acquirer |
| **GDPR personal data breach** | Supervisory Authority | 72 hours | Country-specific |
| **EU AI Act prohibited practice** | National Competent Authority | Immediate | Country-specific |
| **Critical infrastructure cyber incident** | CISA | 72 hours | https://www.cisa.gov/report |
| **FBI cyber crime** | FBI | Immediate | IC3.gov or local field office |
| **SEC cybersecurity disclosure** | SEC | 4 business days | EDGAR filing |

---

## Evidence Preservation

### What to Collect

| Evidence Type | Description | Retention |
|---------------|-------------|-----------|
| **AegisGate detection logs** | Full event data with timestamps | 7 years |
| **Prompt text** | Full prompt content (redacted if privileged) | 7 years |
| **User session logs** | User activity before/after incident | 7 years |
| **Network logs** | Firewall, proxy, DNS logs | 7 years |
| **System logs** | OS, application, database logs | 7 years |
| **Screenshots** | UI evidence, error messages | 7 years |
| **Communications** | Emails, chat logs related to incident | 7 years |
| **Forensic images** | Full disk/memory images (if critical) | 7 years |

### Chain of Custody

**Chain of Custody Template:**

```
CHAIN OF CUSTODY RECORD

Evidence ID: EV-YYYY-NNNNN
Incident ID: INC-YYYY-NNNNN
Evidence Type: [Description]
Collection Date/Time: YYYY-MM-DD HH:MM UTC
Collected By: [Name, Title, Signature]

Storage Location: [Secure location description]
Access Log:
- Date/Time: YYYY-MM-DD HH:MM, Accessed By: [Name], Purpose: [Reason]
- Date/Time: YYYY-MM-DD HH:MM, Accessed By: [Name], Purpose: [Reason]

Transfer Log (if applicable):
- Date/Time: YYYY-MM-DD HH:MM, Transferred To: [Name], Reason: [Reason]

Disposition: [Destroyed/Returned/Retained on Date]
```

---

## Regulatory Notification Decision Tree

```
Incident Detected
        │
        ▼
┌───────────────────┐
│ Is PII/PHI        │
│ exposed?          │
└────────┬──────────
         │ Yes
         ▼
┌───────────────────┐
│ How many          │
│ individuals?      │
└────────┬──────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
  <500      ≥500
    │         │
    ▼         ▼
  Log     Notify HHS
  for     within
  annual  60 days
  report
```

---

## Metrics & KPIs

**Incident Response Metrics:**

| Metric | Target | Calculation |
|--------|--------|-------------|
| **Mean Time to Detect (MTTD)** | <1 hour | Avg time from occurrence to detection |
| **Mean Time to Contain (MTTC)** | <4 hours | Avg time from detection to containment |
| **Mean Time to Eradicate (MTTE)** | <24 hours | Avg time from containment to eradication |
| **Mean Time to Recover (MTTR)** | <48 hours | Avg time from eradication to recovery |
| **Incident Recurrence Rate** | <5% | % of incidents that recur within 90 days |
| **False Positive Rate** | <10% | % of alerts that are false positives |

---

## Related Runbooks

- **RUNBOOK-001 through RUNBOOK-009**: Specific threat detection
- **RUNBOOK-011**: Insider Threat Detection
- **RUNBOOK-012**: Critical Infrastructure Protection
- **RUNBOOK-014**: AI Red Team Operations

---

**Version:** 1.0  
**Last Updated:** 2026-08-14  
**Author:** AegisGate Security, LLC  
**Review Cycle:** Annually (or after any major incident)
