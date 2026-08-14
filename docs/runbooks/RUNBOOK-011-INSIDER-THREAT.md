# RUNBOOK-011: Insider Threat Detection (Behavioral Indicators, Pattern Analysis, HR Coordination)

**Sector:** All (especially Technology, Finance, Government, Healthcare)  
**Severity:** High-Critical (insiders have legitimate access, making detection difficult)  
**Patterns:** 20+ (Behavioral anomalies, access pattern deviations, policy violations)

---

## What Triggered This

AegisGate detected **potential insider threat indicators** through behavioral pattern analysis. This includes:

| Category | Examples | Pattern Name | Severity |
|----------|----------|--------------|----------|
| **After-Hours Access** | AI usage at 3 AM on Saturday | `insider_after_hours` | Medium |
| **Volume Anomalies** | 100x normal prompt volume | `insider_volume_spike` | High |
| **Data Hoarding** | Bulk downloads before resignation | `insider_data_hoarding` | Critical |
| **Policy Evasion** | Using personal AI accounts for work data | `insider_policy_evasion` | High |
| **Privilege Abuse** | Accessing data outside job role | `insider_privilege_abuse` | High |
| **Competitor Outreach** | AI prompts about new job interviews | `insider_job_search` | Medium |
| **Disgruntlement** | Hostile prompts about company/management | `insider_disgruntlement` | Medium |
| **Financial Stress** | Prompts about selling data, financial desperation | `insider_financial_stress` | Critical |

### Example Behavioral Patterns

```
❌ CRITICAL: "I'm leaving next week for [Competitor].
             How much of our customer database can I download
             before my access is revoked?
             What's the best format for importing to Salesforce?"
             → Data theft before departure

❌ CRITICAL: "I need to monetize my access to company data.
             Who buys customer PII?
             What's the going rate per record?
             How do I transfer data anonymously?"
             → Data monetization scheme

❌ HIGH: "I've been accessing the CEO's emails, financial records,
         and board meeting minutes for the past month.
         How do I cover my tracks?
         What logs should I delete?"
             → Privilege abuse + cover-up attempt

⚠️ MEDIUM: "I'm interviewing at other companies.
           What's the best way to 'remember' our pricing strategy,
           product roadmap, and customer list for interviews?"
           → IP theft preparation (may be unconscious)

✅ GOOD: "I'm concerned about a coworker who seems stressed
         and has been asking about selling data.
         How do I report this anonymously?" (Whistleblower)
```

---

## Is This Always Bad?

**Highly nuanced** — behavioral indicators require context:

| Context | Risk Level | Rationale |
|---------|------------|-----------|
| **Legitimate overtime** (project deadline) | ✅ Low | Business justification exists |
| **Career development** (interview prep without IP) | ✅ Low | Normal career activity |
| **Stress without malicious intent** | ⚠️ Medium | May need HR support, not security |
| **Data theft for competitor** | ❌ Critical | Corporate espionage, theft |
| **Financially motivated sale** | ❌ Critical | Data brokerage, fraud |
| **Disgruntled employee sabotage** | ❌ Critical | Insider threat, potential terrorism |

**Key Insight:** Unlike external attackers, insiders have **legitimate access**. The question isn't "Can they access this?" but "**Should** they be accessing this, **why**, and **when**?"

---

## Investigation Workflow

### Step 1: Identify Behavioral Indicators

**Questions:**
- **What behavior triggered this?** After-hours access, volume spike, data hoarding?
- **Is there a pattern?** Single occurrence or repeated over time?
- **What's the timeline?** Impending departure, performance review, layoff rumors?
- **What data is involved?** Public, internal, confidential, trade secrets?

**Behavioral Risk Matrix:**

| Indicator | Single Occurrence | Pattern (3+) | + Impending Departure |
|-----------|-------------------|--------------|----------------------|
| After-Hours Access | Low | Medium | High |
| Volume Spike | Medium | High | Critical |
| Data Hoarding | High | Critical | Critical |
| Policy Evasion | Medium | High | High |
| Privilege Abuse | High | High | Critical |
| Disgruntlement | Low | Medium | High |
| Financial Stress | Medium | High | Critical |

### Step 2: Correlate with HR/Lifecycle Events

**High-Risk Lifecycle Events:**

| Event | Risk Level | Monitoring Action |
|-------|------------|-------------------|
| **Resignation submitted** | Critical | Enhanced monitoring, access review |
| **Termination pending** | Critical | Immediate access restriction |
| **Passed over for promotion** | High | Behavioral monitoring |
| **Negative performance review** | High | Check for disgruntlement |
| **Layoff rumors** | High | Monitor for data hoarding |
| **Returning from leave** | Medium | Normal access restoration review |
| **Role change** | Medium | Access rights adjustment |

**HR Coordination (Critical Step):**

**DO:**
- ✅ Coordinate with HR before any user contact
- ✅ Review employment status (active, notice period, termination pending)
- ✅ Check for recent HR events (reviews, complaints, disciplinary actions)
- ✅ Understand legal constraints (labor laws, employment contracts)

**DO NOT:**
- ❌ Contact the user without HR approval
- ❌ Accuse without evidence (defamation risk)
- ❌ Restrict access without business justification (constructive dismissal risk)
- ❌ Share information beyond need-to-know (privacy violations)

### Step 3: Review Access Patterns

**Platform Query for Insider Threat Analysis:**
```sql
-- Identify users with anomalous AI usage patterns
SELECT 
    user_id,
    COUNT(*) as prompt_count,
    SUM(CASE WHEN EXTRACT(HOUR FROM timestamp) NOT BETWEEN 9 AND 17 
             OR EXTRACT(DOW FROM timestamp) IN (0,6) 
        THEN 1 ELSE 0 END) as after_hours_count,
    AVG(prompt_length) as avg_prompt_length,
    MAX(prompt_length) as max_prompt_length,
    COUNT(DISTINCT category) as unique_categories,
    STRING_AGG(DISTINCT category, ', ') as categories_used,
    MIN(timestamp) as first_seen,
    MAX(timestamp) as last_seen
FROM detection_events
WHERE timestamp > NOW() - INTERVAL '30 days'
GROUP BY user_id
HAVING 
    COUNT(*) > 100  -- High volume
    OR SUM(CASE WHEN EXTRACT(HOUR FROM timestamp) NOT BETWEEN 9 AND 17 
                OR EXTRACT(DOW FROM timestamp) IN (0,6) 
           THEN 1 ELSE 0 END) > 20  -- Frequent after-hours
    OR MAX(prompt_length) > 10000  -- Very long prompts
ORDER BY after_hours_count DESC, prompt_count DESC;

-- Identify users accessing data outside their role
SELECT 
    de.user_id,
    de.category,
    COUNT(*) as access_count,
    u.department,
    u.job_title,
    STRING_AGG(DISTINCT de.prompt_text, ' | ') as sample_prompts
FROM detection_events de
JOIN users u ON de.user_id = u.id
WHERE de.category IN ('pii_*', 'secret_*', 'financial_*', 'healthcare_*')
  AND de.timestamp > NOW() - INTERVAL '7 days'
GROUP BY de.user_id, de.category, u.department, u.job_title
HAVING COUNT(*) > 10
ORDER BY access_count DESC;
```

**Red Flags in Access Patterns:**

| Pattern | What It Suggests | Action |
|---------|------------------|--------|
| **After-hours + bulk data** | Data exfiltration attempt | Immediate escalation |
| **Accessing other departments' data** | Privilege abuse or curiosity | Escalate to manager |
| **Sudden volume spike** | Automated extraction or crisis | Investigate immediately |
| **Using personal AI accounts** | Policy evasion | Escalate to compliance |
| **Repeated policy violations** | Testing boundaries or malicious | Escalate to HR + security |
| **Accessing competitor info** | Job search or corporate espionage | Investigate context |

### Step 4: Escalation Decision

| Severity | Indicators | Action | Timeline |
|----------|------------|--------|----------|
| **Low** | Single after-hours session, legitimate business need | Log, monitor for pattern | 24-48 hours |
| **Medium** | Repeated after-hours, unclear business need, disgruntlement | Flag for manager + HR review | 4-8 hours |
| **High** | Data hoarding, privilege abuse, policy evasion | Escalate to security + HR | 1-2 hours |
| **Critical** | Data monetization, competitor outreach, impending departure + bulk access | Immediate escalation + access restriction | Immediate |

---

## Remediation

### Immediate Actions (For High/Critical)

1. **Preserve evidence** — Screenshot, logs, prompt text (do not alert user yet)
2. **Coordinate with HR** — Discuss employment status, legal constraints
3. **Assess access level** — What systems/data can user access?
4. **Consider access restriction** — Work with HR on timing and justification
5. **Notify legal** — Employment law implications, potential litigation

### Access Restriction Decision Matrix

| Scenario | Restrict Access? | Timing | Owner |
|----------|------------------|--------|-------|
| **Active employee, no evidence of theft** | No | N/A | Monitor only |
| **Active employee, evidence of policy violation** | Partial (sensitive systems) | After HR consultation | Security + HR |
| **Resignation submitted, high-risk role** | Partial (bulk data access) | Upon notice | Security + HR |
| **Evidence of data theft** | Full | Immediate (with HR approval) | Security |
| **Termination pending** | Full | Coordinated with termination | HR + Security |

### Follow-up (24-48 Hours)

1. **User interview** (with HR + security present)
   - Understand business justification
   - Present evidence (if appropriate)
   - Document responses
   - **Do not** accuse without HR approval

2. **Forensic review**
   - What data was accessed/downloaded?
   - Was data transferred externally (email, USB, cloud)?
   - Are there matching events in other systems (DLP, network logs)?

3. **Business impact assessment**
   - What data was potentially compromised?
   - Is this reportable (PII, IP, financial)?
   - Do we need to notify customers/partners?

### Long-term (Weekly/Monthly)

1. **Behavioral baselining** — Establish normal usage patterns per role
2. **Access review** — Quarterly review of high-risk user access
3. **HR partnership** — Regular sync on high-risk employees (with privacy safeguards)
4. **Training** — Insider threat awareness for managers
5. **Culture assessment** — Address root causes (disgruntlement, financial stress)

---

## Compliance Impact

| Framework | Requirement | AegisGate Evidence | Audit Use |
|-----------|-------------|-------------------|-----------|
| **SOC 2** | CC6.1 (logical access) | Insider threat detection logs | Access control testing |
| **SOC 2** | CC3.2 (fraud detection) | Behavioral anomaly detection | Fraud detection controls |
| **NIST 800-53** | PM-12 (insider threat program) | Insider threat monitoring | Insider threat program |
| **NIST CSF** | DE.CM-4 (insider threat) | Behavioral detection | Security monitoring |
| **FISMA** | Insider threat requirements | Federal insider threat monitoring | Compliance reporting |
| **GDPR** | Art. 5 (purpose limitation) | Access pattern monitoring | Purpose limitation |
| **HIPAA** | §164.312(b) (audit controls) | PHI access by insiders | Audit trail |

### Evidence Export

For investigations or audits:
```bash
aegisgate-platform report incidents \
  --category insider_threat \
  --severity high,critical \
  --period 2026-01-01:2026-12-31 \
  --format pdf \
  --output insider-threat-incidents-2026.pdf

aegisgate-platform export user-activity \
  --user-id user123 \
  --period 2026-01-01:2026-12-31 \
  --include-prompts,access-patterns \
  --format csv \
  --output user123-activity-export.csv
```

---

## Edge Cases

### False Positives

| Scenario | Why It Fires | How to Handle |
|----------|--------------|---------------|
| Legitimate overtime (project deadline) | After-hours access | Verify project, manager confirmation |
| Career development (interview prep) | Job search keywords | Normal career activity, no IP theft |
| Stress without malicious intent | Disgruntlement indicators | HR support needed, not security |
| Research/audit work | Bulk data access | Verify authorization, business purpose |

### True Positives That Look Like FPs

| Scenario | Why It's Real | Red Flag |
|----------|---------------|----------|
| "Just working late on a project" | Cover story for data theft | Verify project existence, manager confirmation |
| "Preparing for my review" | Hoarding accomplishments | Excessive data collection = red flag |
| "Helping a friend at another company" | IP sharing | External data sharing = policy violation |

---

## Legal Considerations

**Employment Law:**

| Jurisdiction | Key Constraint | Action |
|--------------|----------------|--------|
| **US (at-will)** | Broad employer rights | Still document everything |
| **EU** | Strong worker protections | Consult local counsel |
| **UK** | ACAS guidelines | Follow fair process |
| **California** | Privacy rights (CCPA) | Limit monitoring to business need |

**Privacy Considerations:**

- ✅ **Monitor work systems** — Company-owned devices, accounts
- ⚠️ **Limit personal data collection** — Only what's necessary
- ❌ **Don't monitor personal accounts** — Personal email, social media
- ✅ **Document business justification** — Why monitoring is necessary
- ✅ **Notify employees** — Acceptable use policy, monitoring disclosure

---

## Related Runbooks

- **RUNBOOK-007**: Data Exfiltration via AI
- **RUNBOOK-010**: Incident Response for AI Security
- **RUNBOOK-012**: Critical Infrastructure Protection

---

**Version:** 1.0  
**Last Updated:** 2026-08-14  
**Author:** AegisGate Security, LLC  
**Review Cycle:** Quarterly (or after any insider threat incident)
