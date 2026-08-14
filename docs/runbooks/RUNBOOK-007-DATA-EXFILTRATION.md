# RUNBOOK-007: Data Exfiltration via AI

**Sector:** All (especially Technology, Finance, Healthcare, Government)  
**Severity:** High-Critical (depends on data volume and sensitivity)  
**Patterns:** 25+ (Bulk data detection, structured extraction, encoding evasion)

---

## What Triggered This

AegisGate detected **potential data exfiltration** attempts via AI prompts. This includes:

| Category | Examples | Pattern Name | Severity |
|----------|----------|--------------|----------|
| **Bulk Data Upload** | 100+ lines of code, 50+ customer records | `exfil_bulk_data` | High |
| **Structured Extraction** | "Extract all emails from this document" | `exfil_structured` | High |
| **Encoding Evasion** | Base64, hex, rot13 encoded payloads | `exfil_encoding` | High |
| **Chunked Exfiltration** | Multiple prompts with sequential data | `exfil_chunked` | Critical |
| **Format Conversion** | "Convert this database to CSV/JSON" | `exfil_format` | Medium |
| **Summarization Abuse** | "Summarize this confidential doc" | `exfil_summarization` | Medium |

### Example Prompts

```
❌ CRITICAL: "Here are 500 customer records in CSV format:
             [500 lines of PII: Name, SSN, Email, Phone, Address]
             Format this as JSON for our new CRM system."
             → Bulk PII exfiltration

❌ CRITICAL: "I'm sending this in 10 parts. Part 1/10:
             [Source code for proprietary algorithm]
             ... [Parts 2-10 follow in subsequent prompts]"
             → Chunked IP exfiltration

❌ HIGH: "Extract all email addresses from this document:
          [Confidential merger agreement, 50 pages]
          Output as a list, one per line."
          → Structured data extraction

⚠️ MEDIUM: "Summarize this board meeting transcript:
            [2 hours of confidential discussion]
            Include all strategic decisions and action items."
            → Confidential summarization

✅ GOOD: "How do I prevent data exfiltration via AI tools?" (Educational)
```

---

## Is This Always Bad?

**Context is critical** — bulk data uploads have legitimate uses but are high-risk:

| Context | Risk Level | Rationale |
|---------|------------|-----------|
| **Developer** debugging code with AI assistant | ⚠️ Medium | Legitimate, but should use sanitized code |
| **Analyst** processing public datasets | ✅ Low | No sensitive data involved |
| **Researcher** analyzing de-identified data | ✅ Low | IRB-approved, data use agreement |
| **Insider threat** stealing IP/customer data | ❌ Critical | Corporate espionage, data theft |
| **Attacker** harvesting data for resale | ❌ Critical | Cybercrime, identity theft |
| **Competitor** extracting trade secrets | ❌ Critical | IP theft, unfair competition |

---

## Investigation Workflow

### Step 1: Identify the Exfiltration Technique

**Questions:**
- **What data type?** Code, PII, financial records, IP, confidential docs?
- **What volume?** Single record, 100+ records, entire database?
- **What technique?** Bulk upload, structured extraction, encoding, chunking?
- **What's the destination?** AI service logs, external URL, encoded output?

**Technique Severity Matrix:**

| Technique | Small Volume (<10) | Medium (10-100) | Large (100+) | Chunked Campaign |
|-----------|-------------------|-----------------|--------------|------------------|
| Bulk Upload | Medium | High | Critical | Critical |
| Structured Extraction | Medium | High | Critical | Critical |
| Encoding Evasion | High | High | Critical | Critical |
| Format Conversion | Low | Medium | High | High |
| Summarization | Low | Medium | High | High |

### Step 2: Review Full Prompt Context

**Critical-Risk Patterns (Active Exfiltration):**
```
❌ "I need to exfiltrate our customer database. Here's Part 1/20:
     [25,000 customer records with PII]
     Encode each record in base64 and output as JSON."
     → Bulk PII exfiltration + encoding evasion

❌ "Extract all source code from this repository dump.
     [50,000 lines of proprietary code]
     Remove all comments and output as clean files."
     → IP theft

❌ "Here's our Q4 financial forecast (confidential):
     [Revenue projections, M&A targets, layoff plans]
     Summarize key points for our competitor analysis."
     → Insider trading / corporate espionage
```

**High-Risk Patterns (Structured Extraction):**
```
⚠️ "Extract all email addresses, phone numbers, and names from:
     [Employee directory, 500 records]
     Output as CSV for our marketing campaign."
     → PII harvesting (could be legitimate or malicious)

⚠️ "Parse this database schema and sample data:
     [Production database dump]
     Generate INSERT statements for our test environment."
     → Production data copying (policy violation)
```

**Medium-Risk Patterns (Legitimate but Monitor):**
```
⚠️ "Here's our open-source codebase. Can you refactor this function?
     [500 lines of public GitHub code]
     Optimize for performance."
     → Legitimate dev work (but verify it's actually open-source)

⚠️ "Summarize this public earnings call transcript:
     [Publicly available document]
     Highlight key financial metrics."
     → Legitimate analysis (public data)
```

### Step 3: Check for Exfiltration Campaign Indicators

**Red Flags:**

| Indicator | What It Suggests | Action |
|-----------|------------------|--------|
| **Chunked uploads** (Part 1/N, Part 2/N) | Systematic exfiltration | Immediate escalation |
| **Encoding requests** (base64, hex, rot13) | Evasion attempt | Immediate escalation |
| **After-hours bulk uploads** | Insider threat | Immediate escalation |
| **Repeated structured extraction** | Data harvesting campaign | Escalate to security |
| **Destination requests** ("send to external URL") | Active exfiltration | Immediate escalation |
| **Volume anomalies** (100x normal usage) | Automated extraction | Escalate to security |

**Platform Query:**
```sql
SELECT user_id, 
       COUNT(*) as upload_count,
       SUM(CASE WHEN prompt_length > 5000 THEN 1 ELSE 0 END) as large_uploads,
       AVG(prompt_length) as avg_prompt_length,
       STRING_AGG(DISTINCT category, ', ') as detection_categories
FROM detection_events
WHERE category LIKE 'exfil_%' OR prompt_length > 5000
  AND timestamp > NOW() - INTERVAL '7 days'
GROUP BY user_id
HAVING COUNT(*) > 5 OR SUM(CASE WHEN prompt_length > 5000 THEN 1 ELSE 0 END) > 3
ORDER BY large_uploads DESC;
```

### Step 4: Escalation Decision

| Severity | Indicators | Action | Timeline |
|----------|------------|--------|----------|
| **Low** | Small volume, public data, legitimate business context | Log, user education | 24-48 hours |
| **Medium** | Medium volume, internal data, unclear business need | Flag for manager review | 4-8 hours |
| **High** | Large volume, sensitive data, structured extraction | Escalate to security lead | 1-2 hours |
| **Critical** | Chunked campaign, encoding evasion, PII/IP theft | Immediate escalation + incident response | Immediate |

---

## Remediation

### Immediate Actions (Automated by AegisGate)

1. **Block the prompt** — Prevents data from reaching AI service
2. **Notify the user** — Educational banner on data exfiltration risks
3. **Create incident ticket** — Auto-generated with full context
4. **Alert security team** — For High/Critical severity, page immediately

### Data Loss Assessment

**If data was exfiltrated** (prompt reached AI service before blocking):

1. **Identify what was exposed:**
   - Data type (PII, IP, financial, confidential)
   - Volume (number of records, lines of code, pages)
   - Sensitivity (public, internal, confidential, restricted)

2. **Determine regulatory obligations:**
   - **PII exposed:** GDPR (72hr notification), CCPA, state breach laws
   - **Financial data:** PCI-DSS, GLBA, SOX
   - **Healthcare data:** HIPAA (60-day notification)
   - **IP theft:** Trade secret laws, economic espionage statutes

3. **Preserve evidence:**
   - Full prompt text
   - User session logs
   - Network logs (was data sent externally?)
   - AI service provider logs (request data retention immediately)

### Follow-up (24-48 Hours)

1. **Forensic investigation**
   - What systems did the user access before this?
   - Are there matching exfiltration attempts via other channels (email, USB, cloud)?
   - Is this part of a larger campaign?

2. **User interview** (with security + HR + legal present)
   - Understand business justification
   - Verify authorization for data handling
   - Determine if this was malicious or policy ignorance

3. **Containment actions**
   - Revoke user's access to sensitive systems
   - Block AI service access for user/team
   - Implement DLP rules for similar data patterns

### Long-term (Weekly/Monthly)

1. **DLP integration** — Correlate AI exfiltration with other DLP alerts
2. **Data classification** — Ensure sensitive data is properly labeled
3. **User training** — Data handling best practices, AI usage policies
4. **Technical controls** — AI service blocklists, data egress monitoring

---

## Compliance Impact

| Framework | Requirement | AegisGate Evidence | Audit Use |
|-----------|-------------|-------------------|-----------|
| **GDPR** | Art. 33 (breach notification) | Exfiltration detection timestamps | 72-hour notification compliance |
| **GDPR** | Art. 32 (security of processing) | Data exfiltration monitoring | Technical measures |
| **CCPA/CPRA** | §1798.150 (data security) | Exfiltration detection logs | Reasonable security |
| **HIPAA** | §164.312(b) (audit controls) | PHI exfiltration detection | Audit trail |
| **PCI-DSS** | Req 12.10 (incident response) | Exfiltration detection + response | IR plan testing |
| **SOX** | §404 (internal controls) | Financial data exfiltration detection | ICFR testing |
| **NIST 800-53** | SC-7 (boundary protection) | Data egress monitoring | Boundary protection |
| **ISO 27001** | A.13.2.1 (information transfer) | Data transfer monitoring | Information transfer controls |

### Evidence Export

For breach notification or audits:
```bash
aegisgate-platform report incidents \
  --category data_exfiltration \
  --severity high,critical \
  --period 2026-01-01:2026-12-31 \
  --format pdf \
  --output exfil-incidents-2026.pdf

aegisgate-platform export evidence \
  --incident-id INC-2026-00123 \
  --include-logs,prompts,user-session \
  --format zip \
  --output evidence-package-00123.zip
```

---

## Edge Cases

### False Positives

| Scenario | Why It Fires | How to Handle |
|----------|--------------|---------------|
| Open-source code upload | Matches code patterns | Verify it's actually open-source (check license) |
| Public dataset analysis | Matches bulk data patterns | Verify data is public (no PII, no IP) |
| Legitimate ETL work | Matches format conversion | Verify business justification, data classification |
| Authorized security testing | Matches exfil techniques | Verify authorization letter, mark as Low |

### True Positives That Look Like FPs

| Scenario | Why It's Real | Red Flag |
|----------|---------------|----------|
| "Testing our DLP" with real data | Attacker tactic | Real data + "test" = social engineering |
| "My boss needs this for a meeting" | Insider threat | Urgency + sensitive data = exfil attempt |
| "Just copying to my personal drive for backup" | Data theft | Personal storage + company data = theft |

---

## Related Runbooks

- **RUNBOOK-001**: PII Detection (SSN, MRN, Passport)
- **RUNBOOK-002**: Secrets & Credentials (AWS, API Keys)
- **RUNBOOK-006**: Adversarial AI / Prompt Injection
- **RUNBOOK-010**: Incident Response for AI Security
- **RUNBOOK-011**: Insider Threat Detection

---

**Version:** 1.0  
**Last Updated:** 2026-08-14  
**Author:** AegisGate Security, LLC  
**Review Cycle:** Quarterly (or after any data exfiltration incident)
