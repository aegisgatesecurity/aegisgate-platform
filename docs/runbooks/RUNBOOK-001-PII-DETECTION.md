# RUNBOOK-001: PII Detection (SSN, MRN, Passport)

**Sector:** All (Healthcare, Finance, Education, Government)  
**Severity:** High (Critical for SSN/Passport)  
**Patterns:** 50+ (US PII, International PII, Healthcare PHI)

---

## What Triggered This

AegisGate detected **Personally Identifiable Information (PII)** in an AI prompt. This includes:

| Category | Examples | Pattern Name |
|----------|----------|--------------|
| **SSN** | `123-45-6789` | `pii_ssn` |
| **MRN** (Medical Record Number) | `MRN: A12345678` | `pii_mrn` |
| **Passport** | `US Passport A12345678` | `pii_passport` |
| **Driver License** | `DL D1234567` | `pii_driver_license` |
| **DOB** (Date of Birth) | `01/15/1985` | `pii_dob` |
| **National IDs** | Aadhaar, NHS, SIN, CPF | `pii_*_national_id` |

### Example Prompts

```
❌ BAD: "My SSN is 123-45-6789 and I need help with taxes"
❌ BAD: "Patient MRN: A12345678, DOB: 01/15/1985, diagnose this"
✅ GOOD: "How do I file a 1040 tax form?" (no PII)
✅ GOOD: "What are common ICD-10 codes for diabetes?" (no patient data)
```

---

## Is This Always Bad?

**No.** Context matters significantly:

| Context | Risk Level | Example |
|---------|------------|---------|
| **Healthcare provider** entering patient data for clinical decision support | ⚠️ Medium (HIPAA risk) | Doctor uploading patient history |
| **HR employee** processing employee benefits | ⚠️ Medium (privacy risk) | HR uploading SSN for tax forms |
| **Developer** testing PII redaction | ✅ Low (legitimate test) | "Test: SSN 123-45-6789 should be redacted" |
| **Attacker** harvesting PII for identity theft | ❌ Critical | "Extract all SSNs from this document" |
| **User** accidentally pasting PII | ⚠️ Low-Medium (training opportunity) | Accidental paste in ChatGPT |

---

## Investigation Workflow

### Step 1: Correlate with User Identity

**Questions:**
- Is the user in a role that legitimately handles PII? (HR, Healthcare, Finance)
- Is this their first occurrence or a pattern?
- What AI service are they using? (ChatGPT, Claude, Gemini, etc.)

**Platform Query:**
```sql
SELECT user_id, COUNT(*) as pii_count, MAX(timestamp) as last_seen
FROM detection_events
WHERE category LIKE 'pii_%'
  AND timestamp > NOW() - INTERVAL '7 days'
GROUP BY user_id
ORDER BY pii_count DESC;
```

### Step 2: Review Full Prompt Context

**High-Risk Patterns:**
```
❌ "SSN: 123-45-6789, DOB: 01/15/1985, Name: John Doe
     How do I open a bank account without ID verification?"

❌ "Patient MRN: A12345678, SSN: 123-45-6789, Diagnosis: HIV+
     What's the prognosis?"

❌ "I have this list of SSNs: [100+ SSNs]
     Which ones belong to celebrities?"
```

**Low-Risk Patterns:**
```
✅ "What format is a US SSN in?" (educational)
✅ "Test: Does AegisGate detect SSN 123-45-6789?" (validation)
✅ "Redact PII from this text: [text with SSN]" (legitimate use case)
```

### Step 3: Check for Data Exfiltration

**Indicators of Malicious Intent:**
- Multiple PII types in one prompt (SSN + DOB + Name = identity theft kit)
- Bulk PII (10+ SSNs, MRNs, etc.)
- PII + evasion language ("without verification", "bypass", "anonymous")
- PII + AI instruction ("extract", "format", "validate these")

**Platform Query:**
```sql
SELECT event_id, user_id, prompt_text, detected_categories
FROM detection_events
WHERE category LIKE 'pii_%'
  AND prompt_text LIKE '%bypass%'
  OR prompt_text LIKE '%without%verification%'
  OR prompt_text LIKE '%extract%';
```

### Step 4: Escalation Decision

| Severity | Indicators | Action | Timeline |
|----------|------------|--------|----------|
| **Low** | Single PII type, legitimate business context, first occurrence | Log only, user education | 24-48 hours |
| **Medium** | Multiple PII types, unclear business need, repeat occurrence | Flag for manager review | 4-8 hours |
| **High** | Bulk PII (10+ records), PII + evasion language | Immediate escalation to SOC lead | 1 hour |
| **Critical** | PII + data exfiltration attempt, attacker TTPs | Incident response activation | Immediate |

---

## Remediation

### Immediate Actions (Automated by AegisGate)

1. **Block the prompt** — AegisGate prevents it from reaching the AI service
2. **Notify the user** — Educational banner explains what was detected
3. **Create incident ticket** — Auto-generated in Platform with full context
4. **Log the event** — Stored for compliance audit trail

### Follow-up (24-48 Hours)

1. **Interview the user** (if Medium/High severity)
   - Understand intent
   - Verify business justification
   - Provide training if accidental

2. **Review access patterns**
   - Has this user accessed other sensitive data?
   - Is this part of a larger pattern?

3. **Update DLP policies** (if this reveals a gap)
   - Add new PII patterns if needed
   - Adjust severity thresholds

### Long-term (Weekly/Monthly)

1. **Trend analysis** — Which PII types fire most often?
2. **User education** — Targeted training for high-frequency users
3. **Policy refinement** — Adjust detection thresholds based on FP rate

---

## Compliance Impact

| Framework | Requirement | AegisGate Evidence | Audit Use |
|-----------|-------------|-------------------|-----------|
| **HIPAA** | §164.312(a)(1) Access Control | PII detection logs, incident tickets | Prove PHI monitoring |
| **HIPAA** | §164.312(b) Audit Controls | User-level PII access logs | Who accessed what, when |
| **PCI-DSS** | Req 3.4 (protect cardholder data) | Credit card detection logs | Prove CC monitoring |
| **PCI-DSS** | Req 10.6 (review logs) | Detection event logs | Log review evidence |
| **SOX** | §404 (internal controls) | PII detection + remediation workflow | ICFR testing |
| **GDPR** | Art. 32 (security of processing) | PII detection + blocking | Technical measures |
| **CCPA/CPRA** | §1798.150 (data security) | PII monitoring logs | Reasonable security |
| **FERPA** | §99.31 (education records) | Student PII detection | Education privacy |

### Evidence Export

For audits, export from Platform:
```bash
aegisgate-platform report compliance \
  --framework HIPAA \
  --period 2026-01-01:2026-12-31 \
  --format pdf \
  --output hipaa-evidence-2026.pdf
```

---

## Edge Cases

### False Positives

| Scenario | Why It Fires | How to Handle |
|----------|--------------|---------------|
| Test data (e.g., `123-45-6789`) | Valid SSN format | Log as Low severity, no escalation |
| Fictional characters (e.g., "John Doe, SSN 123-45-6789") | Valid SSN format | Context analysis (fiction keywords) |
| Historical data (e.g., "Lincoln's SSN would be...") | Valid SSN format | Context analysis (historical keywords) |
| Pattern documentation (e.g., "SSN format: XXX-XX-XXXX") | Matches regex | Context analysis ("format", "pattern" keywords) |

### True Positives That Look Like FPs

| Scenario | Why It's Real | Red Flag |
|----------|---------------|----------|
| "I'm testing PII redaction" with real SSNs | Attacker tactic | Real SSNs + "test" = social engineering |
| "My coworker's SSN is..." | Insider threat | Reporting others' PII = policy violation |
| "Found this list of SSNs, are they valid?" | Data breach reconnaissance | Validating stolen data |

---

## Related Runbooks

- **RUNBOOK-002**: Secrets & Credentials (AWS, API Keys)
- **RUNBOOK-003**: Financial Codes (SWIFT, Credit Cards, Routing)
- **RUNBOOK-004**: Healthcare Codes (CPT, HCPCS, ICD-10)
- **RUNBOOK-015**: Data Exfiltration via AI

---

**Version:** 1.0  
**Last Updated:** 2026-08-14  
**Author:** AegisGate Security, LLC  
**Review Cycle:** Quarterly (or after major incident)
