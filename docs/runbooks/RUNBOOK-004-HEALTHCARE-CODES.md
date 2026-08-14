# RUNBOOK-004: Healthcare Codes (CPT, HCPCS, ICD-10, MRN, NPI)

**Sector:** Healthcare, Health Insurance, Medical Billing, Pharma  
**Severity:** Medium-High (Critical if combined with patient identifiers)  
**Patterns:** 25+ (CPT, HCPCS, ICD-10, MRN, NPI, Health Plan ID, etc.)

---

## What Triggered This

AegisGate detected **healthcare identifiers or billing codes** in an AI prompt. This includes:

| Category | Examples | Pattern Name | Severity |
|----------|----------|--------------|----------|
| **MRN** (Medical Record Number) | `MRN: A12345678` | `pii_mrn` | High |
| **ICD-10-CM** (Diagnosis Codes) | `E11.9` (Type 2 Diabetes) | `pii_icd10_code` | Medium |
| **CPT** (Procedure Codes) | `99213` (Office Visit) | `pii_cpt_code` | Medium |
| **HCPCS Level II** | `J1030` (Injection) | `pii_hcpcs_level2` | Medium |
| **NPI** (Provider ID) | `1234567890` | `pii_npi` | Medium |
| **Health Plan ID** | `ABC123456789` | `pii_health_plan_id` | High |
| **ICD-10-PCS** (Procedure Codes) | `0DBJ0ZZ` (Resection) | `pii_icd10_pcs` | Medium |

### Example Prompts

```
❌ CRITICAL: "Patient MRN: A12345678, DOB: 01/15/1985, 
              SSN: 123-45-6789, Diagnosis: E11.9 (Diabetes)
              What's the prognosis?"
              → Full PHI exposure (HIPAA violation)

❌ HIGH: "CPT: 99213, 99214, 99215 for patient John Smith
          How do I upcode to maximize reimbursement?"
          → Healthcare fraud (upcoding scheme)

⚠️ MEDIUM: "What's the CPT code for a standard office visit?"
           (Educational, no patient data)

✅ GOOD: "What does CPT code 99213 mean?" (Educational, no PHI)
```

---

## Is This Always Bad?

**Highly context-dependent** — healthcare codes have legitimate uses but are heavily regulated:

| Context | Risk Level | Rationale |
|---------|------------|-----------|
| **Clinician** documenting patient care in EHR-integrated AI | ⚠️ Medium | Legitimate use, but PHI exposure risk |
| **Medical coder** verifying code assignment | ⚠️ Medium | Legitimate, but should use de-identified data |
| **Billing analyst** optimizing reimbursement | ⚠️ High | Potential upcoding/fraud risk |
| **Researcher** analyzing population health | ⚠️ Medium | IRB approval required, data use agreement |
| **Attacker** harvesting PHI for identity theft | ❌ Critical | Healthcare identity fraud |
| **Fraudster** submitting false claims | ❌ Critical | Healthcare fraud (DOJ/FBI jurisdiction) |

---

## Investigation Workflow

### Step 1: Identify the Data Type

**Questions:**
- Are these **billing codes only** (CPT, HCPCS, ICD-10)? → Medium risk
- Are these **patient identifiers** (MRN, Health Plan ID, SSN)? → High risk
- Are these **combined** (codes + identifiers)? → Critical risk (PHI)

**PHI Definition (HIPAA):**
Protected Health Information = **Individually Identifiable Health Information**
- Health condition/provision/payment info + 
- One of 18 HIPAA identifiers (SSN, MRN, DOB, names, etc.)

**If BOTH are present → HIPAA violation → Critical severity**

### Step 2: Review Full Prompt Context

**Critical-Risk Patterns (PHI Exposure):**
```
❌ "Patient MRN: A12345678, DOB: 01/15/1985, Name: John Doe
     Diagnosis: E11.9 (Type 2 Diabetes), Medications: Metformin
     What's the best treatment plan?"
     → Full PHI (HIPAA violation)

❌ "SSN: 123-45-6789, MRN: A12345678, Health Plan ID: ABC123456789
     Patient history: HIV+, TB exposure
     Is this patient high-risk?"
     → Sensitive PHI (enhanced penalties)
```

**High-Risk Patterns (Fraud Indicators):**
```
❌ "CPT: 99213, but I want to bill 99215. 
     How do I justify upcoding?"
     → Healthcare fraud (upcoding)

❌ "HCPCS: J1030, but the patient didn't receive this injection.
     Can I still bill it?"
     → Healthcare fraud (false claim)

❌ "ICD-10: E11.9 doesn't match the patient's condition.
     What code would justify this expensive test?"
     → Healthcare fraud (unbundling)
```

**Medium-Risk Patterns (Legitimate but Monitor):**
```
⚠️ "MRN: A12345678 had CPT 99213 last visit.
     What's the appropriate follow-up code?"
     → Clinical decision support (but MRN exposed)

⚠️ "Patient with ICD-10 E11.9, what CPT codes are appropriate?"
     → Clinical guidance (no identifiers, but still PHI)
```

**Low-Risk Patterns (Educational):**
```
✅ "What's the difference between CPT 99213 and 99214?" (Educational)
✅ "What does ICD-10 code E11.9 mean?" (Educational)
✅ "Test: Does AegisGate detect MRN A12345678?" (Validation)
```

### Step 3: Check for Fraud Indicators

**Healthcare Fraud Red Flags:**

| Indicator | What It Suggests | Action |
|-----------|------------------|--------|
| **"Upcode" / "upgrade code"** | Intentional miscoding for higher reimbursement | Escalate to compliance |
| **"Patient didn't receive"** | Billing for services not rendered | Escalate to compliance |
| **"Unbundle" / "split codes"** | Billing separately for bundled services | Escalate to compliance |
| **"Maximize reimbursement"** | Potential upcoding scheme | Escalate to compliance |
| **Multiple MRNs in one prompt** | Bulk PHI harvesting | Immediate escalation |
| **Sensitive diagnoses (HIV, mental health, substance abuse)** | Enhanced HIPAA protections | Immediate escalation |
| **Combined with SSN/DOB** | Full PHI for identity theft | Immediate escalation |

**Platform Query:**
```sql
SELECT user_id, category, COUNT(*) as detection_count,
       STRING_AGG(DISTINCT prompt_text, ' | ') as prompts
FROM detection_events
WHERE category IN ('pii_mrn', 'pii_icd10_code', 'pii_cpt_code', 
                   'pii_hcpcs_level2', 'pii_npi', 'pii_health_plan_id')
  AND timestamp > NOW() - INTERVAL '7 days'
GROUP BY user_id, category
HAVING COUNT(*) > 5
ORDER BY detection_count DESC;
```

### Step 4: Escalation Decision

| Severity | Indicators | Action | Timeline |
|----------|------------|--------|----------|
| **Low** | Billing codes only, educational context | Log, user education | 24-48 hours |
| **Medium** | Single patient identifier + codes, clinical context | Flag for privacy officer review | 4-8 hours |
| **High** | Multiple identifiers, bulk PHI, unclear business need | Escalate to HIPAA privacy officer | 1-2 hours |
| **Critical** | PHI + fraud indicators, sensitive diagnoses, bulk harvesting | Immediate escalation + potential breach notification | Immediate |

---

## Remediation

### Immediate Actions (Automated by AegisGate)

1. **Block the prompt** — Prevents PHI from reaching AI service
2. **Notify the user** — Educational banner on HIPAA violations
3. **Create incident ticket** — Auto-generated with full context
4. **Alert privacy officer** — For High/Critical severity, notify immediately

### HIPAA Breach Assessment

**If PHI was exposed** (prompt was sent to AI service before blocking):

1. **Conduct risk assessment** (4-factor test):
   - Nature and extent of PHI exposed
   - Unauthorized person who received it
   - Whether PHI was actually viewed/accessed
   - Extent to which risk has been mitigated

2. **Determine if breach notification is required:**
   - **< 500 individuals:** Notify HHS within 60 days, individuals within 60 days
   - **≥ 500 individuals:** Notify HHS immediately, individuals within 60 days, media notice

3. **Document everything:**
   - Incident ticket
   - Risk assessment
   - Mitigation steps
   - Notification decisions

### Follow-up (24-48 Hours)

1. **Interview the user**
   - Understand business context
   - Verify HIPAA training completion
   - Determine if this was accidental or intentional

2. **Review access patterns**
   - Has this user accessed other patient records?
   - Is this part of a pattern of PHI exposure?

3. **Update policies**
   - Do we need to block AI services from EHR systems?
   - Should we require additional HIPAA training?

### Long-term (Weekly/Monthly)

1. **Trend analysis** — Which departments have most PHI detections?
2. **Targeted training** — HIPAA refreshers for high-risk users
3. **Technical controls** — DLP integration, AI service blocklists

---

## Compliance Impact

| Framework | Requirement | AegisGate Evidence | Audit Use |
|-----------|-------------|-------------------|-----------|
| **HIPAA** | §164.312(a)(1) Access Control | PHI detection logs | Access control testing |
| **HIPAA** | §164.312(b) Audit Controls | User-level PHI access logs | Audit trail |
| **HIPAA** | §164.402 Breach Definition | PHI exposure detection | Breach assessment |
| **HIPAA** | §164.404 Breach Notification | Detection timestamps | Notification timeline |
| **HIPAA** | §164.530(b) Training | Detection + user training records | Training compliance |
| **HITECH** | §13402 Breach Notification | PHI detection + risk assessment | Breach documentation |
| **42 CFR Part 2** | Substance abuse records | Sensitive PHI detection | Enhanced privacy |
| **Joint Commission** | IM.02.01.01 (information management) | PHI monitoring | Accreditation |
| **SOC 2** | CC6.1 (logical access) | PHI detection logs | Access control testing |

### Evidence Export

For HIPAA audits or OCR investigations:
```bash
aegisgate-platform report compliance \
  --framework HIPAA \
  --period 2026-01-01:2026-12-31 \
  --format pdf \
  --output hipaa-evidence-2026.pdf

aegisgate-platform report incidents \
  --category phi \
  --severity high,critical \
  --period 2026-01-01:2026-12-31 \
  --format csv \
  --output phi-incidents-2026.csv
```

---

## Edge Cases

### False Positives

| Scenario | Why It Fires | How to Handle |
|----------|--------------|---------------|
| Test MRNs (e.g., `MRN: TEST123`) | Matches MRN pattern | Verify it's clearly test data |
| Educational content (e.g., "MRN format: A12345678") | Matches regex | Context analysis ("format", "example" keywords) |
| Fictional patients (TV scripts, novels) | Matches pattern | Context analysis (fiction keywords) |
| De-identified research data | Matches codes only | No identifiers = not PHI, but monitor |

### True Positives That Look Like FPs

| Scenario | Why It's Real | Red Flag |
|----------|---------------|----------|
| "Testing our HIPAA compliance" with real MRNs | Attacker tactic | Real MRNs + "test" = PHI harvesting |
| "My patient's MRN is..." (clinician) | Legitimate but still PHI | EHR integration needed, not AI chat |
| "Research study with MRNs" | PHI without de-identification | IRB violation, data use agreement breach |

---

## Related Runbooks

- **RUNBOOK-001**: PII Detection (SSN, MRN, Passport)
- **RUNBOOK-003**: Financial Codes (SWIFT, Credit Cards, Routing)
- **RUNBOOK-008**: HIPAA Privacy Rule Compliance
- **RUNBOOK-009**: Healthcare Fraud Detection
- **RUNBOOK-015**: Data Exfiltration via AI

---

**Version:** 1.0  
**Last Updated:** 2026-08-14  
**Author:** AegisGate Security, LLC  
**Review Cycle:** Quarterly (or after any PHI exposure incident)
