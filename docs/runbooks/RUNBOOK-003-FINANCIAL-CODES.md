# RUNBOOK-003: Financial Codes (SWIFT, Credit Cards, Routing Numbers)

**Sector:** Banking, Finance, FinTech, Accounting  
**Severity:** High (Critical for bulk financial data)  
**Patterns:** 20+ (Credit Cards, SWIFT/BIC, Routing, Account Numbers, IBAN, Crypto)

---

## What Triggered This

AegisGate detected **financial identifiers** in an AI prompt. This includes:

| Category | Examples | Pattern Name | Severity |
|----------|----------|--------------|----------|
| **Credit Cards** | `4532-8323-0754-2253` | `pii_credit_card` | High |
| **SWIFT/BIC** | `CHASUS33XXX` | `pii_banking_swift_*` | High |
| **Routing (ABA)** | `021000021` | `pii_bank_account` | High |
| **Account Numbers** | `Account: 123456789012` | `pii_bank_account` | High |
| **IBAN** | `DE89370400440532013000` | `pii_international_iban` | High |
| **Crypto Wallets** | `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` | `pii_crypto_btc` | High |

### Example Prompts

```
❌ CRITICAL: "SWIFT: CHASUS33XXX, Account: 123456789012, 
              Routing: 021000021. How do I transfer $50K 
              without triggering AML alerts?"

❌ HIGH: "Credit card: 4532-8323-0754-2253, CVV: 123, 
          Exp: 12/28. Process this payment."

⚠️ MEDIUM: "What's the SWIFT code for JPMorgan Chase?" 
           (Educational, but still sensitive)

✅ GOOD: "What is a SWIFT code used for?" (Educational, no codes)
```

---

## Is This Always Bad?

**Context is critical** — financial codes have legitimate uses but are high-value targets for fraud:

| Context | Risk Level | Rationale |
|---------|------------|-----------|
| **Bank employee** processing wire transfers | ⚠️ Medium | Legitimate business, but monitor for insider threat |
| **Fraud analyst** investigating transactions | ⚠️ Medium | Legitimate, but should use redacted data |
| **Customer** asking about their own account | ⚠️ Low | Customer service use case, educate on secure channels |
| **Attacker** testing stolen card numbers | ❌ Critical | Active fraud attempt |
| **Money launderer** structuring transactions | ❌ Critical | Financial crime |

---

## Investigation Workflow

### Step 1: Identify the Financial Instrument

**Questions:**
- What type of financial code was detected? (Credit card, SWIFT, Routing, etc.)
- Is it a single code or bulk data?
- Is it combined with other sensitive data (names, amounts, dates)?

**Pattern Severity Matrix:**

| Pattern | Single Occurrence | Bulk (10+) | + Evasion Language |
|---------|-------------------|------------|---------------------|
| Credit Card | High | Critical | Critical |
| SWIFT/BIC | Medium | High | Critical |
| Routing + Account | High | Critical | Critical |
| IBAN | Medium | High | Critical |
| Crypto Wallet | Medium | High | High |

### Step 2: Review Full Prompt Context

**Critical-Risk Patterns:**
```
❌ "SWIFT: CHASUS33XXX, Account: 123456789012, Routing: 021000021
     Name: John Doe, Amount: $50,000
     How do I structure this to avoid CTR reporting?"
     → Money laundering (structuring)

❌ "I have these 100 credit card numbers: [list]
     Which ones are valid?"
     → Card testing (fraud)

❌ "SWIFT: CHASUS33XXX
     How do I send money to [sanctioned country] without detection?"
     → Sanctions evasion
```

**Medium-Risk Patterns:**
```
⚠️ "What's the SWIFT code for [Bank Name] international wires?"
     → Could be legitimate customer inquiry

⚠️ "My account number is 123456789012, why was my transfer rejected?"
     → Customer service issue (but account number exposed)
```

**Low-Risk Patterns:**
```
✅ "What format is a SWIFT code in?" (Educational)
✅ "How do I read an IBAN number?" (Educational)
✅ "Test: Does AegisGate detect credit card 4532-8323-0754-2253?" 
    (Validation with test card)
```

### Step 3: Check for Fraud Indicators

**Red Flags:**

| Indicator | What It Suggests | Action |
|-----------|------------------|--------|
| **Multiple card numbers** | Card testing or bulk fraud | Immediate escalation |
| **Card + CVV + Expiry** | Full card data (ready for fraud) | Immediate escalation |
| **SWIFT + "avoid CTR"** | Money laundering (structuring) | Immediate escalation |
| **SWIFT + sanctioned country** | Sanctions evasion | Immediate escalation |
| **Routing + Account + "verify"** | Account takeover attempt | Escalate to fraud team |
| **Crypto wallet + "mixer"** | Money laundering | Escalate to compliance |

**Platform Query:**
```sql
SELECT user_id, category, COUNT(*) as detection_count,
       STRING_AGG(prompt_text, ' | ') as prompts
FROM detection_events
WHERE category IN ('pii_credit_card', 'pii_banking_swift_*', 'pii_bank_account')
  AND timestamp > NOW() - INTERVAL '24 hours'
GROUP BY user_id, category
HAVING COUNT(*) > 3
ORDER BY detection_count DESC;
```

### Step 4: Escalation Decision

| Severity | Indicators | Action | Timeline |
|----------|------------|--------|----------|
| **Low** | Single financial code, educational context | Log, user education | 24-48 hours |
| **Medium** | Single code + customer service context | Flag for fraud review | 4-8 hours |
| **High** | Multiple codes, bulk data, unclear business need | Escalate to fraud team | 1-2 hours |
| **Critical** | Financial codes + evasion language, sanctions, structuring | Immediate escalation + SAR filing consideration | Immediate |

---

## Remediation

### Immediate Actions (Automated by AegisGate)

1. **Block the prompt** — Prevents it from reaching the AI service
2. **Notify the user** — Educational banner explains what was detected
3. **Create incident ticket** — Auto-generated with full context
4. **Alert fraud team** — For High/Critical severity, page immediately

### Follow-up (24-48 Hours)

1. **Interview the user** (if Medium/High severity)
   - Understand business context
   - Verify authorization to handle financial data
   - Provide training if accidental

2. **Review transaction history**
   - Has this user initiated unusual wire transfers?
   - Are there matching transactions in core banking systems?

3. **Check for data breach**
   - If bulk card numbers, was this from a compromised database?
   - Report to card brands if necessary (Visa, Mastercard)

### Regulatory Reporting Considerations

| Scenario | Report Type | Timeline |
|----------|-------------|----------|
| **Suspected money laundering** (structuring, sanctions evasion) | SAR (Suspicious Activity Report) | 30 days |
| **Credit card fraud** (bulk card testing) | Report to card brands | Immediate |
| **Account takeover** | Report to account holder + law enforcement | 24 hours |
| **Insider threat** (employee facilitating fraud) | SAR + internal investigation | 30 days |

**Note:** Consult your Compliance/Legal team before filing SARs. AegisGate detection alone may not meet SAR thresholds, but it's a strong indicator for further investigation.

---

## Compliance Impact

| Framework | Requirement | AegisGate Evidence | Audit Use |
|-----------|-------------|-------------------|-----------|
| **PCI-DSS** | Req 3.4 (protect cardholder data) | CC detection + blocking logs | Prove CHD monitoring |
| **PCI-DSS** | Req 10.6 (review logs) | Detection event logs | Log review evidence |
| **BSA/AML** | 31 CFR 1010 (CTR/SAR reporting) | Detection logs for suspicious activity | SAR supporting documentation |
| **OFAC** | Sanctions compliance | Detection of sanctioned country references | Sanctions program testing |
| **SOX** | §404 (internal controls) | Financial data detection + workflow | ICFR testing |
| **GLBA** | Safeguards Rule (financial data) | Customer financial data monitoring | Safeguards compliance |
| **FFIEC** | IT Handbook (banking security) | Financial data detection logs | Regulatory examination |
| **NYDFS 23 NYCRR 500** | Cybersecurity regulation | Financial data monitoring | Regulatory compliance |

### Evidence Export

For audits or regulatory exams:
```bash
aegisgate-platform report compliance \
  --framework PCI-DSS \
  --period 2026-01-01:2026-12-31 \
  --format pdf \
  --output pci-evidence-2026.pdf

aegisgate-platform report incidents \
  --category financial \
  --severity high,critical \
  --period 2026-01-01:2026-12-31 \
  --format csv \
  --output financial-incidents-2026.csv
```

---

## Edge Cases

### False Positives

| Scenario | Why It Fires | How to Handle |
|----------|--------------|---------------|
| Test card numbers (e.g., `4532-8323-0754-2253`) | Valid Luhn checksum | Verify it's a known test card (Visa test range) |
| Documentation (e.g., "SWIFT code format: AAAABBBBXXX") | Matches regex | Context analysis ("format", "example" keywords) |
| Fictional data (e.g., movie scripts, novels) | Matches pattern | Context analysis (fiction keywords) |
| Historical data (e.g., "Titanic passenger account numbers") | Matches pattern | Context analysis (historical keywords) |

### True Positives That Look Like FPs

| Scenario | Why It's Real | Red Flag |
|----------|---------------|----------|
| "Testing our fraud detection" with real cards | Attacker tactic | Real cards + "test" = card testing fraud |
| "My customer provided this card" | Social engineering | Customer service should use secure channels |
| "Found this list of cards on the dark web" | Reconnaissance | Validating stolen card data |

---

## Related Runbooks

- **RUNBOOK-001**: PII Detection (SSN, MRN, Passport)
- **RUNBOOK-002**: Secrets & Credentials (AWS, API Keys)
- **RUNBOOK-004**: Healthcare Codes (CPT, HCPCS, ICD-10)
- **RUNBOOK-007**: Anti-Money Laundering (AML) Detection
- **RUNBOOK-012**: Sanctions Screening

---

**Version:** 1.0  
**Last Updated:** 2026-08-14  
**Author:** AegisGate Security, LLC  
**Review Cycle:** Quarterly (or after any fraud incident)
