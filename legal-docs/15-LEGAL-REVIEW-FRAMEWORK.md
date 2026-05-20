# LEGAL REVIEW FRAMEWORK
## AegisGate Security Platform — Business-Favorable Contract Revisions

**Document Version:** 1.0  
**Last Updated:** 2026-05-20  
**Purpose:** Identify clauses requiring revision to favor business while maintaining legal compliance

---

## EXECUTIVE SUMMARY

After review of our legal documents, we've identified **17 critical clauses** that require revision to protect AegisGate's business interests while maintaining HIPAA/GDPR compliance. These revisions shift risk appropriately between parties and limit our exposure.

---

## CRITICAL CLAUSES REQUIRING REVISION

### Category 1: Liability and Indemnification

| # | Document | Current Clause | Problem | Revision |
|---|----------|---------------|---------|----------|
| **L1** | BAA §6.1 | "Company shall indemnify from ANY claims" | No cap, no carve-outs | Add liability cap at 12-month fees, carve-out for Subscriber negligence |
| **L2** | BAA §6.1 | "arising out of or related to" | Overly broad trigger | Change to "directly caused by Company's material breach" |
| **L3** | MSA §6.2 | "Total liability shall not exceed" | Cap applies to all damages | Confirm cap excludes willful misconduct and indemnification |
| **L4** | ToS §10.1 | "Indemnify for any violation" | No limitations | Add carve-out for Customer's failure to notify or cooperate |

### Category 2: Security Incident Reporting

| # | Document | Current Clause | Problem | Revision |
|---|----------|---------------|---------|----------|
| **S1** | BAA §2.6(b) | "30 days to notify" | Too long for security company | Change to "without unreasonable delay, but not to exceed 72 hours for confirmed breaches" |
| **S2** | BAA §2.6(c) | "Security Incident includes attempted" | Every probe is a report | Limit to "successful unauthorized access resulting in confirmed data exposure" |
| **S3** | BAA §2.7 | "Mitigate any harmful effect" | Open-ended obligation | Change to "mitigate to extent commercially reasonable" |

### Category 3: Termination and Data Handling

| # | Document | Current Clause | Problem | Revision |
|---|----------|---------------|---------|----------|
| **T1** | BAA §4.4(a) | "Return or destroy ALL PHI immediately" | May conflict with legal holds | Add: "except as required by law or valid legal hold; destruction within 90 days" |
| **T2** | BAA §4.2 | "30 days to cure" | Too short for complex issues | Change breach to "material breach of a term that substantially affects compliance" |
| **T3** | MSA §7.2 | "Termination for any material breach" | Subjective | Define "material breach" clearly; add cure period exceptions |

### Category 4: Operational Burdens

| # | Document | Current Clause | Problem | Revision |
|---|----------|---------------|---------|----------|
| **O1** | BAA §2.10 | "Accounting of disclosures" | Expensive compliance burden | Limit to "disclosures for purposes other than treatment/payment/operations" |
| **O2** | BAA §2.9 | "Make PHI available for access" | Operational burden | Clarify "within 30 days of valid request, during normal business hours" |
| **O3** | DPA §4.9 | "Allow and contribute to audits" | Unlimited audit rights | Limit to "once per calendar year, with 30 days notice" |

### Category 5: Customer Obligations

| # | Document | Current Clause | Problem | Revision |
|---|----------|---------------|---------|----------|
| **C1** | BAA §3.1 | "Not request Company to use PHI in any manner not permitted" | Vague | Add explicit list of permitted uses |
| **C2** | BAA §3.2 | "Not disclose PHI to third party without consent" | Overly restrictive | Allow disclosures to customer's own subprocessors under DPA |

### Category 6: Insurance and Warranties

| # | Document | Current Clause | Problem | Revision |
|---|----------|---------------|---------|----------|
| **I1** | BAA §7 | "Maintain appropriate insurance" | Vague | Specify minimum coverage amounts |
| **I2** | ToS §9.1 | "Service performs substantially as described" | Implied warranty | Add "AS IS" disclaimer clearly |
| **I3** | EULA §8.1 | "NO WARRANTY" in small text | May not be enforceable | Move to prominent position, require acknowledgment |

---

## BUSINESS-FAVORABLE POSITIONING PRINCIPLES

### 1. Shared Responsibility Model
- Company: Implements and maintains security safeguards
- Customer: Ensures lawful input data and proper configuration
- Neither party bears full risk for the other's domain

### 2. Tiered Compliance
- Community: Basic safeguards
- Professional/Enterprise: Enhanced safeguards + BAA
- Customer responsible for determining tier suitability

### 3. Clear Scope Limitations
- Company processes PHI only when Customer transmits it through Service
- Company not liable for Customer's internal security failures
- Customer responsible for their own infrastructure

### 4. Reasonable Timelines
- Security notifications: 72 hours for confirmed breaches
- Audit rights: Annual, with notice
- Data return: 90 days (allows for legal holds)

### 5. Liability Caps
- Standard: 12 months of fees paid
- Exception: Gross negligence, willful misconduct (uncapped)
- Cyber liability insurance required at minimum $2M

---

## REVISION PRIORITY

### Priority 1 (Must Fix Before Launch)
| Clause | Impact | Risk |
|--------|--------|------|
| L1-L2 | Unlimited indemnification exposure | CRITICAL |
| S1-S2 | Over-broad security incident definition | HIGH |
| T1 | Conflicting legal hold obligations | HIGH |

### Priority 2 (Should Fix Before Launch)
| Clause | Impact | Risk |
|--------|--------|------|
| O1-O3 | Operational burden | MEDIUM |
| I1 | Vague insurance requirements | MEDIUM |

### Priority 3 (Nice to Have)
| Clause | Impact | Risk |
|--------|--------|------|
| C1-C2 | Customer relationship friction | LOW |
| T2-T3 | Termination disputes | LOW |

---

## LEGAL COUNSEL CHECKLIST

Before submitting to legal counsel, verify:

- [ ] All revisions align with state Bar rules for attorney-client privilege
- [ ] Liability caps are enforceable in target jurisdictions
- [ ] Security incident definitions meet HIPAA minimum requirements
- [ ] Insurance minimums are appropriate for company size
- [ ] Customer obligation clauses are realistic

---

## REVISION TEMPLATES

### Template 1: Indemnification Clause (Business-Favorable)

```
6.1 Indemnification by Company

Company shall indemnify Subscriber from third-party claims arising directly from 
Company's material breach of this Agreement, PROVIDED THAT:
(a) Subscriber provides prompt written notice of any claim;
(b) Subscriber provides reasonable cooperation in the defense;
(c) Subscriber allows Company to control the defense and settlement;
(d) Subscriber's damages are not caused by Subscriber's own negligence or 
    failure to comply with this Agreement.

COMPANY'S TOTAL INDEMNIFICATION LIABILITY SHALL NOT EXCEED THE FEES PAID 
BY SUBSCRIBER IN THE TWELVE (12) MONTHS PRECEDING THE CLAIM.

EXCEPTION: This limitation does not apply to damages arising from Company's 
gross negligence, willful misconduct, or violation of law.
```

### Template 2: Security Incident Notification (Business-Favorable)

```
2.6 Security Incidents

Company shall notify Subscriber without unreasonable delay, but in no event 
later than seventy-two (72) hours after Company's determination that:
(a) A successful unauthorized access, use, or disclosure of PHI has occurred; AND
(b) The incident requires notification under HIPAA.

For purposes of this Agreement, "Security Incident" means:
- Successful unauthorized access that results in confirmed exposure of PHI; OR
- Successful unauthorized modification or destruction of PHI.

Attempted intrusions, probes, or unsuccessful attacks shall not constitute 
a Security Incident requiring notification under this section.
```

### Template 3: Termination Data Handling (Business-Favorable)

```
4.4 Effect of Termination

Upon termination of this Agreement for any reason:

(a) DATA RETURN/DESTRUCTION: Company shall, at Subscriber's election:
    (i) Return all PHI to Subscriber in portable format within thirty (30) days; OR
    (ii) Securely destroy all PHI within ninety (90) days, providing 
         certification of destruction.

    EXCEPTION: PHI may be retained if:
    - Required by law, regulation, or court order;
    - Subject to a valid legal hold notice provided prior to termination;
    - Necessary for Company's legal defense in pending litigation.
    
    Retained PHI remains subject to confidentiality obligations of this Agreement.

(b) NOTIFICATION: Company shall notify Subscriber of any PHI that cannot be 
    returned or destroyed due to legal requirements within ten (10) days 
    of termination.
```

---

## NEGOTIATING POSITIONS BY CUSTOMER TIER

| Customer Type | Position |
|---------------|----------|
| **Small Healthcare Startup** | Accept standard terms; may request minor modifications |
| **Enterprise Hospital** | Expect counter-proposals; prepare fallback positions |
| **Enterprise Health System** | Prepare for redlines on indemnification and SLA |

---

*This document is intended to guide legal counsel review. All revisions must be reviewed by qualified legal counsel before implementation.*

**Version:** 1.0  
**Last Updated:** 2026-05-20