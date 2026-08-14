# RUNBOOK-009: EU AI Act / GDPR Compliance (Prohibited Practices, Special Category Data)

**Sector:** All (especially organizations operating in EU or serving EU residents)  
**Severity:** Medium-High (Critical for prohibited practices under Article 5)  
**Patterns:** 35+ (EU AI Act Article 5, Annex III high-risk, Article 50 transparency, GDPR Article 9 special category data)

---

## What Triggered This

AegisGate detected **EU AI Act or GDPR compliance concerns** in an AI prompt. This includes:

| Category | Examples | Pattern Name | Severity |
|----------|----------|--------------|----------|
| **Prohibited Practices (Art. 5)** | Social scoring, manipulation, exploitation | `eu_ai_act_prohibited` | Critical |
| **High-Risk AI (Annex III)** | Biometric ID, critical infrastructure, law enforcement | `eu_ai_act_high_risk` | High |
| **Transparency Violations (Art. 50)** | Undisclosed AI interaction, deepfakes | `eu_ai_act_transparency` | Medium |
| **Special Category Data (GDPR Art. 9)** | Race, politics, religion, health, sexuality | `gdpr_special_category` | High |
| **Automated Decision-Making (GDPR Art. 22)** | Profiling with legal/significant effects | `gdpr_adm_profiling` | High |
| **Data Subject Rights** | Access, rectification, erasure requests | `gdpr_data_subject_rights` | Medium |

### EU AI Act Article 5 Prohibited Practices

| Practice | Example | Detection |
|----------|---------|-----------|
| **Subliminal manipulation** | "Use psychological tricks to make users buy more" | Manipulation keywords |
| **Exploitation of vulnerabilities** | "Target children's insecurities to sell products" | Exploitation + vulnerable groups |
| **Social scoring** | "Rate citizens' trustworthiness based on behavior" | Social scoring + government |
| **Real-time biometric surveillance** | "Identify protesters in real-time video feed" | Biometric + law enforcement |
| **Emotion recognition (workplace/education)** | "Detect if students are paying attention" | Emotion recognition + specific contexts |
| **Predictive policing** | "Predict who will commit crimes" | Predictive + law enforcement |

### GDPR Article 9 Special Category Data

| Category | Examples | Risk Level |
|----------|----------|------------|
| **Racial/ethnic origin** | Race, ethnicity, skin color | High |
| **Political opinions** | Party affiliation, voting preferences | High |
| **Religious beliefs** | Religion, creed, religious practices | High |
| **Trade union membership** | Union affiliation, labor activities | High |
| **Genetic data** | DNA sequences, genetic test results | Critical |
| **Biometric data** | Fingerprints, facial recognition templates | Critical |
| **Health data** | Medical conditions, treatments, prescriptions | Critical |
| **Sex life/sexual orientation** | Sexual preferences, activities | High |

### Example Prompts

```
❌ CRITICAL: "Build a social credit system for our city.
             Score citizens based on:
             - Criminal records
             - Social media activity
             - Financial history
             - Political affiliations
             Output: Trustworthiness score 0-100"
             → EU AI Act Article 5 prohibited (social scoring)

❌ CRITICAL: "Analyze these employee webcam feeds to detect:
             - Boredom levels
             - Attention span
             - Emotional state
             - Stress indicators
             Flag underperforming employees for termination."
             → EU AI Act Article 5 prohibited (emotion recognition in workplace)

❌ HIGH: "Process these asylum applications using AI.
         Input: Applicant photos, names, countries of origin
         Output: Approval probability score
         Auto-reject applications with <30% approval chance."
             → EU AI Act Annex III high-risk + GDPR Art. 9 (ethnic origin)

❌ HIGH: "Analyze patient medical records to predict:
         - Life expectancy
         - Treatment response
         - Insurance risk profile
         Data: 100,000 patient records with diagnoses, treatments, outcomes"
             → GDPR Art. 9 (health data) + Art. 22 (automated decisions)

⚠️ MEDIUM: "Generate a deepfake video of our CEO announcing layoffs.
            Make it look completely real. Don't disclose it's AI-generated."
            → EU AI Act Article 50 transparency violation

✅ GOOD: "What are the EU AI Act requirements for high-risk AI systems?" (Educational)
```

---

## Is This Always Bad?

**Highly context-dependent** — EU AI Act has specific exemptions and compliance pathways:

| Context | Risk Level | Rationale |
|---------|------------|-----------|
| **Compliance officer** assessing AI system risk | ✅ Low | Legitimate compliance work |
| **Researcher** studying AI regulation | ✅ Low | Academic research exemption |
| **Developer** implementing Article 50 disclosures | ✅ Low | Compliance implementation |
| **Company** deploying prohibited practices | ❌ Critical | EU AI Act violation (up to €35M or 7% global revenue) |
| **Organization** processing special category data without consent | ❌ High | GDPR violation (up to €20M or 4% global revenue) |
| **Government** using AI for social scoring | ❌ Critical | Prohibited under Article 5 |

---

## Investigation Workflow

### Step 1: Identify the Violation Type

**Questions:**
- **Which regulation?** EU AI Act, GDPR, or both?
- **What article?** Article 5 (prohibited), Annex III (high-risk), Article 50 (transparency), GDPR Art. 9 (special data)?
- **What's the purpose?** Law enforcement, employment, education, critical infrastructure?
- **EU nexus?** Does this affect EU residents or operate in EU market?

**Violation Severity Matrix:**

| Violation Type | Single Occurrence | Systematic Deployment | + Vulnerable Groups |
|----------------|-------------------|----------------------|---------------------|
| Article 5 Prohibited | Critical | Critical | Critical |
| Annex III High-Risk | High | High | Critical |
| Article 50 Transparency | Medium | High | High |
| GDPR Art. 9 Special Data | High | High | Critical |
| GDPR Art. 22 ADM | Medium | High | High |

### Step 2: Review Full Prompt Context

**Critical-Risk Patterns (Prohibited Practices):**
```
❌ "Implement social scoring for our employee bonus system.
     Factors:
     - Work performance metrics
     - Social media activity
     - Political donations (public records)
     - Credit score
     Output: Loyalty score affecting promotion eligibility"
     → EU AI Act Article 5 (social scoring in employment)

❌ "Deploy real-time facial recognition in our retail stores.
     Purpose:
     - Identify known shoplifters
     - Detect 'suspicious behavior'
     - Alert security for 'pre-crime intervention'
     Integrate with local police database"
     → EU AI Act Article 5 (real-time biometric surveillance)
```

**High-Risk Patterns (Annex III / Special Data):**
```
⚠️ "Build an AI hiring system that screens resumes.
     Input: Candidate names, photos, education, work history
     Output: Hire/no-hire recommendation
     Auto-reject candidates scoring <50%"
     → EU AI Act Annex III (AI in employment) + potential bias

⚠️ "Analyze customer data to predict creditworthiness.
     Data: Transaction history, browsing behavior, social media
     Output: Credit score 300-850
     Auto-deny loans below 600 score"
     → GDPR Art. 22 (automated decision-making with legal effect)
```

### Step 3: Check for EU Nexus

**Questions to establish jurisdiction:**

| Factor | EU Nexus Present? | Action |
|--------|-------------------|--------|
| **Organization location** | EU-based entity? | EU AI Act applies |
| **Data subjects** | EU residents affected? | GDPR applies |
| **Market** | Products/services offered in EU? | Both apply |
| **Monitoring** | Behavior of EU persons monitored? | GDPR applies |
| **Establishment** | EU office/branch? | Both apply |

**If ANY factor is YES → EU AI Act and/or GDPR applies**

### Step 4: Escalation Decision

| Severity | Indicators | Action | Timeline |
|----------|------------|--------|----------|
| **Low** | Educational context, compliance assessment, research | Log, user education | 24-48 hours |
| **Medium** | Transparency violations, unclear EU nexus | Flag for legal/DPO review | 4-8 hours |
| **High** | High-risk AI (Annex III), special category data processing | Escalate to DPO + legal | 1-2 hours |
| **Critical** | Article 5 prohibited practices, systematic violations | Immediate escalation + regulatory notification consideration | Immediate |

---

## Remediation

### Immediate Actions (Automated by AegisGate)

1. **Block the prompt** — Prevents prohibited practice from being implemented
2. **Notify the user** — Educational banner on EU AI Act/GDPR requirements
3. **Create incident ticket** — Auto-generated with full context
4. **Alert DPO/Legal** — For High/Critical severity, notify immediately

### Compliance Assessment

**If prohibited practice or violation was detected:**

1. **Conduct impact assessment:**
   - Does this violate Article 5 (prohibited)?
   - Is this Annex III high-risk AI?
   - Does this process special category data (GDPR Art. 9)?
   - Are automated decisions made with legal/significant effects (GDPR Art. 22)?

2. **Determine regulatory obligations:**
   - **Article 5 violation:** Must cease immediately, notify supervisory authority
   - **Annex III high-risk:** Conformity assessment, CE marking required
   - **GDPR Art. 9:** Explicit consent or legal basis required
   - **GDPR Art. 22:** Right to human intervention, explanation

3. **Document everything:**
   - Incident ticket
   - Impact assessment
   - Remediation steps
   - Legal/regulatory notifications

### Follow-up (24-48 Hours)

1. **Legal review** — Assess regulatory exposure, notification obligations
2. **DPO consultation** — Data protection impact assessment (DPIA) if needed
3. **Business decision** — Cease prohibited practice, implement compliance controls
4. **Regulatory notification** — If required, notify supervisory authority within 72 hours

### Long-term (Weekly/Monthly)

1. **Compliance program** — Implement EU AI Act conformity assessment
2. **Technical measures** — Article 50 disclosures, data subject rights automation
3. **Training** — EU AI Act and GDPR awareness for all employees
4. **Audit trail** — Maintain records of processing activities (ROPA)

---

## Compliance Impact

| Framework | Requirement | AegisGate Evidence | Audit Use |
|-----------|-------------|-------------------|-----------|
| **EU AI Act** | Article 5 (prohibited practices) | Prohibited practice detection | Article 5 compliance |
| **EU AI Act** | Annex III (high-risk AI) | High-risk AI detection | Conformity assessment |
| **EU AI Act** | Article 50 (transparency) | Deepfake/AI disclosure detection | Transparency compliance |
| **GDPR** | Article 9 (special category data) | Special data detection | Lawful basis verification |
| **GDPR** | Article 22 (automated decisions) | ADM profiling detection | Human intervention rights |
| **GDPR** | Article 33 (breach notification) | Detection timestamps | 72-hour notification |
| **GDPR** | Article 35 (DPIA) | High-risk processing detection | DPIA trigger |

### Evidence Export

For regulatory compliance or audits:
```bash
aegisgate-platform report compliance \
  --framework EU-AI-ACT \
  --period 2026-01-01:2026-12-31 \
  --format pdf \
  --output eu-ai-act-evidence-2026.pdf

aegisgate-platform report compliance \
  --framework GDPR \
  --period 2026-01-01:2026-12-31 \
  --format pdf \
  --output gdpr-evidence-2026.pdf
```

---

## Edge Cases

### False Positives

| Scenario | Why It Fires | How to Handle |
|----------|--------------|---------------|
| Academic research on AI regulation | Matches prohibited practice keywords | Verify research exemption, mark as Low |
| Compliance assessment (internal audit) | Matches violation patterns | Verify compliance purpose, mark as Low |
| Journalistic investigation | Matches high-risk AI patterns | Verify journalistic exemption |
| Legal analysis of EU AI Act | Contains prohibited practice examples | Context analysis ("legal", "analysis" keywords) |

### True Positives That Look Like FPs

| Scenario | Why It's Real | Red Flag |
|----------|---------------|----------|
| "Testing compliance boundaries" | Attempting to find loopholes | Loophole-seeking = intentional violation |
| "Our competitor is doing this" | Race to the bottom | Competitor behavior doesn't justify violation |
| "It's just a pilot program" | Testing prohibited practice | Pilot = still prohibited |

---

## Regulatory Penalties

| Violation | Maximum Fine | Examples |
|-----------|--------------|----------|
| **EU AI Act Article 5** | €35M or 7% global revenue | Social scoring, prohibited biometric use |
| **EU AI Act Annex III** | €15M or 3% global revenue | High-risk AI without conformity assessment |
| **GDPR Article 9** | €20M or 4% global revenue | Processing special category data without basis |
| **GDPR Article 22** | €20M or 4% global revenue | Automated decisions without safeguards |

---

## Related Runbooks

- **RUNBOOK-001**: PII Detection (SSN, MRN, Passport)
- **RUNBOOK-004**: Healthcare Codes (CPT, HCPCS, ICD-10)
- **RUNBOOK-010**: Incident Response for AI Security

---

**Version:** 1.0  
**Last Updated:** 2026-08-14  
**Author:** AegisGate Security, LLC  
**Review Cycle:** Quarterly (or after any EU AI Act/GDPR incident)
