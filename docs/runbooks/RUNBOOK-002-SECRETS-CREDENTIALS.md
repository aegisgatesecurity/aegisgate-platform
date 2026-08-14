# RUNBOOK-002: Secrets & Credentials (AWS, API Keys, Tokens)

**Sector:** All (Technology, Finance, Healthcare, Government)  
**Severity:** Critical (immediate credential rotation required)  
**Patterns:** 45+ (AWS, GitHub, GCP, Azure, OpenAI, Slack, Database, etc.)

---

## What Triggered This

AegisGate detected **secrets, API keys, or credentials** in an AI prompt. This is a **Critical** severity event because:

1. **AI services log prompts** — Your secrets are now in their logs
2. **AI training data** — Some services use prompts for model training
3. **Insider threat** — User may be exfiltrating credentials
4. **Compromised account** — Attacker may be using AI to test stolen creds

### Detected Secret Types

| Category | Examples | Pattern Name |
|----------|----------|--------------|
| **AWS** | `AKIA[REDACTED]`, `[REDACTED]` | `secret_aws_access_key`, `secret_aws_secret_key` |
| **GitHub** | `ghp_[REDACTED]` | `secret_github_pat` |
| **GCP** | `{"type": "service_account", "private_key": "[REDACTED]"}` | `secret_gcp_service_account` |
| **Azure** | `DefaultEndpointsProtocol=https;AccountName=...` | `secret_azure_connection_string` |
| **OpenAI** | `sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` | `secret_openai_key` |
| **Database** | `postgresql://user:password@host:5432/db` | `secret_database_url` |
| **JWT** | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` | `secret_jwt` |
| **Private Keys** | `[REDACTED PRIVATE KEY]` | `secret_private_key` |

### Example Prompts

```
❌ CRITICAL: "AWS_ACCESS_KEY_ID=AKIA[REDACTED]
              AWS_SECRET_ACCESS_KEY=[REDACTED]
              How do I upload this to S3?"

❌ CRITICAL: "Here's my GitHub PAT: ghp_[REDACTED]
              Can you help me automate repo creation?"

✅ GOOD: "What's the format of an AWS access key?" (educational)
✅ GOOD: "How do I rotate compromised AWS credentials?" (legitimate)
```

---

## Is This Always Bad?

**Yes, with rare exceptions.** Unlike PII, secrets in AI prompts are **almost always a security incident**:

| Context | Risk Level | Rationale |
|---------|------------|-----------|
| **Developer** debugging AWS code | ❌ Critical | Credentials logged by AI service |
| **Security researcher** testing detection | ⚠️ Medium (use test creds only) | Must use rotated/test credentials |
| **Attacker** validating stolen creds | ❌ Critical | Active compromise |
| **User** accidentally pasting .env file | ❌ Critical | Immediate rotation required |

**Rule of Thumb:** If it's a real secret (not a documented example like `AKIAIOSFODNN7EXAMPLE`), treat it as **Critical**.

---

## Investigation Workflow

### Step 1: Immediate Containment (Within 5 Minutes)

**Actions:**
1. **Identify the secret type** — AWS, GitHub, Database, etc.
2. **Determine if it's real or example** — Compare against known test patterns
3. **Notify the credential owner** — Force rotation immediately
4. **Revoke the credential** — If possible, disable before rotation

**Platform Alert:**
```json
{
  "severity": "critical",
  "category": "secret_aws_access_key",
  "action_required": "ROTATE_CREDENTIAL",
  "notification_channels": ["slack-security", "pagerduty"],
  "sla_minutes": 15
}
```

### Step 2: Review Full Prompt Context

**High-Risk Patterns:**
```
❌ "Here are my AWS creds: [REDACTED]
     What can I do with these?" 
     → Attacker testing access

❌ "I found this .env file: [full file contents]
     Is this valuable?"
     → Data exfiltration

❌ "Generate a script that uses this GitHub PAT: ghp_...
     to download all repos"
     → Automated exfiltration
```

**Lower-Risk (But Still Bad) Patterns:**
```
⚠️ "My AWS key [REDACTED] isn't working, why?"
     → Misconfiguration (but key is still exposed)

⚠️ "Is this a real AWS key: AKIA...?"
     → Validation attempt (key may be real)
```

### Step 3: Check for Lateral Movement

**Questions:**
- Has this user uploaded other secrets in the past 7 days?
- Are they accessing AI services from an unusual location?
- Is this part of a bulk exfiltration (multiple secrets, multiple prompts)?

**Platform Query:**
```sql
SELECT user_id, category, COUNT(*) as secret_count, 
       ARRAY_AGG(DISTINCT prompt_text) as prompts
FROM detection_events
WHERE category LIKE 'secret_%'
  AND timestamp > NOW() - INTERVAL '7 days'
GROUP BY user_id, category
HAVING COUNT(*) > 1
ORDER BY secret_count DESC;
```

### Step 4: Escalation Decision

| Severity | Indicators | Action | Timeline |
|----------|------------|--------|----------|
| **Medium** | Example/test credential, educational context | Log, user education | 24 hours |
| **High** | Real credential, single occurrence, accidental paste | Rotate credential, user interview | 1-2 hours |
| **Critical** | Real credential + bulk exfiltration, attacker TTPs | Incident response, full forensic review | Immediate |

---

## Remediation

### Immediate Actions (Within 15 Minutes)

1. **Rotate the credential** — Generate new key, revoke old one
2. **Audit access logs** — What did the attacker access with this key?
3. **Check for persistence** — Did they create backdoors, new users, etc.?
4. **Notify affected teams** — Security, DevOps, application owners

### Credential Rotation Checklist

| Secret Type | Rotation Steps | Verification |
|-------------|----------------|--------------|
| **AWS IAM Key** | 1. Create new key<br>2. Update all applications<br>3. Delete old key<br>4. Test | `aws sts get-caller-identity` |
| **GitHub PAT** | 1. Revoke token in Settings<br>2. Generate new token<br>3. Update CI/CD pipelines | `gh auth status` |
| **Database Password** | 1. Change password in DB<br>2. Update connection strings<br>3. Restart applications | Test connection from app |
| **OpenAI Key** | 1. Revoke in OpenAI dashboard<br>2. Generate new key<br>3. Update .env files | `curl https://api.openai.com/v1/models` |
| **JWT Signing Key** | 1. Rotate key in auth service<br>2. Invalidate all existing tokens<br>3. Force re-authentication | Test login flow |

### Follow-up (24-48 Hours)

1. **Forensic review** — What data was accessed with the exposed credential?
2. **User interview** — Was this accidental or malicious?
3. **Policy update** — Do we need to block AI services from accessing certain environments?
4. **Training** — Educate the team on secrets management

### Long-term (Weekly/Monthly)

1. **Secrets scanning** — Implement pre-commit hooks (e.g., gitleaks, truffleHog)
2. **AI service allowlisting** — Block AI access to production environments
3. **Credential monitoring** — Use services like HaveIBeenPwned for leaked creds
4. **Zero-trust architecture** — Short-lived credentials, no long-lived keys

---

## Compliance Impact

| Framework | Requirement | AegisGate Evidence | Audit Use |
|-----------|-------------|-------------------|-----------|
| **SOC 2** | CC6.1 (logical access) | Secret detection + rotation logs | Access control testing |
| **SOC 2** | CC6.6 (security events) | Detection event logs | Security monitoring |
| **PCI-DSS** | Req 8.3 (secure passwords) | Credential detection logs | Password policy enforcement |
| **PCI-DSS** | Req 10.6 (review logs) | Detection event logs | Log review evidence |
| **HIPAA** | §164.312(a)(1) Access Control | Secret detection in PHI systems | Access control testing |
| **ISO 27001** | A.9.4.3 (password management) | Credential detection + rotation | Password policy compliance |
| **NIST 800-53** | IA-5 (authenticator management) | Secret detection logs | Authenticator management |
| **FedRAMP** | AC-2 (account management) | Credential detection + revocation | Account management controls |

### Evidence Export

For audits, export from Platform:
```bash
aegisgate-platform report compliance \
  --framework SOC2 \
  --period 2026-01-01:2026-12-31 \
  --format pdf \
  --output soc2-evidence-2026.pdf
```

---

## Edge Cases

### False Positives

| Scenario | Why It Fires | How to Handle |
|----------|--------------|---------------|
| Example credentials (e.g., AWS docs use `AKIAIOSFODNN7EXAMPLE`) | Matches AWS pattern | AWS example keys are well-known, mark as Low |
| Documentation (e.g., "AWS key format: AKIA...") | Matches regex | Context analysis ("format", "example" keywords) |
| Test credentials (clearly marked as test) | Matches pattern | Verify it's a test key (not production) |
| Redacted credentials (e.g., `AKIA...XXXX`) | Partial match | Log as Low, no escalation needed |

### True Positives That Look Like FPs

| Scenario | Why It's Real | Red Flag |
|----------|---------------|----------|
| "Testing with my dev key" | Dev keys can access production | No such thing as "dev only" in AI logs |
| "This key expires in 5 minutes" | Still logged forever | AI services retain prompts indefinitely |
| "I'll delete this after" | Too late, already logged | Prompt is already in AI service logs |

---

## Related Runbooks

- **RUNBOOK-001**: PII Detection (SSN, MRN, Passport)
- **RUNBOOK-003**: Financial Codes (SWIFT, Credit Cards, Routing)
- **RUNBOOK-006**: Data Exfiltration via AI
- **RUNBOOK-010**: Incident Response for AI Security

---

**Version:** 1.0  
**Last Updated:** 2026-08-14  
**Author:** AegisGate Security, LLC  
**Review Cycle:** Quarterly (or after any credential exposure incident)
