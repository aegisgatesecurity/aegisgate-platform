# DATA RETENTION SCHEDULE

**Effective Date:** June 1, 2026  
**Version:** 1.0 DRAFT

---

## INTRODUCTION

This Data Retention Schedule defines the retention and deletion periods for data processed by AegisGate Security, LLC ("Company," "we," or "us") in connection with the AegisGate Security Platform services.

This schedule supports compliance with GDPR, HIPAA, PCI-DSS, and other applicable data protection regulations.

---

## 1. DATA CATEGORIES

### 1.1 Categories Defined

| Category ID | Category Name | Description |
|-------------|---------------|-------------|
| DC-01 | Account Data | Subscriber account information |
| DC-02 | Configuration Data | System configurations and settings |
| DC-03 | Audit Logs | Security events and access logs |
| DC-04 | Compliance Reports | Generated compliance documentation |
| DC-05 | Session Data | MCP session metadata |
| DC-06 | Threat Data | Detected threats and patterns |
| DC-07 | Payment Data | Billing and subscription information |
| DC-08 | Support Data | Customer support tickets and communications |
| DC-09 | Usage Metrics | Aggregated usage statistics |

---

## 2. RETENTION PERIODS BY TIER

### 2.1 Community Tier

| Data Category | Retention Period | Legal Basis | Deletion Method |
|---------------|-----------------|-------------|-----------------|
| DC-01 Account Data | Duration of account + 30 days | Contractual obligation | Secure deletion |
| DC-02 Configuration | Duration of account | Legitimate interest | Secure deletion |
| DC-03 Audit Logs | 7 days | Minimal retention for free tier | Automatic purge |
| DC-04 Compliance Reports | Not generated | N/A | N/A |
| DC-05 Session Data | 7 days | Minimal retention | Automatic purge |
| DC-06 Threat Data | 7 days | Minimal retention | Automatic purge |
| DC-07 Payment Data | N/A (no payment) | N/A | N/A |
| DC-08 Support Data | 30 days | Legitimate interest | Secure deletion |
| DC-09 Usage Metrics | 30 days (aggregated) | Legitimate interest | Aggregation |

### 2.2 Starter Tier

| Data Category | Retention Period | Legal Basis | Deletion Method |
|---------------|-----------------|-------------|-----------------|
| DC-01 Account Data | Duration of subscription + 90 days | Contractual obligation | Secure deletion |
| DC-02 Configuration | Duration of subscription | Legitimate interest | Secure deletion |
| DC-03 Audit Logs | 14 days | Service requirement | Automatic purge |
| DC-04 Compliance Reports | 90 days | Service requirement | Secure deletion |
| DC-05 Session Data | 14 days | Service requirement | Automatic purge |
| DC-06 Threat Data | 14 days | Service requirement | Automatic purge |
| DC-07 Payment Data | Duration + 7 years | Tax obligation | Secure deletion |
| DC-08 Support Data | 90 days | Legitimate interest | Secure deletion |
| DC-09 Usage Metrics | 90 days (aggregated) | Legitimate interest | Aggregation |

### 2.3 Developer Tier

| Data Category | Retention Period | Legal Basis | Deletion Method |
|---------------|-----------------|-------------|-----------------|
| DC-01 Account Data | Duration of subscription + 90 days | Contractual obligation | Secure deletion |
| DC-02 Configuration | Duration of subscription | Legitimate interest | Secure deletion |
| DC-03 Audit Logs | 30 days | Service requirement | Automatic purge |
| DC-04 Compliance Reports | 90 days | Service requirement | Secure deletion |
| DC-05 Session Data | 30 days | Service requirement | Automatic purge |
| DC-06 Threat Data | 30 days | Service requirement | Automatic purge |
| DC-07 Payment Data | Duration + 7 years | Tax obligation | Secure deletion |
| DC-08 Support Data | 90 days | Legitimate interest | Secure deletion |
| DC-09 Usage Metrics | 180 days (aggregated) | Legitimate interest | Aggregation |

### 2.4 Professional Tier

| Data Category | Retention Period | Legal Basis | Deletion Method |
|---------------|-----------------|-------------|-----------------|
| DC-01 Account Data | Duration + 6 years | HIPAA requirement | Secure deletion |
| DC-02 Configuration | Duration + 6 years | HIPAA requirement | Secure deletion |
| DC-03 Audit Logs | 90 days | HIPAA/SOC2 requirement | Secure deletion |
| DC-04 Compliance Reports | 6 years | HIPAA requirement | Secure deletion |
| DC-05 Session Data | 90 days | HIPAA requirement | Secure deletion |
| DC-06 Threat Data | 90 days | HIPAA requirement | Secure deletion |
| DC-07 Payment Data | Duration + 7 years | Tax obligation | Secure deletion |
| DC-08 Support Data | 6 years | HIPAA requirement | Secure deletion |
| DC-09 Usage Metrics | 1 year (aggregated) | Legitimate interest | Aggregation |

### 2.5 Enterprise Tier

| Data Category | Retention Period | Legal Basis | Deletion Method |
|---------------|-----------------|-------------|-----------------|
| DC-01 Account Data | Duration + 1 year | Contractual obligation | Secure deletion |
| DC-02 Configuration | Duration + 1 year | Contractual obligation | Secure deletion |
| DC-03 Audit Logs | 1 year | Contractual obligation | Secure deletion |
| DC-04 Compliance Reports | 1 year | Contractual obligation | Secure deletion |
| DC-05 Session Data | 1 year | Contractual obligation | Secure deletion |
| DC-06 Threat Data | 1 year | Contractual obligation | Secure deletion |
| DC-07 Payment Data | Duration + 7 years | Tax obligation | Secure deletion |
| DC-08 Support Data | 1 year | Contractual obligation | Secure deletion |
| DC-09 Usage Metrics | 1 year (aggregated) | Contractual obligation | Aggregation |

---

## 3. REGULATORY RETENTION REQUIREMENTS

### 3.1 HIPAA (Professional Tier)

| Data Type | Minimum Retention | Requirement |
|-----------|------------------|-------------|
| HIPAA-related audit logs | 6 years | 45 C.F.R. § 164.530(j) |
| Business Associate Agreements | 6 years | 45 C.F.R. § 164.530(j) |
| PHI access logs | 6 years | HIPAA Security Rule |
| Compliance documentation | 6 years | HIPAA requirement |

### 3.2 PCI-DSS

| Data Type | Minimum Retention | Requirement |
|-----------|------------------|-------------|
| Audit logs | 1 year | PCI-DSS Req 10.7 |
| Access logs | 90 days | PCI-DSS Req 10.7 |
| Vulnerability scan results | 1 year | PCI-DSS Req 11.2 |

### 3.3 GDPR

| Data Type | Minimum Retention | Requirement |
|-----------|------------------|-------------|
| Processing records | 3 years | Article 30 |
| Data subject requests | 3 years | Accountability principle |
| Breach notifications | 3 years | Accountability principle |
| Consent records | Until withdrawal + 3 years | Accountability principle |

---

## 4. DELETION PROCEDURES

### 4.1 Automatic Deletion
Data approaching end of retention period is automatically purged via scheduled processes.

### 4.2 Secure Deletion
Sensitive data is deleted using industry-standard methods:
- **Logical deletion:** Overwriting with zeros
- **Cryptographic erasure:** Destroying encryption keys
- **Physical destruction:** For storage media (when applicable)

### 4.3 Manual Deletion Requests
Subscribers may request deletion of their data by:
1. Submitting a request via security@aegisgatesecurity.io
2. Verifying account ownership
3. Confirming scope of deletion request

We will process deletion requests within 30 days.

---

## 5. DATA SUBJECT REQUESTS

### 5.1 Right to Erasure (Article 17 GDPR)
Upon valid request, we will:
- Delete personal data within 30 days
- Notify any third-party sub-processors to delete copies
- Provide confirmation of deletion

### 5.2 Exceptions
Deletion may be delayed or denied if:
- Required for legal compliance
- Necessary for establishment, exercise, or defense of legal claims
- Required for public interest (archival, scientific, historical, statistical)

---

## 6. EXPORT AND PORTABILITY

### 6.1 Data Export
Subscribers may export their data:
- **Format:** JSON or CSV (as applicable)
- **Timeline:** Within 30 days of request
- **Method:** Via support request

### 6.2 Charges
Standard data export is free. Custom exports may incur fees.

---

## 7. RETENTION SCHEDULE UPDATES

This schedule is reviewed annually and updated as necessary to reflect:
- Changes in business practices
- Regulatory requirement updates
- Customer feedback

**Last Reviewed:** June 1, 2026  
**Next Review:** June 1, 2027

---

## 8. CONTACT

For questions about data retention or to request data deletion:

**Email:** support@aegisgatesecurity.io  
**Website:** https://aegisgatesecurity.io/privacy

---

*DRAFT - For discussion purposes only. Subject to legal review.*
