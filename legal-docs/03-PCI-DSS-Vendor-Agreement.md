# PCI-DSS VENDOR AGREEMENT

**Effective Date:** [DATE]  
**Version:** 1.0 DRAFT

---

## RECITALS

This PCI-DSS Vendor Agreement ("Agreement") is entered into by and between:

**Vendor:** AegisGate Security, LLC ("Company")  
**Address:** [ADDRESS]  
**Email:** support@aegisgatesecurity.io

and

**Merchant/Client:** The entity identified in the applicable Order Form ("Client")

---

## 1. INTRODUCTION

### 1.1 Purpose
This Agreement establishes the obligations of Company as a service provider in connection with Client's Payment Card Industry Data Security Standard ("PCI-DSS") compliance obligations.

### 1.2 PCI-DSS Requirements
Company acknowledges that Client may be required to comply with PCI-DSS and agrees to support Client's compliance efforts as set forth herein.

### 1.3 Scope of Services
The AegisGate Security Platform services covered under this Agreement are those for which Company processes, stores, or transmits cardholder data or sensitive authentication data on behalf of Client.

---

## 2. DEFINITIONS

### 2.1 "Cardholder Data"
Means the primary account number (PAN) plus any combination of:
- Cardholder name
- Expiration date
- Service code

### 2.2 "Sensitive Authentication Data"
Means security-related information used to authenticate cardholders, including:
- PINs
- PIN blocks
- CVV data
-磁 stripe/CVC data

### 2.3 "PCI-DSS"
Means the Payment Card Industry Data Security Standard, as may be amended from time to time by the PCI Security Standards Council.

### 2.4 "Service Provider"
Means a business entity that processes, stores, or transmits cardholder data on behalf of another entity.

### 2.5 "Segmentation"
Means the isolation of the cardholder data environment from other networks.

---

## 3. OBLIGATIONS OF COMPANY

### 3.1 PCI-DSS Compliance
Company shall:
- (a) Maintain compliance with PCI-DSS requirements applicable to a Level 1 Service Provider
- (b) Provide evidence of compliance upon request
- (c) Notify Client of any compliance violations or breaches

### 3.2 Security Controls
Company shall implement and maintain:
- (a) Firewalls and network segmentation to protect cardholder data
- (b) Strong access control measures
- (c) Encryption of cardholder data in transit and at rest
- (d) Regular security testing and vulnerability management
- (e) Written information security policies

### 3.3 Data Handling
Company shall:
- (a) Not store cardholder data after transaction authorization
- (b) Not store sensitive authentication data after authorization
- (c) Encrypt stored cardholder data using strong cryptography
- (d) Mask PAN when displayed

### 3.4 Access Controls
Company shall:
- (a) Restrict access to cardholder data on a need-to-know basis
- (b) Assign unique IDs to each user
- (c) Implement MFA for administrative access
- (d) Log all access to cardholder data

### 3.5 Incident Response
Company shall:
- (a) Maintain an incident response plan
- (b) Notify Client of suspected or confirmed security incidents
- (c) Investigate incidents and provide reports
- (d) Cooperate with forensic investigations

### 3.6 Audit Rights
Company shall:
- (a) Allow Client to conduct security assessments
- (b) Provide evidence of compliance upon request
- (c) Permit penetration testing of relevant systems
- (d) Remediate identified vulnerabilities

### 3.7 Penetration Testing
Company shall conduct annual penetration testing of the cardholder data environment and provide reports to Client upon request.

### 3.8 Quarterly Scans
Company shall conduct quarterly network vulnerability scans using an Approved Scanning Vendor (ASV) and provide scan reports to Client upon request.

---

## 4. PROHIBITED ACTIVITIES

Company shall not:
- (a) Use vendor default passwords or security parameters
- (b) Store cardholder data beyond transaction authorization
- (c) Share cardholder data with third parties without consent
- (d) Use cardholder data for any purpose other than authorized transaction processing
- (e) Connect systems containing cardholder data to unsecured networks

---

## 5. COMPLIANCE EVIDENCE

### 5.1 Attestation of Compliance
Company shall provide an Attestation of Compliance (AOC) upon request, completed by a Qualified Security Assessor (QSA) or Internal Security Assessor (ISA) at least annually.

### 5.02 Inventory
Company shall maintain an accurate inventory of system components and cardholder data flows.

### 5.03 Documentation
Company shall maintain documentation sufficient to demonstrate compliance with PCI-DSS requirements.

---

## 6. BREACH NOTIFICATION

### 6.1 Notification
Company shall notify Client immediately (within 24 hours) upon discovery of any incident involving:
- Unauthorized access to cardholder data
- Loss or theft of system components containing cardholder data
- Any other event that may compromise cardholder data

### 6.02 Forensic Investigation
Company shall cooperate with forensic investigation of security incidents and provide access to relevant systems and logs.

### 6.03 Costs
Company shall bear costs of forensic investigation and remediation directly related to Company's breach of this Agreement.

---

## 7. TERM AND TERMINATION

### 7.1 Term
This Agreement shall be effective as of the Effective Date and continue for the duration of the Services.

### 7.02 Termination
Either party may terminate upon [30] days written notice if the other party breaches a material term.

### 7.03 Survival
The following sections shall survive termination: 3, 4, 6, and 8.

---

## 8. GENERAL PROVISIONS

### 8.1 Governing Law
This Agreement shall be governed by the laws of [STATE/JURISDICTION].

### 8.2 Entire Agreement
This Agreement constitutes the entire agreement between the parties regarding PCI-DSS compliance.

### 8.03 Amendment
This Agreement may be amended by written agreement of both parties.

### 8.04 Severability
If any provision is held invalid, the remaining provisions shall remain in effect.

---

## SIGNATURES

**COMPANY:**

AegisGate Security, LLC  
Signature: _________________________________  
Date: _________________________________

**CLIENT:**

[CLIENT NAME]  
Signature: _________________________________  
Date: _________________________________

---

*DRAFT - For discussion purposes only. Subject to legal review.*
