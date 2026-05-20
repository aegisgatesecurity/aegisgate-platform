# SECURITY ADDENDUM

**Effective Date:** [DATE]  
**Version:** 1.0 DRAFT

---

## RECITALS

This Security Addendum ("Addendum") is incorporated into and made part of the Master Service Agreement between AegisGate Security, LLC ("Company") and Subscriber. This Addendum establishes additional security requirements applicable to Professional and Enterprise tier services.

---

## 1. SECURITY FRAMEWORK

### 1.1 Compliance Standards
Company maintains security controls aligned with:
- NIST Cybersecurity Framework
- SOC 2 Type II (for Enterprise)
- ISO 27001 principles
- HIPAA Security Rule (when HIPAA module is active)
- PCI-DSS requirements (when PCI-DSS module is active)

### 1.2 Security Certifications
Company maintains the following security certifications:
- Annual penetration testing by independent third party
- Annual SOC 2 Type II audit (Enterprise tier)
- Quarterly vulnerability scanning
- Continuous security monitoring

---

## 2. INFRASTRUCTURE SECURITY

### 2.1 Data Centers
Customer data is hosted in:
- [AWS US-East-1 / GCP us-central1 / Azure East US] (primary)
- [AWS US-West-2 / GCP us-west1 / Azure West US] (backup)

All data centers maintain:
- SOC 2 Type II certification
- ISO 27001 certification
- Physical security controls (badge access, CCTV, security guards)

### 2.2 Network Security
Company implements:
- Network segmentation
- Web Application Firewall (WAF)
- DDoS protection
- Intrusion detection/prevention systems (IDS/IPS)
- Network monitoring and logging

### 2.3 Encryption
All data is encrypted:
- **In Transit:** TLS 1.3 minimum for all connections
- **At Rest:** AES-256 encryption for stored data
- **Keys:** Managed encryption keys with rotation policies

---

## 3. ACCESS CONTROLS

### 3.1 Company Access
Company personnel access to customer data is restricted to:
- Authorized engineering staff with legitimate need
- Temporary elevated access with approval and time limits
- Full audit logging of all access

### 3.2 Authentication
Company enforces:
- Multi-factor authentication (MFA) for all internal systems
- Strong password policies (minimum 16 characters, complexity requirements)
- Regular access reviews (quarterly)
- Immediate revocation upon termination

### 3.3 Privileged Access
Privileged access (administrative accounts) is:
- Limited to minimum necessary personnel
- Subject to additional approval and monitoring
- Reviewed monthly
- Documented in access logs

---

## 4. VULNERABILITY MANAGEMENT

### 4.1 Scanning
Company conducts:
- Quarterly external vulnerability scans
- Monthly internal vulnerability scans
- Annual penetration testing
- Real-time malware detection

### 4.2 Patching
Company maintains:
- Critical patches within 72 hours
- High-severity patches within 7 days
- Medium-severity patches within 30 days
- Emergency patching procedures for critical vulnerabilities

### 4.3 Incident Response
Security incidents are addressed per our Incident Response Policy:
- Critical incidents: Response within 1 hour
- High-severity incidents: Response within 4 hours
- Medium-severity incidents: Response within 24 hours
- Low-severity incidents: Response within 7 days

---

## 5. CUSTOMER SECURITY REQUIREMENTS

### 5.1 Customer Responsibilities
Subscriber is responsible for:
- Securing account credentials
- Implementing appropriate network security
- Encrypting sensitive data in transit
- Following secure integration practices
- Regular security assessments of their environment

### 5.2 Integration Security
When integrating with the Service, Subscriber should:
- Use TLS for all API connections
- Store API keys securely (not in code)
- Implement appropriate access controls
- Monitor access logs for anomalies
- Report security concerns promptly

---

## 6. AUDIT AND COMPLIANCE

### 6.1 Audit Rights
Upon request, Company provides:
- SOC 2 Type II audit reports (Enterprise)
- Penetration test reports (redacted for confidentiality)
- Security certifications and attestations
- Compliance documentation

### 6.2 Compliance Assistance
Company provides reasonable assistance for Subscriber's compliance efforts:
- Security documentation
- Compliance reports
- Technical specifications
- Architecture diagrams

### 6.03 Evidence Collection
For compliance audits, Company provides:
- System inventory
- Access logs (as applicable)
- Configuration documentation
- Security policies (summary)

---

## 7. BUSINESS CONTINUITY

### 7.1 Backup and Recovery
Company maintains:
- Daily backups of customer data
- Weekly backups of system configurations
- Monthly backup restoration testing
- Recovery Point Objective (RPO): 24 hours
- Recovery Time Objective (RTO): 4 hours

### 7.2 Disaster Recovery
Company maintains:
- Geographic redundancy
- Automated failover
- Documented disaster recovery procedures
- Annual DR testing

### 7.3 Incident Notification
In the event of a security incident affecting Subscriber data, Company will:
- Notify within 24 hours of discovery (72 hours for GDPR)
- Provide incident details and scope
- Share remediation steps taken
- Cooperate with investigations

---

## 8. SECURITY QUESTIONNAIRE

### 8.1 Availability
Company maintains a standard security questionnaire that may be provided to Enterprise customers upon request.

### 8.02 Custom Assessments
For Enterprise customers with specific security requirements:
- On-site security assessments (scheduled in advance)
- Custom penetration testing scopes (additional fees may apply)
- Security architecture reviews

---

## 9. CONTACT

For security-related questions or to request compliance documentation:

**Security Email:** security@aegisgatesecurity.io  
**Security Website:** https://aegisgatesecurity.io/security  
**Report Vulnerabilities:** https://aegisgatesecurity.io/security#report

---

## 10. EXHIBIT A: SECURITY CONTROLS SUMMARY

### Access Control (AC)
- AC-1: Access control policy and procedures
- AC-2: Account management
- AC-3: Access enforcement
- AC-6: Least privilege

### Audit and Accountability (AU)
- AU-2: Event logging
- AU-6: Audit review and reporting
- AU-9: Protection of audit information

### System and Communications Protection (SC)
- SC-8: Transmission confidentiality and integrity
- SC-13: Cryptography
- SC-28: Protection of information at rest

### System and Information Integrity (SI)
- SI-3: Malicious code protection
- SI-4: System monitoring
- SI-5: Security alerts and advisories

---

*DRAFT - For discussion purposes only. Subject to legal review.*
