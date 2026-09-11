# AegisGate Vulnerability Disclosure Program (VDP)

## Overview

The AegisGate VDP defines the scope, rules, and process for security researchers to report vulnerabilities in AegisGate products. This program supplements our [Security Policy](./SECURITY.md) with formal scope definitions, safe harbor terms, and recognition guidelines.

## Scope

### In Scope

| Product | Surface | Examples |
|---------|---------|---------|
| AegisGate Platform | Gateway proxy, API, admin panel, Docker image | Authentication bypass, injection, SSRF, RCE, path traversal |
| AegisGate Rampart | Local proxy, MITM interception, IDE plugins | Privilege escalation, local file access, interception failure |
| AegisGate Lens | Browser extension, content scripts, background | XSS in banner UI, CSP bypass, data exfiltration, message spoofing |
| AegisGate Enterprise | Trust Framework, SIEM, compliance modules | Signature bypass, privilege escalation, log injection |
| aegisgatesecurity.io | Website, API endpoints | XSS, SQLi, SSRF, information disclosure |

### Out of Scope

- Vulnerabilities in third-party dependencies (report to upstream maintainers)
- Social engineering or phishing attacks
- Physical security attacks
- Denial of Service (DoS) or Distributed DoS
- Automated scanner reports without manual verification
- Vulnerabilities requiring physical access to a developer's machine
- Bugs in outdated versions (report against latest release only)
- Rate limiting or brute force on authentication endpoints (we handle this operationally)

### Special Considerations for Lens

AegisGate Lens is a **privacy-first** browser extension. The following are **by design** and **not vulnerabilities**:
- Lens reads prompt text from AI chat textareas — this is the core functionality, not data exfiltration
- Lens runs ML inference on-device — no data leaves the browser
- Lens uses `innerHTML` in `banner-ui.js` with escaped content — this has been reviewed and is safe

## Rules of Engagement

1. **Act in good faith** — Do not access or modify data belonging to others
2. **Minimize impact** — Do not degrade or disrupt our services
3. **No automated scanning** — Manual testing only; do not run high-volume scanners against our infrastructure
4. **Respect privacy** — Do not access private information of other users
5. **Report first** — Report vulnerabilities before public disclosure
6. **Allow reasonable time** — Give us at least 90 days before public disclosure
7. **One vulnerability per report** — Keep reports focused for faster triage

## Reporting Process

### How to Report

1. Email: **security@aegisgatesecurity.io**
2. Include: product name, version, vulnerability description, reproduction steps, impact assessment
3. PGP key available on request (fingerprint: B528 D336 DE00 5528 3B10 236D 899C 3B0F A233 6D7B)

### Response Timeline

| Milestone | Target | Notes |
|-----------|--------|-------|
| Acknowledgment | 48 hours | Confirm receipt and assign tracking ID |
| Initial assessment | 5 business days | Determine severity and validity |
| Fix or mitigation plan | 10 business days | Communicate remediation plan to reporter |
| Fix released | 30-90 days | Severity-dependent (Critical: 30d, High: 60d, Medium/Low: 90d) |
| Public disclosure | After fix | Coordinated with reporter; credit given |

### Severity Rating

We use the CVSS v3.1 scoring system:

| Severity | CVSS Range | Fix Timeline |
|----------|-----------|--------------|
| Critical | 9.0-10.0 | 30 days |
| High | 7.0-8.9 | 60 days |
| Medium | 4.0-6.9 | 90 days |
| Low | 0.1-3.9 | Next release |

## Safe Harbor

AegisGate Security, LLC will **not** pursue legal action against security researchers who:

1. Act in good faith and in compliance with these rules
2. Do not access or modify data belonging to others
3. Do not degrade or disrupt our services or infrastructure
4. Report vulnerabilities through the process described above
5. Give us reasonable time to fix before any public disclosure
6. Do not demand financial compensation as a condition of reporting

This safe harbor does **not** cover:
- Unauthorized access to customer data or production systems
- Attacks that cause service disruption
- Attempts to exploit vulnerabilities for financial gain
- Violations of applicable laws

## Recognition

With the reporter's permission, we will:
- Acknowledge the contribution in our release notes
- List the researcher in our security advisories
- Provide a public thank-you on our website

We do not currently offer monetary rewards (bug bounty). This may change as the program matures.

## Contact

- **Security email:** security@aegisgatesecurity.io
- **PGP fingerprint:** B528 D336 DE00 5528 3B10 236D 899C 3B0F A233 6D7B
- **GitHub Security Advisories:** Use GitHub's private vulnerability reporting on each repo
- **Discussions:** https://github.com/aegisgatesecurity/aegisgate-platform/discussions

---

*Copyright © 2026 AegisGate Security, LLC. All rights reserved.*