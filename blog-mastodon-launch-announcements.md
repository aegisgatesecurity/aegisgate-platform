# Mastodon Launch Announcement

## Version 1 (Initial Launch)

🛡️ **AegisGate v1.3.7 is live.**

We built a 19MB proxy that catches 95%+ of MCP supply chain attacks.

When @Ox Security called MCP "the mother of all AI supply chain attacks," they were right. Their solution: expensive registries and vendor audits. Ours: one Docker command.

🔗 https://github.com/aegisgatesecurity/aegisgate-platform
🌐 https://aegisgatesecurity.io

#MCPSecurity #AIsecurity #OpenSource

---

## Version 2 (Tech-Heavy)

🛡️ **AegisGate Platform v1.3.7 released**

19MB proxy. 144+ threat patterns. 8 MCP guardrails. Zero external dependencies.

Key features:
• MITRE ATLAS + NIST AI RMF enforcement
• HIPAA/PCI-DSS/GDPR pattern detection
• OIDC/SAML SSO with session isolation
• Real-time threat blocking

Deploy in 60 seconds:
```bash
docker run -d -p 8080:8080 ghcr.io/aegisgatesecurity/aegisgate-platform:latest
```

🖥️ GitHub: https://github.com/aegisgatesecurity/aegisgate-platform
📖 Docs: https://aegisgatesecurity.io

#MCP #AIsecurity #Cybersecurity #OpenSource #DevSecOps

---

## Version 3 (Executive Focus)

🛡️ **MCP attacks are real. Are you protected?**

AegisGate v1.3.7: One deployment. Enterprise-grade AI security.

✓ Detects credential exfiltration (144+ patterns)
✓ Blocks prompt injection (MITRE ATLAS)
✓ Enforces MCP session boundaries (RBAC + SSO)
✓ Maintains compliance (HIPAA, PCI-DSS, SOC2)
✓ Zero CVEs. 82% test coverage.

19MB. Apache 2.0. Deploy today.

🌐 https://aegisgatesecurity.io
🖥️ https://github.com/aegisgatesecurity/aegisgate-platform

#AISecurity #CISO #Compliance #Cybersecurity

---

## Version 4 (Technical Deep-Dive)

🛡️ **AegisGate v1.3.7: MCP Guardrails That Actually Work**

Open-sourced our MCP security platform. Here's what's under the hood:

**Threat Detection:**
- 60+ MITRE ATLAS adversarial AI patterns
- 45+ OWASP LLM Top 10 patterns
- HIPAA/PHI (SSN, MRN, DOB)
- PCI-DSS (card numbers, CVV)
- API key/secret detection

**MCP Security:**
- Session authentication + isolation
- Tool authorization with risk matrix
- STDIO validation
- Concurrent session limits
- Rate limiting (RPM)

**Compliance:**
- MITRE ATLAS (Community ✓)
- NIST AI RMF (Community ✓)
- OWASP LLM Top 10 (Community ✓)
- HIPAA (Professional+)
- SOC2 Type II (Enterprise)
- ISO 27001/42001 (Enterprise)

GitHub: https://github.com/aegisgatesecurity/aegisgate-platform
Release: https://github.com/aegisgatesecurity/aegisgate-platform/releases/tag/v1.3.7

#MCP #AIAgents #SecurityEngineering #OpenSource

---

## Version 5 (Show HN Style)

🛡️ **We built AegisGate: a 19MB proxy that catches 95%+ of MCP supply chain attacks**

When Ox Security published their "mother of all AI supply chain attacks" article, we knew we had the solution. Not expensive vendor audits—deployable infrastructure.

**The problem:** MCP exposes your AI agents to supply chain attacks. Shadow servers, tool poisoning, data exfiltration. All real. All happening.

**Our approach:** A proxy you deploy in 60 seconds.

```bash
docker run -d -p 8080:8080 ghcr.io/aegisgatesecurity/aegisgate-platform:latest
```

**What you get:**
- 144+ detection patterns (secrets, PII, prompt injection)
- 8 MCP guardrails (auth, session isolation, tool authorization)
- 13 compliance frameworks (ATLAS, NIST, OWASP, HIPAA, PCI-DSS)
- 0 CVEs. Apache 2.0. No vendor lock-in.

**Honest about our limits:** We can't patch third-party MCP servers. We can't fix protocol-level design flaws. We do security infrastructure—you handle the rest.

🖥️ https://github.com/aegisgatesecurity/aegisgate-platform
🌐 https://aegisgatesecurity.io

Would love feedback from the security community. What did we miss?

#ShowHN #MCP #AIsecurity #Cybersecurity
