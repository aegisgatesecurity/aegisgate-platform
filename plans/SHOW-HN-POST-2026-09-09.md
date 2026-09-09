# Hacker News "Show HN" Post — Draft

**Date:** 2026-09-09  
**Purpose:** Free visibility to the exact audience that cares about open-source security tools  
**Timing:** Tuesday, Wednesday, or Thursday — 8:00-10:00 AM ET (peak HN traffic)  
**Account requirement:** HN account with >0 karma (if you don't have one, create one and participate in a few threads first)

---

## The Post

**Title:**

```
Show HN: I built an open-source AI security gateway that blocks data exfiltration to AI tools
```

**Body:**

---

Hi HN,

I'm a solo developer who spent the last year building AegisGate — an open-source, self-hosted security layer for AI tools. It sits between your users and ChatGPT, Copilot, Claude, and any LLM API, and blocks sensitive data from leaving your infrastructure.

**The problem:** Every company is using AI tools now. Employees paste API keys, customer PII, source code, and trade secrets into ChatGPT and Copilot every day. There's no security layer. DLP tools weren't built for AI. AI safety tools focus on prompt injection, not data exfiltration.

**What it does:**
- 216 regex patterns: PII (SSNs, credit cards, emails, phones, international IDs), API keys (AWS, GCP, Azure, GitHub, Slack, Stripe, etc.), secrets, OT protocols (Modbus, DNP3, OPC-UA), harmful content
- 33 compliance frameworks: HIPAA, PCI DSS, SOC 2, EU AI Act, ISO 42001, FedRAMP, NIST AI RMF, MITRE ATLAS, OWASP LLM Top 10, and more
- Custom ML model (CharCNN-BiLSTM, 1.58M params, ONNX) running locally — no cloud calls, no data sent anywhere
- 99.8/100 evasion resistance across 2,600 adversarial test cases (52 MITRE ATLAS payloads × 50 transforms)
- 0% false positive rate

**Three products:**
- **Lens** — browser extension for ChatGPT/Claude/Gemini (free)
- **Rampart** — local proxy for Copilot/Cursor/Claude Code (free)
- **Platform** — enterprise gateway proxy (free Community tier, paid tiers from $79/mo)

**Key things HN will care about:**
- Single 34.7MB Go binary, zero runtime dependencies
- 0.42ms p50 latency, 23,578 RPS, 0% error at 5,000 concurrent users (8-hour endurance tested)
- Apache 2.0 licensed
- Self-hosted — no SaaS, no data egress, works air-gapped
- Covers MCP (Model Context Protocol), A2A (agent-to-agent), ACP, and standard HTTP proxy
- Trust Framework: per-agent ECDSA identity, capability contracts, real-time trust scoring, signed attestations

**Architecture:** 3-layer detection — regex scanner → ATLAS/compliance engine → neural network. Each layer can run independently. The ML model runs via ONNX Runtime (Go) or pure JS (browser extension).

**What I learned building this solo:**
- Training a production ML model for security detection is harder than I expected — 10 iterations to get from 83% detection to 99.8%
- Evasion resistance is the real challenge — attackers will use Unicode tricks, keyboard walk encoding, character substitution. I built a 50-transform evasion suite and tested against it
- Compliance frameworks are a rabbit hole — EU AI Act alone has 82 controls across 9 categories
- Performance matters more than I thought — 20ms latency from a SaaS competitor vs 0.42ms locally is the difference between "security team mandates it" and "users bypass it"

**Links:**
- GitHub: https://github.com/aegisgatesecurity
- Website: https://aegisgatesecurity.io
- Docs: https://aegisgatesecurity.io/docs/

I'm currently looking for design partners — companies that want to deploy this in production for free in exchange for feedback. If your team uses AI tools and you want a security layer, I'd love to talk.

Happy to answer any technical questions about the architecture, the ML model, the detection patterns, or the compliance frameworks.

---

## Posting Tips

1. **Don't use marketing language.** HN can smell it. The draft above is intentionally technical and honest.
2. **Be present in the comments.** Respond to every comment within 1 hour. Technical depth = credibility on HN.
3. **Expect skepticism.** Someone will ask "how is this different from [X]?" — have your answer ready (the multi-protocol + self-hosted + compliance + ML combination is the differentiator).
4. **Have data ready.** If someone asks about false positive rates, share the actual test results. If someone asks about performance, share the benchmark methodology.
5. **Don't link to a pricing page in the post.** Let people find it. HN dislikes salesy posts.
6. **Engage with critics.** The person who says "this won't work because [reason]" is giving you free product feedback. Thank them and address the concern.
7. **Post on Tuesday-Thursday, 8-10 AM ET.** This is when HN traffic is highest and the "new" page moves slowest.
8. **If it gets flagged or doesn't take off, don't be discouraged.** Try again in 2-4 weeks with a different angle (e.g., "Show HN: A self-hosted ML model that detects AI prompt injection with 0% false positives").

## Anticipated Questions & Prepared Answers

**Q: How is this different from Lakera Guard or Prompt Security?**
A: They're SaaS — your data goes through their servers. AegisGate is self-hosted. They cover prompt injection; we cover data exfiltration + compliance. They support 1 protocol; we support 6 (MCP, A2A, ACP, ANP, HTTP proxy, response scanning). We have 33 compliance frameworks; they have 0-5. We're open source; they're proprietary.

**Q: 0% false positive rate? That sounds too good to be true.**
A: The 0% FPR is on the evasion test suite (2,600 adversarial cases). In production with real traffic, expect 0.1-0.5% FPR. The ML model is threshold-tuned at 0.50 and the regex patterns are precision-optimized. The key is the 3-layer approach — the regex layer catches exact patterns (near-zero FPR), the compliance layer catches framework violations (rule-based, deterministic), and the ML layer catches novel/obfuscated threats.

**Q: Why not just use a DLP tool?**
A: DLP tools (Nightfall, Microsoft Purview) are built for email and file sharing, not AI tool prompts. They don't understand MCP protocol, they don't map to AI-specific compliance frameworks (EU AI Act, NIST AI RMF, MITRE ATLAS), and they're SaaS (data goes to their servers). AegisGate is purpose-built for AI tool security.

**Q: What's the Trust Framework?**
A: Every AI agent gets an ECDSA P-256 identity. When agent A sends a message to agent B, it carries a signed capability contract (what it's allowed to do), a trust score (based on behavior), and a signed attestation. Agent B can verify the sender's identity and decide whether to trust the request. It's like mTLS but for AI agents.

**Q: How long did this take?**
A: About 12 months, solo. The codebase is ~530K LOC of Go with 12,700+ tests. The ML model went through 10 training iterations.

**Q: What's the business model?**
A: Open source with paid tiers. Free Community tier (unlimited users, basic detection). Developer $79/mo. Professional $499/mo (compliance modules, Trust Framework, SIEM integration). Enterprise $2,000+/mo (SSO, SLA, air-gapped support). Compliance modules are add-ons ($79-499/mo each).