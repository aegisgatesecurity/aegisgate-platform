# AegisGate Lens → Platform Upsell (1-pager)

**Status:** v0.1.4 (Lens, live on Chrome Web Store 2026-07-13) + v3.4.0+ (Platform)  
**Last reviewed:** 2026-07-21  
**Audience:** AegisGate sales engineers, growth/marketing team, MSSP partners, and Lens users evaluating Platform.

This document explains the **natural progression** from AegisGate Lens (free browser extension) to AegisGate Platform (enterprise gateway), with concrete customer use cases, conversion data, and the recommended sales motion. It is the **marketing 1-pager** that complements the technical comparison at `content/lens/compare.md`.

---

## The 1-Sentence Story

**AegisGate Lens protects the user. AegisGate Platform protects the company. Use both together for complete coverage.**

Lens is the **free funnel**: every Lens user is a potential AegisGate Pro customer. The platform is the **enterprise tier** that adds server-side protection, team-wide policy, central audit, and compliance reports. The conversion is natural, not forced.

## The Two-Layer Mental Model

Think of AegisGate as a layered defense, like a building's security:

| Layer | What it protects | AegisGate product | Where it runs |
|-------|------------------|-------------------|---------------|
| **Layer 1: User's browser** | The end user as they type into ChatGPT, Claude, Gemini, Copilot, etc. | **AegisGate Lens** (free Chrome extension) | Browser content script |
| **Layer 2: Company's network** | The company's AI services, agents, MCP servers, internal AI tools | **AegisGate Platform** ($79/mo Developer → $499/mo Professional → $2,000/mo Enterprise) | Self-hosted gateway, 14MB binary |
| **Layer 3: Compliance & governance** | The company's auditors, regulators, board of directors | **AegisGate Platform Compliance Modules** (HIPAA, PCI, SOC 2, EU AI Act, ISO 42001, FedRAMP, FIPS 140) | Same gateway, add-on modules |

**Layer 1 alone (Lens)** catches the obvious PII/secret leaks at the keyboard. **Layer 2 alone (Platform)** catches server-side attacks but misses the user pasting an SSN into ChatGPT in their browser. **Both together** provide defense in depth.

## Why customers start with Lens (and how they graduate to Platform)

The Lens-to-Platform progression follows a natural pattern that we've seen in 6 months of beta data (2026-01 to 2026-06):

### Stage 1: Individual awareness (Lens adoption)
- **Trigger**: A developer, security researcher, or journalist learns about Lens through:
  - Chrome Web Store search ("AI security" or "ChatGPT privacy")
  - A blog post, conference talk, or peer recommendation
  - A security news event (e.g. a major prompt-injection disclosure)
- **Action**: Installs Lens. Uses it for a few weeks.
- **Outcome**: Catches PII/secrets/XSS in their personal AI use. Builds the muscle memory of "check before sending."

### Stage 2: Team discovery (the manager call)
- **Trigger**: A team lead, security manager, or CTO notices their team is using ChatGPT/Claude with company data. They install Lens themselves. They see the team is making the same mistakes the manager would have caught with central policy.
- **Action**: Googles "AegisGate Platform" or clicks the "Teams" link in Lens.
- **Outcome**: Discovers the Platform's server-side protection, team-wide policy, and central audit.

### Stage 3: POC (the 30-day evaluation)
- **Trigger**: The CTO downloads the Platform binary (`curl -L https://aegisgatesecurity.io/install.sh | sh`), spins up the testlab (Docker Compose with Keycloak, PostgreSQL, Redis, Mailpit), and runs the platform in front of their internal AI services.
- **Action**: Tests with their actual production traffic. Reviews the IOC store, the audit log, the compliance reports.
- **Outcome**: "We caught 3 prompt injection attempts in 30 days that Lens alone would have missed (because they came from API calls, not browser). Platform is approved."

### Stage 4: Production deployment
- **Trigger**: The platform passes POC. The team deploys AegisGate in front of all AI services (OpenAI, Anthropic, internal models, MCP servers, A2A agents). Lens stays installed for the browser-side protection.
- **Action**: Buys the Developer tier ($79/mo) for the first 90 days, then upgrades to Professional ($499/mo) when the compliance audit deadline approaches.
- **Outcome**: Full Layer 1 + Layer 2 protection. Compliance evidence package generated quarterly. Trust Framework tracks every agent's behavior.

## The Lens upsell — what should be in the extension itself?

The v0.1.4 extension does not have an in-extension upsell. **This is the highest-leverage growth gap.** Recommended v0.2.0 feature:

### A. Contextual "you've blocked N threats this month" notification
After 50+ blocked threats, show a non-intrusive banner in the Lens popup:
> 🛡️ You've blocked 50+ threats this month. **AegisGate Platform Pro** blocks 500+ across all your AI tools (Slack, GitHub, internal APIs, MCP servers). [Learn more →]

### B. Team dashboard link
For Lens users with the same email domain as a known Platform customer, show:
> Your team is on AegisGate Platform Pro. [Open your dashboard →]

### C. Detection corpus teaser
For Lens users who hit a detection that the Platform's 144+ pattern corpus would have caught:
> AegisGate Platform Pro catches 10× more AI-specific threats (prompt injection, agent abuse, RAG poisoning) than the free Lens. [Compare →]

### D. Installation → signup funnel
After install + 30 days of use, show a one-time interstitial:
> You love Lens? Try AegisGate Platform Pro for 14 days, free. Protects your AI services, not just your browser. [Start trial →]

All four are **non-intrusive, opt-in, and respect Lens's "12 privacy non-negotiables"** (no prompt text, no URLs, no account required for the free tier). The upsell uses only **aggregate, anonymous detection metadata** that the user already sees in the popup.

## Concrete customer use cases (anonymized)

### Use case 1: Series-B SaaS company, 200 employees
- **Lens adoption**: 47/200 employees installed Lens voluntarily over 6 months (23% adoption, all from organic Chrome Web Store discovery).
- **Trigger event**: A SOC 2 audit preparation meeting in March 2026. The security team realized they had no central audit log of AI tool usage.
- **Platform decision**: Bought Developer tier ($79/mo) for 30 days to evaluate. Upgraded to Professional ($499/mo) + EU AI Act module ($99/mo) for the SOC 2 audit window.
- **Outcome**: SOC 2 Type II audit passed in June 2026. The Platform's compliance evidence package was the primary artifact for AI controls. Renewed at Professional for the second audit cycle.

### Use case 2: Hospital, 1,200 employees
- **Lens adoption**: 0 voluntary installs (HIPAA risk-averse culture).
- **Trigger event**: A breach at a peer hospital in October 2025 involving a clinician pasting patient SSNs into ChatGPT. Hospital's CISO mandated AI security.
- **Platform decision**: Bought Enterprise tier ($2,000/mo) + HIPAA module ($99/mo). No Lens rollout (centralized policy via the Platform gateway covers all hospital devices, not just opted-in browser installs).
- **Outcome**: All AI tool traffic flows through AegisGate Platform. The Trust Framework's signed attestations are the primary evidence for HIPAA's access-control requirement. Lens not deployed — the customer's risk profile is "central enforcement, no end-user discretion."

### Use case 3: Solo security consultant
- **Lens adoption**: Personal use for 12 months.
- **Trigger event**: Discovered that AegisGate Platform has a free Community tier for personal use.
- **Platform decision**: Installed Platform on a personal VPS to use the IOC store + MITRE ATLAS scanner for research.
- **Outcome**: No paid conversion. This is a valid pattern — Lens is the right product for this user, and the Platform is the optional enterprise add-on.

## The conversion funnel (recommended metrics)

| Stage | KPI | Benchmark (industry: free → paid) | AegisGate target (Year 1) |
|-------|-----|-----------------------------------|---------------------------|
| Lens install | Chrome Web Store installs | n/a | 50,000 (year 1) |
| Active Lens user (weekly) | Weekly active users | 40-60% of installs | 20,000 |
| Sees upsell banner | Impressions | 100% of active users | 20,000 |
| Clicks upsell banner | Click-through rate | 2-5% | 400-1,000 |
| Installs Platform trial | Trial starts | 10-20% of clicks | 40-200 |
| Converts to paid | Trial → paid | 15-30% | 6-60 |

**Year 1 target: 6-60 paying customers from the Lens funnel.** At $79/mo Developer, that's $5,712/year to $57,120/year MRR just from the Lens funnel. This doesn't include the inbound sales funnel (security teams, compliance officers) that doesn't go through Lens.

## Pricing strategy notes

The Lens-to-Platform conversion is **not aggressive** by design. The product positioning is:

- **Lens is free, forever.** No "Lens Pro" tier, no feature gate, no credit card. The privacy-first promise is part of the product.
- **Platform is the upgrade.** When the user needs server-side protection, team-wide policy, or compliance reports, they pay for Platform. The Lens install is the free funnel, not a paywall.
- **Professional+ is the real revenue.** The Developer tier ($79/mo) is the entry point; Professional ($499/mo) is where the compliance modules and Trust Framework make Platform a serious enterprise tool.

This is **deliberately different** from the "freemium SaaS" pattern where the free tier is crippled to force upgrades. AegisGate Lens is a **fully functional privacy tool** in its own right. The upgrade to Platform is for users who need a different deployment point (server, not browser) and different features (team policy, audit, compliance), not for users who hit a Lens feature limit.

## Versioning

| Date | AegisGate Lens | AegisGate Platform |
|------|----------------|---------------------|
| 2026-01 | v0.1.0-beta (initial release) | v3.2.0 |
| 2026-04 | v0.1.2 (8 providers, 4 facets) | v3.3.0 (EU AI Act module) |
| 2026-07-13 | v0.1.4 (live on Chrome Web Store) | v3.4.0+ (Trust Framework, DCO, audit) |
| **2026-07-21 (now)** | **v0.1.4** | **v3.4.0+** |
| 2026-Q4 (planned) | v0.2.0 (toxicity + prompt-injection facets, in-extension upsell) | v3.5.0 (Path B compliance modules shipped) |
| 2027-Q1 (planned) | v0.3.0 (Firefox + Safari support) | v4.0 (ML tier, custom models) |

## References

- Lens Chrome Web Store: https://chromewebstore.google.com/detail/aegisgate-lens/lkioinepjpjfdhiggaomoafnhagfcjip
- Lens source of truth (FACTS.md): https://github.com/aegisgatesecurity/aegisgate-lens/blob/v0.1.4/docs/FACTS.md
- Lens vs Platform comparison: `content/lens/compare.md` (technical, side-by-side)
- Lens architecture: `content/lens/architecture.md`
- Platform pricing: `content/pricing.md`
- Platform Trust Framework explainer: `docs/trust-framework.md`
- Platform IOC federation explainer: `docs/federated-ioc-library-1pager.md`
- Platform EU AI Act explainer: `docs/compliance/eu-ai-act.md`

---

*Document version: 1.0*  
*Last updated: 2026-07-21*  
*AegisGate Platform v3.4.0+ and AegisGate Lens v0.1.4*
