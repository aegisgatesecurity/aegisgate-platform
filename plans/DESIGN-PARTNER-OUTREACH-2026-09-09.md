# Design Partner Outreach — Email Templates & Strategy

**Date:** 2026-09-09  
**Goal:** Recruit 3-5 design partners in 60-90 days  
**Cost:** $0 (your time only)

---

## Target Profile

- **Company size:** 50-500 employees (Series A-B SaaS, health-tech, fintech, AI startups)
- **Role:** CISO, VP Engineering, CTO, Head of Security, Head of Platform
- **Signals:** Uses Copilot/ChatGPT/Claude, has compliance requirements (HIPAA/PCI/SOC 2), engineering team of 10+, AI in production
- **Where to find:** LinkedIn search, Y Combinator company directory, Hacker News "Who's Hiring", AI security conference attendee lists

## Pipeline Math

- 50 companies identified → 50 emails sent
- 10% response rate → 5 conversations
- 60% demo conversion → 3 demos
- 80% deployment conversion → 2-3 design partners deployed
- **Target: 3-5 design partners in 60-90 days**

---

## Email Template A: CISO / Head of Security

**Subject:** Open-source AI security gateway — looking for 3-5 design partners

---

Hi [First Name],

I noticed [Company] is using AI tools across the engineering team — and like most companies, there's no security layer between your engineers and ChatGPT, Copilot, and Claude.

I've built an open-source AI security gateway that:
- Blocks PII, API keys, and secrets from reaching AI services (216 detection patterns)
- Covers 33 compliance frameworks including HIPAA, PCI, SOC 2, and the EU AI Act
- Runs as a self-hosted single binary — no data leaves your infrastructure
- Adds 0.42ms latency (benchmarked at 23,000 requests/second with 0% errors)

It's the only product that secures MCP, A2A, and agent protocols — the protocols your team is probably already using with Cursor and Copilot.

I'm looking for 3-5 design partners to deploy it in production. In exchange:
- Free deployment (you self-host, I provide setup support)
- 6 months free, then 50% off the first year
- Case study rights (with your approval)
- Feature requests prioritized for your use cases

Would a 30-minute demo be worth your time?

Best,
[Your Name]
AegisGate Security
https://aegisgatesecurity.io

---

## Email Template B: VP Engineering / CTO

**Subject:** Free AI security for your engineering team (open source, self-hosted)

---

Hi [First Name],

Your engineers are using Copilot, Cursor, and ChatGPT every day. Every prompt is a potential data exfiltration event — source code, API keys, customer data flowing to third-party AI services.

I've built AegisGate — an open-source, self-hosted AI security gateway that sits between your engineers and AI tools. It catches:
- API keys and credentials before they hit the AI service
- PII (SSNs, credit cards, email addresses, phone numbers)
- Source code patterns and internal identifiers
- Custom patterns you define

It also has a local proxy (Rampart) that runs on each developer's workstation, and a browser extension (Lens) for ChatGPT/Claude/Gemini.

I'm recruiting 3-5 design partners. You get:
- Free deployment and setup support
- 6 months free, then 50% off first year
- Direct input on feature roadmap
- Production-tested AI security at zero cost

It's a 34.7MB binary with zero dependencies, deploys in 15 minutes, and adds less than 1ms of latency.

Interested in a 30-minute walkthrough?

Best,
[Your Name]
AegisGate Security
https://aegisgatesecurity.io

---

## Email Template C: Health-Tech / HIPAA-Focused

**Subject:** Prevent PHI leaks to ChatGPT/Copilot — free design partner program

---

Hi [First Name],

Healthcare organizations are adopting AI tools fast — but every prompt to ChatGPT or Copilot is a potential HIPAA violation. PHI in a prompt = PHI on a third-party server.

I've built AegisGate, an open-source AI security gateway that:
- Detects and blocks 11 categories of PHI before it reaches any AI service
- Provides full HIPAA audit logging of all AI interactions
- Runs self-hosted — no PHI ever leaves your infrastructure
- Includes 82 HIPAA compliance controls mapped to the Security Rule

I'm looking for 3-5 healthcare design partners. You get:
- Free deployment (self-hosted, I provide setup support)
- 6 months free, then 50% off first year
- HIPAA compliance reporting for AI tool usage
- Case study rights (with your approval)

Would a 30-minute demo work for your team?

Best,
[Your Name]
AegisGate Security
https://aegisgatesecurity.io

---

## Email Template D: Fintech / PCI-Focused

**Subject:** Prevent cardholder data leaks to AI tools — open source, self-hosted

---

Hi [First Name],

Your engineering team uses AI tools every day. Every prompt to Copilot or ChatGPT is a potential PCI DSS violation — cardholder data, API keys, and internal system details flowing to third-party servers.

I've built AegisGate, an open-source AI security gateway that:
- Detects and blocks credit card numbers, PANs, and payment data before reaching AI services
- Covers PCI DSS 4.0 compliance requirements for AI interactions
- Runs self-hosted — no data leaves your infrastructure
- Provides full audit logging for PCI compliance

I'm recruiting 3-5 fintech design partners. You get:
- Free deployment and setup support
- 6 months free, then 50% off first year
- PCI compliance reporting for AI tool usage
- Direct input on feature roadmap

30-minute demo?

Best,
[Your Name]
AegisGate Security
https://aegisgatesecurity.io

---

## Follow-Up Sequence

### If no response after 5 days:

**Subject:** Re: [original subject]

Hi [First Name],

Just following up — I know you're busy. The short version: free AI security gateway, self-hosted, blocks data leaks to ChatGPT/Copilot, looking for design partners. 30-minute demo, no strings attached.

Worth a conversation?

Best,
[Your Name]

### If no response after 10 days:

**Subject:** One more thing about AI security at [Company]

Hi [First Name],

Last email — I promise. I'll be at [upcoming conference/meetup] if you want to grab coffee. Or if AI security isn't your priority right now, I'd appreciate knowing who on your team handles this — happy to reach out directly.

Best,
[Your Name]

### If they respond positively but don't commit:

Send a calendar link with 3 time options. Keep it to 30 minutes. Prepare a live demo environment (Docker Compose with the testlab stack). Show:
1. A prompt with an API key being blocked (5 seconds)
2. The compliance scan report (30 seconds)
3. The dashboard with real-time detection (30 seconds)
4. The deployment command (15 seconds)
5. Q&A (remaining time)

---

## Design Partner Agreement Terms (Simple)

1. **Duration:** 6 months design period
2. **Cost:** Free during design period, 50% off first year after
3. **Commitments from partner:**
   - Deploy in production (not just test)
   - Weekly feedback call (30 min)
   - Case study after 90 days (with approval)
   - Reference call after 6 months (optional)
4. **Commitments from AegisGate:**
   - Setup support (you deploy it for them)
   - Priority bug fixes (24h response)
   - Feature requests prioritized
   - Dedicated Slack channel or email support

---

## Tracking

Use a simple spreadsheet or Trello board:
- Company name
- Contact name + role
- Date contacted
- Response status (none / responded / demo scheduled / deployed / declined)
- Notes
- Follow-up date