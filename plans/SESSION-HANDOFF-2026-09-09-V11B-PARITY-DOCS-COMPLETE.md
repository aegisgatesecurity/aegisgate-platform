# Session Handoff — 2026-09-12 (Updated with Patent + Copyright Filings)

**Date:** 2026-09-12
**Session focus:** Patent filing (5 provisionals FILED), copyright registration (2 FILED), Guardian article analysis + LinkedIn post, SBIR letter revision, IP document quality assurance (6 corrections), website patent pending notices, E&O insurance research

---

## Repository State (All CI Green ✅)

| Repo | HEAD | Tag | CI | Security | SBOM | CodeQL |
|------|------|-----|-----|----------|------|--------|
| Platform | `dacfe40` | v4.4.1 | ✅ | ✅ | ✅ SPDX+Cosign | ✅ |
| Rampart | `f03817c` | v0.7.1 | ✅ | ✅ | ✅ CycloneDX+SPDX | ✅ |
| Lens | `0ebcbfb` | v0.4.1 | ✅ | ✅ | ✅ CycloneDX+SPDX | ✅ |
| Enterprise | `7c19486` | none | ✅ (8 jobs) | ✅ (in CI) | ✅ CycloneDX+SPDX | N/A |
| Website | `9099a84` | N/A | ✅ (Netlify) | ✅ | N/A | N/A |
| .github | `002b56c` | N/A | N/A | N/A | N/A | N/A |

## Model Parity (v11b across all products)
- **Model**: CharCNN-BiLSTM, 1,596,034 params, Latin-1 vocab (256), 256-char input, threshold 0.50
- **ONNX**: opset 18, SHA-256 `8e13c793c32816aa0f6e2af13ffadd4f38f707b4ac8906b56ddfa77da51ea8e5`
- **Lens JS weights**: float16→gzip→base64 JSON, SHA `c09eef58c79928bb6ff19bcd155da34ee1809c0ff0165d1afd6b049b400615d7`, 3.75 MB
- **Evasion suite**: 2,600 tests (52 ATLAS payloads × 50 transforms). Score: 99.8/100, 0 in-scope misses
- **FPR**: 0.64% raw (35/5,479), 0% calibrated (CalibrationManager threshold tuning)

## Session Accomplishments (Chronological)

### Phase 1: VC/Investor Assessment
- Delivered 11-part comprehensive analysis (investor types, valuation scenarios, non-dilutive funding, term sheets, growth strategy)
- User corrected 3 errors (Stripe is live, LinkedIn exists, GA exists)
- Fixed stale Stripe docs (pricing.md, doc.go)
- Persisted: `plans/INVESTOR-ASSESSMENT-2026-09-09.md` (416 lines)

### Phase 2: Business Deliverables (6 tasks A-F)
- Executive Summary, Design Partner Outreach (4 email templates), Show HN post
- Gotchas 101-103, session handoff + resume prompt updated
- Committed ef46ae4

### Phase 3: IP Protection Moat
- Identified 5 patentable inventions
- Drafted 5 provisional patent specs + filing guide (gitignored, local only)
- Created model weight license (WEIGHTS-LICENSE.md) deployed to all 3 open-source repos
- Enterprise: TRADE-SECRET-NOTICE.md, confidentiality headers on 101 Go files, SPDX fixed
- 6-layer legal moat: patents + weights + trade secrets + copyright + trademark + commercial license

### Phase 4: "What Have We Missed?" (12 items, then 23 items)
- User corrected 3 more (GPG-signed tags exist, SBOM exists for Platform/Rampart, security advisories enabled)
- Fixed genuine gaps: Lens SBOM CI, Enterprise CI (8 jobs), Enterprise SECURITY.md
- Fixed 4 rounds of CI failures (CycloneDX XML, dynamic interpolation, cross-module imports, gitleaks fingerprint format)

### Phase 5: GitHub Org Hygiene (items 1-10)
- Rampart: description, 16 topics, homepage URL set
- Lens: description updated to v0.4.1
- README badges fixed: Lens v0.4.0→v0.4.1, Rampart v0.7.0→v0.7.1
- Created `.github` repo with org README + SECURITY.md
- Org profile: name, description, blog, email set
- Enabled Discussions on Rampart + Lens
- Added gitleaks to Lens CI
- Added .dockerignore to Rampart + Enterprise
- Pushed GITLEAKS_LICENSE secret to all 4 repos

### Phase 6: Legal/Compliance Docs (items 11-23)
- THIRD-PARTY-LICENSES.md: All 4 repos (Platform 200 deps, Rampart 24, Enterprise 200, Lens 0 deps)
- CODE_OF_CONDUCT.md: Added to Rampart
- VDP.md: 111-line vulnerability disclosure program
- EXPORT-CLASSIFICATION.md: 94-line EAR self-classification (all products EAR99)
- Copyright registration guide: 377 lines, 2 registrations ($130 total)

### Phase 7: Email Security
- DMARC upgraded: `p=quarantine` → `p=reject; rua=mailto:security@aegisgatesecurity.io`
- MTA-STS: DNS A records for `mta-sts.aegisgatesecurity.io`, policy file committed, Netlify cert provisioned
- Both verified live via dig + curl

### Phase 8: Comprehensive IP Review (6 corrections)
- P1: Patent 01 capability types — 10 fabricated types replaced with 22 actual types
- P2: Patents 02/04 keyWalkReverse map — 54→50 entries (verified in code)
- P3: Patent 04 FPR — "0%" → "calibrated 0% on benign corpus" (raw is 0.64%)
- P4: Patent 04 ATLAS — "52 techniques" → "MITRE ATLAS adversarial techniques" (52 is payload count)
- P5: Patents 03/04 frameworks — "33+" → "30+" (29 in mapping.go + CSA STAR = 30, all listed by name)
- C1: Copyright guide — "unpublished collection" → "collection registration"
- C2: Copyright guide — legal citation fixed from 17 USC 408(c)(1) to 37 CFR 202.3(b)(4)
- C3: Copyright guide — added group registration eligibility risk + fallback strategy

## Complete Filing Scorecard

| # | Item | Status | Cost |
|---|------|--------|------|
| 11 | THIRD-PARTY-LICENSES.md | ✅ All 4 repos | Free |
| 12 | CODE_OF_CONDUCT.md (Rampart) | ✅ | Free |
| 13 | .dockerignore | ✅ Rampart + Enterprise | Free |
| 14 | Enable Discussions | ✅ Rampart + Lens | Free |
| 15 | DMARC upgrade | ✅ p=reject + rua | Free |
| 16 | MTA-STS | ✅ DNS + cert + policy | Free |
| 17 | File 5 provisional patents | ✅ **FILED** 09/12/2026 — 64/153,573–64/153,577 | $325 ✅ |
| 18 | Copyright registration | ✅ **FILED** 09/12/2026 — 1-15259252537 (Enterprise), 1-15259254081 (Open-Source Collection) | $130 ✅ |
| 19 | E&O insurance | 📋 Before first customer | $500-2K/yr |
| 20 | Formal VDP | ✅ VDP.md created | Free |
| 21 | Tax compliance | ✅ Stripe Tax activated | Free |
| 22 | Export control self-classification | ✅ EXPORT-CLASSIFICATION.md | Free |
| 23 | International trademarks | 📋 When selling internationally | $1K+/region |

**13 of 13 actionable items done. 2 remaining awareness items = $500-2K insurance + $1K+ international trademarks**

## Key Verified Business Facts
- Stripe: LIVE (pk_live key, real product IDs)
- LinkedIn: EXISTS at linkedin.com/company/aegisgate-security
- Google Analytics: Set up (dashboard-level via Netlify)
- Stripe Tax: ACTIVATED (automatic calculation at checkout)
- Pre-revenue, zero paying customers, sole founder, bootstrapping
- GPG-signed releases: All 3 tags signed (key B528D336DE0055283B10236D899C3B0FA2336D7B)

## Email Security Status
- SPF: `v=spf1 include:_spf.protonmail.ch ~all` ✅
- DMARC: `v=DMARC1; p=reject; rua=mailto:security@aegisgatesecurity.io` ✅
- MTA-STS: `mta-sts.aegisgatesecurity.io` → Netlify, policy file live, cert with SANs ✅
- MX: `mail.protonmail.ch` (pri 10), `mailsec.protonmail.ch` (pri 20) ✅

## IP Document Locations (all in plans/, gitignored except copyright guide)

### Provisional Patents — FILED September 12, 2026
- `plans/provisional-patent-01-trust-framework.pdf` — **App. No. 64/153,573** — 10 claims, ECDSA P-256 identity + capability contracts + trust scoring + attestations
- `plans/provisional-patent-02-multi-protocol-interception.pdf` — **App. No. 64/153,574** — 10 claims, MCP/A2A/ACP/ANP interception
- `plans/provisional-patent-03-compliance-mapping.pdf` — **App. No. 64/153,575** — 10 claims, 30 frameworks, real-time control mapping
- `plans/provisional-patent-04-three-layer-detection.pdf` — **App. No. 64/153,576** — 10 claims, regex→ATLAS/compliance→CharCNN-BiLSTM
- `plans/provisional-patent-05-response-scanning.pdf` — **App. No. 64/153,577** — 10 claims, AI output scanning (PII/secrets/hallucinations/toxicity)
- **Priority date:** September 12, 2026 (all 5)
- **Non-provisional deadline:** September 12, 2027
- **Total cost:** $325 ($65 each, micro entity)
- **Inventor:** Joshua Colvin

### Copyright Registrations — FILED September 12, 2026
- Registration 1 (Open-Source Collection): **App. No. 1-15259254081** — Platform + Rampart + Lens, published collection
- Registration 2 (Enterprise): **App. No. 1-15259252537** — Enterprise, unpublished
- **Total cost:** $130 ($65 each)
- **Author:** Joshua Colvin (individual) | **Claimant:** AegisGate Security, LLC
- **Deposit PDFs:** `plans/copyright-deposit-1-opensource.pdf` (97 pages), `plans/copyright-deposit-2-enterprise.pdf` (10 pages)

### Filing Guides (gitignored)
- `plans/provisional-patent-filing-guide.md` — filing instructions
- `plans/copyright-registration-guide.md` — filing instructions (all fields filled in)

## LinkedIn Posting Cadence
- Posts made: 5 (General AegisGate, Lens, Rampart, AI agents/data exfiltration, Trust Framework/Guardian article)
- Cadence: Every other day
- Next post: Platform deep-dive OR design partner recruitment post
- Trust Framework post published 09/12/2026 with "patent pending" — references Guardian article about OpenAI agents going rogue

## Next Session Priorities
1. **E&O insurance** — get quotes before first paying customer ($500-2K/yr)
2. **Continue LinkedIn cadence** — Platform deep-dive post, then design partner recruitment post
3. **Non-provisional patent conversion** — by September 12, 2027, decide which provisionals to convert ($300 each + attorney fees)
4. **Design partner outreach** — send emails from plans/DESIGN-PARTNER-OUTREACH-2026-09-09.md
5. **SBIR applications** — submit DHS and/or NSF concept papers with letters of support
6. **Show HN / community launch** — consider dev.to, Reddit r/cybersecurity, Product Hunt
7. **International trademarks** — when selling internationally ($1K+/region)