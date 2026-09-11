# Session Resume Prompt — 2026-09-11 EOD

Copy/paste this prompt to begin a new session with full context.

---

## Prompt

I am the sole founder and developer of AegisGate Security, LLC. We build AI security software that protects users and organizations from data exfiltration when using AI tools (ChatGPT, Claude, GitHub Copilot, Cursor, AI agents, etc.).

### Products (all v11b model parity, all CI green)
- **Platform** (v4.4.1): Open-source AI security gateway proxy. 401K LOC Go. 10,706 tests. Apache 2.0 + WEIGHTS-LICENSE.md
- **Rampart** (v0.7.1): Local proxy firewall for AI coding tools. 51K LOC Go. 1,326 tests. Apache 2.0 + WEIGHTS-LICENSE.md
- **Lens** (v0.4.1): Privacy-first browser extension. 8.5K LOC JS. 257+ tests. Apache 2.0 + WEIGHTS-LICENSE.md
- **Enterprise** (no tag): Proprietary trust framework, SIEM, premium compliance, training pipeline. 26.7K LOC Go. 654 tests. Commercial license + TRADE-SECRET-NOTICE.md

### Technology
- 3-layer detection: L1 (216 regex patterns) → L2 (ATLAS/compliance mapping, 30 frameworks) → L3 (CharCNN-BiLSTM, 1.6M params, ONNX opset 18)
- v11b model: 99.8/100 evasion score, 0% calibrated FPR, 70,572 training samples
- Trust Framework: ECDSA P-256 identity, 22 capability types, weighted trust scoring, signed attestations
- SIEM: 12 platforms, 5 formats (JSON, CEF, LEEF, RFC 5424, CSV)
- SSO: 19,595 LOC, SAML 2.0 + OIDC + OAuth 2.0
- SOAR: PagerDuty, Jira, ServiceNow, Custom webhook

### Business Status
- Pre-revenue, zero paying customers, bootstrapping, self-funding
- Stripe LIVE (pk_live key, real product IDs, Stripe Tax activated)
- Pricing: Community (free), Developer ($79/mo), Professional ($499/mo), Enterprise ($2,000+/mo)
- LinkedIn: linkedin.com/company/aegisgate-security — posting every other day (3 posts so far: general, Lens, Rampart)
- GitHub: aegisgatesecurity org, 8 public repos, 1 follower, 0 stars

### IP Protection Moat (6 layers)
1. **5 provisional patents** — specs drafted, reviewed, corrected (6 factual errors fixed). NOT YET FILED. $325 total. Located in `plans/provisional-patent-*.md` (gitignored)
2. **Model weight license** — WEIGHTS-LICENSE.md deployed to all 3 open-source repos. Non-commercial free, commercial requires license
3. **Trade secrets** — Enterprise has TRADE-SECRET-NOTICE.md, confidentiality headers on 101 Go files, SPDX: AegisGate-Enterprise
4. **Copyright** — Registration guide drafted and reviewed. NOT YET FILED. $130 total. Located in `plans/copyright-registration-guide.md`
5. **Trademark** — AegisGate filed with USPTO
6. **Commercial license** — Enterprise LICENSE file

### Session Work Completed (2026-09-09 to 2026-09-11)
- VC/investor assessment (11-part, 416 lines)
- 5 provisional patent specs + filing guide (reviewed, 6 corrections applied)
- Copyright registration guide (reviewed, 3 corrections applied)
- Model weight license deployed to 3 repos
- Enterprise trade secret protection (notice + headers + SPDX fix)
- CI/CD hardening: Lens SBOM, Enterprise CI (8 jobs), 4 rounds of CI fixes
- GitHub org hygiene: .github repo, org profile, repo metadata, README badges, Discussions enabled
- Legal docs: THIRD-PARTY-LICENSES.md (4 repos), VDP.md, EXPORT-CLASSIFICATION.md, CODE_OF_CONDUCT.md (Rampart)
- Email security: DMARC p=reject, MTA-STS with cert
- Gitleaks: added to Lens CI, GITLEAKS_LICENSE secret on all 4 repos
- .dockerignore: added to Rampart + Enterprise
- Gotchas 101-106 documented
- 12 of 13 "what have we missed" items done

### Remaining Tasks (in priority order)
1. **File 5 provisional patents** ($325) — go to patentscenter.uspto.gov, fill in [INVENTOR NAME], upload specs as PDF
2. **File copyright registrations** ($130) — go to eco.copyright.gov, follow guide in plans/copyright-registration-guide.md
3. **Post Trust Framework LinkedIn post** — after filing provisionals, can say "patent pending"
4. **Post design partner recruitment LinkedIn post**
5. **Continue LinkedIn cadence** (every other day)
6. **E&O insurance** ($500-2K/yr) — before first paying customer
7. **International trademarks** — when selling internationally

### Key Files
- `plans/SESSION-HANDOFF-2026-09-09-V11B-PARITY-DOCS-COMPLETE.md` — full session handoff
- `plans/INVESTOR-ASSESSMENT-2026-09-09.md` — VC analysis
- `plans/EXECUTIVE-SUMMARY-2026-09-09.md` — 1-2 page exec summary
- `plans/DESIGN-PARTNER-OUTREACH-2026-09-09.md` — 4 email templates
- `plans/provisional-patent-*.md` — 5 patent specs + filing guide (gitignored)
- `plans/copyright-registration-guide.md` — copyright filing guide
- `plans/gotchas-lessons-learned.md` — 106 lessons learned
- `plans/SHOW-HN-POST-2026-09-09.md` — HN post draft

### Operating Rules
- NEVER commit protected paths (pkg/ml/models/, training/, pkg/trust/, pkg/siem/, pkg/compliance/premium/)
- DCO sign-off on ALL commits: `git commit -s -m "..."`
- Branch protection: disable enforce_admins before push, re-enable after
- Patent specs are gitignored — use `git add -f` only for copyright-registration-guide.md
- Verify before claiming — 9 corrections made across 2 sessions
- 3 separate products — NEVER conflate them
- Lens has NO ONNX (pure JS inference with JSON weights)

### Working Directories
- Platform: `consolidated/aegisgate-platform/` (active dev)
- Community: `aegisgate-platform/` (synced clone)
- Rampart: `aegisgate-rampart/`
- Lens: `aegisgate-lens/`
- Enterprise: `consolidated/aegisgate-enterprise/`
- Website: `websites/aegisgate-site/`
- Lens site: `websites/aegisgate-lens-site/`
- .github repo: `.github-repo/`