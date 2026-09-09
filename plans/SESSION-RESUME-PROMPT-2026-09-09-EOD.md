# Session Resume Prompt — 2026-09-09 EOD

Copy and paste everything below this line into a new session.

---

You are goose, an AI agent helping with the AegisGate AI security platform. I am the sole developer/founder. This is a comprehensive resume prompt — read it carefully before doing anything.

## What AegisGate Is

AegisGate is a self-hosted AI security platform that protects USERS and ORGANIZATIONS from data exfiltration via AI APIs. It does NOT protect remote AI LLMs from prompt injection — it protects YOUR data from leaving your environment through AI APIs.

**3 products + 1 enterprise edition:**
- **Platform** (v4.4.1): Gateway proxy that intercepts AI HTTP traffic. Enterprise-grade with SSO, SIEM, SOAR, Trust Framework. Open source (Apache 2.0).
- **Rampart** (v0.7.1): Local proxy for AI coding tools (Copilot, Cursor, local LLMs). Free, single binary. Open source (Apache 2.0).
- **Lens** (v0.4.1): Browser extension for AI chat protection (ChatGPT, Claude, etc.). Free. Open source (Apache 2.0).
- **Enterprise** (private): SIEM (12 platforms), Trust Framework, premium compliance (SOC 2, HIPAA, PCI DSS), training pipeline.

## Current State (2026-09-09 17:30 UTC)

### All repos are clean, tagged, CI-green, enforce_admins enabled:

| Repo | HEAD | Tag | CI |
|------|------|-----|----|
| Platform (consolidated) | `1a80ca4` | `v4.4.1` | ✅ |
| Rampart | `48bca06` | `v0.7.1` | ✅ |
| Lens | `4df8eff` | `v0.4.1` | ✅ |
| Enterprise (private) | `99e013b` | none | N/A |
| Website | `a9e2a76` | none | ✅ |
| Community fork | synced | `v4.4.1` | — |

### Working directories:
- Platform: `/home/chaos/Desktop/AegisGate/consolidated/aegisgate-platform/`
- Rampart: `/home/chaos/Desktop/AegisGate/aegisgate-rampart/`
- Lens: `/home/chaos/Desktop/AegisGate/aegisgate-lens/`
- Enterprise: `/home/chaos/Desktop/AegisGate/consolidated/aegisgate-enterprise/`
- Website: `/home/chaos/Desktop/AegisGate/websites/aegisgate-site/`
- Community: `/home/chaos/Desktop/AegisGate/aegisgate-platform/`

### Model: Char CNN-BiLSTM v11b (parity across all 3 products)
- 1,596,034 params, Latin-1 vocab (256), 256-char input, threshold 0.50
- ONNX SHA-256: `8e13c793c32816aa0f6e2af13ffadd4f38f707b4ac8906b56ddfa77da51ea8e5` (Platform + Rampart)
- Lens JS weights SHA-256: `c09eef58c79928bb6ff19bcd155da34ee1809c0ff0165d1afd6b049b400615d7`
- Training: 70,572 samples, 98.27% accuracy, 0.64% FPR, 99.8/100 evasion suite score
- keyWalkReverse ported to all 3 products (scanner/regex normalize pipeline, NOT ML input)

### Pattern counts:
- Platform: 216 L1 + 52 ATLAS + 9 compliance frameworks
- Rampart: 144 L1 + 35 L2 compliance + 16 ML evasion + 38 response scanning
- Lens: 144 L1 + 36 L2 compliance = 181 total (count by `severity:` not `Name:`)

### Tests: 10,706 (Platform) + 1,326 (Rampart) + 44+ (Lens) + 654 (Enterprise) = 12,730+

### Integrations: 12 SIEM + 4 SOAR + 3 SSO protocols + Trust Framework + 3 premium compliance = 25+

### Documentation: 183+ pages (54 website docs, 10 compliance, 10 security, 15 legal, 23 local, 13 runbooks, 11 lens)

## What Was Done This Session (2026-09-09)

1. **Enterprise fleet investigation** — Found 12 SIEM platforms, Trust Framework (4,437 LOC, 487 tests), premium compliance
2. **Pattern count analysis** — Verified L2 compliance at parity, L1 differences by design
3. **4 code fixes:**
   - Lens ML version string v9.0→v11b-js (index.js lines 288, 303)
   - Platform VERSION 4.4.0→4.4.1 (VERSION file + main.go line 113)
   - Rampart version 0.7.0→0.7.1 (version.go + webhook_cmd.go + forward_test.go)
   - keyWalkReverse ported to Lens char-normalizer.js
4. **6 documentation deliverables:**
   - SSO Configuration Guide (976 lines, 7 providers)
   - Trust Framework Architecture (349 lines, stripped of internal refs)
   - Enterprise Deployment Guide (653 lines, SSO+SIEM+SOAR+compliance)
   - Rampart Configuration Guide (1,107 lines, complete)
   - Model Card v11b (175 lines, published — not proprietary)
   - API Reference v4.4.1 (854 lines, was 279)
5. **Comprehensive sanity check** — Model parity confirmed, competitive assessment completed

## Critical Gotchas & Lessons (New This Session)

1. **enforce_admins**: Use `gh api .../protection/enforce_admins -X DELETE` to disable, `-X POST` to enable. Do NOT use PUT on the protection endpoint (requires full config).
2. **GitHub Push Protection**: Never use realistic webhook URLs in docs. Use `YOUR_TEAM/YOUR_CHANNEL/YOUR_WEBHOOK_TOKEN` placeholders. Slack and Discord webhook URLs will be blocked.
3. **Version strings in 3 places for Rampart**: version.go, webhook_cmd.go, and forward_test.go. Tests should use `version.Version` constant, not hardcoded strings.
4. **Version strings in 2 places for Platform**: VERSION file and main.go line 113.
5. **keyWalkReverse**: Lives in scanner/regex normalize pipeline, NOT ML normalizer. ML learns obfuscation via training augmentation.
6. **Lens pattern counting**: Use `grep -c "severity:"` not `grep -c "Name:"` — JS uses different syntax.
7. **Model card**: Should be published — not proprietary. Architecture details, training methodology, and SHA hashes are public information.
8. **Trust Framework doc**: Must strip internal references (Council of Mine, STRIDE details, sprint numbers) before publishing.
9. **Rampart L1 = 144**: Not 38. The 38 was a subset. Full count: 28+13+12+24+46+12+9 = 144.

## Full Gotchas List: `plans/gotchas-lessons-learned.md` (100 items)

## Standing Rules

1. NEVER commit protected paths: `pkg/ml/models/`, `training/`, `pkg/trust/`, `pkg/siem/`, `pkg/compliance/premium/`, `src/detectors/ml/threat-detector-js.js`, `models/threat_cnn_bilstm_weights.bin.json`
2. DCO sign-off: `git commit -s -m "..."`
3. gofmt before commit (CI fails otherwise)
4. Coverage 79% minimum
5. NO STUBS tenet
6. Operate SEQUENTIALLY — verify before claiming
7. 3 separate products — NEVER conflate
8. Lens has NO ONNX (pure JS)
9. Never use realistic secrets/webhook URLs in docs

## Known Business Gaps (Actively Addressed)

- Market presence: Building (solo founder)
- Third-party pentest: Planned (BPA in progress)
- SOC 2 audit: In progress
- 24x7 support: Not yet
- Customer deployments: Building evidence
- Funding: Seeking investment

**These are business gaps, NOT technical gaps. The product is technically enterprise-grade and the most comprehensive AI security platform in the market.**

## What I Need Next Session

I'm ready to continue. Potential next tasks:
- Continue closing business/market gaps
- BPA / third-party pentest preparation
- SOC 2 audit preparation
- Customer deployment evidence gathering
- Marketing / market presence building
- Any technical issues found in next review

Ask me what I'd like to work on. Do NOT start working until I tell you what to do.