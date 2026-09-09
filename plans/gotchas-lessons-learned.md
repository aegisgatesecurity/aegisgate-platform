# Gotchas & Lessons Learned

**Last Updated:** 2026-09-09 17:30 UTC

## NEW Gotchas from v11b Model Retrain + Documentation Session (2026-09-09)

### 91. enforce_admins Sub-Endpoint — Use DELETE/POST, Not PUT

**Date:** 2026-09-09
**Context:** Trying to update branch protection with `gh api .../protection -X PUT --field 'enforce_admins=false'` fails with 422 ("required_status_checks, required_pull_request_reviews, restrictions weren't supplied"). The PUT endpoint requires the FULL protection config.

**Fix:** Use the dedicated sub-endpoints:
- Disable: `gh api .../branches/main/protection/enforce_admins -X DELETE`
- Enable: `gh api .../branches/main/protection/enforce_admins -X POST`

**Lesson:** GitHub's branch protection API has dedicated sub-endpoints for boolean toggles. Don't try to update the whole protection config just to flip one field. This was discovered across all 3 product repos (Platform, Rampart, Lens).

### 92. GitHub Push Protection Catches Webhook URLs in Docs

**Date:** 2026-09-09
**Context:** Pushing Rampart documentation to the website repo was rejected by GitHub Push Protection. The doc contained example Slack and Discord webhook URLs that matched secret-scanning patterns.

**Fix:** Replaced with placeholder format using `YOUR_TEAM`/`YOUR_CHANNEL`/`YOUR_WEBHOOK_TOKEN` in URLs instead of realistic-looking IDs.

**Lesson:** Never use realistic-looking webhook URLs in documentation, even as examples. GitHub Push Protection will block the push. Always use `YOUR_*` placeholder format for any URL that matches a secret-scanning pattern (Slack webhooks, Discord webhooks, AWS keys, etc.).

### 93. Rampart Version Is in THREE Places — Not Two

**Date:** 2026-09-09
**Context:** When bumping Rampart version from 0.7.0 to 0.7.1, found version hardcoded in:
1. `internal/version/version.go` (the canonical source)
2. `cmd/rampart/webhook_cmd.go` line 219 (hardcoded in webhook status output)
3. `internal/platformforward/forward_test.go` line 328 (test asserts specific version string)

**Fix:** Fixed #1 and #2 in commit f15433c. For #3, imported the `version` package and changed the test to use `version.Version` constant instead of hardcoded string (commit 48bca06). This makes the test version-agnostic.

**Lesson:** When bumping versions, grep for ALL occurrences of the old version string across the entire codebase — not just the version file. Tests that assert version strings should use the version constant, not a hardcoded string. Otherwise CI breaks on every version bump.

### 94. Platform Version Is in TWO Places

**Date:** 2026-09-09
**Context:** Platform version 4.4.0 → 4.4.1 required updating:
1. `VERSION` file (the canonical source)
2. `cmd/aegisgate-platform/main.go` line 113: `version = "4.4.0"` (hardcoded string)

**Fix:** Updated both in commit eebe132.

**Lesson:** Same as #93 — always grep for all version references. Platform's main.go has a `version` variable that must match the VERSION file.

### 95. keyWalkReverse Architecture — Scanner, NOT ML Normalizer

**Date:** 2026-09-09
**Context:** When porting keyWalkReverse to Lens, initially considered adding it to the ML normalizer (char-normalizer.js `normalize()` function). But the ML model learns keyboard-walk obfuscation through training data augmentation — applying keyWalkReverse to ML input would double-correct and potentially harm detection.

**Correct architecture:** keyWalkReverse lives in the scanner/regex normalize pipeline. It generates alternate text variants that the regex patterns scan against. The ML model input is NOT keyWalkReverse-corrected.

**Locations:**
- Platform: `upstream/aegisgate/pkg/scanner/normalize.go` line 127
- Rampart: `internal/detectors/normalize.go` line 53
- Lens: `src/detectors/ml/char-normalizer.js` (exported as `reverseKeyboardWalk` and `normalizeAllVariants` for regex facets to use)

**Lesson:** Understand WHY a normalization exists before porting it. keyWalkReverse is for regex evasion resistance, not ML input preprocessing. The ML model handles obfuscation through training augmentation. This architecture is consistent across all 3 products.

### 96. Lens Model Version String — Two Locations in index.js

**Date:** 2026-09-09
**Context:** Lens ML version string was outdated in `src/detectors/index.js`:
- Line 288: `mlEvent.ml_model_version = 'char-cnn-bilstm-v9.0'`
- Line 303: `lowEvent.ml_model_version = 'char-cnn-bilstm-v9.0'`
- Also in `src/detectors/ml/threat-detector-js.js`: `MODEL_VERSION = 'char-cnn-bilstm-v11b-js'` (already correct)

**Fix:** Updated lines 288 and 303 to `'char-cnn-bilstm-v11b-js'` in commit 4df8eff.

**Lesson:** Telemetry version strings are in multiple places. Always grep for the old version string across all JS files. The ML model version appears in: the model file (MODEL_VERSION), the telemetry event builder (index.js), and potentially the popup/settings UI.

### 97. Model Card — Should Be Published, Is NOT Proprietary

**Date:** 2026-09-09
**Context:** User asked "SHOULD THIS BE PUBLISHED? or is it considered proprietary?" regarding the model card.

**Assessment:** The model card SHOULD be published. It contains:
- Architecture details (params, vocab, layers) = standard ML transparency
- Training methodology = describes augmentation strategy, not proprietary code
- SHA-256 hashes = already in public repo (pkg/ml/detector.go)
- All training data is synthetic or public datasets
- No proprietary information is disclosed

**Decision:** Published to website at `content/docs/model-card.md`. Also updated local copy from v9 to v11b.

**Lesson:** Model cards are transparency documents. Publishing them is a competitive advantage (EU AI Act Art 11, NIST AI RMF compliance). The proprietary part is the training augmentation CODE (in enterprise `pkg/ml/training/augment.go`), not the training methodology DESCRIPTION.

### 98. Trust Framework Doc — Must Strip Internal References

**Date:** 2026-09-09
**Context:** Local `docs/trust-framework.md` contained internal references that should not be published:
- "Council of Mine unanimous Devil's Advocate vote" — internal governance process
- "Section 2.6 (10 STRIDE threats, CVSS 8.5–9.0)" — internal threat model details
- Internal sprint numbers and development milestones

**Fix:** Rewrote the Trust Framework architecture doc for the website from scratch, keeping only: standardized cryptographic primitives (ECDSA P-256, SHA-256), public API endpoints, configuration examples, and regulatory use cases. Removed all internal governance and process references.

**Lesson:** When publishing internal docs externally, review for: internal team structures, governance processes, internal threat model details, sprint/milestone references, and internal pricing decisions. Keep only technical facts that would be in a public API doc.

### 99. Lens Pattern Count Syntax — JS Uses `severity:` Not `Name:`

**Date:** 2026-09-09
**Context:** Counting Lens regex patterns by `Name:` (like Platform/Rampart) returns 0. Lens JS pattern files use a different structure: `pattern_name: { severity: 'critical', re: /regex/g }`. The key is `severity:` not `Name:`.

**Fix:** Count by `severity:` occurrences: `grep -c "severity:" src/detectors/regex/*.js`

**Lesson:** Each product has its own pattern definition syntax. Platform/Rampart (Go) use `Name:` in struct literals. Lens (JS) uses `severity:` in object literals. Always adapt the counting grep to the product's syntax. Total Lens patterns: 181 (36 compliance + 144 L1 + 1 PII aggregator).

### 100. Rampart Has 144 L1 Patterns — Not 38

**Date:** 2026-09-09
**Context:** Earlier session reported "Rampart: 38 L1 patterns" which was incorrect. The 38 count was only from a subset of detector files. Full count across all detector files:
- PII US Core: 28
- PII US Extended: 13
- PII Financial: 12
- PII International: 24
- Secrets: 46
- XSS: 12
- OT Protocols: 9
- Total L1: 144

Plus 35 L2 compliance + 16 ML evasion resistance + 38 response scanning patterns (11 PII + 17 secrets + 4 hallucination + 6 toxicity).

**Lesson:** Always count patterns from ALL detector files, not just the main ones. Rampart splits patterns across 7 detector files + compliance + response scanners. The README says "176 regex patterns" which includes L1 + response scanning (144 L1 + 38 response - 6 overlap = ~176).

---

## Prior Gotchas (91-100 above are new)

### Items 1-90: See git history of this file for prior gotchas covering:
- Framework count (31 not 25), "Easy Button" trademark, CI coverage floor, interactive test input counting, sed escape issues, Hugo server, three documentation locations, SAML certificate encoding, Docker Alpine→Debian migration, ONNX Runtime glibc requirement, CGO-only test files, protected branch force-push, dev machine paths in production code, NO STUBS tenet, efficacy test file tracking