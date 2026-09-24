# Gotchas & Lessons Learned

**Last Updated:** 2026-09-20 01:15 UTC

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

### 101. Stripe integration was LIVE in code but documentation said "test mode"

**Context:** The pricing page (`content/pricing.md` in platform repo) and `pkg/billing/doc.go` both said "Stripe Buy Buttons are in test mode (use card 4242 4242 4242 4242)" and "live mode is gated on H1 legal + H4 pentest sign-off." But `billing-config.json` contained a real `pk_live_` publishable key and real Stripe product/price IDs. The website repo's `pricing.md` was already clean with real `buy.stripe.com` URLs.

**Lesson:** Stale documentation can undermine buyer confidence even when the backend is correct. A visitor to the pricing page saw "🟡 Test Mode" and "No real money is charged" while the actual payment system was live. Always verify documentation claims against actual code state. Fixed in commit `088d34b`.

### 102. Platform content/pricing.md is gitignored — website repo has separate copy

**Context:** When committing the Stripe documentation fix, `content/pricing.md` in the platform repo was gitignored. The platform repo's `content/` directory appears to be a template/source copy, not the live website content. The website repo (`websites/aegisgate-site/content/pricing.md`) has its own separate copy that was already clean.

**Lesson:** Always check the website repo for live content state. The platform repo's `content/` directory may be outdated or gitignored. When fixing website-facing documentation, verify which copy is actually deployed.

### 103. Verify before claiming — three corrections in one session

**Context:** In the VC/investor assessment, I claimed three things that were wrong:
1. "Stripe is in test mode" → It was LIVE (pk_live key in billing-config.json)
2. "Create a LinkedIn company page" → It already existed (linked from website baseof.html)
3. "Set up Google Analytics" → It was already set up (dashboard-level)

**Lesson:** This is Rule #1 ("Verify before claiming") applied to business infrastructure, not just code. Before claiming something "doesn't exist" or "needs to be created," check the codebase, config files, website templates, and dashboard-level configurations. The user corrected all three. Each correction erodes trust and wastes time.

---

## Prior Gotchas (91-100 above are new)

### Items 1-90: See git history of this file for prior gotchas covering:
- Framework count (31 not 25), "Easy Button" trademark, CI coverage floor, interactive test input counting, sed escape issues, Hugo server, three documentation locations, SAML certificate encoding, Docker Alpine→Debian migration, ONNX Runtime glibc requirement, CGO-only test files, protected branch force-push, dev machine paths in production code, NO STUBS tenet, efficacy test file tracking
### 104. Stale version badges in READMEs across multiple repos

**Context:** Lens README had version badges saying v0.4.0 while manifest.json, git tag, and GitHub release all said v0.4.1. Rampart README had version badge saying v0.7.0, Docker image reference saying v0.6.2, and "What's New" section saying v0.6.2 — all while version.go and git tag said v0.7.1. The GitHub repo descriptions were also stale (Lens said v0.2.0, Rampart had no description at all).

**Lesson:** When bumping versions and tagging releases, always update README badges, Docker image references, "What's New" sections, and GitHub repo descriptions/topics. Create a release checklist that includes: version.go, manifest.json, README badges, Docker image refs, GitHub repo description, and changelog sections.

### 105. GitHub org profile was completely blank — no .github repo

**Context:** The GitHub org at github.com/aegisgatesecurity had no name, no description, no blog URL, and no email. There was no `.github` repository (which provides an org-level README shown on the org profile page and an org-level SECURITY.md). Any VC, customer, or developer visiting the org page saw a blank profile with 14 repos (5 of which were dead/archived).

**Lesson:** The `.github` repo is a standard GitHub pattern — it provides an org profile README, org-level security policy, and default issue/PR templates. It's free and takes 10 minutes to set up. Also set the org name, description, blog URL, and email via the GitHub API or org settings page.

### 106. Rampart repo had zero GitHub metadata — no description, no topics, no homepage

**Context:** Platform had 18 topics and a full description. Lens had 14 topics and a description (stale). Rampart had null description, empty topics array, and null homepage. GitHub search uses topics for discoverability — Rampart was invisible to anyone searching for "AI security," "MCP proxy," "secret detection," etc.

**Lesson:** Every public repo should have: a description (160 chars max for GitHub API), 10-20 relevant topics, and a homepage URL. This is a 30-second fix via `gh api` that directly impacts discoverability. Set topics that users would actually search for.

### 107. Patent specs had 6 factual errors that didn't match the codebase

**Context:** Drafted 5 provisional patent specs with technical claims. During review, found 6 claims that didn't match actual code: (1) 10 capability types were fabricated (code has 22 different ones), (2) keyWalkReverse map said 54 entries but code has 50, (3) FPR claim said "0%" but raw FPR is 0.64% (0% is calibrated only), (4) "52 MITRE ATLAS techniques" confused test payload count with mapped technique count, (5) "33+ compliance frameworks" was overcounted (actual: 30), (6) copyright guide cited wrong legal statute.

**Lesson:** Before filing any legal document that costs money, cross-reference EVERY technical claim against the actual codebase. Use grep, wc, and direct file inspection. A provisional patent with incorrect technical details may fail to establish priority for the actual invention if the non-provisional can't reference it accurately.

### 108. Patent specs were accidentally re-added to public git tracking

**Context:** Patent specs were previously `git rm --cached` and gitignored. During a fix commit, `git add -f` was used to stage the corrected specs, which re-added them to git tracking. The commit pushed them to the public repo. Had to `git rm --cached` again and push the removal.

**Lesson:** `git add -f` overrides .gitignore and adds files to tracking. When committing fixes to gitignored files that should NOT be tracked, stage ONLY the non-gitignored files. For gitignored files that need local-only edits, never use `git add -f` — make edits locally and verify with `git ls-files` that they're not tracked.

### 109. CWS listing rejected for keyword spam (Yellow Argon)

**Context:** Chrome Web Store rejected the Lens v0.4.1 listing update because the description listed brand names: "AWS, Azure, Google Cloud, GitHub, GitLab, Slack, Stripe, Twilio, SendGrid, Mailgun." CWS classifies this as keyword stuffing ("Yellow Argon" policy violation). Fixed by replacing the brand list with: "access keys for major cloud infrastructure, source-control, payment, messaging, and email-delivery platforms."

**Lesson:** CWS (and other extension stores) strictly enforce keyword spam policies. Never list competitor or integration brand names in listing descriptions — use generic category descriptions instead. Even legitimate integration references can trigger automated rejection. Review CWS developer policies before submitting listing updates.

### 110. Google Analytics measurement ID was for the wrong property

**Context:** Attempted to add Google Analytics to aegisgatesecurity.io using measurement ID G-LP7XKYPPBM. This ID was actually for the Chrome Web Store developer property (chrome.google.com/webstore), not for aegisgatesecurity.io. Adding the gtag snippet with this ID to the website would have sent website traffic data to the CWS property. Had to remove the GA code, revert CSP changes, and switch to Cloudflare Web Analytics instead.

**Lesson:** Always verify which GA property/stream a measurement ID belongs to before deploying. GA properties are per-domain — a measurement ID for one property cannot track a different domain. When using multiple Google properties (CWS, website, etc.), label them clearly in the GA dashboard. For a privacy-focused security product, Cloudflare Web Analytics (cookieless, no GDPR consent needed) is a better fit than GA.

### 111. Dependabot didn't run `go mod tidy` after bumping prometheus/client_golang

**Context:** Dependabot merged PR #2 on Enterprise repo bumping `prometheus/client_golang` from 1.18.0 to 1.24.1. This pulled in `prometheus/common v0.70.1` as a transitive dependency, which imports `github.com/munnerz/goautoneg`. Dependabot updated `go.mod` but failed to add the checksum for this transitive dependency to `go.sum`. CI failed with "missing go.sum entry for module providing package github.com/munnerz/goautoneg." Fixed by running `go mod tidy` locally and pushing the updated go.sum.

**Lesson:** Dependabot updates `go.mod` directives but sometimes doesn't fully synchronize all transitive `go.sum` entries. After merging any Dependabot Go dependency PR, always verify CI passes. If it fails with "missing go.sum entry," run `go mod tidy` and push the fix. This is a known Dependabot limitation with Go modules.

### 112. GitHub Sponsors/donations undermine enterprise positioning at pre-revenue stage

**Context:** Considered enabling GitHub Sponsors for the 3 open-source repos. Analysis showed that for a pre-revenue company with 0 GitHub stars and enterprise pricing ($499-$2,000+/mo), a "Donate" button signals desperation and creates price ambiguity. Users may think "why pay $499/mo when I can donate $5?" It also shifts focus from "enterprise security platform" to "open-source side project." GitHub Sponsors should be enabled only after 500+ stars AND validated paid revenue.

**Lesson:** Monetization signaling matters. For enterprise-targeted products, donation buttons and "buy me a coffee" patterns undermine premium positioning. Enable donation/sponsor mechanisms only after establishing market validation (stars, users, revenue). The open-source community edition serves as the funnel to paid tiers — it doesn't need its own monetization.

### 113. Platform CodeQL alerts are Trivy container CVEs, not Go code vulnerabilities

**Context:** 25 CodeQL alerts on the Platform repo were initially alarming. Investigation showed all 25 were OS package vulnerabilities in the `debian:bookworm-slim` Docker base image (glibc, zlib, wget, util-linux), NOT vulnerabilities in the Go code itself. These are tracked by Trivy container scanning and flagged by GitHub's CodeQL integration. They're accepted risk waiting for upstream Debian patches.

**Lesson:** When CodeQL alerts fire, check whether they're code vulnerabilities or container image OS package CVEs. Container CVEs in the base image (Debian, Alpine, etc.) are upstream issues — you can only wait for patches or switch base images. Don't conflate container OS CVEs with code vulnerabilities when assessing security posture. Go statically compiled binaries are largely immune to glibc-level CVEs.

## Gotchas 114-127 (Session 2026-09-14 to 09-16)

- **114**: Hugo blog list.html .Permalink needs {{ with }} block not pipe — calling .Permalink with arguments fails
- **115**: Google Fonts woff2 downloads fail via direct URL — must extract font URLs from CSS API response
- **116**: Hugo frontmatter must be at line 1 or it renders as body content (lens/architecture.md had frontmatter at line 4)
- **117**: mermaid:true in body text (not just frontmatter) renders as visible h2 headings — remove from body, keep only in frontmatter
- **118**: Hardcoded CSS colors (#1a1a2e, #333, #555, #666) invisible on dark theme — always use CSS variables (var(--text-primary), var(--text-secondary))
- **119**: home-redirect.js DOM injection causes INP regression — inline the HTML element instead of JS-injecting it
- **120**: .hero::before pseudo-element causes CLS — use direct background property on .hero itself
- **121**: Google Search Console reports robots.txt blocked pages that are in sitemap — don't block pages that are in your sitemap
- **122**: Hugo tag pages are thin content with duplicate titles — add noindex,follow to taxonomy/term pages
- **123**: Missing canonical URL tag causes 'duplicate without user-selected canonical' in GSC — always add <link rel="canonical">
- **124**: IFTTT free tier requires Pro+ for RSS triggers — use dlvr.it instead (free tier supports X, Mastodon, Discord)
- **125**: Buttondown RSS-to-email AND MailerLite RSS automation are both paid features — manual sending until 100+ subscribers
- **126**: STAR for AI registry costs ~€650 — premature at pre-revenue/zero-customers, defer until first paying customer
- **127**: dlvr.it can post to Discord — no need for MonitoRSS as a separate tool, one tool handles all platforms

---

## Gotchas 128-134 (Session 2026-09-17)

### 128. LOC vs bytes — know the difference
**What happened:** AICM mapping claimed "73K LOC" for framework_mapping.go. The file is 73,636 BYTES (73KB) but only 1,398 LINES. A reviewer would immediately catch this.  
**Lesson:** LOC = lines of code. KB = kilobytes. Never confuse them. When citing file size, specify which unit you mean. When citing code size, use lines, not bytes.

### 129. "AI-Specific" control count must match your own table
**What happened:** Summary doc said "17 AI-Specific controls" but the table below it listed 32 rows. Internal contradiction that a reviewer catches in 5 seconds.  
**Lesson:** Any count in prose must match the count in your table. Cross-check every number against every other place it appears.

### 130. Bias detection ≠ toxicity detection
**What happened:** GRC-11 evidence claimed "toxicity filter, biased output detection." The toxicity filter detects violence/weapons/illegal/self-harm/harassment — NOT bias or fairness. No bias detector exists in the response guard. Bias injection IS detected at ingress (regex, ATLAS, ML training) but biased OUTPUTS are not detected.  
**Lesson:** Don't conflate detection categories. "Harassment" ≠ "bias." "Bias injection attack" ≠ "biased output." Be precise about what your code detects and what it doesn't.

### 131. AIBOM "TODO-302" is a design review tag, not an "unimplemented" marker
**What happened:** Initial review flagged AIBOM as a stub because of "TODO-302" in the doc.go header. After reading the actual source code, AIBOM is fully implemented: generator (18 functions), signing (ECDSA P-256), verification. The TODO tag is a design-pattern review reference, not an unimplemented marker.  
**Lesson:** TODO tags in code comments may be ticket references, not implementation status. Always read the actual code before claiming something is unimplemented.

### 132. Don't claim what you can't verify in source code
**What happened:** Multiple claims in the AICM mapping were wrong because they were based on summaries/memories, not source code verification. ML params were "1.6M" (code says "2-5M"), DSAR was "GDPR/CCPA" (code says GDPR only).  
**Lesson:** For any claim about your codebase, grep the actual source. Don't rely on memory or prior summaries. If you can't find it in the code, don't claim it.

### 133. STAR submission requires CSA's original template format
**What happened:** Generated our own AI-CAIQ Excel file from the crosswalk data. Would have been rejected — CSA requires the original template with only columns C/D/E/F modified. No structural changes allowed.  
**Lesson:** When submitting to a standards body, use THEIR template. Read the submission guide carefully. Don't add/remove columns, rows, or tabs. Only modify the fields they specify.

### 134. Don't claim submissions that haven't happened
**What happened:** Listed "AICM mapping submitted to CSA WG" as complete when it hadn't been submitted — only published to GitHub. User corrected this. The plan was always to submit after the first WG meeting.  
**Lesson:** "Published on GitHub" ≠ "submitted to WG." "Ready to submit" ≠ "submitted." Track the actual status, not the intended status.

---

## Gotchas 135-142 (Session 2026-09-18 to 09-20: v4.5.0 ML Detection + Two-Tier L3 + Cross-Repo Sync)

### 135. onnxruntime_go version must match installed C library API version
**Date:** 2026-09-19
**Context:** ML Detection Gate CI ran in heuristic-only mode (88.7/100) because ONNX runtime failed with "Error setting ORT API base: 2". `onnxruntime_go v1.36.0` bundles C API headers with `ORT_API_VERSION = 29` (shipped with ORT 1.29.0). CI installed ORT 1.18.0 (API v19). `GetApi(29)` on old library returns NULL → error code 2.
**Fix:** Changed `ORT_VERSION="1.18.0"` → `ORT_VERSION="1.29.0"` in `ml-detection-gate.yml`.
**Lesson:** The Go ONNX binding version determines which C API version it expects. The installed C library must support that API version. Always check `ORT_API_VERSION` in the binding's headers against the installed library. Version mismatch manifests as error code 2 from `SetAPIFromBase`, not a clear "version mismatch" message.

### 136. go test CWD ≠ shell CWD — relative env var paths resolve differently
**Date:** 2026-09-19
**Context:** `AEGISGATE_ML_MODEL_PATH=pkg/ml/models/threat_cnn_bilstm.onnx` (relative) worked when the platform binary ran from repo root, but the evasion suite Go test binary's CWD was `upstream/aegisgate/pkg/proxy/` (the package directory), not `upstream/aegisgate/` (the shell CWD). The relative path resolved to `upstream/aegisgate/pkg/proxy/pkg/ml/models/` which doesn't exist. Model didn't load → score 88.7.
**Fix:** Changed env var to `${{ github.workspace }}/upstream/aegisgate/pkg/ml/models/threat_cnn_bilstm.onnx` (absolute path).
**Lesson:** `go test ./pkg/proxy/` runs with the test binary's CWD at the package directory, not the shell's CWD. Relative paths in env vars resolve from the test binary's perspective. Always use absolute paths for env vars in CI, especially for file paths that tests need to resolve. This took 5 rounds of CI debugging to find.

### 137. CGO_ENABLED must be set explicitly in CI for ONNX build tag
**Date:** 2026-09-19
**Context:** Evasion suite CI step didn't set `CGO_ENABLED=1`. Without CGO, the ONNX build tag is not activated and the `noonnx` fallback is used silently. Tests pass but the neural detector doesn't run.
**Fix:** Added `CGO_ENABLED: '1'` to the evasion suite step env in the workflow YAML.
**Lesson:** Go build tags for CGO-dependent features (like ONNX runtime) require `CGO_ENABLED=1` explicitly in CI. The default may be 0 in CI runners. Silent fallback to heuristic-only mode masks the problem — the tests still pass, just with a lower score. Always check the CI log for "ONNX model loaded" vs "heuristic-only mode" to confirm.

### 138. Model hash in code must match model on GitHub releases
**Date:** 2026-09-19
**Context:** Updated `ExpectedModelHash` in `pkg/ml/detector.go` to v12 hash (`9ce1e81a...`), but the GitHub v4.5.0 release still had the v11b model (`8e13c793...`). CI downloaded the old model, hash didn't match, fell back to heuristic-only mode.
**Fix:** Uploaded v12 model to GitHub release v4.5.0 as `threat_cnn_bilstm.onnx`, deleted old asset.
**Lesson:** When retraining and updating `ExpectedModelHash`, the model file in GitHub releases must also be updated. The hash verification is a two-part check: code constant + release asset. Forgetting either one causes silent fallback. Always update the release asset and verify the hash matches before pushing the code change.

### 139. Training corpus gaps cause systematic false positives on entire categories
**Date:** 2026-09-19
**Context:** v11b model flagged UUIDs (0.9987), SHA-256 hashes (1.0000), ARNs (0.9993) as adversarial. The training corpus had only 3 UUID-like, 2 timestamp-like, 0 hash-like benign examples. The model learned "numeric-heavy strings = adversarial."
**Fix:** Generated 4,585 numeric benign examples across 13 categories (UUIDs, timestamps, hashes, ARNs, JWTs, versions, IPs, API keys, base64, numeric IDs, DB connection strings, URLs, config values). Merged into v12 corpus (75,157 total). Retrained. UUID→0.0001, sha256→0.0035, ARN→0.0003.
**Lesson:** Model false positives are often training corpus gaps, not model architecture problems. Before retraining or tuning hyperparameters, audit the training corpus for underrepresented benign categories. A handful of examples per category is not enough — need hundreds. The model can't learn what it hasn't seen enough of.

### 140. Two-tier L3 blocking is the correct architecture for ML detection + corroboration
**Date:** 2026-09-19
**Context:** 621 L3-only evasions (character-level: transposition, vowel deletion, word reversal) were detected by the neural model but only logged, not blocked, because the old architecture required L1/L2 corroboration — which character-level evasions bypass by design.
**Fix:** Implemented two-tier L3: Tier 1 (score ≥ 0.95) blocks independently, Tier 2 (0.50–0.94) requires L1/L2 corroboration, Tier 3 (< 0.50) logs only. Added `ReasonMLThreatHigh` metrics label.
**Lesson:** A single threshold for ML-based blocking is too rigid. High-confidence ML detections (> 0.95) should block independently — they don't need regex corroboration because the model is confident enough. Lower-confidence detections need corroboration to prevent FPs. The two-tier approach eliminates the 15% detection gap without introducing FPs.

### 141. Upstream and platform metrics labels must stay in sync
**Date:** 2026-09-19
**Context:** Added `ReasonMLThreatHigh` to platform `pkg/metrics/labels.go` but the proxy uses upstream `pkg/metrics/metrics.go` which didn't have it. Compile error: `undefined: metrics.ReasonMLThreatHigh`.
**Fix:** Added `ReasonMLThreatHigh` to `upstream/aegisgate/pkg/metrics/metrics.go` as well.
**Lesson:** When adding a new metrics label, check both the platform copy (`pkg/metrics/labels.go`) and the upstream copy (`upstream/aegisgate/pkg/metrics/metrics.go`). The proxy imports the upstream package. Forgetting either one causes a compile error. This applies to all shared constants, not just metrics labels.

### 142. Branch protection enforce_admins — use full PUT with complete config if protection was fully deleted
**Date:** 2026-09-19
**Context:** After pushing to Lens and Rampart, tried to re-enable `enforce_admins` using `gh api .../protection/enforce_admins -X POST` (the sub-endpoint from gotcha #91). Got 404 on some repos. The sub-endpoint requires the protection to already exist; if it was fully deleted, it 404s.
**Fix:** Used full `PUT .../branches/main/protection` with complete JSON config including `enforce_admins: true`, `required_status_checks`, `required_linear_history`, etc.
**Lesson:** Gotcha #91 (use DELETE/POST sub-endpoints) works when branch protection already exists. But if branch protection was fully deleted (not just enforce_admins disabled), you must use the full PUT endpoint to recreate the entire protection config. Check if protection exists first with a GET, then choose the right approach.

### 143. ALWAYS work from canonical locations — verify the source of truth before making claims
**Date:** 2026-09-20
**Context:** During a comprehensive project assessment, I made multiple false claims by checking stale copies of files instead of the canonical/live versions:
- Claimed "RLS not fully wired" — cited a stale Aug 28 audit document. Migration 012 had since fixed all 7 stores. Code was the source of truth.
- Claimed "v4.5.0 not released" — it was already tagged and published on GitHub. `gh release list` was the source of truth.
- Claimed "DIST gaps remain" — cited a stale regression action plan. The code (`pkg/auth/distillation_detect.go`, 683 LOC) was the source of truth.
- Claimed "v4.5.0 blog post not published" — searched `websites/aegisgate-site/content/blog/` (a stale copy with no git remote) instead of `aegisgate-site/content/blog/` (the live repo with git remote `aegisgatesecurity/aegisgate-site`). The live copy had the blog post.
- Claimed "no security training program" — the live website had `security/training.md` and `security/training-records.md`. Never checked.
- Claimed "Lens has 0 tests" — never looked in `aegisgate-lens/test/` which has 28 unit tests, e2e tests, integration tests, and headless smoke tests.

**Root cause:** Checking whichever copy of a file I found first, without verifying it was the canonical/live version. Multiple stale copies exist on disk (e.g., `websites/aegisgate-site/` vs `aegisgate-site/`, planning documents vs actual code, audit reports vs current migrations).

**Fix:** Before making ANY claim about project state, verify against the canonical source:
- **Code:** Check `consolidated/aegisgate-platform/` (Platform), `aegisgate-rampart/` (Rampart), `aegisgate-lens/` (Lens), `consolidated/aegisgate-enterprise/` (Enterprise)
- **Website:** Check `aegisgate-site/` (has git remote to `aegisgatesecurity/aegisgate-site`), NOT `websites/aegisgate-site/` (stale copy, no remote)
- **Release status:** Use `gh release list` / `gh release view`, not planning documents
- **Migration status:** Check `pkg/ioc/migrations/*.sql` in the actual code, not audit reports
- **Test status:** Run the tests or count test files in the actual repo, don't cite old numbers from README badges
- **Blog/publications:** Check the live website directory (`aegisgate-site/content/`), not stale copies

**Lesson:** NEVER cite a planning document, audit report, or stale file copy as evidence of current state. ALWAYS verify against the canonical source — the live code, the live repository, the GitHub API. If there are multiple copies of something on disk, identify which one has the git remote (canonical) before trusting it. When in doubt, `git remote -v` tells you which copy is live. This is the single most important discipline for accurate assessments. Stale documents are written before fixes are implemented — they describe the past, not the present.

### 144. computeFileHash must hash entire file, not first N bytes
**Date:** 2026-09-24
**Context:** `computeFileHash()` in `upstream/aegisgate/pkg/ml/threat_detector.go` and `threat_detector_noonnx.go` only hashed the first 32 bytes of the ONNX model file (`data[:minInt(len(data), 32)]`). This is a critical supply-chain integrity weakness — an attacker could replace a model file with a trojaned version that matches the first 32 bytes but differs after that. The hash check would pass, and the trojaned model would be loaded.
**Fix:** Replaced with `sha256.Sum256(data)` over the entire file. Removed `minInt` helper. Added `crypto/sha256`, `encoding/hex`, `path/filepath` imports.
**Lesson:** Integrity checks must cover the entire file, not a prefix. Hashing only the first N bytes provides almost no security — an attacker only needs to craft a file where the first N bytes match. This is especially critical for model files in ML security pipelines where a tampered model could silently allow adversarial inputs. Always use `sha256.Sum256(data)` over the full file contents.

### 145. SSRF protection is correct — verify the test exercises the right code path before assuming a bug
**Date:** 2026-09-24
**Context:** `TestMITM_Integration_FullFlow` in Rampart failed with 403 Forbidden. Initial assumption was that the proxy had an SSRF bug. In reality, the test connected to `127.0.0.1:backendPort` through the proxy, which triggered the tunnel path → `isBlockedAddress("127.0.0.1")` → blocked loopback (correct SSRF protection). The test was exercising the wrong code path entirely.
**Fix:** Rewrote the test to send requests to `https://api.openai.com` (a target domain), which triggers the MITM intercept path instead of the tunnel path. Overrode `sharedTransport.DialTLSContext` to route upstream to the mock backend on loopback. Loaded test CA via `p.certMgr.LoadCAFromFiles()`.
**Lesson:** Before assuming production code has a bug, verify which code path the test actually exercises. A 403 from SSRF protection on a loopback address is correct behavior, not a bug. The test was wrong, not the proxy. Always trace the request through the code to understand which branch is taken before diagnosing the failure.

### 146. Pattern naming conventions differ across products — renamed equivalents are not "missing"
**Date:** 2026-09-24
**Context:** Pattern count comparison showed Platform 216, Rampart 185, Lens 183. Initial analysis flagged 49 "missing" patterns in Rampart. On closer inspection, 24 were renamed equivalents (e.g., Platform's `AmexCreditCard` = Rampart's `pii_credit_card_amex`). Only 26 were truly missing. Similarly, Rampart's `pii_credit_card` is a consolidated pattern that covers 5 separate Platform patterns (`VisaCreditCard`, `AmexCreditCard`, `MastercardCreditCard`, `AmexSpaced`, `MastercardSpaced`), explaining the 216 vs 211 gap.
**Fix:** Extracted the 26 truly missing patterns to JSON, used parallel delegates to sync to both Rampart and Lens. Left the 24 renamed equivalents as-is (they already detect the same things under different names). Documented the naming convention difference.
**Lesson:** Pattern count differences across products don't automatically mean patterns are missing. Products may use different naming conventions (CamelCase vs snake_case) or consolidate related patterns into a single broader pattern. Always compare regex patterns by their actual detection capability (regex + severity + category), not just by name. A name diff overstates the gap; a semantic diff is the truth.

### 147. RE2 (Go) does not support `\uXXXX` — use `\x{XXXX}` syntax instead
**Date:** 2026-09-24
**Context:** The `PromptInjectionUnicode` pattern uses Unicode zero-width characters (`\u200b`–`\u200f`, `\u2028`–`\u202f`, `\ufeff`). In Go's RE2 engine, `\u200b` is not valid syntax — it's interpreted literally, not as a Unicode escape.
**Fix:** Changed to RE2-compatible syntax: `\x{200b}-\x{200f}\x{2028}-\x{202f}\x{feff}`. RE2 supports `\x{XXXX}` for Unicode code points.
**Lesson:** Go's RE2 regex engine differs from PCRE and JavaScript regex. `\uXXXX` (JavaScript/PCRE Unicode escape) is not supported in RE2. Use `\x{XXXX}` instead. This is especially relevant when porting patterns from JS (Lens) to Go (Platform/Rampart) or vice versa. Always test regex patterns in the target engine after porting.

### 148. Stale on-disk JSON reports from no-ONNX runs can be confused with real results
**Date:** 2026-09-24
**Context:** The Rampart evasion suite JSON on disk showed 26.1% — a catastrophic score. Investigation revealed this was from a no-ONNX run (CGO disabled, heuristic-only fallback). The committed Markdown report showed the real score: 100.0/100. The JSON was gitignored and had been overwritten by the no-ONNX run.
**Fix:** Restored the committed MD via `git checkout`. Noted that the JSON is gitignored and only the MD is the canonical evidence. For future runs, always ensure `CGO_ENABLED=1` and ONNX runtime is available before running the evasion suite.
**Lesson:** Gitignored JSON reports on disk can be stale or from a degraded run (no ONNX, heuristic-only). Always check the committed Markdown report for the canonical score. If a JSON shows a dramatically different score from the committed MD, suspect a no-ONNX run overwrote it. Always verify `CGO_ENABLED=1` and ONNX model loaded before trusting evasion suite results.
