# Copyright Registration Guide — AegisGate Software

**Date:** 2026-09-11
**Total cost:** $65 (single collection registration for open-source repos) + $65 (Enterprise separate registration) = **$130 total**
**Timeline:** Can be filed online in ~30 minutes

---

## What You're Registering

Copyright registration protects the **original expression** of your source code — the specific way you wrote it. It does NOT protect the ideas, methods, or systems (those are covered by patents). Copyright and patents are complementary:

- **Patents** protect the *invention* (the 5 inventions described in your provisional patent specs)
- **Copyright** protects the *expression* (the specific Go and JavaScript source code files)
- **Trade secrets** protect the *proprietary know-how* (Enterprise TRADE-SECRET-NOTICE.md)
- **Model weight license** protects the *trained weights* (WEIGHTS-LICENSE.md)

### Registration Strategy

| Registration | Repos Covered | Form | Type | Cost |
|-------------|---------------|------|------|------|
| Registration 1 | Platform + Rampart + Lens | eCO TX (single collection) | Published software | $65 |
| Registration 2 | Enterprise | eCO TX (standalone) | Unpublished software | $65 |

**Total: $130**

### Why Two Separate Registrations?

1. **Open-source repos (Platform, Rampart, Lens)** are published — they've been publicly available on GitHub since their first commits. They share the same author, same copyright notice format, and same general purpose. They can be registered as a single "collection" under one title, saving $130 in filing fees.

2. **Enterprise** is unpublished (private repo, never made public) and has a different license (commercial vs. Apache 2.0). It must be registered separately.

---

## Before You File

### Step 1: Confirm Authorship and Ownership

**Author:** [YOUR FULL LEGAL NAME] — the individual who wrote the code.

**Claimant:** AegisGate Security, LLC — the entity that owns the copyright.

**Transfer:** The author created the works as an independent developer and assigned all rights to AegisGate Security, LLC. This is documented by:
- The copyright notices in all source files: `Copyright 2024-2026 AegisGate Security, LLC`
- The LICENSE files in all repositories naming AegisGate Security, LLC
- The git commit history showing all work performed under the AegisGate Security identity

> **Important:** If you formed the LLC BEFORE writing the code, and you wrote the code as an employee/owner of the LLC, the works may be "works made for hire" with the LLC as the author. If you wrote code BEFORE forming the LLC and then assigned it, you are the individual author who transferred rights to the LLC. Either way, the claimant is AegisGate Security, LLC. The distinction affects how you fill in the "Author" field on the registration form:
> - **If LLC existed when code was written:** Author = AegisGate Security, LLC (work made for hire)
> - **If code was written before LLC formation:** Author = [Your Name], transferred to AegisGate Security, LLC by assignment

> **For this guide, we assume the LLC existed and you wrote code as its owner.** If that's not the case, adjust the "Author" field accordingly.

### Step 2: Confirm Publication Status

**Open-source repos (published):**

| Repo | First Publication Date | First Version |
|------|----------------------|---------------|
| Platform | 2026-04-16 | v1.2.0 (first git commit) |
| Rampart | 2026-08-06 | Phase 1 initial commit |
| Lens | 2026-07-04 | v0.1.0-beta scaffold |

"Publication" under copyright law means distributing copies to the public. Making source code publicly available on GitHub constitutes publication.

**Enterprise (unpublished):**
- First commit: 2026-08-19
- Never made publicly available (private GitHub repository)
- Status: Unpublished

### Step 3: Prepare Deposit Materials

The Copyright Office requires "deposit" of identifying portions of the work. For software:

#### Registration 1 — Open-Source Collection (Published)

For published software, the deposit is:
- **First 25 pages and last 25 pages of source code** (50 pages total), OR
- If the work is 50 pages or less, the **entire source code**

**What to submit:**
- Generate a single PDF containing the first 25 and last 25 pages of representative source code from each of the 3 repos
- Use the most significant files (main entry points, core detection engines, ML inference)
- **Redact nothing** — the code is open-source and publicly available on GitHub

> **Note:** The Copyright Office allows you to submit source code in PDF format. Each page should have page numbers. The deposit does NOT need to be the entire codebase — 50 pages is sufficient.

**Recommended files for the deposit (to represent each repo's original authorship):**

Platform (first 25 pages — pick highest-LOC original files):
- `cmd/aegisgate-platform/main.go` — entry point
- `pkg/scanner/scanner.go` — L1 regex scanner
- `pkg/ml/threat_detector.go` — L3 ML detection
- `pkg/scanner/patterns.go` — detection patterns
- `pkg/proxy/proxy.go` — reverse proxy core

Platform (last 25 pages):
- `pkg/billing/stripe.go` — billing integration
- `pkg/sso/saml.go` — SSO SAML implementation
- `pkg/soar/soar.go` — SOAR integration
- `pkg/compliance/compliance.go` — compliance framework

Rampart (include key files):
- `internal/proxy/mitm.go` — MITM proxy
- `internal/detectors/detector.go` — detection engine
- `internal/detectors/normalize.go` — keyWalkReverse normalization

Lens (include key files):
- `src/detectors/ml/threat-detector-js.js` — JS ML inference
- `src/detectors/ml/char-normalizer.js` — character normalization
- `src/detectors/index.js` — detection orchestrator
- `src/util/banner-ui-html.js` — UI component

#### Registration 2 — Enterprise (Unpublished)

For unpublished software, the deposit is:
- **The entire source code** OR
- **First 25 and last 25 pages** with trade secret material redacted

**What to submit:**
- Generate a PDF with the first 25 and last 25 pages of representative Enterprise source code
- **Redact trade secret portions** — you may redact (black out) sections that contain proprietary algorithms, trade secrets, or sensitive implementation details
- Mark redacted sections with `[REDACTED — TRADE SECRET]`

**Recommended files for the Enterprise deposit:**
- `pkg/trust/identity/identity.go` — ECDSA identity (representative, may redact key generation details)
- `pkg/trust/scoring/scoring.go` — trust scoring algorithm (may redact scoring formula)
- `pkg/siem/siem.go` — SIEM integration framework
- `pkg/compliance/premium/soc2.go` — SOC 2 compliance module

### Step 4: Identify Excluded Material

You must identify material that is NOT part of your copyright claim:

**Excluded from all registrations:**
- All third-party Go modules listed in `THIRD-PARTY-LICENSES.md` (200+ dependencies)
- Standard library code (Go standard library, browser APIs)
- Any code derived from or based on third-party tutorials, examples, or templates
- The Apache License 2.0 text (it is not your original work)

**Included in the copyright claim:**
- All original AegisGate source code (Go files, JavaScript files)
- Original configuration files written by AegisGate (detection patterns, compliance mappings)
- The ML model architecture implementation code (NOT the model weights — those are under a separate license)
- Original documentation written by AegisGate

---

## How to File — Registration 1: Open-Source Collection

### Via Electronic Copyright Office (eCO)

1. Go to **https://eco.copyright.gov**
2. Create an account if you don't have one (free)
3. Click **"Register a New Claim"**
4. Select **"Standard Application"** (single application)
5. Fill in the form as follows:

#### Section 1: Type of Work

| Field | Value |
|-------|-------|
| Type of Work | **Other Digital Content** → **Computer Program** (or "Literary Work" → "Computer Program" if that option is presented) |
| Number of Works | **1** (single collection) |

#### Section 2: Title

| Field | Value |
|-------|-------|
| Title of Work | **AegisGate Security Software Collection** |
| Type of Title | **Title Appears on Work** |
| Alternative Title | (leave blank) |

> **Why a collection?** 37 CFR § 202.3(b)(4) and the Compendium of U.S. Copyright Office Practices (Third Edition, Chapter 1100) allow registration of a "group of works" as a single registration when they share the same copyright claimant and were published in the same calendar year. Your 3 repos share the same author, same claimant, same copyright notice, and were all published in 2026.
>
> **Note on group registration eligibility:** The three repos have different publication dates (April, July, August 2026). Group registration for published works requires that the works be published as part of a "unit of publication" — meaning they were first published as a single collective unit. Three independently-published GitHub repositories may not meet this requirement. If the Copyright Office rejects the group registration, file three separate Standard Applications ($65 each = $195). The group filing is worth attempting first to save $130, but the fallback is three separate filings.

#### Section 3: Publication

| Field | Value |
|-------|-------|
| Published? | **Yes** |
| Publication Date | **2026-04-16** (earliest publication date — Platform's first commit) |
| Publication Nation | **United States** |
| Publication Medium | **Online** (GitHub) |

> The publication date should be the EARLIEST date any part of the collection was published. Platform's first commit (2026-04-16) is the earliest.

#### Section 4: Author

| Field | Value |
|-------|-------|
| Author Name | **AegisGate Security, LLC** (if work made for hire) |
| Year of Birth | (leave blank for entities) |
| Citizenship/Domicile | **United States** |
| Nature of Authorship | **Computer program; original source code in Go and JavaScript** |

> If you are claiming as an individual author (not work made for hire):
> - Author Name: [YOUR FULL LEGAL NAME]
> - Citizenship: United States
> - Nature of Authorship: "Computer program; original source code in Go and JavaScript"

#### Section 5: Claimant

| Field | Value |
|-------|-------|
| Claimant Name | **AegisGate Security, LLC** |
| Address | [YOUR LLC BUSINESS ADDRESS] |
| Transfer Statement | "The author created the works as works made for hire for AegisGate Security, LLC" (if LLC is author) |
| Transfer Statement | "The author transferred all rights to AegisGate Security, LLC by assignment" (if individual author) |

#### Section 6: Limitation of Claim

This is CRITICAL — it excludes material you don't own from your copyright claim.

| Field | Value |
|-------|-------|
| Material Excluded | "Third-party open-source libraries licensed under Apache 2.0, MIT, BSD, ISC, and MPL licenses as listed in THIRD-PARTY-LICENSES.md. Go standard library code. Apache License 2.0 license text." |
| New Material Included | "Original AegisGate source code, detection patterns, compliance mappings, and documentation." |

#### Section 7: Rights and Permissions

| Field | Value |
|-------|-------|
| Corresponding Author | [YOUR NAME] |
| Corresponding Email | security@aegisgatesecurity.io |
| Phone | [YOUR PHONE NUMBER] |
| Address | [YOUR LLC BUSINESS ADDRESS] |

#### Section 8: Certification

| Field | Value |
|-------|-------|
| Certifying Person | [YOUR FULL LEGAL NAME] |
| Capacity | **Authorized Agent** (or **Owner** if you are the LLC owner) |
| Date | [DATE OF FILING] |

#### Section 9: Deposit

Upload the PDF deposit (first 25 + last 25 pages of representative source code, as described in Step 3 above).

#### Payment

Pay $65 filing fee via credit card / ACH.

---

## How to File — Registration 2: Enterprise (Unpublished)

### Via eCO

1. Go to **https://eco.copyright.gov**
2. Click **"Register a New Claim"**
3. Select **"Standard Application"**
4. Fill in the form:

#### Section 1: Type of Work

| Field | Value |
|-------|-------|
| Type of Work | **Computer Program** |

#### Section 2: Title

| Field | Value |
|-------|-------|
| Title of Work | **AegisGate Enterprise Software** |

#### Section 3: Publication

| Field | Value |
|-------|-------|
| Published? | **No** (unpublished — private repository, never made public) |

> Unpublished works are not subject to the deposit requirements for published works. You submit "identifying portions" — the first 25 and last 25 pages with redactions for trade secrets.

#### Section 4: Author

| Field | Value |
|-------|-------|
| Author Name | **AegisGate Security, LLC** (work made for hire) |
| Nature of Authorship | **Computer program; original source code in Go including trust framework, SIEM integration, and compliance modules** |

#### Section 5: Claimant

| Field | Value |
|-------|-------|
| Claimant Name | **AegisGate Security, LLC** |
| Transfer Statement | "The author created the works as works made for hire for AegisGate Security, LLC" |

#### Section 6: Limitation of Claim

| Field | Value |
|-------|-------|
| Material Excluded | "Third-party open-source libraries licensed under Apache 2.0, MIT, BSD, and ISC licenses as listed in THIRD-PARTY-LICENSES.md. Go standard library code. Trade secret material has been redacted from the deposit." |
| New Material Included | "Original AegisGate Enterprise source code including trust framework identity management, capability contracts, trust scoring, SIEM integration, premium compliance modules, and training pipeline." |

#### Section 7-8: Rights, Permissions, Certification

Same as Registration 1 above.

#### Section 9: Deposit

Upload the PDF deposit (first 25 + last 25 pages with trade secret portions redacted).

#### Payment

Pay $65 filing fee.

---

## After Filing

### What You Get
- **Registration number** for each filing (typically issued 3-8 months after filing)
- The registration is **effective as of the date the Copyright Office receives your application** (not the date they issue the number)

### What Registration Gives You

1. **Prima facie evidence** of copyright ownership in court (registered within 5 years of publication)
2. **Statutory damages and attorney's fees** — if registered within 3 months of first publication OR before infringement begins. If you register later, you can only get actual damages (which are harder to prove).
3. **Right to record** the registration with U.S. Customs to prevent import of infringing copies
4. **Public record** of your copyright claim

### Critical Timing Note

For the open-source repos, the **3-month statutory damage window** has already passed for early versions (Platform was first published April 2026). However:
- **New versions** published within 3 months of registration get full statutory damages protection
- You should register **ASAP** to protect the latest versions (v4.4.1, v0.7.1, v0.4.1, published September 2026)
- If you register within 3 months of the September 2026 releases, those versions get full statutory damages protection

**Recommendation:** File both registrations before December 9, 2026 (3 months after the September 9, 2026 releases) to maximize protection for the latest versions.

---

## Relationship Between Copyright, Patents, and Other IP

| IP Right | What It Protects | What It Covers | How to Enforce |
|----------|-----------------|----------------|----------------|
| **Copyright** | Expression | Source code files, documentation | Infringement suit (copying) |
| **Patents (5 provisional)** | Inventions | Methods/systems for detection, trust, compliance | Patent infringement suit |
| **Trade Secrets** | Proprietary know-how | Enterprise algorithms, scoring formulas, SIEM integration | Misappropriation suit (UTSA/DTSA) |
| **Model Weight License** | Trained weights | ONNX model, JS weight files | Breach of contract / license violation |
| **Trademark** | Brand | "AegisGate", "Rampart", "Lens" | Trademark infringement |

### No Conflicts

- Copyright and patents protect **different aspects** of the same software — no overlap or conflict
- The copyright deposit can include code that implements the patented inventions — the copyright protects the specific code, the patent protects the method
- Trade secret law does not apply to the open-source repos (they're public) but applies to Enterprise
- The model weight license is a contract-based restriction, separate from both copyright and patent

---

## Cost Summary

| Item | Cost | When |
|------|------|------|
| Registration 1 (Open-Source Collection — single filing) | $65 | Before December 9, 2026 |
| Registration 1 Fallback (3 separate filings, if group rejected) | $195 | Before December 9, 2026 |
| Registration 2 (Enterprise) | $65 | Anytime (unpublished, no deadline) |
| **Total (best case)** | **$130** | |
| **Total (fallback)** | **$260** | |

---

## Checklist Before Filing

- [ ] Confirm whether LLC existed before code was written (affects "Author" field)
- [ ] Confirm your LLC's legal business address
- [ ] Prepare Deposit PDF 1 (open-source: first 25 + last 25 pages, no redactions)
- [ ] Prepare Deposit PDF 2 (Enterprise: first 25 + last 25 pages, trade secrets redacted)
- [ ] File Registration 1 at https://eco.copyright.gov
- [ ] File Registration 2 at https://eco.copyright.gov
- [ ] Save registration confirmation receipts
- [ ] Save registration numbers when issued (3-8 months)

---

*This guide is based on U.S. Copyright Office regulations and practices as of September 2026. Copyright law is federal (17 U.S.C.) and administered by the U.S. Copyright Office. This document is not legal advice — consult with an intellectual property attorney for complex situations.*

*Copyright © 2026 AegisGate Security, LLC. All rights reserved.*