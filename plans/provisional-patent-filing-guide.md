# Provisional Patent Filing Guide

**Date:** 2026-09-10
**Total cost:** $325 ($65 × 5 applications, micro entity rate)
**Timeline:** Can be filed all in one day

---

## What You're Filing

| # | Patent Application | File | Key Invention |
|---|---|---|---|
| 1 | Trust Framework | `provisional-patent-01-trust-framework.md` | Per-agent cryptographic identity + capability contracts + trust scoring + attestations |
| 2 | Multi-Protocol Interception | `provisional-patent-02-multi-protocol-interception.md` | Intercepting/scanning MCP, A2A, ACP, ANP messages for data exfiltration |
| 3 | Compliance Mapping | `provisional-patent-03-compliance-mapping.md` | Mapping AI security detections to 33+ compliance framework controls |
| 4 | 3-Layer Detection Pipeline | `provisional-patent-04-three-layer-detection.md` | Regex → ATLAS/compliance → CharCNN-BiLSTM pipeline for AI prompt content |
| 5 | Response Scanning | `provisional-patent-05-response-scanning.md` | Scanning AI model outputs for PII, secrets, hallucinations, toxicity |

## Before You File

1. **Replace [INVENTOR NAME] in each file** with your full legal name (first, middle, last).
2. **Review each spec** — make sure the technical descriptions match your implementation. If something is described differently than how you built it, note the difference. The spec doesn't need to match exactly, but it should be close enough that a non-provisional filed later can reference it.
3. **Confirm micro entity status.** You qualify as a micro entity if:
   - You have not been named on more than 4 previously filed patent applications
   - Your gross income is less than 150% of the US median household income (~$80K/yr for a single filer, but this may be higher — check current threshold)
   - You have not assigned (transferred) the invention to a non-micro entity
   - If any of these don't apply, you're a "small entity" ($150 per application instead of $65)

## How to File

### Option A: Online via Patent Center (Recommended)

1. Go to https://patentscenter.uspto.gov
2. Create an account if you don't have one (free)
3. Select "File a new application"
4. Select application type: **Provisional**
5. Enter inventor name(s), entity status (Micro Entity), and title
6. Upload the specification as a PDF
7. Pay the fee ($65 per application for micro entity)
8. You'll receive a filing receipt with your application number and priority date

### Option B: File by Mail

Download the forms from uspto.gov, fill them out, and mail to:
```
Commissioner for Patents
P.O. Box 1450
Alexandria, VA 22313-1450
```
(Not recommended — slower and no instant confirmation)

## Filing Strategy

### Recommended: File All 5 on the Same Day

File all 5 provisional applications on the same day. This:
- Establishes the same priority date for all 5 inventions
- Simplifies tracking (all expire on the same date — 12 months from filing)
- Allows you to reference cross-related applications

### Cross-Referencing

When you eventually file non-provisional applications, you can claim priority from these provisionals. You may also be able to file a single non-provisional that combines multiple provisionals if the inventions are related (e.g., the 3-layer detection pipeline and multi-protocol interception could potentially be combined).

## After Filing

### What You Get
- **Application number** for each filing (e.g., 63/XXX,XXX)
- **Priority date** = the filing date
- **"Patent Pending" status** — you can use this phrase immediately after filing

### What You Can Do Now
1. **Say "patent pending"** in marketing materials, LinkedIn posts, website
2. **Talk publicly** about the inventions without losing patent rights
3. **Recruit design partners** with the confidence that your IP is protected
4. **Approach investors** with IP protection in place

### What You Must Do Within 12 Months
1. **Decide whether to file non-provisional applications** for any/all of the 5 inventions
2. **If yes:** File non-provisional within 12 months of the provisional filing date. The non-provisional claims priority from the provisional. Cost: $300 (micro entity) + attorney fees ($5-15K) if you use one.
3. **If no:** The provisional expires. You lose priority but the published provisional creates prior art that prevents competitors from patenting the same thing.

### Strategic Decision Framework (12-Month Window)

By month 9 of the 12-month window, you should decide for each invention:

| Situation | Decision |
|-----------|----------|
| Invention is core to your product, competitors are entering the space | File non-provisional |
| Invention is valuable but no competitor is close | File non-provisional (defensive) |
| Invention is minor, unlikely to be independently invented | Let provisional expire (prior art) |
| Invention has been publicly disclosed and competitors can't patent it | Let provisional expire (prior art) |
| You've raised funding and can afford attorney fees | File non-provisional for all 5 |

## Cost Summary

| Item | Cost | When |
|------|------|------|
| 5 provisional applications (micro entity) | $325 | Now |
| Non-provisional applications (if you file all 5) | $300 × 5 = $1,500 + attorney fees | Within 12 months |
| Total if you file all 5 non-provisionals with attorney | ~$50K | Within 12 months |
| Total if you file non-provisionals self-filed | ~$1,825 | Within 12 months |

**Note on attorney fees:** You CAN file non-provisionals yourself (pro se). The USPTO does not require an attorney. However, patent claims are legally complex and a poorly written claim may be unenforceable. For the non-provisional stage, an attorney is recommended but not required. By then (12 months from now), you may have revenue or funding to afford it.

## Important Notes

1. **Provisionals are never examined.** The USPTO will not review your provisional for patentability. It's simply filed and stored. This means the quality of your provisional spec only matters when you file a non-provisional that claims priority from it.

2. **The provisional spec must enable the invention.** The description must be detailed enough that "one skilled in the art" could reproduce the invention. If it's too vague, the non-provisional may not get the benefit of the provisional's priority date.

3. **You can't add new matter in a non-provisional.** The non-provisional can only claim priority for what was described in the provisional. If you invent something new after filing the provisional, you need another provisional or a continuation application.

4. **Public disclosure after filing is safe.** Once the provisional is filed, you can talk about, demo, sell, or publish the invention without losing patent rights. The filing date is your priority date.

5. **Keep your filing receipts.** You'll need the application numbers and filing dates when you file non-provisionals.