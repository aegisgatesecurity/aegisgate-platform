<!-- SPDX-License-Identifier: Apache-2.0 -->
# ML Detection Withdrawn (2026-11-23)

**Status: ALL neural ML detection in this repository is WITHDRAWN and hard-disabled.**

Effective 2026-11-23, every learned model shipped in or alongside this repository is withdrawn:

- The CharCNN-BiLSTM "threat detector" (v9/v11/v12/v15/v22b lineage, sha256 `948b6500…`).
- The DeBERTa and RoBERTa transformer detectors (L3-A lineage).
- The hybrid / meta-classifier artifacts derived from the same training data.

**Why.** A full audit of the training corpus (see internal report `corpus-certification-2026-11-23`) found that the attack-side labels are not trustworthy: 109 of 154 adjudicated attack-labeled samples flip to benign (~71%), benign-side flip rate is ~0.6%. All headline detection metrics (including every "XX% catch rate", "0% FPR", "99.8", "98.99%", "100% ML detection" figure in our docs) were measured against this compromised data and are **void**. They describe nothing real and must not be quoted, repeated, or relied upon.

**What still works.** All deterministic layers (regex/signature, scanner rules, policy engine, MCP screening, rate limiting, etc.) are unaffected — they contain no learned components and no training data. Only the neural L3 path is withdrawn.

**Current behavior.** The ML path is hard-disabled in code: `NewThreatDetector` forces `Enabled=false`/`ShadowMode=false`, and `LoadModel` / `LoadModelDeBERTa` / `LoadModelRoBERTa` refuse to load any model. Distributions shipped before this notice may still contain inert model files; they cannot be enabled at runtime.

**Reinstatement.** ML will return only after (1) a full corpus re-audit and scoped rebuild, (2) a re-frozen ruler, (3) retraining, and (4) re-baselined metrics published from that new ruler. Until then: no ML detection claims, in any document, in this repository or externally.

Historical reports and changelogs are retained as historical record and are **not** to be cited as current capability.
