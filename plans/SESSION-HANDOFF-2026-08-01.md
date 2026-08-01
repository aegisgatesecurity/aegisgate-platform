# AegisGate Session Handoff — 2026-08-01

## Current State: Evasion Resistance 82.0 → 88.5/100

### Metric Summary

| Metric | Start (7/31) | After Session | Δ |
|--------|-------------|---------------|---|
| **Evasion Resistance** | 82.0 | **88.5** | **+6.5** |
| Character Substitution | 53.8% | **65.0%** | +11.2pp |
| Encoding Evasion | 71.7% | **89.4%** | +17.7pp |
| Whitespace Manipulation | 95.0% | **98.7%** | +3.7pp |
| Linguistic Obfuscation | 95.4% | 95.4% | — |
| Prompt Fragmentation | 93.8% | 93.8% | — |
| Baseline TPR | 98.1% | 98.1% | — |
| ATLAS FPR | 0.0% | **0.0%** | — |
| Benign FPR | 0.0% | **0.0%** | — |

### Key Variant Improvements

| Variant | Start | Now | Δ | Fix Applied |
|---------|-------|-----|---|-------------|
| char_repeat | 34.6% | 82.7% | +48.1pp | NormalizeRepeatingChars + AggressiveRepeatingChars |
| rot13_partial | 30.8% | 71.2% | +40.4pp | NormalizeSlidingROT13 |
| l33t_common | 36.5% | 98.1% | +61.6pp | NormalizeAggressiveL33t |
| url_encode_spaces | 30.8% | 96.2% | +65.4pp | decodeURLEncoding in NormalizeText |
| backslash_escape | 42.3% | 98.1% | +55.8pp | NormalizeBackslashEscapes |
| word_split_newline | 61.5% | 98.1% | +36.6pp | NormalizeNewlineCollapse |
| mixed_encoding | 30.8% | 46.2% | +15.4pp | NormalizeMultiPass |

### Remaining Gaps (Require ML)

| Variant | Rate | Why Can't Fix Deterministically |
|---------|------|--------------------------------|
| char_transpose_adjacent | 3.8% | Needs edit-distance matching against known attack keywords |
| char_delete_vowels | 19.2% | Needs vowel reconstruction + dictionary lookup |
| char_reverse_words | 21.2% | Needs word reversal + dictionary lookup |
| keyboard_walk_shift | 42.3% | Could improve to ~55% with proximity matching |
| mixed_encoding | 46.2% | Needs deeper multi-step decoding |

**Verdict: Deterministic detection is MAXED OUT at 88.5/100.**

---

## Git Commits (This Session)

| Commit | Repo | Description |
|--------|------|-------------|
| `6223df2` | platform | ATLAS pattern gap fixes + normalization |
| `ff50665` | platform | 5 new normalization variants (+4.7 pts) |
| `d423081` | platform | Aggressive repeating + sliding ROT13 (+1.8 pts) |
| `b829762` | source | Sync: normalize.go from platform |
| `493cf86` | source | Sync: aggressive repeating + sliding ROT13 |

---

## Key Files Modified

| File | Lines | Purpose |
|------|-------|---------|
| `pkg/scanner/normalize.go` | ~426 | 10 normalization functions + 7 internal helpers |
| `pkg/scanner/normalize_test.go` | ~567 | 80+ test cases, 6 benchmarks |
| `pkg/compliance/atlas.go` | ~900 | 9 pattern expansions (from prior session) |
| `pkg/proxy/proxy.go` | — | Uses NormalizeAllVariants() for all 14 variants |
| `pkg/proxy/evasion_suite_test.go` | ~1345 | Uses NormalizeAllVariants() in detectAll() |

---

## Normalization Architecture

### NormalizeAllVariants() returns up to 14 variants:
1. Original text (unmodified)
2. NormalizeText (idempotent 5-pass: zero-width → URL decode → insertion removal → l33t → whitespace)
3. NormalizeKeyboardWalk (destructive: QWERTY left-shift)
4. NormalizeROT13 (destructive: full ROT13 decode)
5. NormalizeRepeatingChars (semi-destructive: 3+ identical → 2)
6. NormalizeBackslashEscapes (destructive: strip all `\`)
7. NormalizeAggressiveL33t (destructive: l33t without context checks)
8. NormalizeNewlineCollapse (destructive: strip \n/\r between alphanumerics)
9. NormalizeMultiPass (destructive: URL decode → strip \ → zero-width → insertion → aggressive l33t → repeat collapse → newline collapse → whitespace)
10. NormalizeRepeatingCharsAggressive (destructive: 2+ identical → 1)
11-14. NormalizeSlidingROT13 (up to 5 variants with ROT13 on individual 4+ char runs)

### Design Principle
NormalizeText is IDEMPOTENT (safe for all text). All other variants are DESTRUCTIVE and must only be used as separate scanning variants. The proxy scans all variants and merges findings by pattern name (scanner) / technique ID (ATLAS).

---

## ML/AI v4.x Architecture Decision (APPROVED)

### Model: Custom Char CNN-BiLSTM with Attention
- **2-5M parameters**, ~800KB on disk, <1ms inference on CPU
- Character-level input (no tokenizer needed — sees transpositions, vowel deletions directly)
- Architecture: Embed(128 chars) → Conv1D(filters=256, kernels=[3,5,7]) → BiLSTM(128) → Attention → Dense(64) → Sigmoid
- Apache 2.0, fully vendored in source code, no external deps
- Export format: ONNX (via `onnxruntime-go`)

### Runtime: ONNX Runtime
- `onnxruntime-go` native Go bindings
- Single .onnx file (~800KB) loaded at startup
- No Python runtime in production
- Inference <1ms on CPU

### What User Is NOT Considering (Discussed)
1. **Data flywheel**: Need ~10K adversarial + ~50K benign. Lens corpus has 158 entries. Public datasets (HarmBench, JailbreakBench, PromptInject, AdvGLUE) add ~2,400. Augmentation pipeline needed.
2. **Calibration layer**: Model outputs score 0-1. Need threshold where FPR=0%. Solved via: run 10K benign → find max benign score → set threshold = max + margin. Shadow-mode for 7 days before enabling.
3. **Cold-start deployment**: Ship disabled, log predictions only, enable after 7-day shadow validation.
4. **Model versioning**: ONNX files need SHA256 hashes, version tracking, feature-flag toggle for instant rollback.

### Lens Corpus Assets Available
- `v0.1.1-sxc-corpus.jsonl`: 158 entries (79 adversarial, 79 benign) across ATLAS, OWASP, XSS, PII, secrets
- `FPR-BENCHMARK-2026-07-18.json`: 12K-entry FPR benchmark corpus
- Lens detector patterns: 60+ regex patterns (PII, secrets, XSS, compliance)
- Path: `/home/chaos/Desktop/AegisGate/aegisgate-lens/test/benchmarks/corpus/sxc/`

### Public Datasets for ML Training (Apache 2.0 / MIT)
- HarmBench (400+), JailbreakBench (1,400+), PromptInject (600+), AdvGLUE (800+), RealToxicityPrompts (curate 10K), ToxiGen (curate 5K)

---

## Gotchas & Lessons Learned

1. **Normalization order matters**: Insertion removal must run BEFORE l33t deobfuscation so `1.g.n.0.r.3` → `1gn0r3` → `ignore`. Wrong order = broken.
2. **Destructive vs idempotent is critical**: NormalizeText must be safe for ALL text. Anything that corrupts normal input (keyboard-walk, ROT13, aggressive l33t) MUST be a separate variant.
3. **FPR discipline**: Every new normalization variant was tested against 20 benign inputs × all variants. 0% FPR maintained across 146 checks.
4. **Variant explosion**: NormalizeAllVariants returns up to 14 variants. Each must be scanned independently. Short-circuit on first hit per layer. Latency: 29.3μs for normalization, well under budget.
5. **Context-aware l33t**: The idempotent l33t (NormalizeText) only replaces digits/symbols adjacent to letters. The aggressive variant (NormalizeAggressiveL33t) replaces ALL l33t chars regardless of context. Both are needed — idempotent for safety, aggressive for catching `1gn0r3`.
6. **User burned ML down 3 times**: Previous attempts with wrong models (BERT-large, GPT-based classifiers, general-purpose "is this toxic?" classifiers) failed. The right architecture is a TINY character-level model that only supplements regex, not replaces it.
7. **ML should NOT replace regex**: ML catches the ~11.5% that regex misses (transposition, vowel deletion, word reversal). Regex catches 88.5% at 0% FPR. ML should only run when regex doesn't trigger (supplementary, never primary).

---

## Next Steps (Priority Order)

### Immediate (Ready to Start)
1. **ML data pipeline**: Build augmentation pipeline using existing 52 ATLAS payloads × evasion transforms + public datasets
2. **ML model**: Train Char CNN-BiLSTM on augmented dataset, export to ONNX
3. **Calibration manager**: Implement `pkg/ml/calibration.go` with threshold management and shadow-mode logging

### After ML
4. **Load testing at scale**: 1K-10K RPS benchmark (from Phase 0 roadmap)
5. **SOC 2 evidence packager**: Automated evidence collection (from Phase 0 roadmap)
6. **Executive summary**: 3-page CISO brief (from Phase 0 roadmap)