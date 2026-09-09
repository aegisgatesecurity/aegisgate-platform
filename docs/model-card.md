<!-- SPDX-License-Identifier: Apache-2.0 -->

# AegisGate Threat Detection Model Card

## Model Details

- **Model name**: AegisGate Threat Detector v11b
- **Model type**: Character CNN-BiLSTM with Attention
- **Version**: 11b (char-cnn-bilstm-v11b)
- **Release date**: 2026-09-09
- **License**: Apache 2.0
- **Architecture**: 1,596,034 parameters, character-level input (256 chars max), Latin-1 vocabulary (256 tokens), ~6.1MB ONNX export (float32), ~3.75MB JSON weights (float16, gzip+base64 for Lens)
- **Inference**: <1ms CPU inference via ONNX Runtime (Go), pure JS inference in browser (~5-50ms Chrome V8)
- **Training framework**: PyTorch → ONNX export (opset 18)

## Intended Use

- **Primary intended uses**: Detect adversarial AI threats mapped to MITRE ATLAS framework in HTTP API requests, MCP tool calls, A2A inter-agent communication, ACP protocol messages, and AI responses
- **Primary intended users**: Security engineers deploying AI systems in production
- **Out-of-scope uses**: Not a general-purpose text classifier. Not designed for content moderation of user-generated content outside the AI threat domain. Not a replacement for human security review.

## Training Data

- **Adversarial examples**: 52 ATLAS payload seeds × 50 augmentation transforms (character substitution, encoding, linguistic, whitespace, fragmentation) plus prompt injection datasets, jailbreak collections, and data leakage synthetic examples
- **Benign examples**: 7 categories (system admin, security research, AI/ML, general, near-miss, benign evasion-transformed, data leakage benign) including near-miss examples designed to stress-test the FPR boundary
- **Total corpus**: 70,572 samples (train: 56,457, val: 7,057, test: 7,058)
- **Data sources**: Alpaca (cleaned), AGNews, Dolly-15k, OpenOrca, TruthfulQA, HH-RLHF (red team), ToxiGen, WikiText, security education, synthetic ATLAS augmentations, synthetic data leakage, prompt injection collections
- **Data collection**: All synthetic or publicly available datasets — no real user data. Seeds derived from publicly documented ATLAS techniques.
- **Preprocessing**: Character-level normalization to Latin-1 (256-char max sequence, 256-token vocabulary, PAD=0, UNK=1)

## Evaluation Data

- **Evaluation methodology**: Stratified split (80/10/10 train/val/test) with category-level stratification
- **Test set**: Held-out 10% of both adversarial and benign examples
- **Metrics reported on test set**:
  - Test Accuracy: 98.27%
  - Test Precision: 97.71%
  - Test Recall: 94.49%
  - Test F1: 96.07%
  - True Positive Rate (TPR): 94.49% (1,492/1,579 adversarial patterns detected)
  - False Positive Rate (FPR): 0.64% (35/5,479 benign examples flagged)
  - Confusion Matrix: TP=1492, FP=35, FN=87, TN=5444

### Evasion Suite Results

- **Evasion test suite**: 2,600 tests (52 ATLAS payloads × 50 transforms)
- **Layered detection score (L1+L2+L3)**: 99.8/100 (0 in-scope misses)
- **L3 (ML) standalone**: Catches adversarial paraphrasing that regex layers miss
- **Heuristic fallback**: Covers obfuscated/l33tspeak variants that the model alone misses

## Performance Metrics

- **Latency**: <1ms CPU inference (ONNX Runtime), ~5-50ms pure JS (Chrome V8 estimated)
- **Model size**: ~6.1MB ONNX file (float32), ~3.75MB JSON weights (float16, gzip+base64 for Lens)
- **Weight quantization**: float16 for Lens (max error ~0.0002), float32 for Platform/Rampart
- **SHA-256 (ONNX, float32)**: `8e13c793c32816aa0f6e2af13ffadd4f38f707b4ac8906b56ddfa77da51ea8e5`
- **SHA-256 (Lens JS weights, float16)**: `c09eef58c79928bb6ff19bcd155da34ee1809c0ff0165d1afd6b049b400615d7`

## Limitations

- Heuristic fallback covers adversarial examples that the model alone misses (obfuscated/l33tspeak variants)
- Character-level model: cannot detect semantic-level attacks that don't manifest as character patterns
- Latin-1 vocabulary: non-Latin scripts (CJK, Arabic, Cyrillic) are mapped to UNK and handled by the Unicode homoglyph detector, not the model
- The model is trained on synthetic and public data; real-world performance may differ
- Shadow mode (logging-only) is recommended for the first 7 days of deployment

## Ethical Considerations

- The model detects attack patterns, not attackers. It should not be used for user profiling or discrimination
- False positives (0.64% on test set) may vary in production environments. Shadow mode provides a safety net
- The model's training data ensures no real user data was used
- Calibration manager provides zero-FPR threshold tuning from benign corpus

## Deployment

- **Feature flag**: `ml_threat_detection_enabled` (default: false)
- **Shadow mode**: `ml_shadow_mode` (default: true)
- **Threshold**: 0.50 (calibrated: 100% PI TPR, 97.5% exfil TPR, 0% FPR on benign corpus)
- **Calibration**: CalibrationManager provides zero-FPR threshold tuning from benign corpus
- **Graceful degradation**: When ML is disabled or ONNX runtime unavailable, heuristic detection maintains coverage with 0% FPR
- **A/B testing**: Built-in A/B testing framework for comparing model variants in production

## Version History

| Version | Date | Key Changes | SHA-256 |
|---------|------|-------------|---------|
| v9 | 2026-09-08 | Initial ATLAS-focused training, 66K samples | `0076b66d...` |
| v11 | 2026-09-09 | Expanded corpus to 70K, added evasion augmentation | `32b7db74...` |
| **v11b** | **2026-09-09** | **Final calibration, 99.8/100 evasion score** | **`8e13c793...`** |

## Citation

```
AegisGate Platform v4.4.1
Char CNN-BiLSTM with Attention — Threat Detection Model v11b
Apache License 2.0
https://github.com/aegisgatesecurity/aegisgate-platform
```