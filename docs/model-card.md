<!-- SPDX-License-Identifier: Apache-2.0 -->

# AegisGate Threat Detection Model Card

## Model Details

- **Model name**: AegisGate Threat Detector v9
- **Model type**: Character CNN-BiLSTM with Attention
- **Version**: 9.0.0
- **Release date**: 2026-09-08
- **License**: Apache 2.0
- **Architecture**: 1.6M parameters, character-level input (256 chars max), Latin-1 vocabulary (256 tokens), ~6.4MB ONNX export
- **Inference**: <1ms CPU inference via ONNX Runtime (Go), pure JS inference in browser (~5-50ms Chrome V8)
- **Training framework**: PyTorch → ONNX export (opset 18)

## Intended Use

- **Primary intended uses**: Detect adversarial AI threats mapped to MITRE ATLAS framework in HTTP API requests, MCP tool calls, A2A inter-agent communication, ACP protocol messages, and AI responses
- **Primary intended users**: Security engineers deploying AI systems in production
- **Out-of-scope uses**: Not a general-purpose text classifier. Not designed for content moderation of user-generated content outside the AI threat domain. Not a replacement for human security review.

## Training Data

- **Adversarial examples**: 52 ATLAS payload seeds × 50 augmentation transforms (character substitution, encoding, linguistic, whitespace, fragmentation)
- **Benign examples**: 7 categories (system admin, security research, AI/ML, general, near-miss) including near-miss examples designed to stress-test the FPR boundary
- **Total corpus**: 66,077 samples (train: 52,861, val: 6,607, test: 6,609)
- **Data collection**: All synthetic — no real user data. Seeds derived from publicly documented ATLAS techniques.
- **Preprocessing**: Character-level normalization to Latin-1 (256-char max sequence, 256-token vocabulary, PAD=0, UNK=1)

## Evaluation Data

- **Evaluation methodology**: Stratified split (80/10/10 train/val/test) with category-level stratification
- **Test set**: Held-out 10% of both adversarial and benign examples
- **Metrics reported on test set**:
  - Test Accuracy: 98.2%
  - Test Precision: 97.1%
  - Test Recall: 93.9%
  - Test F1: 95.5%
  - True Positive Rate (TPR): 93.9% (1,226/1,305 adversarial patterns detected)
  - False Positive Rate (FPR): 0.7% (37/5,304 benign examples flagged)
  - Confusion Matrix: TP=1226, FP=37, FN=79, TN=5267

## Performance Metrics

- **Latency**: <1ms CPU inference (ONNX Runtime), ~5-50ms pure JS (Chrome V8 estimated)
- **Model size**: ~6.4MB ONNX file (float32), ~3.75MB JSON weights (float16, gzip+base64 for Lens)
- **Weight quantization**: float16 for Lens (max error ~0.0002), float32 for Platform/Rampart
- **SHA-256**: `0076b66d069ca445589526624ebeb67b65a1df68d615525b83e528f03e0bd4b7`

## Limitations

- Heuristic fallback covers adversarial examples that the model alone misses (obfuscated/l33tspeak variants)
- Character-level model: cannot detect semantic-level attacks that don't manifest as character patterns
- Latin-1 vocabulary: non-Latin scripts (CJK, Arabic, Cyrillic) are mapped to UNK and handled by the Unicode homoglyph detector, not the model
- The model is trained on synthetic data; real-world performance may differ
- Known false positive: temporal queries ("What time is it in...") may score above threshold; a post-inference temporal query exemption mitigates this
- Shadow mode (logging-only) is recommended for the first 7 days of deployment

## Ethical Considerations

- The model detects attack patterns, not attackers. It should not be used for user profiling or discrimination
- False positives (0.7% on test set) may vary in production environments. Shadow mode provides a safety net
- The model's synthetic training data ensures no real user data was used

## Deployment

- **Feature flag**: `ml_threat_detection_enabled` (default: false)
- **Shadow mode**: `ml_shadow_mode` (default: true)
- **Threshold**: 0.5 (calibrated: 100% PI TPR, 97.5% exfil TPR, 0% FPR on benign corpus)
- **Calibration**: CalibrationManager provides zero-FPR threshold tuning from benign corpus
- **Graceful degradation**: When ML is disabled or ONNX runtime unavailable, heuristic detection maintains coverage with 0% FPR

## Citation

```
AegisGate Platform v4.3.2
Char CNN-BiLSTM with Attention — Threat Detection Model v9
Apache License 2.0
https://github.com/aegisgatesecurity/aegisgate-platform
```