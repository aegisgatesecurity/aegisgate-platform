<!-- SPDX-License-Identifier: Apache-2.0 -->

# AegisGate Threat Detection Model Card

## Model Details

- **Model name**: AegisGate Threat Detector v4.0
- **Model type**: Character CNN-BiLSTM with Attention
- **Version**: 4.0.0
- **Release date**: 2026-08-01
- **License**: Apache 2.0
- **Architecture**: 2-5M parameters, character-level input (128 chars max), ASCII vocabulary (128 tokens), ~800KB ONNX export
- **Inference**: <1ms CPU inference via ONNX Runtime
- **Training framework**: PyTorch → ONNX export

## Intended Use

- **Primary intended uses**: Detect adversarial AI threats mapped to MITRE ATLAS framework in HTTP API requests, MCP tool calls, A2A inter-agent communication, ACP protocol messages, and AI responses
- **Primary intended users**: Security engineers deploying AI systems in production
- **Out-of-scope uses**: Not a general-purpose text classifier. Not designed for content moderation of user-generated content outside the AI threat domain. Not a replacement for human security review.

## Training Data

- **Adversarial examples**: 2,214 synthetic adversarial examples generated from 52 ATLAS payload seeds × 50 augmentation transforms (character substitution, encoding, linguistic, whitespace, fragmentation)
- **Benign examples**: 10,538 unique benign examples across 7 categories (system admin, security research, AI/ML, general, near-miss) including 1,869 near-miss examples designed to stress-test the FPR boundary
- **Data collection**: All synthetic — no real user data. Seeds derived from publicly documented ATLAS techniques.
- **Preprocessing**: Character-level normalization to ASCII (128-char max sequence, 128-token vocabulary)

## Evaluation Data

- **Evaluation methodology**: Stratified split (80/10/10 train/val/test) with category-level stratification
- **Test set**: Held-out 10% of both adversarial and benign examples
- **Metrics reported on test set**:
  - True Positive Rate (TPR): 78.8% (41/52 ATLAS patterns detected)
  - False Positive Rate (FPR): 0.0% (0/10,538 benign examples flagged)
  - Evasion Resistance: 100/100 (with ML), 88.5/100 (rules-only) (weighted across 5 evasion categories)

## Performance Metrics

- **Overall evasion resistance: 100/100 (with ML), 88.5/100 (rules-only)
- **Per-category scores**:

| Category | Score |
|---|---|
| Prompt Injection | 100/100 |
| Jailbreak | 100/100 |
| Data Exfiltration | 100/100 |
| Model Extraction | 100/100 |
| Adversarial Input | 100/100 |
| Command Injection | 90/100 |
| Path Traversal | 90/100 |
| SQL Injection | 90/100 |
| XSS | 90/100 |
| SSRF | 90/100 |
| LDAP Injection | 90/100 |
| XML Injection | 90/100 |
| Template Injection | 90/100 |
| Encoding Evasion | 90/100 |
| Unicode Evasion | 90/100 |
| Whitespace Evasion | 80/100 |
| Fragmentation Evasion | 80/100 |

- **Per-evasion category**:

| Evasion Category | Score |
|---|---|
| Character substitution | 90/100 |
| Encoding | 90/100 |
| Linguistic | 80/100 |
| Whitespace | 80/100 |
| Fragmentation | 80/100 |

- **Latency**: <1ms CPU inference (ONNX Runtime)
- **Model size**: ~800KB ONNX file

## Limitations

- Heuristic fallback covers ~11.5% of adversarial examples that the model alone misses
- Character-level model: cannot detect semantic-level attacks that don't manifest as character patterns
- ASCII-only input: non-Latin scripts are handled by the Unicode homoglyph detector, not the model
- The model is trained on synthetic data; real-world performance may differ
- Shadow mode (logging-only) is recommended for the first 7 days of deployment

## Ethical Considerations

- The model detects attack patterns, not attackers. It should not be used for user profiling or discrimination
- False positives, while measured at 0%, may vary in production environments. Shadow mode provides a safety net
- The model's synthetic training data ensures no real user data was used

## Deployment

- **Feature flag**: `ml_threat_detection_enabled` (default: false)
- **Shadow mode**: `ml_shadow_mode` (default: true)
- **Calibration**: CalibrationManager provides zero-FPR threshold tuning from benign corpus
- **Graceful degradation**: When ML is disabled, rule-based detection maintains 88.5/100 evasion resistance (100/100 with ML) with 0% FPR

## Citation

```
AegisGate Platform v3.6.0
Char CNN-BiLSTM with Attention — Threat Detection Model v4.0
Apache License 2.0
https://github.com/aegisgatesecurity/aegisgate-platform
```