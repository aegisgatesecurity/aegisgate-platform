# AegisGate v4.0 ML/AI Planning Document

## Architecture Decision: Char CNN-BiLSTM with Attention

### Model Specification
- **Architecture**: Character-level CNN-BiLSTM with Attention
- **Parameters**: 2-5M
- **Disk size**: ~800KB (ONNX format)
- **Inference**: <1ms on CPU
- **License**: Apache 2.0, fully vendored, no external deps
- **Export**: PyTorch → ONNX → `onnxruntime-go`

### Architecture Detail
```
Input: raw bytes (max 128 chars, zero-padded)
  ↓
Embedding(128 chars → 64 dim)
  ↓
Conv1D(filters=256, kernel_sizes=[3,5,7], parallel branches)
  ↓
Concatenate conv outputs
  ↓
BiLSTM(128 hidden, bidirectional)
  ↓
Attention mechanism (learned weights)
  ↓
Dense(64, ReLU) → Dropout(0.3)
  ↓
Dense(1, Sigmoid) → threat_score [0,1]
```

### Runtime: ONNX Runtime
- Go binding: `onnxruntime-go`
- Load: single `.onnx` file at proxy startup
- No Python runtime in production
- Feature-flag toggle for instant rollback

### Integration Point
- ML detector runs as **supplementary layer** behind regex pre-filter
- Only runs when regex doesn't trigger (catches the ~11.5% regex misses)
- Never overrides regex — only adds detections
- Threshold calibrated for 0% FPR on benign traffic

---

## Data Pipeline

### Phase 1: Deterministic Augmentation (DONE — 2,600 examples)
- 52 ATLAS payloads × 50 evasion transforms = 2,600 labeled adversarial examples
- Each labeled with: technique ID, evasion category, original text, evaded text

### Phase 2: Paraphrase Augmentation (~2,600 additional)
- Use LLM API (one-time) to generate 5 paraphrases per ATLAS payload
- Cost: ~$5-10 total
- Store in: `pkg/ml/training/paraphrases.jsonl`

### Phase 3: Public Dataset Integration (~2,400 additional)
- HarmBench (400+ MIT)
- JailbreakBench (1,400+ MIT)
- PromptInject (600+ MIT)
- AdvGLUE (800+ Apache 2.0)
- Store in: `pkg/ml/training/external/`

### Phase 4: Benign Calibration Corpus (50K+)
- Curated from RealToxicityPrompts (10K benign subset)
- Curated from ToxiGen (5K benign subset)
- Lens benign corpus (79 entries)
- Synthetic benign prompts (generated, no API needed)
- Store in: `pkg/ml/training/benign.jsonl`

### Total Target: ~30K+ labeled examples

---

## Calibration Strategy

### Step 1: Build Calibration Dataset
- 10K benign examples from corpus
- Run through all 14 normalization variants
- Record max benign score per detection layer

### Step 2: Find Zero-FPR Threshold
- Sort benign scores descending
- Set threshold = max_benign_score + margin (0.05)
- Any detection above threshold = guaranteed non-FP on calibration data

### Step 3: Shadow-Mode Validation
- Deploy model in shadow mode (log only, don't block)
- Run 7 days on production-like traffic
- Verify zero-FPR threshold holds on real traffic
- Only then enable blocking

### Step 4: Dynamic Threshold Adjustment
- `CalibrationManager` in `pkg/ml/calibration.go`
- Stores calibrated threshold (default: 0.7)
- `IsAboveThreshold(score) bool` checks against calibrated value
- Logs all predictions with scores for shadow analysis
- Supports dynamic adjustment without restart

---

## Cold-Start Deployment Checklist

- [ ] Model shipped DISABLED by default (feature flag `ml_detection_enabled: false`)
- [ ] Shadow-mode logging only (feature flag `ml_shadow_mode: true`)
- [ ] 7-day shadow validation period before enabling
- [ ] FPR < 0.01% on calibration dataset verified
- [ ] Instant rollback mechanism (feature flag toggle)
- [ ] Model card with SHA256 hash, training date, metrics
- [ ] ONNX file vendored in `pkg/ml/models/threat_cnn_bilstm.onnx`