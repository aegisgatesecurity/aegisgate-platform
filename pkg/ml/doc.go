// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Threat Detection
// =========================================================================
//
// Package ml provides neural network-based threat detection as a supplementary
// layer behind the regex pre-filter. The ML detector catches the ~11.5% of
// attacks that evade deterministic pattern matching (transposition, vowel
// deletion, word reversal).
//
// Architecture: Char CNN-BiLSTM with Attention
// - Character-level input (no tokenizer needed)
// - 2-5M parameters, ~800KB ONNX export
// - <1ms CPU inference via onnxruntime-go
// - Apache 2.0, fully vendored, no external deps
//
// Design Principles:
// 1. ML is SUPPLEMENTARY — it never overrides regex detections
// 2. ML only runs when regex doesn't trigger (catches the gaps)
// 3. Threshold calibrated for 0% FPR on benign traffic
// 4. Shadow-mode deployment: log predictions before enabling blocking
// 5. Feature-flag toggle for instant rollback
//
// =========================================================================

package ml
