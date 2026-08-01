// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Training Data Pipeline
// =========================================================================
//
// Package training provides data generation and augmentation for ML model
// training. It generates labeled examples (adversarial + benign) from ATLAS
// payload seeds using evasion transforms.
//
// The augmentation engine mirrors the transforms in the evasion suite test
// so training data matches production attack vectors.
//
// Architecture Decision: Char CNN-BiLSTM with Attention
// - Character-level input (no tokenizer needed)
// - 2-5M parameters, ~800KB ONNX
// - <1ms CPU inference via onnxruntime-go
// - Apache 2.0, fully vendored, no external deps
//
// =========================================================================

package training
