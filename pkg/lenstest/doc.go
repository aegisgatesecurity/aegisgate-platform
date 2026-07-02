// SPDX-License-Identifier: Apache-2.0
// Package lenstest provides the Phase 4 test corpus and harness
// for the AegisGate Lens detector.
//
// The harness achieves "10x industry standard" rigor by:
//  1. Testing the canonical Go patterns directly (ground truth)
//  2. Testing the JS-detector port (via subprocess to node)
//  3. Cross-validating Go vs JS output (drift detection)
//  4. Measuring TPR, FPR, severity accuracy, per-pattern recall
//
// Layout:
//
//	pkg/lenstest/
//	  corpus/         - labeled test data (attacks, normal usage, per-pattern)
//	  detector/       - detector wrapper for Go (calls JS via subprocess)
//	  adversarial/    - obfuscation, banner-XSS, prototype-pollution tests
//	  privacy/        - network-capture privacy boundary tests
//	  crossprovider/  - cross-provider consistency tests
//	  doc.go          - this file
//
// Plain Go, stdlib only (no testing frameworks beyond stdlib testing).
// Deterministic via seeded RNG.
package lenstest
