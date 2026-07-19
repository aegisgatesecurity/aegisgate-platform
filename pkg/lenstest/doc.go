// SPDX-License-Identifier: Apache-2.0
// Package lenstest provides the Phase 4 test corpus and harness
// for the AegisGate Lens detector.
//
// ⚠️ v0.2.0 A15 DEPRECATION NOTICE (2026-07-19):
//
// This package was designed for Lens v0.1.0 (plain-JS pivot), which
// had a standalone Node.js entry point for the detector. Lens v0.2.0
// runs as a Chrome MV3 service worker with a different architecture,
// different pattern names, and no standalone detect.js script.
//
// The corpus tests (pkg/lenstest/corpus/) are gated behind a
// //go:build manual tag and will not run in normal CI until the
// harness is rebuilt for v0.2.0. The detector/ package still compiles
// but will fail at runtime (MODULE_NOT_FOUND) because /tmp/detect.js
// no longer exists.
//
// The goside/ package (Go-side detector for cross-validation) is
// still valid and passes, but its pattern names need updating to
// match v0.2.0's 4 detection facets.
//
// The lensbackend/ package (HTTP telemetry backend) is NOT affected
// by this deprecation — it already uses the v0.2.0 schema with
// lens_event_version: 1.
//
// Plan: rebuild the test harness for v0.2.0's architecture, then
// remove the //go:build manual tags.
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
