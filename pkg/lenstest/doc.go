// SPDX-License-Identifier: Apache-2.0
// Package lenstest provides test infrastructure for the AegisGate
// Platform's Lens integration.
//
// ⚠️ v0.2.0 A15 CLEANUP (2026-07-19):
//
// This package was redesigned following the Lens v0.2.0 release.
// The previous contents (detector/ subprocess, goside/ cross-validation,
// equivalence.go, and the full corpus/) were designed for Lens v0.1.0
// which had a standalone Node.js detector. Lens v0.2.0 is a Chrome
// MV3 extension with no standalone Node.js entry point.
//
// The correct integration contract is:
//
//	Lens v0.2.0 ──(4 fields over HTTPS)──► pkg/lensbackend/ ──► pkg/ioc/
//
// The privacy boundary test (formerly corpus/privacy_test.go) has been
// moved to pkg/lensbackend/privacy_boundary_test.go where it validates
// the same 9-field schema contract that the Lens extension must obey.
// This test is self-contained (no external dependencies) and runs in
// normal CI.
//
// What was deleted:
//   - pkg/lenstest/detector/  — Node.js subprocess wrapper for /tmp/detect.js
//   - pkg/lenstest/goside/    — Go-side cross-validation (redundant without JS)
//   - pkg/lenstest/equivalence.go — Go↔JS pattern name mapping (no JS target)
//   - pkg/lenstest/corpus/    — Full corpus (8 gated tests, gen files, data)
//   - pkg/lenstest/types.go   — CanonicalEntry (unused after corpus removal)
//   - pkg/lenstest/testdata/  — 290MB WildChat parquet file
//   - tools/build-lens-extension/ — v0.1.0 build tool (Lens has its own)
//
// What remains:
//   - pkg/lensbackend/          — Production HTTP backend (12/12 tests pass)
//   - pkg/lensbackend/privacy_boundary_test.go — Privacy invariants test
//   - pkg/ioc/                  — Shared IOC store
//   - cmd/lensbackend/          — Standalone pen-test binary
//   - tools/port-detections/    — Platform→Lens code generator
//   - tools/test-extension/     — Headless Chromium harness (separate module)
//
// Design principle: Lens tests Lens. Platform tests Platform. The contract
// between them is the 4-field schema, validated by TestPrivacyBoundary_NoLeak.
package lenstest