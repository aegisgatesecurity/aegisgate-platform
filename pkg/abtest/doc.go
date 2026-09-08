// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Package abtest provides A/B testing for ML model variants in the
// AegisGate Security Platform.
//
// The Service manages tests that compare detection performance across
// multiple model configurations. Each Test contains one or more Variants
// with weighted assignment. Request IDs are deterministically assigned
// to variants via FNV-1a hashing, ensuring consistent routing across
// retries.
//
// Key types:
//   - Service: Manages test lifecycle (create, start, stop, list)
//   - Test: A test definition with variants and status
//   - Variant: A single variant with name, weight, and model reference
//   - VariantMetrics: Per-variant detection and latency metrics
//
// The package is used by the gRPC ABTestService and the HTTP API at
// /api/v1/abtest/tests to support model rollout decisions.
// =========================================================================
package abtest
