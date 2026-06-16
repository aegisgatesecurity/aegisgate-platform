// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 5)
// =========================================================================
//
// reputation_math.go is a tiny shim that wraps math.Pow in a
// file separate from reputation.go. The reason for the split
// is that reputation.go is mostly API surface and the math
// helper is an implementation detail; keeping them separate
// makes the public API of the reputation package easier to
// scan.
//
// v3.5.0+ Track 6 Task 5.
// =========================================================================

package ioc

import "math"

// pow2Impl returns 2^x. It is a thin wrapper around math.Pow
// so the implementation can be swapped (e.g., for a faster
// intrinsic) without touching the public API.
func pow2Impl(x float64) float64 {
	return math.Pow(2, x)
}
