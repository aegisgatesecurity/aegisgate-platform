// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Safe Integer Conversions
// =========================================================================
//
// Provides bounds-checked conversions for int → int32 and int64 → byte.
// Eliminates CodeQL G115 (integer overflow) false positives by making
// the overflow check explicit.
//
// =========================================================================

package safecast

import "math"

// Int32 converts an int to int32, clamping to [math.MinInt32, math.MaxInt32].
// Returns 0 for negative values that would overflow, and MaxInt32 for
// positive values that would overflow.
func Int32(v int) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	if v < math.MinInt32 {
		return math.MinInt32
	}
	return int32(v)
}

// Byte converts an int64 to byte, clamping to [0, 255].
// Values outside this range are clamped to the nearest valid byte.
func Byte(v int64) byte {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return byte(v)
}
