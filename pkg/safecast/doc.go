// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Package safecast provides safe numeric type conversion helpers for
// the AegisGate Security Platform.
//
// Go's native type conversions (e.g., int32(x)) silently truncate or
// wrap on overflow, which can cause security-relevant bugs when
// converting between integer types of different widths. These helpers
// perform bounds checking and return the zero value (or a clamped
// value) when the input is out of range for the target type.
//
// Functions:
//   - Int32: Converts int to int32, returning 0 on overflow
//   - Byte:  Converts int64 to byte, returning 0 on out-of-range
//
// Used primarily in gRPC service handlers where protocol buffer fields
// use fixed-width integers (int32) but the platform's internal logic
// uses Go's native int.
// =========================================================================
package safecast
