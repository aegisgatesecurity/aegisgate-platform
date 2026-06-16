// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - JCS / RFC 8785 Canonicalization (v3.5.0+, Tier 5 prep)
//
// canonical.go implements the JSON Canonicalization Scheme (JCS)
// from RFC 8785 in ~200 LOC, with NO external dependencies.
//
// The AegisGate envelope convention is that all string values in
// the signed payload are ASCII-only and already NFC-normalized
// at the application layer. This simplifies the canonicalizer by
// removing the Unicode normalization step from JCS.
//
// The canonicalizer is validated against the RFC 8785 test
// vectors (Appendix A) in canonical_test.go.
//
// Frozen 2026-06-15d (Council of Mine 8/8 unanimous Devil's
// Advocate on the "no vendored JCS" decision).

package attestation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
)

// canonicalMarshal is the entry point for JCS canonicalization.
// It takes any Go value (struct, map, slice, primitive),
// marshals it via the stdlib json package, then re-marshals
// the result with sorted keys, no whitespace, and (per the
// AegisGate convention) no Unicode normalization.
//
// Returns the canonical byte slice, or an error if the input
// contains a value that cannot be JSON-marshaled.
func canonicalMarshal(v interface{}) ([]byte, error) { // Step 1: Stdlib JSON marshaling.
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("attestation: canonicalMarshal: json.Marshal: %w", err)
	}

	// Step 2: Unmarshal to interface{} to get a generic JSON tree.
	// This is what makes key sorting work — Go's struct tags
	// would otherwise preserve field declaration order.
	var generic interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("attestation: canonicalMarshal: json.Unmarshal: %w", err)
	}

	// Step 3: Recursive walk, producing canonical bytes.
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, fmt.Errorf("attestation: canonicalMarshal: %w", err)
	}
	return buf.Bytes(), nil
}

// CanonicalizeJSON is the public wrapper around canonicalMarshal.
// It takes already-JSON-encoded bytes (the output of encoding/json),
// unmarshals them, and re-marshals in JCS canonical form. This is
// the entry point for callers who have a JSON byte slice (e.g.,
// from json.Marshal) and want to canonicalize it.
func CanonicalizeJSON(jsonBytes []byte) ([]byte, error) {
	var generic interface{}
	if err := json.Unmarshal(jsonBytes, &generic); err != nil {
		return nil, fmt.Errorf("attestation: CanonicalizeJSON: %w", err)
	}
	return canonicalMarshal(generic)
}

// writeCanonical is the recursive walk. It writes a single
// JSON value to buf in JCS canonical form.
func writeCanonical(buf *bytes.Buffer, v interface{}) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		// Per the AegisGate convention, all strings in the
		// envelope are ASCII-only. Validate and emit.
		if !isASCII(val) {
			return fmt.Errorf("non-ASCII string in canonical form: %q (AegisGate envelope convention requires ASCII-only)", val)
		}
		// Use json.Marshal to handle the JSON string encoding
		// (escapes, quotes). It's guaranteed to produce valid
		// JSON for a Go string.
		encoded, err := json.Marshal(val)
		if err != nil {
			return fmt.Errorf("string encode: %w", err)
		}
		buf.Write(encoded)
	case float64:
		// Per ES6 / RFC 8785, numbers are formatted as:
		//   - Integers: no decimal point ("42" not "42.0")
		//   - Floats: shortest representation that round-trips
		//   - No leading zeros except for "0" or "0."
		//   - No trailing zeros after the decimal
		//   - NaN, Infinity, -Infinity are NOT valid JSON
		//
		// Go's strconv.FormatFloat with 'g' format is the
		// closest match to ES6. For integers (when 'g' would
		// emit "42" or "42.0"), we explicitly drop the ".0"
		// to match ES6.
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return fmt.Errorf("non-finite number in canonical form: %v", val)
		}
		buf.WriteString(formatNumber(val))
	case map[string]interface{}:
		// Sort keys by Unicode code point (byte-by-byte for ASCII).
		keys := make([]string, 0, len(val))
		for k := range val {
			if !isASCII(k) {
				return fmt.Errorf("non-ASCII key in canonical form: %q (AegisGate envelope convention requires ASCII-only)", k)
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encoded, err := json.Marshal(k)
			if err != nil {
				return fmt.Errorf("key encode: %w", err)
			}
			buf.Write(encoded)
			buf.WriteByte(':')
			if err := writeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		return fmt.Errorf("unsupported type: %T", v)
	}
	return nil
}

// formatNumber formats a float64 per ES6 / RFC 8785 spec.
// Integer values are emitted without a decimal point; floats
// use the shortest representation that round-trips.
//
// ES6 Number.prototype.toString() rules:
//   - Integers: no decimal point ("42" not "42.0")
//   - Floats with absolute value in [1e-6, 1e21): decimal form
//   - Floats outside that range: scientific notation
//   - Negative zero: emits "0" (per RFC 8785)
//
// Go's strconv.FormatFloat:
//   - 'f' format: decimal form, no exponent
//   - 'e' format: scientific form, always
//
// We use 'f' for "normal" floats and 'e' for extreme values
// to match ES6.
func formatNumber(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		// Caller should reject these; defensive return.
		return "null"
	}
	// Integers: no decimal point.
	if f == math.Trunc(f) && f >= math.MinInt64 && f <= math.MaxInt64 {
		return strconv.FormatInt(int64(f), 10)
	}
	// Negative zero normalizes to "0" (per RFC 8785).
	if f == 0 {
		return "0"
	}
	abs := math.Abs(f)
	// Use decimal form for "normal" floats, scientific otherwise.
	if abs >= 1e-6 && abs < 1e21 {
		// 'f' with -1 precision gives the shortest decimal
		// representation that round-trips.
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	// Scientific form for extreme values.
	return strconv.FormatFloat(f, 'e', -1, 64)
}

// isASCII reports whether s contains only ASCII characters
// (codepoints 0-127). The AegisGate envelope convention is
// that all strings in the signed payload are ASCII-only;
// this is enforced at canonicalization time.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
