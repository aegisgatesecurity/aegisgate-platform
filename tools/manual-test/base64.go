// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Manual Test Tool: Base64 Helper
// =========================================================================
//
// base64.go provides base64 decoding for the CDP screenshot
// data. CDP returns screenshots as base64-encoded PNGs in the
// Page.captureScreenshot response. We decode them with stdlib's
// encoding/base64.
//
// We use stdlib only; no third-party deps.
// =========================================================================

package main

import (
	"encoding/base64"
)

// base64Decode decodes a base64-encoded string to bytes.
func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
