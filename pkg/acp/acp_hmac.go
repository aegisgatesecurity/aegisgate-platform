// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ACP HMAC Message Integrity
// =========================================================================

package acp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// HMACVerifier provides message integrity verification for ACP messages
type HMACVerifier struct {
	secretKey          []byte
	timestampTolerance time.Duration
}

// NewHMACVerifier creates a new HMAC verifier
func NewHMACVerifier(secret string) *HMACVerifier {
	return &HMACVerifier{
		secretKey:          []byte(secret),
		timestampTolerance: 5 * time.Minute,
	}
}

// VerifyMessageSignature verifies the HMAC signature of an ACP message
func (hv *HMACVerifier) VerifyMessageSignature(timestamp int64, payload []byte, signature string) error {
	// Check timestamp freshness
	msgTime := time.Unix(timestamp, 0)
	if time.Since(msgTime) > hv.timestampTolerance {
		return ErrTokenExpired
	}

	// Compute expected signature
	mac := hmac.New(sha256.New, hv.secretKey)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(payload)

	expectedSig := hex.EncodeToString(mac.Sum(nil))

	// Compare signatures (constant time)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return ErrHMACVerification
	}

	return nil
}

// SignMessage creates an HMAC signature for an ACP message
func (hv *HMACVerifier) SignMessage(payload []byte) (timestamp int64, signature string) {
	timestamp = time.Now().Unix()

	mac := hmac.New(sha256.New, hv.secretKey)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(payload)

	signature = hex.EncodeToString(mac.Sum(nil))
	return
}

// ParseHMACHeader parses an ACP HMAC header
// Format: t=<timestamp>,v1=<signature>
func ParseHMACHeader(header string) (timestamp int64, signature string, err error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, "", fmt.Errorf("empty header")
	}

	var tStr, sigStr string

	// Try fmt.Sscanf first
	n, _ := fmt.Sscanf(header, "t=%d,v1=%s", &tStr, &sigStr)
	if n == 2 {
		timestamp, _ = strconv.ParseInt(tStr, 10, 64)
		signature = sigStr
		return
	}

	// Manual parsing
	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.Split(strings.TrimSpace(part), "=")
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestamp, err = strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				return 0, "", fmt.Errorf("invalid timestamp: %w", err)
			}
		case "v1":
			signature = kv[1]
		}
	}

	if timestamp == 0 {
		return 0, "", fmt.Errorf("timestamp not found or invalid")
	}
	if signature == "" {
		return 0, "", fmt.Errorf("signature not found")
	}

	return
}

// VerifyHeader verifies HMAC from a parsed header
func (hv *HMACVerifier) VerifyHeader(header string, payload []byte) error {
	timestamp, signature, err := ParseHMACHeader(header)
	if err != nil {
		return err
	}

	return hv.VerifyMessageSignature(timestamp, payload, signature)
}
