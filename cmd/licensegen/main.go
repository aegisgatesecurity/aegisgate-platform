// SPDX-License-Identifier: Apache-2.0
// Package main implements the AegisGate license key generation CLI.
//
// Usage:
//
//	licensegen generate \
//	  --customer "Acme Corp" \
//	  --tier enterprise \
//	  --duration 365d \
//	  --key secrets/aegisgate-private.pem \
//	  --output license.key
//
// The generated license key is a base64-encoded JSON structure containing
// the license payload and an ECDSA P-256 signature. The AegisGate platform
// validates licenses using the embedded public key (pkg/license/keys.go).
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

var (
	flagCustomer   = flag.String("customer", "", "Customer name or identifier (required)")
	flagTier       = flag.String("tier", "professional", "License tier: community, developer, professional, enterprise")
	flagDuration   = flag.String("duration", "365d", "License duration (e.g., 30d, 365d, never)")
	flagKey        = flag.String("key", "", "Path to ECDSA P-256 private key PEM file (required)")
	flagOutput     = flag.String("output", "", "Output file path (default: stdout)")
	flagFeatures   = flag.String("features", "", "Comma-separated feature overrides (optional)")
	flagMaxServers = flag.Int("max-servers", 0, "Maximum servers (0 = unlimited)")
	flagMaxUsers   = flag.Int("max-users", 0, "Maximum users (0 = unlimited)")
	flagQuiet      = flag.Bool("quiet", false, "Suppress informational output")
	flagDev        = flag.Bool("dev", false, "Development mode: skip key pair verification (allows test keys)")
)

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Validate required flags
	if *flagCustomer == "" {
		return fmt.Errorf("--customer is required")
	}
	if *flagKey == "" {
		return fmt.Errorf("--key is required (path to ECDSA P-256 private key PEM)")
	}

	// Parse tier
	licenseTier, err := tier.ParseTier(*flagTier)
	if err != nil {
		return fmt.Errorf("invalid tier %q: %w", *flagTier, err)
	}

	// Parse duration
	duration, err := parseDuration(*flagDuration)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", *flagDuration, err)
	}

	// Load private key
	privateKey, err := loadPrivateKey(*flagKey)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Verify the key matches our embedded public key (skip in --dev mode for testing)
	if !*flagDev {
		if err := verifyKeyPair(privateKey); err != nil {
			return fmt.Errorf("private key does not match embedded public key: %w", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARNING: --dev mode enabled; skipping key pair verification\n")
	}

	// Parse optional features
	var features []string
	if *flagFeatures != "" {
		features = strings.Split(*flagFeatures, ",")
		for i, f := range features {
			features[i] = strings.TrimSpace(f)
		}
	}

	// Build the license payload
	now := time.Now().UTC()
	expiresAt := time.Time{} // zero value = never for perpetual
	if duration > 0 {
		expiresAt = now.Add(duration)
	}

	payload := license.LicensePayload{
		LicenseID:  generateUUID(),
		Tier:       licenseTier.String(),
		Customer:   *flagCustomer,
		IssuedAt:   now,
		ExpiresAt:  expiresAt,
		Features:   features,
		MaxServers: *flagMaxServers,
		MaxUsers:   *flagMaxUsers,
	}

	// Sign the payload
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	hash := sha256.Sum256(payloadJSON)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign payload: %w", err)
	}

	// Convert signature to r||s format (32 bytes each for P-256)
	sigBytes := make([]byte, 64)
	r.FillBytes(sigBytes[:32])
	s.FillBytes(sigBytes[32:])

	// Build the license key format
	keyFormat := license.LicenseKeyFormat{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(sigBytes),
	}

	// Encode as base64 (JSON → base64)
	keyJSON, err := json.Marshal(keyFormat)
	if err != nil {
		return fmt.Errorf("failed to marshal license key: %w", err)
	}

	licenseKey := base64.StdEncoding.EncodeToString(keyJSON)

	// Output
	if *flagOutput != "" {
		if err := os.WriteFile(*flagOutput, []byte(licenseKey+"\n"), 0600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		if !*flagQuiet {
			fmt.Fprintf(os.Stderr, "License key written to %s\n", *flagOutput)
		}
	} else {
		fmt.Println(licenseKey)
	}

	// Print summary unless quiet
	if !*flagQuiet {
		expiresStr := "never (perpetual)"
		if !expiresAt.IsZero() {
			expiresStr = expiresAt.Format(time.RFC3339)
		}
		fmt.Fprintf(os.Stderr, "--- License Summary ---\n")
		fmt.Fprintf(os.Stderr, "  Customer:  %s\n", payload.Customer)
		fmt.Fprintf(os.Stderr, "  License ID: %s\n", payload.LicenseID)
		fmt.Fprintf(os.Stderr, "  Tier:       %s\n", licenseTier.DisplayName())
		fmt.Fprintf(os.Stderr, "  Issued:     %s\n", payload.IssuedAt.Format(time.RFC3339))
		fmt.Fprintf(os.Stderr, "  Expires:    %s\n", expiresStr)
		if len(features) > 0 {
			fmt.Fprintf(os.Stderr, "  Features:   %s\n", strings.Join(features, ", "))
		}
		if *flagMaxServers > 0 {
			fmt.Fprintf(os.Stderr, "  Max Servers: %d\n", *flagMaxServers)
		}
		if *flagMaxUsers > 0 {
			fmt.Fprintf(os.Stderr, "  Max Users:   %d\n", *flagMaxUsers)
		}
		fmt.Fprintf(os.Stderr, "  Key Length:  %d bytes\n", len(licenseKey))
	}

	return nil
}

// loadPrivateKey loads an ECDSA P-256 private key from a PEM file
func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- Path from CLI flag, not user input
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w (ensure key is ECDSA P-256)", err)
	}

	if key.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("key is on curve %s, expected P-256", key.Curve.Params().Name)
	}

	return key, nil
}

// verifyKeyPair ensures the private key matches the embedded public key
func verifyKeyPair(privateKey *ecdsa.PrivateKey) error {
	pubKey, err := license.GetEmbeddedPublicKey()
	if err != nil {
		return fmt.Errorf("get embedded public key: %w", err)
	}

	if privateKey.PublicKey.X.Cmp(pubKey.X) != 0 || privateKey.PublicKey.Y.Cmp(pubKey.Y) != 0 {
		return fmt.Errorf("private key does not match embedded public key (key mismatch)")
	}

	return nil
}

// parseDuration parses a human-friendly duration string (e.g., "30d", "365d", "never")
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))

	if s == "never" || s == "0" || s == "" {
		return 0, nil // perpetual license
	}

	// Handle days: Nd or N days
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(daysStr, "%d", &days); err != nil {
			return 0, fmt.Errorf("invalid day count: %q", daysStr)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	// Handle years: Ny
	if strings.HasSuffix(s, "y") {
		yearsStr := strings.TrimSuffix(s, "y")
		var years int
		if _, err := fmt.Sscanf(yearsStr, "%d", &years); err != nil {
			return 0, fmt.Errorf("invalid year count: %q", yearsStr)
		}
		return time.Duration(years) * 365 * 24 * time.Hour, nil
	}

	// Try Go duration
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("cannot parse duration %q (use Nd for days, Ny for years, or 'never')", s)
	}
	return d, nil
}

// generateUUID creates a UUID v4 for license identification
func generateUUID() string {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		// Fallback to timestamp-based ID (extremely unlikely)
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant 2
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// verifySignatureIndependently double-checks that the generated license validates
// by re-verifying the signature independently (belt-and-suspenders check)
func verifySignatureIndependently(payload license.LicensePayload, sigBytes []byte, pubKey *ecdsa.PublicKey) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	hash := sha256.Sum256(payloadJSON)

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return fmt.Errorf("independent signature verification failed")
	}
	return nil
}
