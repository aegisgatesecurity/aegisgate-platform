// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — OIDC JWKS Key Set
// =========================================================================
//
// This file implements RFC 7517 (JSON Web Key Set) fetching and JWT
// signature verification for OIDC ID tokens. It uses only the Go
// standard library — no external JWT dependencies.
//
// The verification process:
//   1. Parse the JWT header to extract the key ID ("kid").
//   2. Fetch the JWKS from the issuer's jwks_uri endpoint.
//   3. Find the JWK matching the kid.
//   4. Verify the JWT signature using the JWK's public key.
//   5. Validate standard claims (exp, iss, aud).
//
// Supported algorithms: RS256, RS384, RS512, ES256, ES384, ES512.
// =========================================================================

package sso

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWKS holds a JSON Web Key Set (RFC 7517).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key (RFC 7517).
type JWK struct {
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg"`
	Use       string `json:"use,omitempty"`

	// RSA fields (kty = "RSA")
	RSAExponent string `json:"e,omitempty"`
	RSAModulus  string `json:"n,omitempty"`

	// EC fields (kty = "EC")
	Curve  string `json:"crv,omitempty"`
	XCoord string `json:"x,omitempty"`
	YCoord string `json:"y,omitempty"`
}

// jwksCache caches fetched JWKS to avoid refetching on every token validation.
type jwksCache struct {
	mu         sync.RWMutex
	keys       map[string]*JWK // kid → JWK
	fetched    time.Time       // when the cache was last populated
	jwksURL    string
	httpClient *http.Client
	ttl        time.Duration // cache validity
}

const defaultJWKSTTL = 15 * time.Minute

// newJWKSCache creates a new JWKS cache for the given URL.
func newJWKSCache(jwksURL string, httpClient *http.Client) *jwksCache {
	return &jwksCache{
		keys:       make(map[string]*JWK),
		jwksURL:    jwksURL,
		httpClient: httpClient,
		ttl:        defaultJWKSTTL,
	}
}

// getKey returns the JWK for the given key ID, fetching the JWKS if needed.
func (c *jwksCache) getKey(kid string) (*JWK, error) {
	// Try cache first (read lock).
	c.mu.RLock()
	if key, ok := c.keys[kid]; ok && time.Since(c.fetched) < c.ttl {
		c.mu.RUnlock()
		return key, nil
	}
	c.mu.RUnlock()

	// Cache miss or expired — fetch.
	if err := c.fetch(); err != nil {
		// If fetch fails but we have a stale cached key, use it.
		c.mu.RLock()
		key, ok := c.keys[kid]
		c.mu.RUnlock()
		if ok {
			return key, nil
		}
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("JWKS: key ID %q not found in key set", kid)
	}
	return key, nil
}

// fetch retrieves the JWKS from the configured URL and updates the cache.
func (c *jwksCache) fetch() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check under write lock.
	if len(c.keys) > 0 && time.Since(c.fetched) < c.ttl {
		return nil
	}

	resp, err := c.httpClient.Get(c.jwksURL)
	if err != nil {
		return fmt.Errorf("JWKS fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch: unexpected status %d from %s", resp.StatusCode, c.jwksURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return fmt.Errorf("JWKS fetch: read body: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("JWKS fetch: parse: %w", err)
	}

	// Update cache.
	c.keys = make(map[string]*JWK, len(jwks.Keys))
	for i := range jwks.Keys {
		k := jwks.Keys[i]
		c.keys[k.KeyID] = &k
	}
	c.fetched = time.Now()

	return nil
}

// jwtHeader represents the JWT header (JWS protected header).
type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid,omitempty"`
	Type      string `json:"typ,omitempty"`
}

// verifyJWTSignature verifies the JWS signature of a JWT using the given JWK.
// It returns nil if the signature is valid, or an error describing why it failed.
func verifyJWTSignature(jwt string, key *JWK) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode header.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWT header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("failed to parse JWT header: %w", err)
	}

	// Sign the signing input: base64(header) + "." + base64(payload).
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode JWT signature: %w", err)
	}

	// Build the public key from the JWK and verify.
	switch key.KeyType {
	case "RSA":
		return verifyRSASignature(signingInput, signature, key, header.Algorithm)
	case "EC":
		return verifyECSignature(signingInput, signature, key, header.Algorithm)
	default:
		return fmt.Errorf("unsupported JWK key type: %s", key.KeyType)
	}
}

// verifyRSASignature verifies an RSA-JWT signature (RS256/384/512).
func verifyRSASignature(signingInput string, signature []byte, key *JWK, alg string) error {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.RSAModulus)
	if err != nil {
		return fmt.Errorf("JWKS: failed to decode RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.RSAExponent)
	if err != nil {
		return fmt.Errorf("JWKS: failed to decode RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	pubKey := &rsa.PublicKey{N: n, E: int(e.Int64())}

	var hash crypto.Hash
	switch alg {
	case "RS256":
		hash = crypto.SHA256
	case "RS384":
		hash = crypto.SHA384
	case "RS512":
		hash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported RSA JWT algorithm: %s", alg)
	}

	h := hash.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKey, hash, hashed, signature)
}

// verifyECSignature verifies an ECDSA-JWT signature (ES256/384/512).
func verifyECSignature(signingInput string, signature []byte, key *JWK, alg string) error {
	xBytes, err := base64.RawURLEncoding.DecodeString(key.XCoord)
	if err != nil {
		return fmt.Errorf("JWKS: failed to decode EC X coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.YCoord)
	if err != nil {
		return fmt.Errorf("JWKS: failed to decode EC Y coordinate: %w", err)
	}

	var curve elliptic.Curve
	var hash crypto.Hash
	switch alg {
	case "ES256":
		curve = elliptic.P256()
		hash = crypto.SHA256
	case "ES384":
		curve = elliptic.P384()
		hash = crypto.SHA384
	case "ES512":
		curve = elliptic.P521()
		hash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported EC JWT algorithm: %s", alg)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	h := hash.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	// ECDSA signatures in JWT are raw R||S, not ASN.1 DER.
	if len(signature) != 64 && len(signature) != 96 && len(signature) != 132 {
		return fmt.Errorf("invalid ECDSA signature length: %d", len(signature))
	}
	halfLen := len(signature) / 2
	r := new(big.Int).SetBytes(signature[:halfLen])
	s := new(big.Int).SetBytes(signature[halfLen:])

	if !ecdsa.Verify(pubKey, hashed, r, s) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

// publicKeyFromJWK builds a crypto.PublicKey from a JWK for use in x509 operations.
// This is a helper for callers that need the raw public key.
func publicKeyFromJWK(key *JWK) (crypto.PublicKey, error) {
	switch key.KeyType {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(key.RSAModulus)
		if err != nil {
			return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.RSAExponent)
		if err != nil {
			return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
		}
		n := new(big.Int).SetBytes(nBytes)
		e := new(big.Int).SetBytes(eBytes)
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		xBytes, err := base64.RawURLEncoding.DecodeString(key.XCoord)
		if err != nil {
			return nil, fmt.Errorf("failed to decode EC X: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(key.YCoord)
		if err != nil {
			return nil, fmt.Errorf("failed to decode EC Y: %w", err)
		}
		var curve elliptic.Curve
		switch key.Curve {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", key.Curve)
		}
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", key.KeyType)
	}
}

// Ensure x509 is used (for potential future certificate extraction).
var _ = x509.CertPool{}
