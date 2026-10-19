// SPDX-License-Identifier: Apache-2.0
// Phase 4 unit tests for SSO package — covers DefaultSAMLConfig, Mu,
// getTenantID, isAdmin, saml_test_helpers, canonicalizeXML, writeEscaped,
// JWKS cache/fetch/verify, and other uncovered paths.

package sso

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- DefaultSAMLConfig ---

func TestPhase4_DefaultSAMLConfig(t *testing.T) {
	cfg := DefaultSAMLConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if !cfg.ValidateSignature {
		t.Error("expected ValidateSignature=true")
	}
	if !cfg.WantAssertionsSigned {
		t.Error("expected WantAssertionsSigned=true")
	}
	if !cfg.WantResponseSigned {
		t.Error("expected WantResponseSigned=true")
	}
}

// --- Manager.Mu ---

func TestPhase4_Manager_Mu(t *testing.T) {
	m, _ := NewManager(&ManagerConfig{})
	mu := m.Mu()
	if mu == nil {
		t.Fatal("expected non-nil mutex")
	}
	// Verify it's a working RWMutex
	mu.Lock()
	mu.Unlock()
	mu.RLock()
	mu.RUnlock()
}

// --- getTenantID and isAdmin ---

func TestPhase4_getTenantID(t *testing.T) {
	ctx := context.WithValue(context.Background(), ssoCtxKeyTenantID, "tnt_test123")
	if got := getTenantID(ctx); got != "tnt_test123" {
		t.Errorf("getTenantID: got %q, want %q", got, "tnt_test123")
	}

	// Empty context should return empty string
	if got := getTenantID(context.Background()); got != "" {
		t.Errorf("getTenantID empty: got %q, want empty", got)
	}
}

func TestPhase4_isAdmin(t *testing.T) {
	ctx := context.WithValue(context.Background(), ssoCtxKeyIsAdmin, true)
	if !isAdmin(ctx) {
		t.Error("isAdmin: expected true")
	}

	// Empty context should return false
	if isAdmin(context.Background()) {
		t.Error("isAdmin empty: expected false")
	}

	// Non-bool value should return false
	ctx2 := context.WithValue(context.Background(), ssoCtxKeyIsAdmin, "true")
	if isAdmin(ctx2) {
		t.Error("isAdmin with string: expected false")
	}
}

// --- saml_test_helpers ---

func TestPhase4_SAMLTestHelpers(t *testing.T) {
	// These functions just read env vars — verify they return strings
	_ = getTestSignedSAMLResponse()
	_ = getTestSAMLResponse()
	_ = getTestIDPSSOURL()
	_ = getTestIDPMetadataURL()
	// No assertion needed — just verify they don't panic
}

// --- writeEscaped ---

func TestPhase4_writeEscaped(t *testing.T) {
	var buf bytes.Buffer
	writeEscaped(&buf, `<a>&"b"`)
	got := buf.String()
	want := "&lt;a&gt;&amp;&quot;b&quot;"
	if got != want {
		t.Errorf("writeEscaped: got %q, want %q", got, want)
	}
}

func TestPhase4_writeEscaped_ControlChars(t *testing.T) {
	var buf bytes.Buffer
	writeEscaped(&buf, "\r\n\t")
	got := buf.String()
	want := "&#13;&#10;&#9;"
	if got != want {
		t.Errorf("writeEscaped control: got %q, want %q", got, want)
	}
}

func TestPhase4_writeEscaped_NormalText(t *testing.T) {
	var buf bytes.Buffer
	writeEscaped(&buf, "hello world")
	if got := buf.String(); got != "hello world" {
		t.Errorf("writeEscaped normal: got %q, want %q", got, "hello world")
	}
}

// --- canonicalizeXML ---

func TestPhase4_canonicalizeXML(t *testing.T) {
	input := []byte(`<root><child attr="b" attr2="a">text</child></root>`)
	output, err := canonicalizeXML(input)
	if err != nil {
		t.Fatalf("canonicalizeXML: %v", err)
	}
	if len(output) == 0 {
		t.Fatal("expected non-empty output")
	}
	// Should contain the root and child elements
	s := string(output)
	if !strings.Contains(s, "root") {
		t.Error("expected 'root' in output")
	}
	if !strings.Contains(s, "child") {
		t.Error("expected 'child' in output")
	}
}

func TestPhase4_canonicalizeXML_InvalidXML(t *testing.T) {
	_, err := canonicalizeXML([]byte(`<root><unclosed>`))
	if err == nil {
		t.Fatal("expected error for invalid XML")
	}
}

func TestPhase4_canonicalizeXML_Empty(t *testing.T) {
	output, err := canonicalizeXML([]byte{})
	if err != nil {
		t.Fatalf("canonicalizeXML empty: %v", err)
	}
	if len(output) != 0 {
		t.Errorf("expected empty output, got %q", string(output))
	}
}

func TestPhase4_canonicalizeXML_Namespaced(t *testing.T) {
	input := []byte(`<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference></ds:SignedInfo>`)
	output, err := canonicalizeXML(input)
	if err != nil {
		t.Fatalf("canonicalizeXML namespaced: %v", err)
	}
	if len(output) == 0 {
		t.Fatal("expected non-empty output")
	}
}

// --- JWKS Cache ---

func TestPhase4_JWKSCache_NewAndFetch(t *testing.T) {
	// Mock JWKS server with an RSA key
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate a minimal JWKS response with a fake RSA key
		jwks := JWKS{
			Keys: []JWK{
				{
					KeyID:       "test-key-1",
					KeyType:     "RSA",
					Algorithm:   "RS256",
					Use:         "sig",
					RSAExponent: "AQAB",
					RSAModulus:  base64.RawURLEncoding.EncodeToString(big.NewInt(12345).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	cache := newJWKSCache(srv.URL, &http.Client{Timeout: 5 * time.Second})
	key, err := cache.getKey("test-key-1")
	if err != nil {
		t.Fatalf("getKey: %v", err)
	}
	if key.KeyID != "test-key-1" {
		t.Errorf("KeyID: got %q, want %q", key.KeyID, "test-key-1")
	}
	if key.KeyType != "RSA" {
		t.Errorf("KeyType: got %q, want %q", key.KeyType, "RSA")
	}
}

func TestPhase4_JWKSCache_CacheHit(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		jwks := JWKS{
			Keys: []JWK{
				{KeyID: "cached-key", KeyType: "RSA", Algorithm: "RS256", RSAExponent: "AQAB", RSAModulus: "dGVzdA"},
			},
		}
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	cache := newJWKSCache(srv.URL, &http.Client{Timeout: 5 * time.Second})

	// First call — should fetch
	_, err := cache.getKey("cached-key")
	if err != nil {
		t.Fatalf("first getKey: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 fetch, got %d", callCount)
	}

	// Second call — should use cache
	_, err = cache.getKey("cached-key")
	if err != nil {
		t.Fatalf("second getKey: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 fetch (cached), got %d", callCount)
	}
}

func TestPhase4_JWKSCache_KeyNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := JWKS{Keys: []JWK{{KeyID: "other-key", KeyType: "RSA", RSAExponent: "AQAB", RSAModulus: "dGVzdA"}}}
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	cache := newJWKSCache(srv.URL, &http.Client{Timeout: 5 * time.Second})
	_, err := cache.getKey("nonexistent-key")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestPhase4_JWKSCache_FetchError(t *testing.T) {
	cache := newJWKSCache("http://nonexistent-host:9999/jwks", &http.Client{Timeout: 100 * time.Millisecond})
	_, err := cache.getKey("any-key")
	if err == nil {
		t.Fatal("expected error for unreachable JWKS URL")
	}
}

func TestPhase4_JWKSCache_FetchNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cache := newJWKSCache(srv.URL, &http.Client{Timeout: 5 * time.Second})
	_, err := cache.getKey("any-key")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestPhase4_JWKSCache_FetchInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	cache := newJWKSCache(srv.URL, &http.Client{Timeout: 5 * time.Second})
	_, err := cache.getKey("any-key")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestPhase4_JWKSCache_StaleCacheFallback(t *testing.T) {
	// First server returns valid JWKS
	callCount := 0
	var firstSrvURL string
	firstSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		jwks := JWKS{Keys: []JWK{{KeyID: "stale-key", KeyType: "RSA", RSAExponent: "AQAB", RSAModulus: "dGVzdA"}}}
		json.NewEncoder(w).Encode(jwks)
	}))
	firstSrvURL = firstSrv.URL
	defer firstSrv.Close()

	cache := newJWKSCache(firstSrvURL, &http.Client{Timeout: 5 * time.Second})
	// Set very short TTL so cache expires immediately
	cache.ttl = 1 * time.Nanosecond

	// First fetch
	_, err := cache.getKey("stale-key")
	if err != nil {
		t.Fatalf("first getKey: %v", err)
	}

	// Change URL to unreachable — should fall back to stale cache
	cache.jwksURL = "http://nonexistent-host:9999/jwks"
	// Wait for TTL to expire
	time.Sleep(2 * time.Millisecond)

	// Should return stale cached key instead of erroring
	key, err := cache.getKey("stale-key")
	if err != nil {
		t.Fatalf("stale cache fallback: %v", err)
	}
	if key.KeyID != "stale-key" {
		t.Errorf("KeyID: got %q, want %q", key.KeyID, "stale-key")
	}
}

// --- verifyJWTSignature ---

func TestPhase4_verifyJWTSignature_InvalidFormat(t *testing.T) {
	err := verifyJWTSignature("not.a.jwt.extra", &JWK{KeyType: "RSA"})
	if err == nil {
		t.Fatal("expected error for invalid JWT format")
	}
}

func TestPhase4_verifyJWTSignature_InvalidHeader(t *testing.T) {
	// JWT with invalid header encoding
	jwt := "!!!.payload.signature"
	err := verifyJWTSignature(jwt, &JWK{KeyType: "RSA"})
	if err == nil {
		t.Fatal("expected error for invalid header")
	}
}

func TestPhase4_verifyJWTSignature_UnsupportedKeyType(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"test"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	jwt := fmt.Sprintf("%s.%s.%s", header, payload, sig)

	err := verifyJWTSignature(jwt, &JWK{KeyType: "oct"})
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

// --- verifyRSASignature ---

func TestPhase4_verifyRSASignature_InvalidModulus(t *testing.T) {
	err := verifyRSASignature("input", []byte("sig"), &JWK{KeyType: "RSA", RSAModulus: "!!!invalid", RSAExponent: "AQAB"}, "RS256")
	if err == nil {
		t.Fatal("expected error for invalid modulus")
	}
}

func TestPhase4_verifyRSASignature_InvalidExponent(t *testing.T) {
	err := verifyRSASignature("input", []byte("sig"), &JWK{KeyType: "RSA", RSAModulus: "dGVzdA", RSAExponent: "!!!invalid"}, "RS256")
	if err == nil {
		t.Fatal("expected error for invalid exponent")
	}
}

func TestPhase4_verifyRSASignature_UnsupportedAlg(t *testing.T) {
	err := verifyRSASignature("input", []byte("sig"), &JWK{KeyType: "RSA", RSAModulus: "dGVzdA", RSAExponent: "AQAB"}, "HS256")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestPhase4_verifyRSASignature_BadSignature(t *testing.T) {
	// Generate a real RSA key
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nBytes := privKey.N.Bytes()
	eBytes := big.NewInt(int64(privKey.E)).Bytes()

	jwk := &JWK{
		KeyType:     "RSA",
		RSAModulus:  base64.RawURLEncoding.EncodeToString(nBytes),
		RSAExponent: base64.RawURLEncoding.EncodeToString(eBytes),
	}

	// Use a bad signature
	err := verifyRSASignature("input", []byte("badsig"), jwk, "RS256")
	if err == nil {
		t.Fatal("expected error for bad RSA signature")
	}
}

// --- verifyECSignature ---

func TestPhase4_verifyECSignature_InvalidX(t *testing.T) {
	err := verifyECSignature("input", []byte("sig"), &JWK{KeyType: "EC", XCoord: "!!!invalid", YCoord: "dGVzdA"}, "ES256")
	if err == nil {
		t.Fatal("expected error for invalid X coordinate")
	}
}

func TestPhase4_verifyECSignature_InvalidY(t *testing.T) {
	err := verifyECSignature("input", []byte("sig"), &JWK{KeyType: "EC", XCoord: "dGVzdA", YCoord: "!!!invalid"}, "ES256")
	if err == nil {
		t.Fatal("expected error for invalid Y coordinate")
	}
}

func TestPhase4_verifyECSignature_UnsupportedAlg(t *testing.T) {
	err := verifyECSignature("input", []byte("sig"), &JWK{KeyType: "EC", XCoord: "dGVzdA", YCoord: "dGVzdA"}, "HS256")
	if err == nil {
		t.Fatal("expected error for unsupported EC algorithm")
	}
}

func TestPhase4_verifyECSignature_InvalidSigLength(t *testing.T) {
	// Generate a real EC key
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xBytes := privKey.X.Bytes()
	yBytes := privKey.Y.Bytes()

	jwk := &JWK{
		KeyType: "EC",
		Curve:   "P-256",
		XCoord:  base64.RawURLEncoding.EncodeToString(xBytes),
		YCoord:  base64.RawURLEncoding.EncodeToString(yBytes),
	}

	// Invalid signature length (should be 64 for P-256)
	err := verifyECSignature("input", []byte("short"), jwk, "ES256")
	if err == nil {
		t.Fatal("expected error for invalid signature length")
	}
}

func TestPhase4_verifyECSignature_BadSignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xBytes := privKey.X.Bytes()
	yBytes := privKey.Y.Bytes()

	jwk := &JWK{
		KeyType: "EC",
		Curve:   "P-256",
		XCoord:  base64.RawURLEncoding.EncodeToString(xBytes),
		YCoord:  base64.RawURLEncoding.EncodeToString(yBytes),
	}

	// 64-byte signature that won't verify
	badSig := make([]byte, 64)
	for i := range badSig {
		badSig[i] = 0xFF
	}
	err := verifyECSignature("input", badSig, jwk, "ES256")
	if err == nil {
		t.Fatal("expected error for bad EC signature")
	}
}

// --- publicKeyFromJWK ---

func TestPhase4_publicKeyFromJWK_RSA(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nBytes := privKey.N.Bytes()
	eBytes := big.NewInt(int64(privKey.E)).Bytes()

	jwk := &JWK{
		KeyType:     "RSA",
		RSAModulus:  base64.RawURLEncoding.EncodeToString(nBytes),
		RSAExponent: base64.RawURLEncoding.EncodeToString(eBytes),
	}

	pub, err := publicKeyFromJWK(jwk)
	if err != nil {
		t.Fatalf("publicKeyFromJWK RSA: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
	_, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Error("expected *rsa.PublicKey")
	}
}

func TestPhase4_publicKeyFromJWK_EC(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xBytes := privKey.X.Bytes()
	yBytes := privKey.Y.Bytes()

	jwk := &JWK{
		KeyType: "EC",
		Curve:   "P-256",
		XCoord:  base64.RawURLEncoding.EncodeToString(xBytes),
		YCoord:  base64.RawURLEncoding.EncodeToString(yBytes),
	}

	pub, err := publicKeyFromJWK(jwk)
	if err != nil {
		t.Fatalf("publicKeyFromJWK EC: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
	_, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Error("expected *ecdsa.PublicKey")
	}
}

func TestPhase4_publicKeyFromJWK_UnsupportedType(t *testing.T) {
	_, err := publicKeyFromJWK(&JWK{KeyType: "oct"})
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestPhase4_publicKeyFromJWK_InvalidRSA(t *testing.T) {
	_, err := publicKeyFromJWK(&JWK{KeyType: "RSA", RSAModulus: "!!!invalid", RSAExponent: "AQAB"})
	if err == nil {
		t.Fatal("expected error for invalid RSA modulus")
	}
}

func TestPhase4_publicKeyFromJWK_InvalidEC(t *testing.T) {
	_, err := publicKeyFromJWK(&JWK{KeyType: "EC", XCoord: "!!!invalid", YCoord: "dGVzdA", Curve: "P-256"})
	if err == nil {
		t.Fatal("expected error for invalid EC coordinates")
	}
}

func TestPhase4_publicKeyFromJWK_UnsupportedCurve(t *testing.T) {
	_, err := publicKeyFromJWK(&JWK{KeyType: "EC", XCoord: "dGVzdA", YCoord: "dGVzdA", Curve: "P-999"})
	if err == nil {
		t.Fatal("expected error for unsupported curve")
	}
}

// --- Additional manager.go coverage ---

func TestPhase4_Manager_Stats_WithSessions(t *testing.T) {
	m, _ := NewManager(&ManagerConfig{})

	// Stats with no sessions
	stats, err := m.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.ActiveSessions != 0 {
		t.Errorf("Stats empty: ActiveSessions=%d, want 0", stats.ActiveSessions)
	}
}

// --- canonicalizeSignedInfo additional coverage ---

func TestPhase4_canonicalizeSignedInfo_AdditionalPaths(t *testing.T) {
	// Test with transforms
	si := &SignedInfo{
		Reference: &Reference{
			URI: "#_body",
			Transforms: &Transforms{
				Transform: []Transform{
					{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
				},
			},
			DigestMethod: &DigestMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256"},
			DigestValue:  "abc123",
		},
	}
	_, err := canonicalizeSignedInfo(si)
	if err != nil {
		t.Logf("canonicalizeSignedInfo: %v (may be expected for partial input)", err)
	}
}
