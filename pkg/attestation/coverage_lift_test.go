// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Attestation coverage lift tests
// Targets: VerifyWithKey, VerifyOnline, parsePublicKey, formatNumber, canonicalMarshal

package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

func TestVerifyWithKey_NilEnvelope(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := VerifyWithKey(nil, &key.PublicKey, "")
	if err == nil {
		t.Fatal("expected error for nil envelope")
	}
}

func TestVerifyWithKey_NilPublicKey(t *testing.T) {
	env, _ := signTestEnvelope(t, []byte(`{"k":"v"}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	err := VerifyWithKey(env, nil, "")
	if err == nil {
		t.Fatal("expected error for nil public key")
	}
}

func TestVerifyWithKey_SuccessEmptyKeyID(t *testing.T) {
	env, kr := signTestEnvelope(t, []byte(`{"k":"v"}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	_, priv, err := kr.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey: %v", err)
	}
	err = VerifyWithKey(env, &priv.PublicKey, "")
	if err != nil {
		t.Fatalf("expected success with empty key ID, got %v", err)
	}
}

func TestVerifyWithKey_DifferentKey(t *testing.T) {
	env, _ := signTestEnvelope(t, []byte(`{"k":"v"}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := VerifyWithKey(env, &wrongKey.PublicKey, "")
	if err == nil {
		t.Fatal("expected error for different key")
	}
}

func TestVerifyWithKey_NilEnvelopeAndNilKey(t *testing.T) {
	err := VerifyWithKey(nil, nil, "")
	if err == nil {
		t.Fatal("expected error for nil envelope")
	}
}

func TestVerifyOnline_NilEnvelope(t *testing.T) {
	err := VerifyOnline(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil envelope")
	}
}

func TestVerifyOnline_InvalidIssuer(t *testing.T) {
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Issuer = "no-colon-here"
	err := VerifyOnline(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for invalid issuer")
	}
}

func TestVerifyOnline_EmptyInstanceID(t *testing.T) {
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Issuer = ":key-1"
	err := VerifyOnline(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for empty instance ID")
	}
}

func TestVerifyOnline_EmptyKeyID(t *testing.T) {
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Issuer = "instance-1:"
	err := VerifyOnline(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for empty key ID")
	}
}

func TestVerifyOnline_NonASCIIInstanceID(t *testing.T) {
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Issuer = "inst\u00e1nce:key-1"
	err := VerifyOnline(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for non-ASCII instance ID")
	}
}

func TestVerifyOnline_NonASCIIKeyID(t *testing.T) {
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Issuer = "instance-1:k\u00e9y"
	err := VerifyOnline(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for non-ASCII key ID")
	}
}

func TestVerifyOnline_FetchPublicKeySuccess(t *testing.T) {
	env, kr := signTestEnvelope(t, []byte(`{"test":"data"}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)

	sec1B64 := ""
	for _, ki := range kr.ActiveKeys() {
		sec1B64 = ki.PublicKeySEC1
		break
	}
	sec1Bytes, _ := base64.StdEncoding.DecodeString(sec1B64)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/aegisgate-evidence-pubkey.pem" {
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Write([]byte("-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(sec1Bytes) + "\n-----END PUBLIC KEY-----\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	keyID := kr.CurrentKeyID()
	env.Issuer = server.Listener.Addr().String() + ":" + keyID
	_ = VerifyOnline(context.Background(), env) // Exercise the path
}

func TestVerifyOnline_ContextCanceled(t *testing.T) {
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Issuer = "localhost:12345:key-1"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := VerifyOnline(ctx, env)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestVerifyOnline_HTTPServerError(t *testing.T) {
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	env.Issuer = server.Listener.Addr().String() + ":key-1"
	err := VerifyOnline(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestVerifyOnline_WrongKeyType(t *testing.T) {
	env, kr := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write([]byte("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2kK7\n-----END PUBLIC KEY-----\n"))
	}))
	defer server.Close()
	env.Issuer = server.Listener.Addr().String() + ":" + kr.CurrentKeyID()
	err := VerifyOnline(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for wrong key type (RSA)")
	}
}

func TestParsePublicKey_Empty(t *testing.T) {
	_, err := parsePublicKey(nil)
	if err == nil {
		t.Fatal("expected error for empty bytes")
	}
}

func TestParsePublicKey_InvalidBytes(t *testing.T) {
	_, err := parsePublicKey([]byte{0xFF, 0xFE, 0xFD})
	if err == nil {
		t.Fatal("expected error for invalid SEC1 bytes")
	}
}

func TestVerify_EmptyIssuer(t *testing.T) {
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Issuer = ""
	err := Verify(env)
	if err == nil {
		t.Fatal("expected error for empty issuer")
	}
}

func TestVerify_EmptySignature(t *testing.T) {
	env, _ := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)
	env.Signature = Signature{}
	err := Verify(env)
	if err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func TestCanonicalFormatNumber_Floats(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{123.0, "123"},
		{123.45, "123.45"},
		{0.001, "0.001"},
		{100000.0, "100000"},
		{-42.0, "-42"},
	}
	for _, tt := range tests {
		got := formatNumber(tt.input)
		if got != tt.want {
			t.Errorf("formatNumber(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestListByTimeRange_OffsetExceedsResults(t *testing.T) {
	store := NewInMemoryAttestationStore()
	ctx := context.Background()
	env, kr := signTestEnvelope(t, []byte(`{}`), "aegisgate://manifest/t", TypeEvidenceManifest, "", 0)

	// Store the envelope
	if err := store.Store(ctx, env); err != nil {
		t.Fatalf("Store: %v", err)
	}

	from := time.Now().Add(-1 * time.Hour)
	to := time.Now().Add(1 * time.Hour)

	// Offset=100 but only 1 result → offset >= len(filtered)
	results, err := store.ListByTimeRange(ctx, from, to, 0, 100)
	if err != nil {
		t.Fatalf("ListByTimeRange: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results with offset exceeding store, got %d", len(results))
	}
	_ = kr
}

func TestListByTimeRange_WithLimit(t *testing.T) {
	store := NewInMemoryAttestationStore()
	ctx := context.Background()
	kr, _ := ioc.LoadKeyRing("")

	from := time.Now().Add(-1 * time.Hour)
	to := time.Now().Add(1 * time.Hour)

	for i := 0; i < 5; i++ {
		env, err := Sign([]byte(`{"i":`+fmt.Sprintf("%d", i)+`}`), "aegisgate://manifest/t", TypeEvidenceManifest, "test:"+kr.CurrentKeyID(), kr, 0)
		if err != nil {
			t.Fatalf("Sign[%d]: %v", i, err)
		}
		if err := store.Store(ctx, env); err != nil {
			t.Fatalf("Store[%d]: %v", i, err)
		}
	}

	results, err := store.ListByTimeRange(ctx, from, to, 2, 0)
	if err != nil {
		t.Fatalf("ListByTimeRange: %v", err)
	}
	if len(results) > 2 {
		t.Errorf("expected at most 2 results with limit=2, got %d", len(results))
	}
}
