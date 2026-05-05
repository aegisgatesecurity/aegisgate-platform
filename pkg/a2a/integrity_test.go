package a2a

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"testing"
)

// helper creates a request with an HMAC‑SHA256 signature header
func newSignedRequest(secret []byte, payload []byte) *http.Request {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	sig := mac.Sum(nil)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	r := &http.Request{Header: http.Header{}}
	r.Body = io.NopCloser(bytes.NewReader(payload))
	r.Header.Set("A2A-Signature", sigB64)
	return r
}

func TestIntegrityVerifier(t *testing.T) {
	secret := []byte("test-secret-key")
	verifier := NewIntegrityVerifier(secret)

	t.Run("valid signature", func(t *testing.T) {
		payload := []byte(`{"msg":"hello"}`)
		r := newSignedRequest(secret, payload)
		if err := verifier.Verify(r); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("missing header", func(t *testing.T) {
		payload := []byte(`{"msg":"missing"}`)
		r := &http.Request{Header: http.Header{}}
		r.Body = io.NopCloser(bytes.NewReader(payload))
		// no signature header
		if err := verifier.Verify(r); err == nil {
			t.Fatalf("expected error for missing header, got nil")
		}
	})

	t.Run("tampered body", func(t *testing.T) {
		// correct signature for original payload
		original := []byte(`{"msg":"original"}`)
		r := newSignedRequest(secret, original)
		// replace body with tampered content after signature set
		tampered := []byte(`{"msg":"tampered"}`)
		r.Body = io.NopCloser(bytes.NewReader(tampered))
		if err := verifier.Verify(r); err == nil {
			t.Fatalf("expected error for tampered body, got nil")
		}
	})
}
