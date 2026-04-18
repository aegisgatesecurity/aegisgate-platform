package enhanced_test

import (
	"bytes"
	"crypto/tls"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/shared/crypto/enhanced"
)

func TestNewSHA256(t *testing.T) {
	h := enhanced.NewSHA256()
	if h == nil {
		t.Fatal("NewSHA256 returned nil")
	}
	h.Write([]byte("test"))
	sum := h.Sum(nil)
	if len(sum) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(sum))
	}
}

func TestNewSHA3256(t *testing.T) {
	h := enhanced.NewSHA3256()
	if h == nil {
		t.Fatal("NewSHA3256 returned nil")
	}
}

func TestNewBLAKE2b(t *testing.T) {
	h, err := enhanced.NewBLAKE2b(32)
	if err != nil {
		t.Fatalf("NewBLAKE2b failed: %v", err)
	}
	if h == nil {
		t.Fatal("hash is nil")
	}
}

func TestDeriveKeyPBKDF2(t *testing.T) {
	key := enhanced.DeriveKeyPBKDF2([]byte("password"), []byte("salt"), 10000, 32)
	if len(key) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key))
	}
}

func TestChaCha20Poly1305(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("Hello, World!")

	ciphertext, err := enhanced.ChaCha20Poly1305Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := enhanced.ChaCha20Poly1305Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted text doesn't match original")
	}
}

func TestGenerateRSAKey(t *testing.T) {
	_, err := enhanced.GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKey failed: %v", err)
	}

	_, err = enhanced.GenerateRSAKey(1024)
	if err == nil {
		t.Error("expected error for 1024-bit key")
	}
}

func TestGetFIPSCipherSuites(t *testing.T) {
	suites := enhanced.GetFIPSCipherSuites()
	if len(suites) == 0 {
		t.Error("no cipher suites returned")
	}
}

func TestGetSecureTLSConfig(t *testing.T) {
	config := enhanced.GetSecureTLSConfig()
	if config == nil {
		t.Fatal("config is nil")
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2, got %d", config.MinVersion)
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte("test")
	b := []byte("test")
	c := []byte("other")

	if !enhanced.ConstantTimeCompare(a, b) {
		t.Error("should match")
	}
	if enhanced.ConstantTimeCompare(a, c) {
		t.Error("should not match")
	}
}
