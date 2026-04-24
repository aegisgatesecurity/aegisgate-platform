package signature_verification

import (
	"testing"
)

func TestNewKeyManager(t *testing.T) {
	km := NewKeyManager("")
	if km == nil {
		t.Error("NewKeyManager should not return nil")
	}
}

func TestKeyManager_GetPublicKey_Nonexistent(t *testing.T) {
	km := NewKeyManager("")
	_, _, err := km.GetPublicKey("nonexistent")
	if err == nil {
		t.Error("GetPublicKey should error for nonexistent key")
	}
}

func TestKeyManager_RevokeKey_Nonexistent(t *testing.T) {
	km := NewKeyManager("")
	err := km.RevokeKey("nonexistent")
	if err == nil {
		t.Error("RevokeKey should error for nonexistent key")
	}
}

func TestNewSignatureVerifier(t *testing.T) {
	sv := NewSignatureVerifier()
	if sv == nil {
		t.Error("NewSignatureVerifier should not return nil")
	}
}

func TestSignatureVerifier_EnableDisable(t *testing.T) {
	sv := NewSignatureVerifier()
	sv.Enable()
	if !sv.enabled {
		t.Error("Should be enabled after Enable()")
	}
	sv.Disable()
	if sv.enabled {
		t.Error("Should be disabled after Disable()")
	}
}

func TestSignatureVerifier_GetStats(t *testing.T) {
	sv := NewSignatureVerifier()
	stats := sv.GetStats()
	if stats == nil {
		t.Error("GetStats should not return nil")
	}
}

func TestSignatureVerifier_GetStats_AfterVerifications(t *testing.T) {
	sv := NewSignatureVerifier()
	sv.VerifySignature([]byte("p1"), []byte("s1"), []byte("k1"))
	sv.VerifySignature([]byte("p2"), []byte("s2"), []byte("k2"))
	stats := sv.GetStats()
	if stats.TotalVerifications < 2 {
		t.Error("Stats should reflect verifications")
	}
}

func TestSignatureVerifier_StrictMode(t *testing.T) {
	sv := NewSignatureVerifier()
	sv.EnableStrictMode()
	stats := sv.GetStats()
	if stats == nil {
		t.Error("Stats should work in strict mode")
	}
}

func TestNewSignatureValidationService(t *testing.T) {
	svs := NewSignatureValidationService()
	if svs == nil {
		t.Error("NewSignatureValidationService should not return nil")
	}
}

func TestSignatureValidationService_ValidateSignedPackage(t *testing.T) {
	svs := NewSignatureValidationService()
	signed := &SignedPayload{
		Data:      []byte("payload"),
		Signature: []byte("signature"),
	}
	_, _ = svs.ValidateSignedPackage(signed)
}

func TestSignatureValidationService_ValidateStringSignature(t *testing.T) {
	svs := NewSignatureValidationService()
	_, _ = svs.ValidateStringSignature([]byte("payload"), "YmFzZTY0c2lnbmF0dXJl", []byte("key"))
}

func TestNewKeyManagementService(t *testing.T) {
	kms := NewKeyManagementService("")
	if kms == nil {
		t.Error("NewKeyManagementService should not return nil")
	}
}

func TestKeyManagementService_GetPublicKeyInfo_Nonexistent(t *testing.T) {
	kms := NewKeyManagementService("")
	_, err := kms.GetPublicKeyInfo("nonexistent")
	if err == nil {
		t.Error("GetPublicKeyInfo should error for nonexistent key")
	}
}

func TestKeyManagementService_RevokeKey_Nonexistent(t *testing.T) {
	kms := NewKeyManagementService("")
	err := kms.RevokeKey("nonexistent")
	if err == nil {
		t.Error("RevokeKey should error for nonexistent key")
	}
}

func TestConcurrentVerification(t *testing.T) {
	sv := NewSignatureVerifier()
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				sv.VerifySignature([]byte("payload"), []byte("sig"), []byte("key"))
			}
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestMultipleKeyManagement(t *testing.T) {
	km := NewKeyManager("")
	for _, keyID := range []string{"key1", "key2", "key3"} {
		_, _, err := km.GetPublicKey(keyID)
		if err == nil {
			t.Errorf("Key %s should not exist", keyID)
		}
	}
}
