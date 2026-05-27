package identity

import (
	"testing"
)

func TestIdentityGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Errorf("GenerateKeyPair failed: %v", err)
	}
	if priv == nil || pub == nil {
		t.Error("KeyPair should not be nil")
	}
}

func TestIdentityPublicKeyToDER(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	der, err := PublicKeyToDER(pub)
	if err != nil {
		t.Errorf("PublicKeyToDER failed: %v", err)
	}
	if len(der) == 0 {
		t.Error("DER should not be empty")
	}
}

func TestIdentityDERToPublicKey(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	der, _ := PublicKeyToDER(pub)
	pub2, err := DERToPublicKey(der)
	if err != nil {
		t.Errorf("DERToPublicKey failed: %v", err)
	}
	if pub2 == nil {
		t.Error("PublicKey should not be nil")
	}
}

func TestIdentityFingerprint(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	der, _ := PublicKeyToDER(pub)
	fp := Fingerprint(der)
	if fp == "" {
		t.Error("Fingerprint should not be empty")
	}
}

func TestIdentitySignAndVerify(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	data := []byte("test data to sign")

	sig, err := Sign(priv, data)
	if err != nil {
		t.Errorf("Sign failed: %v", err)
	}

	valid := Verify(pub, data, sig)
	if !valid {
		t.Error("Signature should be valid")
	}
}

func TestIdentityVerifyInvalid(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	data := []byte("test data")
	invalidSig := []byte("invalid signature")

	valid := Verify(pub, data, invalidSig)
	if valid {
		t.Error("Invalid signature should fail verification")
	}
}

func TestIdentityNewAgentIdentity(t *testing.T) {
	req := &RegisterRequest{
		Name:    "Test Agent",
		Version: "1.0",
		Owner:   "test-owner",
	}
	identity, _, err := NewAgentIdentity(req)
	if err != nil {
		t.Errorf("NewAgentIdentity failed: %v", err)
	}
	if identity == nil {
		t.Error("Identity should not be nil")
	}
}

func TestIdentityToJSON(t *testing.T) {
	req := &RegisterRequest{Name: "Test", Version: "1.0", Owner: "test"}
	identity, _, _ := NewAgentIdentity(req)

	data, err := identity.ToJSON()
	if err != nil {
		t.Errorf("ToJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("ToJSON returned empty data")
	}
}

func TestIdentityFromJSON(t *testing.T) {
	req := &RegisterRequest{Name: "Test", Version: "1.0", Owner: "test"}
	identity, _, _ := NewAgentIdentity(req)

	data, _ := identity.ToJSON()
	identity2, err := FromJSON(data)
	if err != nil {
		t.Errorf("FromJSON failed: %v", err)
	}
	if identity2 == nil {
		t.Error("FromJSON returned nil")
	}
}
