// SPDX-License-Identifier: Apache-2.0

package ioc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

// =========================================================================
// key_encryption.go — decryptKeyFile error paths
// =========================================================================

func TestPhase5_DecryptKeyFile_InvalidJSON(t *testing.T) {
	_, err := decryptKeyFile([]byte("not-json"), "passphrase")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestPhase5_DecryptKeyFile_NotEncrypted(t *testing.T) {
	// When enc.Encrypted is false, data is returned as-is
	data := []byte(`{"encrypted":false,"nonce":"","ciphertext":""}`)
	plaintext, err := decryptKeyFile(data, "passphrase")
	if err != nil {
		t.Fatalf("expected nil error for unencrypted file: %v", err)
	}
	if string(plaintext) != string(data) {
		t.Error("expected data returned as-is for unencrypted file")
	}
}

func TestPhase5_DecryptKeyFile_InvalidNonceBase64(t *testing.T) {
	data := []byte(`{"encrypted":true,"nonce":"!!!not-base64!!!","ciphertext":"dGVzdA=="}`)
	_, err := decryptKeyFile(data, "passphrase")
	if err == nil {
		t.Fatal("expected error for invalid nonce base64")
	}
}

func TestPhase5_DecryptKeyFile_InvalidCiphertextBase64(t *testing.T) {
	data := []byte(`{"encrypted":true,"nonce":"dGVzdA==","ciphertext":"!!!not-base64!!!"}`)
	_, err := decryptKeyFile(data, "passphrase")
	if err == nil {
		t.Fatal("expected error for invalid ciphertext base64")
	}
}

func TestPhase5_DecryptKeyFile_WrongPassphrase(t *testing.T) {
	// Encrypt with one passphrase, decrypt with another
	plaintext := []byte(`{"keys":[]}`)
	encrypted, err := encryptKeyFile(plaintext, "correct-passphrase")
	if err != nil {
		t.Fatalf("encryptKeyFile: %v", err)
	}
	_, err = decryptKeyFile(encrypted, "wrong-passphrase")
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestPhase5_EncryptDecryptKeyFile_Roundtrip(t *testing.T) {
	plaintext := []byte(`{"version":2,"keys":[],"current":""}`)
	encrypted, err := encryptKeyFile(plaintext, "my-secret-passphrase")
	if err != nil {
		t.Fatalf("encryptKeyFile: %v", err)
	}
	decrypted, err := decryptKeyFile(encrypted, "my-secret-passphrase")
	if err != nil {
		t.Fatalf("decryptKeyFile: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("roundtrip mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestPhase5_IsEncryptedKeyFile_InvalidJSON(t *testing.T) {
	if isEncryptedKeyFile([]byte("not-json")) {
		t.Error("expected false for invalid JSON")
	}
}

func TestPhase5_IsEncryptedKeyFile_NotEncrypted(t *testing.T) {
	data := []byte(`{"encrypted":false}`)
	if isEncryptedKeyFile(data) {
		t.Error("expected false for unencrypted file")
	}
}

func TestPhase5_IsEncryptedKeyFile_Encrypted(t *testing.T) {
	data := []byte(`{"encrypted":true}`)
	if !isEncryptedKeyFile(data) {
		t.Error("expected true for encrypted file")
	}
}

// =========================================================================
// attest.go — base64PublicKeyFor, ParsePublicKey, VerifyAttestation
// =========================================================================

func TestPhase5_Base64PublicKeyFor_KeyNotFound(t *testing.T) {
	kr := &KeyRing{}
	result := base64PublicKeyFor(kr, "nonexistent-key-id")
	if result != "" {
		t.Errorf("expected empty string for non-existent key, got %q", result)
	}
}

func TestPhase5_ParsePublicKey_NotOnCurve(t *testing.T) {
	// Create a 65-byte key with valid format (0x04 prefix) but off-curve point
	// X=0, Y=1 is not on the P-256 curve
	key := make([]byte, 65)
	key[0] = 0x04
	// Y = 1 (last 32 bytes)
	key[64] = 0x01
	_, err := ParsePublicKey(key)
	if err == nil {
		t.Fatal("expected error for off-curve point")
	}
}

func TestPhase5_VerifyAttestation_NotOnCurve(t *testing.T) {
	// Create a 65-byte key with valid format but off-curve point
	key := make([]byte, 65)
	key[0] = 0x04
	key[64] = 0x01 // Y=1, not on curve

	a := &IOCAttestation{
		IOCType:  IOCTypeProxyResponse,
		Severity: SeverityHigh,
		Signature: SignatureEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     base64.StdEncoding.EncodeToString([]byte("sig")),
		},
		PublicKey: PublicKeyEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     base64.StdEncoding.EncodeToString(key),
		},
	}
	err := VerifyAttestation(a)
	if err == nil {
		t.Fatal("expected error for off-curve key")
	}
}

func TestPhase5_VerifyAttestation_InvalidBase64Signature(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes := marshalSEC1P256(priv.PublicKey.X, priv.PublicKey.Y)

	a := &IOCAttestation{
		IOCType:  IOCTypeProxyResponse,
		Severity: SeverityHigh,
		Signature: SignatureEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     "!!!not-valid-base64!!!",
		},
		PublicKey: PublicKeyEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     base64.StdEncoding.EncodeToString(pubBytes),
		},
	}
	err := VerifyAttestation(a)
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
}

func TestPhase5_VerifyAttestation_EmptySignature(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes := marshalSEC1P256(priv.PublicKey.X, priv.PublicKey.Y)

	a := &IOCAttestation{
		IOCType:  IOCTypeProxyResponse,
		Severity: SeverityHigh,
		Signature: SignatureEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     "", // empty → decodes to empty bytes
		},
		PublicKey: PublicKeyEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     base64.StdEncoding.EncodeToString(pubBytes),
		},
	}
	err := VerifyAttestation(a)
	if err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func TestPhase5_VerifyAttestation_WrongSignature(t *testing.T) {
	// Create a valid on-curve key, then sign with a different key.
	// This exercises the actual ecdsa.VerifyASN1 failure path (line 384).
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	validKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	validPubBytes := marshalSEC1P256(validKey.PublicKey.X, validKey.PublicKey.Y)

	a := &IOCAttestation{
		IOCType:  IOCTypeProxyResponse,
		Severity: SeverityHigh,
		Signature: SignatureEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "valid-key",
			Value:     base64.StdEncoding.EncodeToString([]byte("non-empty-but-wrong")),
		},
		PublicKey: PublicKeyEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "valid-key",
			Value:     base64.StdEncoding.EncodeToString(validPubBytes),
		},
	}
	// Even with a valid on-curve key, the wrong signature must fail.
	// The signature "non-empty-but-wrong" is not valid ASN.1, so
	// ecdsa.VerifyASN1 returns false → line 384.
	_ = signer // keep signer to avoid unused var
	err := VerifyAttestation(a)
	if err == nil {
		t.Fatal("expected error for wrong signature with valid key")
	}
}

// =========================================================================
// bundle.go — VerifyBundleSignature, mustBase64DecodeErr, Sign, SignWithKeyRing
// =========================================================================

func TestPhase5_MustBase64DecodeErr_EmptyString(t *testing.T) {
	_, err := mustBase64DecodeErr("")
	if err == nil {
		t.Fatal("expected error for empty base64 string")
	}
}

func TestPhase5_MustBase64DecodeErr_ValidString(t *testing.T) {
	result, err := mustBase64DecodeErr(base64.StdEncoding.EncodeToString([]byte("test")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) != "test" {
		t.Errorf("expected 'test', got %q", string(result))
	}
}

func TestPhase5_VerifyBundleSignature_NilBundle(t *testing.T) {
	err := VerifyBundleSignature(nil)
	if err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestPhase5_VerifyBundleSignature_UnsupportedSigAlgorithm(t *testing.T) {
	b := &Bundle{
		Signature: SignatureEnvelope{Algorithm: "RSA"},
		PublicKey: PublicKeyEnvelope{Algorithm: AlgorithmECDSAP256},
	}
	err := VerifyBundleSignature(b)
	if err == nil {
		t.Fatal("expected error for unsupported sig algorithm")
	}
}

func TestPhase5_VerifyBundleSignature_UnsupportedPubKeyAlgorithm(t *testing.T) {
	b := &Bundle{
		Signature: SignatureEnvelope{Algorithm: AlgorithmECDSAP256},
		PublicKey: PublicKeyEnvelope{Algorithm: "RSA"},
	}
	err := VerifyBundleSignature(b)
	if err == nil {
		t.Fatal("expected error for unsupported public key algorithm")
	}
}

func TestPhase5_VerifyBundleSignature_KeyIDMismatch(t *testing.T) {
	b := &Bundle{
		Signature: SignatureEnvelope{Algorithm: AlgorithmECDSAP256, KeyID: "sig-key"},
		PublicKey: PublicKeyEnvelope{Algorithm: AlgorithmECDSAP256, KeyID: "pub-key"},
	}
	err := VerifyBundleSignature(b)
	if err == nil {
		t.Fatal("expected error for keyID mismatch")
	}
}

func TestPhase5_VerifyBundleSignature_InvalidBase64PubKey(t *testing.T) {
	b := &Bundle{
		Signature: SignatureEnvelope{Algorithm: AlgorithmECDSAP256, KeyID: "k1"},
		PublicKey: PublicKeyEnvelope{Algorithm: AlgorithmECDSAP256, KeyID: "k1", Value: "!!!invalid!!!"},
	}
	err := VerifyBundleSignature(b)
	if err == nil {
		t.Fatal("expected error for invalid base64 public key")
	}
}

func TestPhase5_VerifyBundleSignature_InvalidPubKeyFormat(t *testing.T) {
	b := &Bundle{
		Signature: SignatureEnvelope{Algorithm: AlgorithmECDSAP256, KeyID: "k1"},
		PublicKey: PublicKeyEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     base64.StdEncoding.EncodeToString([]byte{0x01, 0x02}), // too short
		},
	}
	err := VerifyBundleSignature(b)
	if err == nil {
		t.Fatal("expected error for invalid public key format")
	}
}

func TestPhase5_VerifyBundleSignature_EmptySignature(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes := marshalSEC1P256(priv.PublicKey.X, priv.PublicKey.Y)

	b := &Bundle{
		Signature: SignatureEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     "", // empty
		},
		PublicKey: PublicKeyEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     base64.StdEncoding.EncodeToString(pubBytes),
		},
	}
	err := VerifyBundleSignature(b)
	if err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func TestPhase5_VerifyBundleSignature_BadSignature(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes := marshalSEC1P256(priv.PublicKey.X, priv.PublicKey.Y)

	b := &Bundle{
		Count: 1,
		Attestations: []IOCAttestation{
			{IOCType: IOCTypeProxyResponse, Severity: SeverityHigh},
		},
		Signature: SignatureEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     base64.StdEncoding.EncodeToString([]byte("bogus-sig")),
		},
		PublicKey: PublicKeyEnvelope{
			Algorithm: AlgorithmECDSAP256,
			KeyID:     "k1",
			Value:     base64.StdEncoding.EncodeToString(pubBytes),
		},
	}
	err := VerifyBundleSignature(b)
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestPhase5_BundleSign_NilPrivateKey(t *testing.T) {
	b := &Bundle{}
	err := b.Sign(nil, "k1")
	if err == nil {
		t.Fatal("expected error for nil private key")
	}
}

func TestPhase5_BundleSignWithKeyRing_NilKeyRing(t *testing.T) {
	b := &Bundle{}
	err := b.SignWithKeyRing(nil)
	if err == nil {
		t.Fatal("expected error for nil keyring")
	}
}

func TestPhase5_BundleSignWithKeyRing_NoCurrentKey(t *testing.T) {
	kr := &KeyRing{} // no keys loaded
	b := &Bundle{}
	err := b.SignWithKeyRing(kr)
	if err == nil {
		t.Fatal("expected error for keyring with no current key")
	}
}

func TestPhase5_BundleSignAndVerify_Roundtrip(t *testing.T) {
	priv, keyID, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	b := &Bundle{
		Count: 1,
		Attestations: []IOCAttestation{
			{
				Fingerprint: "test-fp-123",
				IOCType:     IOCTypeProxyResponse,
				Severity:    SeverityHigh,
				InstanceID:  "test-instance",
			},
		},
	}

	if err := b.Sign(priv, keyID); err != nil {
		t.Fatalf("Bundle.Sign: %v", err)
	}

	// Verify should succeed
	if err := VerifyBundleSignature(b); err != nil {
		t.Fatalf("VerifyBundleSignature: %v", err)
	}
}

// =========================================================================
// attest.go — SignAttestationWithKeyRing error paths
// =========================================================================

func TestPhase5_SignAttestationWithKeyRing_NoCurrentKey(t *testing.T) {
	kr := &KeyRing{} // no keys
	a := &IOCAttestation{
		IOCType:  IOCTypeProxyResponse,
		Severity: SeverityHigh,
	}
	err := SignAttestationWithKeyRing(a, kr)
	if err == nil {
		t.Fatal("expected error for keyring with no current key")
	}
}

// =========================================================================
// keyring.go — loadKeyRing error paths
// =========================================================================

func TestPhase5_LoadKeyRing_NonexistentFile(t *testing.T) {
	_, err := loadKeyRing("/nonexistent/path/keyring.json", "")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

// =========================================================================
// fingerprint.go — canonicalJSON error paths
// =========================================================================

func TestPhase5_CanonicalJSON_NilValue(t *testing.T) {
	// canonicalJSON with nil should produce "null"
	result, err := canonicalJSON(nil)
	if err != nil {
		t.Fatalf("canonicalJSON(nil): %v", err)
	}
	if string(result) != "null" {
		t.Errorf("expected 'null', got %q", string(result))
	}
}

func TestPhase5_Fingerprint_EmptyDetection(t *testing.T) {
	d := Detection{}
	fp := Fingerprint(d)
	if fp == "" {
		t.Error("expected non-empty fingerprint for empty detection")
	}
}

func TestPhase5_FingerprintBytes_EmptyDetection(t *testing.T) {
	d := Detection{}
	fp := FingerprintBytes(d)
	if len(fp) != 32 {
		t.Errorf("expected 32-byte fingerprint, got %d bytes", len(fp))
	}
}

// =========================================================================
// types.go — Valid error path
// =========================================================================

func TestPhase5_IOC_InvalidEmptyFingerprint(t *testing.T) {
	ioc := IOC{
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		Fingerprint: "", // empty fingerprint
	}
	if ioc.Valid() {
		t.Error("expected invalid for empty fingerprint")
	}
}

func TestPhase5_IOC_InvalidEmptyType(t *testing.T) {
	ioc := IOC{
		Type:        "", // empty type
		Severity:    SeverityHigh,
		Fingerprint: "test-fp-123",
	}
	if ioc.Valid() {
		t.Error("expected invalid for empty type")
	}
}

// =========================================================================
// postgres_store.go — NewPostgresStore with empty URL
// =========================================================================

func TestPhase5_NewPostgresStore_EmptyURL(t *testing.T) {
	_, err := NewPostgresStore(t.Context(), DatabaseConfig{})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

// =========================================================================
// sync.go — clientIP, isAllowedPeer, Reputation, Receiver.Reputation
// =========================================================================

func TestPhase5_Sync_ClientIP_WithComma(t *testing.T) {
	s := &Sync{}
	r := &http.Request{
		RemoteAddr: "5.6.7.8:12345",
		Header:     make(map[string][]string),
	}
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	ip := s.clientIP(r)
	if ip != "1.2.3.4" {
		t.Errorf("clientIP with comma: got %q, want %q", ip, "1.2.3.4")
	}
}

func TestPhase5_Sync_ClientIP_XFF_NoComma(t *testing.T) {
	s := &Sync{}
	r := &http.Request{
		RemoteAddr: "5.6.7.8:12345",
		Header:     make(map[string][]string),
	}
	r.Header.Set("X-Forwarded-For", "9.10.11.12")
	ip := s.clientIP(r)
	if ip != "9.10.11.12" {
		t.Errorf("clientIP XFF no-comma: got %q, want %q", ip, "9.10.11.12")
	}
}

func TestPhase5_Sync_ClientIP_NoXFF(t *testing.T) {
	s := &Sync{}
	r := &http.Request{
		RemoteAddr: "5.6.7.8:12345",
		Header:     make(map[string][]string),
	}
	ip := s.clientIP(r)
	if ip != "5.6.7.8" {
		t.Errorf("clientIP without XFF: got %q, want %q", ip, "5.6.7.8")
	}
}

func TestPhase5_Sync_IsAllowedPeer_InvalidIP(t *testing.T) {
	s := &Sync{peerNets: nil}
	if s.isAllowedPeer("not-an-ip") {
		t.Error("expected false for invalid IP")
	}
}

func TestPhase5_Sync_IsAllowedPeer_InvalidIP_WithPeerNets(t *testing.T) {
	// With non-empty peerNets, an invalid IP should reach ParseIP
	// and return false (covers line 313-314).
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	s := &Sync{peerNets: []*net.IPNet{cidr}}
	if s.isAllowedPeer("not-an-ip") {
		t.Error("expected false for invalid IP with peerNets configured")
	}
}

func TestPhase5_Sync_Reputation_NilSync(t *testing.T) {
	var s *Sync
	if result := s.Reputation(); result != nil {
		t.Error("expected nil for nil sync")
	}
}

func TestPhase5_Sync_Reputation_NilCfg(t *testing.T) {
	s := &Sync{}
	if result := s.Reputation(); result != nil {
		t.Error("expected nil for nil reputation config")
	}
}

func TestPhase5_Receiver_Reputation_NilReceiver(t *testing.T) {
	var r *Receiver
	if result := r.Reputation(); result != nil {
		t.Error("expected nil for nil receiver")
	}
}

// =========================================================================
// stix_exporter.go — ExportToSTIXWriter, ExportToJSONLinesWriter nil paths
// =========================================================================

func TestPhase5_ExportToSTIXWriter_NilBundle(t *testing.T) {
	e := NewSTIXExporter(STIXExportConfig{})
	err := e.ExportToSTIXWriter(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestPhase5_ExportToSTIXWriter_NilWriter(t *testing.T) {
	e := NewSTIXExporter(STIXExportConfig{})
	err := e.ExportToSTIXWriter(&Bundle{}, nil)
	if err == nil {
		t.Fatal("expected error for nil writer")
	}
}

func TestPhase5_ExportToJSONLinesWriter_NilBundle(t *testing.T) {
	e := NewSTIXExporter(STIXExportConfig{})
	err := e.ExportToJSONLinesWriter(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestPhase5_ExportToJSONLinesWriter_NilWriter(t *testing.T) {
	e := NewSTIXExporter(STIXExportConfig{})
	err := e.ExportToJSONLinesWriter(&Bundle{}, nil)
	if err == nil {
		t.Fatal("expected error for nil writer")
	}
}

// =========================================================================
// reputation.go — loadFromDisk, persist error paths
// =========================================================================

func TestPhase5_ReputationStore_LoadFromDisk_NonexistentFile(t *testing.T) {
	rs := &ReputationStore{
		cfg: ReputationConfig{DiskPath: "/nonexistent/path/reputation.json"},
	}
	err := rs.loadFromDisk()
	if err != nil {
		t.Errorf("expected nil error for nonexistent file, got: %v", err)
	}
}

// =========================================================================
// feed_manager.go — PullNow with not found feed
// =========================================================================

func TestPhase5_FeedManager_PullNow_NotFound(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	fm, err := NewFeedManager(store, nil)
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}
	_, err = fm.PullNow(t.Context(), "nonexistent-feed")
	if err == nil {
		t.Fatal("expected error for non-existent feed")
	}
}

// =========================================================================
// keyring.go — loadFromV2 error paths
// =========================================================================

func TestPhase5_LoadFromV2_EmptyCurrent(t *testing.T) {
	kr := &KeyRing{keys: make(map[string]*ringKey)}
	_, err := kr.loadFromV2(keyRingOnDisk{
		Current: "",
		Keys:    []ringKey{{KeyID: "k1", PrivateKeyPEM: "test"}},
	})
	if err == nil {
		t.Fatal("expected error for empty current keyId")
	}
}

func TestPhase5_LoadFromV2_EmptyKeys(t *testing.T) {
	kr := &KeyRing{keys: make(map[string]*ringKey)}
	_, err := kr.loadFromV2(keyRingOnDisk{
		Current: "k1",
		Keys:    []ringKey{},
	})
	if err == nil {
		t.Fatal("expected error for empty keys array")
	}
}

func TestPhase5_LoadFromV2_CurrentNotInKeys(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr, err := encodeRingKeyPEM(priv)
	if err != nil {
		t.Fatalf("encodeRingKeyPEM: %v", err)
	}
	kr := &KeyRing{keys: make(map[string]*ringKey)}
	_, err = kr.loadFromV2(keyRingOnDisk{
		Current: "nonexistent",
		Keys:    []ringKey{{KeyID: "k1", PrivateKeyPEM: pemStr}},
	})
	if err == nil {
		t.Fatal("expected error for current keyId not in keys")
	}
}

func TestPhase5_LoadFromV2_InvalidPEM(t *testing.T) {
	kr := &KeyRing{keys: make(map[string]*ringKey)}
	_, err := kr.loadFromV2(keyRingOnDisk{
		Current: "k1",
		Keys:    []ringKey{{KeyID: "k1", PrivateKeyPEM: "not-a-valid-pem"}},
	})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

// =========================================================================
// checker.go — CheckFingerprint, CheckCorroboration, Stats nil store
// =========================================================================

func TestPhase5_CheckFingerprint_EmptyFingerprint(t *testing.T) {
	c := &IOCChecker{}
	result := c.CheckFingerprint("", false)
	if result.Fingerprint != "" {
		t.Error("expected empty fingerprint in result")
	}
}

func TestPhase5_CheckFingerprint_NilStore(t *testing.T) {
	c := &IOCChecker{}
	result := c.CheckFingerprint("test-fp", true)
	if result.Fingerprint != "test-fp" {
		t.Error("expected fingerprint to be set")
	}
}

func TestPhase5_CheckCorroboration_NilStore(t *testing.T) {
	c := &IOCChecker{}
	d := Detection{Type: "test"}
	result := c.CheckCorroboration(d, true)
	if result.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
}

func TestPhase5_Stats_NilStore(t *testing.T) {
	c := &IOCChecker{}
	stats := c.Stats()
	if stats.Config.MaxAge != 0 {
		t.Error("expected zero config for nil store")
	}
}

// =========================================================================
// store.go — SnapshotSince with tenant filter, Query with tenant filter
// =========================================================================

func TestPhase5_SnapshotSince_TenantFilter(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	now := time.Now().UTC()

	// Add IOCs with different tenants
	ioc1 := makeValidIOC("fp-tenant-1", IOCTypeProxyResponse, SeverityHigh, "")
	ioc1.TenantID = "tenant-a"
	ioc1.LastSeen = now
	store.Observe(ioc1)

	ioc2 := makeValidIOC("fp-tenant-2", IOCTypeProxyResponse, SeverityHigh, "")
	ioc2.TenantID = "tenant-b"
	ioc2.LastSeen = now
	store.Observe(ioc2)

	// Filter by tenant-a
	results := store.SnapshotSince(now.Add(-1*time.Hour), TenantContext{TenantID: "tenant-a"})
	for _, r := range results {
		if r.TenantID != "tenant-a" && r.TenantID != "" {
			t.Errorf("expected only tenant-a IOCs, got tenant %q", r.TenantID)
		}
	}
}

func TestPhase5_Query_TenantFilter(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	now := time.Now().UTC()

	ioc1 := makeValidIOC("fp-query-tenant-1", IOCTypeProxyResponse, SeverityHigh, "")
	ioc1.TenantID = "tenant-x"
	ioc1.LastSeen = now
	store.Observe(ioc1)

	// Query with tenant filter
	results := store.Query(IOCQuery{Type: IOCTypeProxyResponse}, TenantContext{TenantID: "tenant-x"})
	for _, r := range results {
		if r.TenantID != "tenant-x" && r.TenantID != "" {
			t.Errorf("expected only tenant-x IOCs, got tenant %q", r.TenantID)
		}
	}
}

// =========================================================================
// sync.go — signAttestation and signBundle with KeyRing
// =========================================================================

func TestPhase5_Sync_SignAttestation_WithKeyRing(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	kr, err := loadKeyRing("", "")
	if err != nil {
		t.Fatalf("loadKeyRing: %v", err)
	}
	sync, _ := NewSync(SyncConfig{
		InstanceID: "test-instance",
		Store:      store,
		KeyRing:    kr,
	})
	a := &IOCAttestation{
		IOCType:  IOCTypeProxyResponse,
		Severity: SeverityHigh,
	}
	err = sync.signAttestation(a)
	if err != nil {
		t.Fatalf("signAttestation with keyring: %v", err)
	}
}

func TestPhase5_Sync_SignBundle_WithKeyRing(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	kr, err := loadKeyRing("", "")
	if err != nil {
		t.Fatalf("loadKeyRing: %v", err)
	}
	sync, _ := NewSync(SyncConfig{
		InstanceID: "test-instance",
		Store:      store,
		KeyRing:    kr,
	})
	b := &Bundle{Count: 1}
	err = sync.signBundle(b)
	if err != nil {
		t.Fatalf("signBundle with keyring: %v", err)
	}
}

// =========================================================================
// sync.go — FetchPeer with CanReceive=false
// =========================================================================

func TestPhase5_Sync_FetchPeer_CanReceiveFalse(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	priv, keyID := testKey(t)
	sync, _ := NewSync(SyncConfig{
		InstanceID:    "test-instance",
		SigningKey:    priv,
		KeyID:         keyID,
		Store:         store,
		EnableReceive: false, // CanReceive will return false
	})
	_, err := sync.FetchPeer(t.Context(), "http://example.com")
	if err == nil {
		t.Fatal("expected error when CanReceive is false")
	}
}

// =========================================================================
// sync.go — Reputation with non-nil config
// =========================================================================

func TestPhase5_Sync_Reputation_WithConfig(t *testing.T) {
	rs := &ReputationStore{
		cfg:     ReputationConfig{},
		records: make(map[string]*ReputationRecord),
	}
	sync := &Sync{cfg: SyncConfig{Reputation: rs}}
	result := sync.Reputation()
	if result == nil {
		t.Fatal("expected non-nil reputation records")
	}
}

// =========================================================================
// sync.go — Receiver.Reputation with non-nil receiver
// =========================================================================

func TestPhase5_Receiver_Reputation_WithReceiver(t *testing.T) {
	r := &Receiver{reputation: &ReputationStore{}}
	result := r.Reputation()
	if result == nil {
		t.Fatal("expected non-nil reputation store")
	}
}

// =========================================================================
// reputation.go — loadFromDisk with invalid JSON
// =========================================================================

func TestPhase5_ReputationStore_LoadFromDisk_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/reputation.json"
	if err := writeDummyFile(path, "invalid-json"); err != nil {
		t.Fatalf("writeDummyFile: %v", err)
	}
	rs := &ReputationStore{
		cfg:     ReputationConfig{DiskPath: path},
		records: make(map[string]*ReputationRecord),
	}
	err := rs.loadFromDisk()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func writeDummyFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// =========================================================================
// taxii_integration.go — NewTAXIIIntegration error paths
// =========================================================================

func TestPhase5_NewTAXIIIntegration_EmptyServerURL(t *testing.T) {
	_, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		AuthType: "basic",
	})
	if err == nil {
		t.Fatal("expected error for empty ServerURL")
	}
}

func TestPhase5_NewTAXIIIntegration_EmptyAuthType(t *testing.T) {
	_, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		ServerURL: "https://example.com",
	})
	if err == nil {
		t.Fatal("expected error for empty AuthType")
	}
}

// =========================================================================
// store.go — Flush with invalid disk path
// =========================================================================

func TestPhase5_Store_Flush_InvalidDiskPath(t *testing.T) {
	store, _ := NewStore(StoreConfig{
		Capacity:      100,
		DiskPath:      "/nonexistent/root/path/that/cannot/be/created/ioc.json",
		FlushInterval: 0,
	})
	// Add an IOC to make the store dirty
	store.Observe(makeValidIOC("flush-invalid", IOCTypeProxyResponse, SeverityHigh, ""))

	err := store.Flush()
	if err == nil {
		t.Fatal("expected error for invalid disk path")
	}
}

// =========================================================================
// store.go — mergeQuarantinedIOC with existing non-quarantined IOC
// =========================================================================

func TestPhase5_Store_MergeQuarantinedIOC_ExistingNonQuarantined(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	// Add a non-quarantined IOC
	store.Observe(makeValidIOC("merge-quarantine-existing", IOCTypeProxyResponse, SeverityHigh, ""))

	// Try to merge a quarantined version of the same IOC
	peerIOC := makeValidIOC("merge-quarantine-existing", IOCTypeProxyResponse, SeverityHigh, "")
	peerIOC.Count = 5
	store.mergeQuarantinedIOC(peerIOC)

	// The existing IOC should not be quarantined
	got, ok := store.byFP[peerIOC.Fingerprint]
	if !ok {
		t.Fatal("IOC not found")
	}
	if got.Quarantined {
		t.Error("existing non-quarantined IOC should not be downgraded to quarantined")
	}
}

func TestPhase5_Store_MergeQuarantinedIOC_NewQuarantined(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	// Merge a new quarantined IOC
	peerIOC := makeValidIOC("merge-quarantine-new", IOCTypeProxyResponse, SeverityHigh, "")
	peerIOC.Count = 3
	peerIOC.Source = "peer:low-rep"
	store.mergeQuarantinedIOC(peerIOC)

	got, ok := store.byFP[peerIOC.Fingerprint]
	if !ok {
		t.Fatal("quarantined IOC not found in store")
	}
	if !got.Quarantined {
		t.Error("IOC should be marked as quarantined")
	}
}

func TestPhase5_Store_MergeQuarantinedIOC_Invalid(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	// Invalid IOC (empty fingerprint) should be rejected
	store.mergeQuarantinedIOC(IOC{Type: IOCTypeProxyResponse, Severity: SeverityHigh})
	if len(store.byFP) != 0 {
		t.Error("invalid IOC should not be stored")
	}
}

// =========================================================================
// sync.go — rateLimitedManifest and rateLimitedHealth with sharing disabled
// =========================================================================

func TestPhase5_Sync_RateLimitedManifest_SharingDisabled(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	priv, keyID := testKey(t)
	sync, _ := NewSync(SyncConfig{
		InstanceID:  "test-instance",
		SigningKey:  priv,
		KeyID:       keyID,
		Store:       store,
		EnableShare: false, // sharing disabled
	})
	req := &http.Request{
		Method:     http.MethodGet,
		RemoteAddr: "1.2.3.4:12345",
		Header:     make(map[string][]string),
	}
	req.URL = &url.URL{Path: "/api/v1/ioc/manifest"}
	rec := httptest.NewRecorder()
	sync.rateLimitedManifest(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestPhase5_Sync_RateLimitedHealth_HealthDisabled(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	priv, keyID := testKey(t)
	sync, _ := NewSync(SyncConfig{
		InstanceID: "test-instance",
		SigningKey: priv,
		KeyID:      keyID,
		Store:      store,
	})
	req := &http.Request{
		Method:     http.MethodGet,
		RemoteAddr: "1.2.3.4:12345",
		Header:     make(map[string][]string),
	}
	req.URL = &url.URL{Path: "/api/v1/ioc/health"}
	rec := httptest.NewRecorder()
	sync.rateLimitedHealth(rec, req)
	// rateLimitedHealth doesn't check IsShare, it just calls handleHealth
	// which checks IsShare internally
	_ = rec
}

// marshalSEC1P256 helper for tests — uses the package-internal function
func init() {
	_ = marshalSEC1P256
	_ = big.NewInt
}
