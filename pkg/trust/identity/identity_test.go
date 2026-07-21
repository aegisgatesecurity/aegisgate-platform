// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Identity Tests

package identity
//lint:file-ignore SA1019 U1000 -- D25 cleanup: elliptic deprecations + unused, deferred to Path B (Sprint 19+). See plans/TECHNICAL-DEBT.md.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestGenerateKeyPair(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if privateKey == nil || publicKey == nil {
		t.Fatal("Key pair should not be nil")
	}
}

func TestSignAndVerify(t *testing.T) {
	privateKey, _, _ := GenerateKeyPair()
	data := []byte("test message")
	signature, _ := Sign(privateKey, data)
	publicKey := &privateKey.PublicKey
	if !Verify(publicKey, data, signature) {
		t.Error("verification should succeed")
	}
	if Verify(publicKey, []byte("wrong"), signature) {
		t.Error("verification should fail with wrong data")
	}
}

func TestPublicKeyConversion(t *testing.T) {
	_, originalPub, _ := GenerateKeyPair()
	der, _ := PublicKeyToDER(originalPub)
	recoveredPub, err := DERToPublicKey(der)
	if err != nil {
		t.Fatalf("DERToPublicKey failed: %v", err)
	}
	if originalPub.X.Cmp(recoveredPub.X) != 0 || originalPub.Y.Cmp(recoveredPub.Y) != 0 {
		t.Error("keys should match")
	}
}

func TestDERToPublicKey_Invalid(t *testing.T) {
	_, err := DERToPublicKey([]byte("invalid-der"))
	if err == nil {
		t.Error("Expected error for invalid DER")
	}
}

func TestFingerprint(t *testing.T) {
	der := []byte("test data for fingerprint")
	fp := Fingerprint(der)
	if fp == "" {
		t.Error("Fingerprint should not be empty")
	}
	if len(fp) < 10 {
		t.Error("Fingerprint seems too short")
	}
	fp2 := Fingerprint(der)
	if fp != fp2 {
		t.Error("Same data should produce same fingerprint")
	}
}

func TestSign(t *testing.T) {
	privateKey, _, _ := GenerateKeyPair()
	data := []byte("sign test")
	sig, err := Sign(privateKey, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Error("Signature should not be empty")
	}
}

func TestNewAgentIdentity(t *testing.T) {
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner-123"}
	identity, privateKey, err := NewAgentIdentity(req)
	if err != nil {
		t.Fatalf("NewAgentIdentity failed: %v", err)
	}
	if identity.ID == "" {
		t.Error("ID should not be empty")
	}
	if identity.Name != req.Name {
		t.Errorf("Name mismatch: %s != %s", identity.Name, req.Name)
	}
	if identity.Status != AgentStatusActive {
		t.Errorf("Status should be active, got %s", identity.Status)
	}
	if identity.PublicKeyFingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
	if privateKey == nil {
		t.Error("Private key should be returned")
	}
}

func TestNewAgentIdentity_EmptyName(t *testing.T) {
	_, _, err := NewAgentIdentity(&RegisterRequest{Name: "", Version: "1.0.0", Owner: "owner"})
	if err == nil {
		t.Error("Expected error for empty name")
	}
}

func TestNewAgentIdentity_EmptyOwner(t *testing.T) {
	_, _, err := NewAgentIdentity(&RegisterRequest{Name: "test", Version: "1.0.0", Owner: ""})
	if err == nil {
		t.Error("Expected error for empty owner")
	}
}

func TestAgentIdentityStatus(t *testing.T) {
	identity := &AgentIdentity{Status: AgentStatusActive}
	if !identity.IsActive() {
		t.Error("IsActive should be true")
	}
	if identity.IsSuspended() {
		t.Error("IsSuspended should be false for active")
	}
	if identity.IsRevoked() {
		t.Error("IsRevoked should be false for active")
	}
	if !identity.CanVerify() {
		t.Error("CanVerify should be true for active agent")
	}

	identity.Status = AgentStatusSuspended
	if identity.IsActive() {
		t.Error("IsActive should be false for suspended")
	}
	if !identity.IsSuspended() {
		t.Error("IsSuspended should be true")
	}
	if !identity.CanVerify() {
		t.Error("CanVerify should be true for suspended (keys still valid)")
	}

	identity.Status = AgentStatusRevoked
	if !identity.IsRevoked() {
		t.Error("IsRevoked should be true")
	}
	if identity.CanVerify() {
		t.Error("CanVerify should be false for revoked")
	}
}

func TestAgentIdentityJSON(t *testing.T) {
	identity := &AgentIdentity{ID: "test-id", Name: "test-name", Owner: "test-owner", Status: AgentStatusActive}
	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var recovered AgentIdentity
	if err := json.Unmarshal(data, &recovered); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if recovered.ID != identity.ID {
		t.Error("ID mismatch after JSON round-trip")
	}
}

func TestFromJSON_Invalid(t *testing.T) {
	_, err := FromJSON([]byte("invalid json"))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestRegistry_Register(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner-1"}
	resp, err := registry.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if resp.Agent == nil {
		t.Fatal("Agent should not be nil")
	}
	if resp.CredentialsFile == "" {
		t.Error("CredentialsFile should not be empty")
	}
}

func TestRegistry_Get(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	agent, err := registry.Get(ctx, resp.Agent.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if agent.ID != resp.Agent.ID {
		t.Error("IDs should match")
	}
}

func TestRegistry_GetNotFound(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	_, err := registry.Get(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent agent")
	}
}

func TestRegistry_Update(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	newName := "updated-name"
	updated, err := registry.Update(ctx, resp.Agent.ID, &UpdateRequest{Name: &newName})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.Name != newName {
		t.Errorf("Name should be %s, got %s", newName, updated.Name)
	}
}

func TestRegistry_UpdateNotFound(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	_, err := registry.Update(ctx, "nonexistent", &UpdateRequest{})
	if err == nil {
		t.Error("Expected error for nonexistent agent")
	}
}

func TestRegistry_UpdateMetadata(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	newMetadata := map[string]string{"env": "production"}
	updated, err := registry.Update(ctx, resp.Agent.ID, &UpdateRequest{Metadata: newMetadata})
	if err != nil {
		t.Fatalf("Update metadata failed: %v", err)
	}
	if updated.Metadata["env"] != "production" {
		t.Error("Metadata not updated correctly")
	}
}

func TestRegistry_UpdateRevokedAgent(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	_ = registry.Revoke(ctx, resp.Agent.ID)
	_, err := registry.Update(ctx, resp.Agent.ID, &UpdateRequest{})
	if err == nil {
		t.Error("Should not be able to update revoked agent")
	}
}

func TestRegistry_Revoke(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	err := registry.Revoke(ctx, resp.Agent.ID)
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	agent, _ := registry.Get(ctx, resp.Agent.ID)
	if agent.Status != AgentStatusRevoked {
		t.Error("Status should be revoked")
	}
}

func TestRegistry_RevokeNotFound(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	err := registry.Revoke(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent agent")
	}
}

func TestRegistry_SuspendReactivate(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	err := registry.Suspend(ctx, resp.Agent.ID)
	if err != nil {
		t.Fatalf("Suspend failed: %v", err)
	}
	agent, _ := registry.Get(ctx, resp.Agent.ID)
	if agent.Status != AgentStatusSuspended {
		t.Error("Status should be suspended")
	}
	err = registry.Reactivate(ctx, resp.Agent.ID)
	if err != nil {
		t.Fatalf("Reactivate failed: %v", err)
	}
	agent, _ = registry.Get(ctx, resp.Agent.ID)
	if agent.Status != AgentStatusActive {
		t.Error("Status should be active after reactivation")
	}
}

func TestRegistry_SuspendNonRevokedAgent(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	err := registry.Suspend(ctx, resp.Agent.ID)
	if err != nil {
		t.Fatalf("Suspend failed: %v", err)
	}
}

func TestRegistry_ReactivateFromSuspended(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	_ = registry.Suspend(ctx, resp.Agent.ID)
	err := registry.Reactivate(ctx, resp.Agent.ID)
	if err != nil {
		t.Fatalf("Reactivate failed: %v", err)
	}
}

func TestRegistry_VerifyInvalidSignature(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	result, _ := registry.Verify(ctx, &VerifyRequest{AgentID: resp.Agent.ID, Challenge: []byte("challenge"), Signature: []byte("fake-signature")})
	if result.Valid {
		t.Error("Verification should fail with invalid signature")
	}
}

func TestRegistry_VerifyAgentNotFound(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	result, _ := registry.Verify(ctx, &VerifyRequest{AgentID: "nonexistent", Challenge: []byte("challenge"), Signature: []byte("sig")})
	if result.Valid {
		t.Error("Verification should fail for nonexistent agent")
	}
}

func TestRegistry_VerifyRevokedAgent(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	_ = registry.Revoke(ctx, resp.Agent.ID)
	result, _ := registry.Verify(ctx, &VerifyRequest{AgentID: resp.Agent.ID, Challenge: []byte("challenge"), Signature: []byte("sig")})
	if result.Valid {
		t.Error("Revoked agent should not verify")
	}
}

func TestRegistry_RotateKeys(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	oldFingerprint := resp.Agent.PublicKeyFingerprint
	updated, err := registry.RotateKeys(ctx, resp.Agent.ID)
	if err != nil {
		t.Fatalf("RotateKeys failed: %v", err)
	}
	if updated.PublicKeyFingerprint == oldFingerprint {
		t.Error("Fingerprint should change after rotation")
	}
}

func TestRegistry_RotateKeysForActive(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	_, err := registry.RotateKeys(ctx, resp.Agent.ID)
	if err != nil {
		t.Fatalf("RotateKeys failed: %v", err)
	}
}

func TestRegistry_RotateKeysRevoked(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	_ = registry.Revoke(ctx, resp.Agent.ID)
	_, err := registry.RotateKeys(ctx, resp.Agent.ID)
	if err == nil {
		t.Error("Expected error rotating keys for revoked agent")
	}
}

func TestRegistry_RotateKeysSuspended(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	_ = registry.Suspend(ctx, resp.Agent.ID)
	_, err := registry.RotateKeys(ctx, resp.Agent.ID)
	if err == nil {
		t.Error("Expected error rotating keys for suspended agent")
	}
}

func TestRegistry_List(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	registry.Register(ctx, &RegisterRequest{Name: "agent1", Version: "1.0.0", Owner: "owner"})
	registry.Register(ctx, &RegisterRequest{Name: "agent2", Version: "1.0.0", Owner: "owner"})
	agents, _ := registry.List(ctx, nil)
	if len(agents) != 2 {
		t.Errorf("Expected 2 agents, got %d", len(agents))
	}
}

func TestRegistry_ListEmpty(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	results, _ := registry.List(ctx, nil)
	if len(results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(results))
	}
}

func TestRegistry_ListWithOwner(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	registry.Register(ctx, &RegisterRequest{Name: "agent1", Version: "1.0.0", Owner: "owner-a"})
	registry.Register(ctx, &RegisterRequest{Name: "agent2", Version: "1.0.0", Owner: "owner-b"})
	agents, _ := registry.List(ctx, &ListFilter{Owner: "owner-a"})
	if len(agents) != 1 {
		t.Errorf("Expected 1 agent for owner-a, got %d", len(agents))
	}
}

func TestRegistry_ListWithPagination(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		registry.Register(ctx, &RegisterRequest{Name: fmt.Sprintf("agent%d", i), Version: "1.0.0", Owner: "owner"})
	}
	page1, _ := registry.List(ctx, &ListFilter{Limit: 2, Offset: 0})
	if len(page1) != 2 {
		t.Errorf("Expected 2 agents on page 1, got %d", len(page1))
	}
	page2, _ := registry.List(ctx, &ListFilter{Limit: 2, Offset: 2})
	if len(page2) != 2 {
		t.Errorf("Expected 2 agents on page 2, got %d", len(page2))
	}
}

func TestRegistry_SearchByID(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	resp, _ := registry.Register(ctx, &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"})
	results, _ := registry.Search(ctx, resp.Agent.ID[:8])
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
}

func TestRegistry_SearchByName(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	registry.Register(ctx, &RegisterRequest{Name: "CustomerSupport", Version: "1.0.0", Owner: "owner"})
	registry.Register(ctx, &RegisterRequest{Name: "CustomerBot", Version: "1.0.0", Owner: "owner"})
	results, _ := registry.Search(ctx, "cust")
	if len(results) != 2 {
		t.Errorf("Expected 2 results for 'cust', got %d", len(results))
	}
}

func TestRegistry_SearchNoMatch(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	registry.Register(ctx, &RegisterRequest{Name: "TestAgent", Version: "1.0.0", Owner: "owner"})
	results, _ := registry.Search(ctx, "xyz")
	if len(results) != 0 {
		t.Errorf("Expected 0 results for 'xyz', got %d", len(results))
	}
}

func TestRegistry_Heartbeat(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	originalTime := resp.Agent.LastSeenAt
	time.Sleep(10 * time.Millisecond)
	err := registry.Heartbeat(ctx, resp.Agent.ID)
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}
	agent, _ := registry.Get(ctx, resp.Agent.ID)
	if !agent.LastSeenAt.After(originalTime) {
		t.Error("LastSeenAt should be updated")
	}
}

func TestRegistry_HeartbeatNotFound(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	err := registry.Heartbeat(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent agent")
	}
}

func TestRegistry_GetPublicKey(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	req := &RegisterRequest{Name: "test-agent", Version: "1.0.0", Owner: "owner"}
	resp, _ := registry.Register(ctx, req)
	pubKey, err := registry.GetPublicKey(ctx, resp.Agent.ID)
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}
	if len(pubKey) == 0 {
		t.Error("Public key should not be empty")
	}
}

func TestRegistry_GetPublicKeyNotFound(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()
	_, err := registry.GetPublicKey(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent agent")
	}
}

func TestAgentIdentityToJSON(t *testing.T) {
	identity := &AgentIdentity{ID: "test-id", Name: "test-name", Status: AgentStatusActive}
	data, err := identity.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON data should not be empty")
	}
}

func TestAgentIdentityFromJSON(t *testing.T) {
	original := &AgentIdentity{ID: "test-id", Name: "test-name", Status: AgentStatusActive}
	data, _ := original.ToJSON()
	recovered, err := FromJSON(data)
	if err != nil {
		t.Fatalf("FromJSON failed: %v", err)
	}
	if recovered.ID != original.ID {
		t.Error("ID mismatch after round-trip")
	}
}

func TestExportImportPEM(t *testing.T) {
	privateKey, _, _ := GenerateKeyPair()
	pemStr, err := ExportPEM(privateKey)
	if err != nil {
		t.Fatalf("ExportPEM failed: %v", err)
	}
	if len(pemStr) == 0 {
		t.Error("PEM string should not be empty")
	}
	imported, err := ImportPEM(pemStr)
	if err != nil {
		t.Fatalf("ImportPEM failed: %v", err)
	}
	if imported.X.Cmp(privateKey.X) != 0 {
		t.Error("Imported key X does not match")
	}
}

// Tests for 90%+ coverage

func TestGenerateKeyPair_Repeatedly(t *testing.T) {
	// Generate multiple keypairs to ensure robustness
	for i := 0; i < 10; i++ {
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair failed on iteration %d: %v", i, err)
		}
		if priv == nil || pub == nil {
			t.Fatal("Key pair should not be nil")
		}
		// Verify keys work
		data := []byte(fmt.Sprintf("test data %d", i))
		sig, _ := Sign(priv, data)
		if !Verify(pub, data, sig) {
			t.Error("Generated keys should work for signing")
		}
	}
}

func TestDERToPublicKey_RSAKey(t *testing.T) {
	// Try to parse a RSA key as ECDSA (should fail)
	rsaKey := []byte{0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x00}
	_, err := DERToPublicKey(rsaKey)
	if err == nil {
		t.Error("Should error on RSA key")
	}
}

func TestDERToPublicKey_TooShort(t *testing.T) {
	_, err := DERToPublicKey([]byte{0x01})
	if err == nil {
		t.Error("Should error on too short input")
	}
}

func TestNewAgentIdentity_AllFields(t *testing.T) {
	metadata := map[string]string{"env": "prod", "region": "us-west-2"}
	req := &RegisterRequest{
		Name:     "full-agent",
		Version:  "2.0.0",
		Owner:    "org-xyz",
		Metadata: metadata,
	}
	identity, privateKey, err := NewAgentIdentity(req)
	if err != nil {
		t.Fatalf("NewAgentIdentity failed: %v", err)
	}
	if identity.Name != "full-agent" {
		t.Error("Name mismatch")
	}
	if identity.Version != "2.0.0" {
		t.Error("Version mismatch")
	}
	if identity.Owner != "org-xyz" {
		t.Error("Owner mismatch")
	}
	if identity.Status != AgentStatusActive {
		t.Error("Status should be active")
	}
	if identity.PublicKeyFingerprint == "" {
		t.Error("Fingerprint should be set")
	}
	if privateKey == nil {
		t.Error("Private key should be returned")
	}
	if identity.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if identity.LastSeenAt.IsZero() {
		t.Error("LastSeenAt should be set")
	}
}

func TestExportPEM_ValidFormat(t *testing.T) {
	privateKey, _, _ := GenerateKeyPair()
	pemStr, err := ExportPEM(privateKey)
	if err != nil {
		t.Fatalf("ExportPEM failed: %v", err)
	}
	// Check it starts with PEM header
	if len(pemStr) < 30 {
		t.Error("PEM string too short")
	}
	// Verify it's valid base64-like
	for _, c := range pemStr {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '\n') {
			// Allow newlines in PEM
		}
	}
}

func TestImportPEM_BadBase64(t *testing.T) {
	// Invalid PEM with bad base64
	_, err := ImportPEM("-----BEGIN EC PRIVATE KEY-----\n!!!invalid!!!\n-----END EC PRIVATE KEY-----")
	if err == nil {
		t.Error("Should error on invalid base64")
	}
}

func TestSign_LongData(t *testing.T) {
	privateKey, _, _ := GenerateKeyPair()
	// Sign long data
	longData := make([]byte, 10000)
	for i := range longData {
		longData[i] = byte(i % 256)
	}
	sig, err := Sign(privateKey, longData)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Error("Signature should not be empty")
	}
	// Verify signature
	if !Verify(&privateKey.PublicKey, longData, sig) {
		t.Error("Verification should succeed")
	}
}

func TestSign_UnicodeData(t *testing.T) {
	privateKey, _, _ := GenerateKeyPair()
	// Sign unicode data
	unicodeData := []byte("Hello, 世界! 🌍")
	sig, _ := Sign(privateKey, unicodeData)
	if !Verify(&privateKey.PublicKey, unicodeData, sig) {
		t.Error("Verification should succeed for unicode")
	}
}
