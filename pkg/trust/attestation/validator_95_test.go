// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026, AegisGate Security - All rights reserved

package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

func signData(t *testing.T, privateKey *ecdsa.PrivateKey, data []byte) []byte {
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)
	return sig
}

func serializePublicKey(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
}

func TestVerifyWithPublicKey_Success(t *testing.T) {
	v := NewValidator()
	privateKey, publicKey := createTestKeyPair(t)

	att := &Attestation{
		ID:         "test-att-1",
		AgentID:    "agent-123",
		ContractID: "contract-456",
		Frameworks: []Framework{"SOC2", "HIPAA"},
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Statements: []Statement{
			{Type: "compliance", Description: "Test compliance", Passed: true},
			{Type: "security", Description: "Test security", Passed: true},
		},
		SignerPublicKey: serializePublicKey(publicKey),
	}

	data, _ := json.Marshal(map[string]interface{}{
		"id":         att.ID,
		"agentId":    att.AgentID,
		"contractId": att.ContractID,
		"frameworks": att.Frameworks,
		"issuedAt":   att.IssuedAt,
		"expiresAt":  att.ExpiresAt,
		"statements": att.Statements,
	})
	att.Signature = signData(t, privateKey, data)

	result, err := v.VerifyWithPublicKey(att, publicKey)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 2, result.StatementsPass)
	assert.Equal(t, 0, result.StatementsFail)
}

func TestVerifyWithPublicKey_Expired(t *testing.T) {
	v := NewValidator()
	privateKey, publicKey := createTestKeyPair(t)

	att := &Attestation{
		ID:              "test-att-2",
		AgentID:         "agent-123",
		ContractID:      "contract-456",
		IssuedAt:        time.Now().Add(-48 * time.Hour),
		ExpiresAt:       time.Now().Add(-24 * time.Hour),
		Statements:      []Statement{{Type: "test", Description: "Test", Passed: true}},
		SignerPublicKey: serializePublicKey(publicKey),
	}

	data, _ := json.Marshal(map[string]interface{}{
		"id":         att.ID,
		"agentId":    att.AgentID,
		"contractId": att.ContractID,
		"frameworks": att.Frameworks,
		"issuedAt":   att.IssuedAt,
		"expiresAt":  att.ExpiresAt,
		"statements": att.Statements,
	})
	att.Signature = signData(t, privateKey, data)

	result, err := v.VerifyWithPublicKey(att, publicKey)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Contains(t, result.Errors[0], "expired")
}

func TestVerifyWithPublicKey_InvalidSignature(t *testing.T) {
	v := NewValidator()
	wrongPrivateKey, _ := createTestKeyPair(t)
	_, publicKey := createTestKeyPair(t)

	att := &Attestation{
		ID:              "test-att-3",
		AgentID:         "agent-123",
		ContractID:      "contract-456",
		IssuedAt:        time.Now(),
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Statements:      []Statement{{Type: "test", Description: "Test", Passed: true}},
		SignerPublicKey: serializePublicKey(publicKey),
	}

	data, _ := json.Marshal(map[string]interface{}{
		"id":         att.ID,
		"agentId":    att.AgentID,
		"contractId": att.ContractID,
		"frameworks": att.Frameworks,
		"issuedAt":   att.IssuedAt,
		"expiresAt":  att.ExpiresAt,
		"statements": att.Statements,
	})
	att.Signature = signData(t, wrongPrivateKey, data)

	result, err := v.VerifyWithPublicKey(att, publicKey)
	require.NoError(t, err)
	assert.False(t, result.Valid)
}

func TestVerifyWithPublicKey_PartialStatements(t *testing.T) {
	v := NewValidator()
	privateKey, publicKey := createTestKeyPair(t)

	att := &Attestation{
		ID:         "test-att-4",
		AgentID:    "agent-123",
		ContractID: "contract-456",
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Statements: []Statement{
			{Type: "test", Description: "Test 1", Passed: true},
			{Type: "test", Description: "Test 2", Passed: true},
			{Type: "test", Description: "Test 3", Passed: false},
		},
		SignerPublicKey: serializePublicKey(publicKey),
	}

	data, _ := json.Marshal(map[string]interface{}{
		"id":         att.ID,
		"agentId":    att.AgentID,
		"contractId": att.ContractID,
		"frameworks": att.Frameworks,
		"issuedAt":   att.IssuedAt,
		"expiresAt":  att.ExpiresAt,
		"statements": att.Statements,
	})
	att.Signature = signData(t, privateKey, data)

	result, err := v.VerifyWithPublicKey(att, publicKey)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 2, result.StatementsPass)
	assert.Equal(t, 1, result.StatementsFail)
}

func TestValidateStatement_Success(t *testing.T) {
	v := NewValidator()
	stmt := &Statement{Type: "compliance", Description: "Valid statement", Passed: true}
	err := v.ValidateStatement(stmt)
	assert.NoError(t, err)
}

func TestValidateStatement_MissingType(t *testing.T) {
	v := NewValidator()
	stmt := &Statement{Description: "Missing type"}
	err := v.ValidateStatement(stmt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "type is required")
}

func TestValidateStatement_MissingDescription(t *testing.T) {
	v := NewValidator()
	stmt := &Statement{Type: "compliance"}
	err := v.ValidateStatement(stmt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "description is required")
}

func TestParseSignature_Valid(t *testing.T) {
	privateKey, _ := createTestKeyPair(t)
	data := []byte("test data")
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)

	r, s, err := ParseSignature(sig)
	require.NoError(t, err)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
	assert.True(t, r.Sign() > 0)
	assert.True(t, s.Sign() > 0)
}

func TestParseSignature_InvalidASN1(t *testing.T) {
	invalidSig := []byte("not valid asn1")
	r, s, err := ParseSignature(invalidSig)
	assert.Error(t, err)
	assert.Nil(t, r)
	assert.Nil(t, s)
}

func TestParseSignature_Empty(t *testing.T) {
	r, s, err := ParseSignature([]byte{})
	assert.Error(t, err)
	assert.Nil(t, r)
	assert.Nil(t, s)
}
