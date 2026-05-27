// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Secure Key Storage
// =========================================================================

package identity

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
)

// Keystore provides secure storage for ECDSA private keys
type Keystore interface {
	Store(agentID string, key *ecdsa.PrivateKey) error
	Get(agentID string) (*ecdsa.PrivateKey, error)
	Delete(agentID string) error
	Exists(agentID string) bool
}

// memKeystore implements Keystore with in-memory storage
type memKeystore struct {
	mu   sync.RWMutex
	keys map[string]*ecdsa.PrivateKey
}

// New creates a new in-memory keystore
func New() Keystore {
	return &memKeystore{
		keys: make(map[string]*ecdsa.PrivateKey),
	}
}

func (ks *memKeystore) Store(agentID string, key *ecdsa.PrivateKey) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[agentID] = key
	return nil
}

func (ks *memKeystore) Get(agentID string) (*ecdsa.PrivateKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	key, exists := ks.keys[agentID]
	if !exists {
		return nil, fmt.Errorf("key not found for agent: %s", agentID)
	}
	return key, nil
}

func (ks *memKeystore) Delete(agentID string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	delete(ks.keys, agentID)
	return nil
}

func (ks *memKeystore) Exists(agentID string) bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	_, exists := ks.keys[agentID]
	return exists
}

// ExportPEM exports a private key as PEM-encoded string
func ExportPEM(key *ecdsa.PrivateKey) (string, error) {
	privBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})), nil
}

// ImportPEM imports a PEM-encoded private key
func ImportPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}
	return key, nil
}
