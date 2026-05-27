// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Agent Identity Types
// =========================================================================

package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AgentStatus represents the current status of an agent
type AgentStatus string

const (
	AgentStatusRegistered AgentStatus = "registered"
	AgentStatusActive    AgentStatus = "active"
	AgentStatusSuspended AgentStatus = "suspended"
	AgentStatusRevoked   AgentStatus = "revoked"
)

// AgentIdentity represents a registered AI agent with cryptographic identity
type AgentIdentity struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Owner                string            `json:"owner"`
	PublicKey            []byte            `json:"-"` // Never expose in JSON
	PublicKeyFingerprint string            `json:"publicKeyFingerprint"`
	Status               AgentStatus       `json:"status"`
	Metadata             map[string]string `json:"metadata,omitempty"`
	CreatedAt            time.Time         `json:"createdAt"`
	LastSeenAt           time.Time         `json:"lastSeenAt"`
	SuspendedAt          *time.Time       `json:"suspendedAt,omitempty"`
	RevokedAt            *time.Time       `json:"revokedAt,omitempty"`
}

// RegisterRequest contains the information needed to register a new agent
type RegisterRequest struct {
	Name     string            `json:"name" validate:"required"`
	Version  string            `json:"version" validate:"required"`
	Owner    string            `json:"owner" validate:"required"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// RegisterResponse contains the registered agent info and credentials
type RegisterResponse struct {
	Agent           *AgentIdentity `json:"agent"`
	CredentialsFile string         `json:"credentialsFile"`
}

// UpdateRequest contains fields to update on an agent
type UpdateRequest struct {
	Name     *string           `json:"name,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// VerifyRequest contains a challenge/response for verification
type VerifyRequest struct {
	AgentID   string `json:"agentId" validate:"required"`
	Challenge []byte `json:"challenge" validate:"required"`
	Signature []byte `json:"signature" validate:"required"`
}

// VerifyResponse contains the verification result
type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// ListFilter contains optional filters for listing agents
type ListFilter struct {
	Owner  string       `json:"owner,omitempty"`
	Status AgentStatus `json:"status,omitempty"`
	Since  time.Time    `json:"since,omitempty"`
	Limit  int          `json:"limit,omitempty"`
	Offset int          `json:"offset,omitempty"`
}

// GenerateKeyPair generates a new ECDSA P-256 keypair
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}

// PublicKeyToDER converts an ECDSA public key to DER format
func PublicKeyToDER(pub *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

// DERToPublicKey converts a DER-encoded public key back to ECDSA
func DERToPublicKey(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}

	return ecdsaPub, nil
}

// Fingerprint returns the SHA-256 fingerprint of a public key
func Fingerprint(der []byte) string {
	hash := sha256.Sum256(der)
	return base64.URLEncoding.EncodeToString(hash[:])
}

// Sign signs data with an ECDSA private key
func Sign(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return sig, nil
}

// Verify verifies an ECDSA signature
func Verify(pub *ecdsa.PublicKey, data, sig []byte) bool {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(pub, hash[:], sig)
}

// NewAgentIdentity creates a new agent identity with generated keys
func NewAgentIdentity(req *RegisterRequest) (*AgentIdentity, *ecdsa.PrivateKey, error) {
	if req.Name == "" {
		return nil, nil, fmt.Errorf("name is required")
	}
	if req.Owner == "" {
		return nil, nil, fmt.Errorf("owner is required")
	}

	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	publicKeyDER, err := PublicKeyToDER(publicKey)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()

	return &AgentIdentity{
		ID:                   uuid.New().String(),
		Name:                 req.Name,
		Version:              req.Version,
		Owner:                req.Owner,
		PublicKey:            publicKeyDER,
		PublicKeyFingerprint: Fingerprint(publicKeyDER),
		Status:               AgentStatusActive,
		Metadata:             req.Metadata,
		CreatedAt:            now,
		LastSeenAt:           now,
	}, privateKey, nil
}

// ToJSON serializes the agent identity to JSON
func (ai *AgentIdentity) ToJSON() ([]byte, error) {
	return json.Marshal(ai)
}

// FromJSON deserializes an agent identity from JSON
func FromJSON(data []byte) (*AgentIdentity, error) {
	var ai AgentIdentity
	if err := json.Unmarshal(data, &ai); err != nil {
		return nil, fmt.Errorf("failed to unmarshal agent identity: %w", err)
	}
	return &ai, nil
}

// IsActive returns true if the agent is active
func (ai *AgentIdentity) IsActive() bool {
	return ai.Status == AgentStatusActive
}

// IsSuspended returns true if the agent is suspended
func (ai *AgentIdentity) IsSuspended() bool {
	return ai.Status == AgentStatusSuspended
}

// IsRevoked returns true if the agent is revoked
func (ai *AgentIdentity) IsRevoked() bool {
	return ai.Status == AgentStatusRevoked
}

// CanVerify returns true if the agent can be verified (not revoked)
func (ai *AgentIdentity) CanVerify() bool {
	return ai.Status != AgentStatusRevoked
}
