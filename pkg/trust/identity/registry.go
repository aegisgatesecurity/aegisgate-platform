// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Agent Registry
// =========================================================================

package identity

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync"
	"time"
)

// Registry provides agent identity management
type Registry interface {
	Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)
	Get(ctx context.Context, agentID string) (*AgentIdentity, error)
	Update(ctx context.Context, agentID string, req *UpdateRequest) (*AgentIdentity, error)
	Revoke(ctx context.Context, agentID string) error
	Suspend(ctx context.Context, agentID string) error
	Reactivate(ctx context.Context, agentID string) error
	Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error)
	RotateKeys(ctx context.Context, agentID string) (*AgentIdentity, error)
	List(ctx context.Context, filter *ListFilter) ([]*AgentIdentity, error)
	Search(ctx context.Context, query string) ([]*AgentIdentity, error)
	Heartbeat(ctx context.Context, agentID string) error
	GetPublicKey(ctx context.Context, agentID string) ([]byte, error)
}

// inMemoryRegistry implements Registry with in-memory storage
type inMemoryRegistry struct {
	mu      sync.RWMutex
	agents  map[string]*AgentIdentity
	byOwner map[string][]string
	byFing  map[string]string
	keys    map[string]*ecdsa.PrivateKey
}

// NewRegistry creates a new in-memory registry
func NewRegistry() Registry {
	return &inMemoryRegistry{
		agents:  make(map[string]*AgentIdentity),
		byOwner: make(map[string][]string),
		byFing:  make(map[string]string),
		keys:    make(map[string]*ecdsa.PrivateKey),
	}
}

func (r *inMemoryRegistry) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	identity, privateKey, err := NewAgentIdentity(req)
	if err != nil {
		return nil, err
	}

	r.agents[identity.ID] = identity
	r.byOwner[identity.Owner] = append(r.byOwner[identity.Owner], identity.ID)
	r.byFing[identity.PublicKeyFingerprint] = identity.ID
	r.keys[identity.ID] = privateKey

	return &RegisterResponse{
		Agent:           identity,
		CredentialsFile: fmt.Sprintf("agent_%s_credentials.json", identity.ID),
	}, nil
}

func (r *inMemoryRegistry) Get(ctx context.Context, agentID string) (*AgentIdentity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	identity, exists := r.agents[agentID]
	if !exists {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}
	return identity, nil
}

func (r *inMemoryRegistry) Update(ctx context.Context, agentID string, req *UpdateRequest) (*AgentIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	identity, exists := r.agents[agentID]
	if !exists {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}
	if identity.Status == AgentStatusRevoked {
		return nil, fmt.Errorf("cannot update revoked agent")
	}
	if req.Name != nil {
		identity.Name = *req.Name
	}
	if req.Metadata != nil {
		if identity.Metadata == nil {
			identity.Metadata = make(map[string]string)
		}
		for k, v := range req.Metadata {
			identity.Metadata[k] = v
		}
	}
	return identity, nil
}

func (r *inMemoryRegistry) Revoke(ctx context.Context, agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	identity, exists := r.agents[agentID]
	if !exists {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	now := time.Now().UTC()
	identity.Status = AgentStatusRevoked
	identity.RevokedAt = &now
	delete(r.keys, agentID)
	return nil
}

func (r *inMemoryRegistry) Suspend(ctx context.Context, agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	identity, exists := r.agents[agentID]
	if !exists {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	if identity.Status == AgentStatusRevoked {
		return fmt.Errorf("cannot suspend revoked agent")
	}
	now := time.Now().UTC()
	identity.Status = AgentStatusSuspended
	identity.SuspendedAt = &now
	return nil
}

func (r *inMemoryRegistry) Reactivate(ctx context.Context, agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	identity, exists := r.agents[agentID]
	if !exists {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	if identity.Status != AgentStatusSuspended {
		return fmt.Errorf("agent is not suspended")
	}
	identity.Status = AgentStatusActive
	identity.SuspendedAt = nil
	return nil
}

func (r *inMemoryRegistry) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	r.mu.RLock()
	identity, exists := r.agents[req.AgentID]
	r.mu.RUnlock()

	if !exists {
		return &VerifyResponse{Valid: false, Message: "agent not found"}, nil
	}
	if !identity.CanVerify() {
		return &VerifyResponse{Valid: false, Message: fmt.Sprintf("agent is %s", identity.Status)}, nil
	}
	pub, err := DERToPublicKey(identity.PublicKey)
	if err != nil {
		return &VerifyResponse{Valid: false, Message: "failed to parse public key"}, nil
	}
	if !Verify(pub, req.Challenge, req.Signature) {
		return &VerifyResponse{Valid: false, Message: "invalid signature"}, nil
	}
	return &VerifyResponse{Valid: true, Message: "verification successful"}, nil
}

func (r *inMemoryRegistry) RotateKeys(ctx context.Context, agentID string) (*AgentIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	identity, exists := r.agents[agentID]
	if !exists {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}
	if identity.Status != AgentStatusActive {
		return nil, fmt.Errorf("can only rotate keys for active agents")
	}
	_, publicKey, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}
	publicKeyDER, err := PublicKeyToDER(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}
	delete(r.byFing, identity.PublicKeyFingerprint)
	identity.PublicKey = publicKeyDER
	identity.PublicKeyFingerprint = Fingerprint(publicKeyDER)
	r.byFing[identity.PublicKeyFingerprint] = identity.ID
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	r.keys[identity.ID] = privateKey
	return identity, nil
}

func (r *inMemoryRegistry) List(ctx context.Context, filter *ListFilter) ([]*AgentIdentity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if filter == nil {
		filter = &ListFilter{}
	}
	if filter.Limit == 0 {
		filter.Limit = 100
	}

	var result []*AgentIdentity
	for _, agent := range r.agents {
		if filter.Owner != "" && agent.Owner != filter.Owner {
			continue
		}
		if filter.Status != "" && agent.Status != filter.Status {
			continue
		}
		if !filter.Since.IsZero() && agent.CreatedAt.Before(filter.Since) {
			continue
		}
		result = append(result, agent)
	}

	if filter.Offset > 0 && filter.Offset < len(result) {
		result = result[filter.Offset:]
	} else if filter.Offset >= len(result) {
		result = []*AgentIdentity{}
	}
	if len(result) > filter.Limit {
		result = result[:filter.Limit]
	}
	return result, nil
}

func (r *inMemoryRegistry) Search(ctx context.Context, query string) ([]*AgentIdentity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*AgentIdentity
	limit := 20

	for _, agent := range r.agents {
		if len(query) <= len(agent.ID) && agent.ID[:len(query)] == query {
			result = append(result, agent)
		} else if len(query) <= len(agent.Name) {
			match := true
			for i := range query {
				qi := query[i]
				if qi >= 'A' && qi <= 'Z' {
					qi = qi + 32
				}
				ai := agent.Name[i]
				if ai >= 'A' && ai <= 'Z' {
					ai = ai + 32
				}
				if qi != ai {
					match = false
					break
				}
			}
			if match {
				result = append(result, agent)
			}
		}
		if len(result) >= limit {
			break
		}
	}
	return result, nil
}

func (r *inMemoryRegistry) Heartbeat(ctx context.Context, agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	identity, exists := r.agents[agentID]
	if !exists {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	identity.LastSeenAt = time.Now().UTC()
	return nil
}

func (r *inMemoryRegistry) GetPublicKey(ctx context.Context, agentID string) ([]byte, error) {
	r.mu.RLock()
	identity, exists := r.agents[agentID]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}
	return identity.PublicKey, nil
}
