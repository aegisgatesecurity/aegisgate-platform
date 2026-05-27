package attestation

import (
	"context"
	"fmt"
	"sync"
)

// Service provides attestation functionality
type Service struct {
	mu           sync.RWMutex
	attestations map[string]*Attestation
	generator    *Generator
	validator    *Validator
}

// NewService creates a new attestation service
func NewService() (*Service, error) {
	gen, err := NewGenerator()
	if err != nil {
		return nil, err
	}

	return &Service{
		attestations: make(map[string]*Attestation),
		generator:    gen,
		validator:    NewValidator(),
	}, nil
}

// CreateAttestation creates a new attestation
func (s *Service) CreateAttestation(ctx context.Context, req *AttestationRequest, contract *ContractSummary, metrics *MetricsSummary) (*Attestation, error) {
	att, err := s.generator.Generate(req, contract, metrics)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %w", err)
	}

	s.mu.Lock()
	s.attestations[att.ID] = att
	s.mu.Unlock()

	return att, nil
}

// GetAttestation retrieves an attestation by ID
func (s *Service) GetAttestation(ctx context.Context, id string) (*Attestation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	att, exists := s.attestations[id]
	if !exists {
		return nil, fmt.Errorf("attestation not found: %s", id)
	}
	return att, nil
}

// VerifyAttestation verifies an attestation
func (s *Service) VerifyAttestation(ctx context.Context, att *Attestation) (*AttestationResult, error) {
	return s.validator.Verify(att)
}

// ListByAgent lists attestations for an agent
func (s *Service) ListByAgent(ctx context.Context, agentID string) ([]*Attestation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Attestation
	for _, att := range s.attestations {
		if att.AgentID == agentID {
			result = append(result, att)
		}
	}
	return result, nil
}

// RevokeAttestation marks an attestation as expired
func (s *Service) RevokeAttestation(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	att, exists := s.attestations[id]
	if !exists {
		return fmt.Errorf("attestation not found: %s", id)
	}
	att.ExpiresAt = att.IssuedAt // Set expires to issued = effectively revoked
	return nil
}

// GenerateComplianceReport generates a compliance report for frameworks
func (s *Service) GenerateComplianceReport(ctx context.Context, agentID string, frameworks []Framework) (*ComplianceStatus, error) {
	attestations, err := s.ListByAgent(ctx, agentID)
	if err != nil {
		return nil, err
	}

	status := &ComplianceStatus{
		Framework: frameworks[0],
	}

	if len(attestations) == 0 {
		return status, nil
	}

	var totalPass, totalFail int
	for _, att := range attestations {
		for _, stmt := range att.Statements {
			if stmt.Passed {
				totalPass++
			} else {
				totalFail++
			}
		}
	}

	total := totalPass + totalFail
	if total > 0 {
		status.Score = float64(totalPass) / float64(total) * 100
	}
	status.ControlsPass = totalPass
	status.ControlsFail = totalFail
	status.ControlsTotal = total
	status.Compliant = status.Score >= 80.0
	status.LastAudit = attestations[0].IssuedAt
	status.NextAudit = attestations[0].ExpiresAt

	return status, nil
}
