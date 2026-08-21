// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — DSAR (Data Subject Access Request) Service (v4.3.1)
//
// dsar.go provides GDPR Articles 15-20 compliance: right to access
// (data export), right to erasure (right to be forgotten), and
// right to portability (machine-readable export).
//
// The service queries all platform data stores for a given user/agent
// ID, produces a JSON export bundle, and optionally erases the data.
// Erasure is blocked if the entity is under legal hold.
//
// Design:
//   - DataProvider interface: each store implements Export + Erase
//   - Service registers providers at startup
//   - Export produces a structured JSON bundle
//   - Erase checks legal hold before deleting

package dsar

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// DataProvider is implemented by each platform data store that may
// hold user data. The DSAR service queries all registered providers.
type DataProvider interface {
	// Name returns the provider's identifier (e.g., "rbac", "audit").
	Name() string
	// Export returns all data associated with the given entity ID.
	Export(ctx context.Context, entityID string) (json.RawMessage, error)
	// Erase deletes or pseudonymises all data for the entity.
	// Returns the number of records affected.
	Erase(ctx context.Context, entityID string) (int, error)
}

// LegalHoldChecker checks if an entity is under legal hold.
// Implemented by pkg/legalhold.Service.
type LegalHoldChecker interface {
	IsUnderHold(ctx context.Context, entityID string) bool
}

// ExportBundle is the structured data export produced by DSAR.
type ExportBundle struct {
	EntityID   string                     `json:"entity_id"`
	ExportedAt time.Time                  `json:"exported_at"`
	Providers  map[string]json.RawMessage `json:"providers"`
}

// EraseResult records the outcome of an erasure request.
type EraseResult struct {
	EntityID        string         `json:"entity_id"`
	ErasedAt        time.Time      `json:"erased_at"`
	RecordsAffected int            `json:"records_affected"`
	Providers       map[string]int `json:"providers"`
	BlockedBy       string         `json:"blocked_by,omitempty"` // legal hold ID if blocked
}

// Service manages DSAR requests.
type Service struct {
	providers []DataProvider
	holdCheck LegalHoldChecker
	logger    *slog.Logger
}

// NewService creates a new DSAR service.
func NewService(holdCheck LegalHoldChecker, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default().With("component", "dsar")
	}
	return &Service{
		holdCheck: holdCheck,
		logger:    logger,
	}
}

// RegisterProvider adds a data provider to the DSAR service.
func (s *Service) RegisterProvider(p DataProvider) {
	s.providers = append(s.providers, p)
}

// Export produces a data export bundle for the given entity.
// This implements GDPR Article 15 (right of access) and Article 20
// (right to data portability).
func (s *Service) Export(ctx context.Context, entityID string) (*ExportBundle, error) {
	if entityID == "" {
		return nil, fmt.Errorf("entity_id is required")
	}

	bundle := &ExportBundle{
		EntityID:   entityID,
		ExportedAt: time.Now().UTC(),
		Providers:  make(map[string]json.RawMessage),
	}

	for _, p := range s.providers {
		data, err := p.Export(ctx, entityID)
		if err != nil {
			s.logger.Warn("DSAR export provider failed",
				"provider", p.Name(), "entity_id", entityID, "error", err)
			continue
		}
		if data != nil {
			bundle.Providers[p.Name()] = data
		}
	}

	s.logger.Info("DSAR export completed",
		"entity_id", entityID, "providers", len(bundle.Providers))
	return bundle, nil
}

// Erase deletes all data for the given entity, unless the entity
// is under legal hold. This implements GDPR Article 17 (right to
// erasure / right to be forgotten).
func (s *Service) Erase(ctx context.Context, entityID string) (*EraseResult, error) {
	if entityID == "" {
		return nil, fmt.Errorf("entity_id is required")
	}

	// Check legal hold first.
	if s.holdCheck != nil && s.holdCheck.IsUnderHold(ctx, entityID) {
		s.logger.Warn("DSAR erasure blocked by legal hold",
			"entity_id", entityID)
		return &EraseResult{
			EntityID:  entityID,
			BlockedBy: "legal_hold",
		}, fmt.Errorf("erasure blocked: entity %s is under legal hold", entityID)
	}

	result := &EraseResult{
		EntityID:  entityID,
		ErasedAt:  time.Now().UTC(),
		Providers: make(map[string]int),
	}

	totalAffected := 0
	for _, p := range s.providers {
		affected, err := p.Erase(ctx, entityID)
		if err != nil {
			s.logger.Warn("DSAR erase provider failed",
				"provider", p.Name(), "entity_id", entityID, "error", err)
			continue
		}
		result.Providers[p.Name()] = affected
		totalAffected += affected
	}

	result.RecordsAffected = totalAffected
	s.logger.Info("DSAR erasure completed",
		"entity_id", entityID, "records", totalAffected)
	return result, nil
}
