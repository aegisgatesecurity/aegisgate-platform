// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC SIEM Service Implementation
// =========================================================================

package grpc

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SIEMService implements SIEMServiceServer using a SIEMBackend.
type SIEMService struct {
	UnimplementedSIEMServiceServer
	backend SIEMBackend
	logger  *slog.Logger
}

// NewSIEMService creates a new SIEMService with the given backend.
func NewSIEMService(backend SIEMBackend, logger *slog.Logger) *SIEMService {
	return &SIEMService{backend: backend, logger: logger}
}

// GetConfig returns SIEM configuration.
func (s *SIEMService) GetConfig(ctx context.Context, req *GetSIEMConfigRequest) (*GetSIEMConfigResponse, error) {
	cfg, err := s.backend.GetConfig(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get SIEM config: %v", err)
	}

	return &GetSIEMConfigResponse{
		Enabled:       cfg.Enabled,
		BatchSize:     cfg.BatchSize,
		BatchInterval: cfg.BatchInterval,
		RetryAttempts: cfg.RetryAttempts,
		RetryInterval: cfg.RetryInterval,
	}, nil
}

// GetStats returns SIEM statistics.
func (s *SIEMService) GetStats(ctx context.Context, req *GetSIEMStatsRequest) (*GetSIEMStatsResponse, error) {
	stats, err := s.backend.GetStats(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get SIEM stats: %v", err)
	}

	return &GetSIEMStatsResponse{
		EventsSent:    stats.EventsSent,
		EventsDropped: stats.EventsDropped,
		EventsQueued:  stats.EventsQueued,
		LastSendTime:  stats.LastSendTime,
		LastError:     stats.LastError,
	}, nil
}

// GetEvents returns SIEM events.
func (s *SIEMService) GetEvents(ctx context.Context, req *GetSIEMEventsRequest) (*GetSIEMEventsResponse, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = 100 // default limit
	}

	events, err := s.backend.GetEvents(ctx, limit)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get SIEM events: %v", err)
	}

	result := make([]*SIEMEvent, 0, len(events))
	for _, e := range events {
		result = append(result, &SIEMEvent{
			Id:        e.ID,
			Timestamp: e.Timestamp,
			Source:    e.Source,
			Category:  e.Category,
			Type:      e.Type,
			Severity:  e.Severity,
			Message:   e.Message,
			Entity:    e.Entity,
		})
	}

	return &GetSIEMEventsResponse{Events: result}, nil
}

// SendEvent sends an event to SIEM.
func (s *SIEMService) SendEvent(ctx context.Context, req *SendSIEMEventRequest) (*SendSIEMEventResponse, error) {
	if req.Source == "" {
		return nil, status.Errorf(codes.InvalidArgument, "source is required")
	}

	err := s.backend.SendEvent(ctx, req.Source, req.Category, req.Type, req.Severity, req.Message, req.Entity)
	if err != nil {
		return &SendSIEMEventResponse{Success: false, Error: err.Error()}, nil
	}

	return &SendSIEMEventResponse{Success: true}, nil
}

// TestConnection tests the SIEM connection.
func (s *SIEMService) TestConnection(ctx context.Context, req *TestSIEMConnectionRequest) (*TestSIEMConnectionResponse, error) {
	success, message, err := s.backend.TestConnection(ctx, req.Platform)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SIEM connection test failed: %v", err)
	}

	return &TestSIEMConnectionResponse{
		Success: success,
		Message: message,
	}, nil
}
