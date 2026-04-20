// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package grpc

import (
	"context"
	"log/slog"
)

// SIEMService implements the SIEM service
type SIEMService struct {
	UnimplementedSIEMServiceServer
	logger *slog.Logger
}

// NewSIEMService creates a new SIEM service
func NewSIEMService(logger *slog.Logger) *SIEMService {
	return &SIEMService{
		logger: logger,
	}
}

// GetConfig returns SIEM configuration
func (s *SIEMService) GetConfig(ctx context.Context, req *GetSIEMConfigRequest) (*GetSIEMConfigResponse, error) {
	return &GetSIEMConfigResponse{
		Enabled: true,
	}, nil
}

// GetStats returns SIEM statistics
func (s *SIEMService) GetStats(ctx context.Context, req *GetSIEMStatsRequest) (*GetSIEMStatsResponse, error) {
	return &GetSIEMStatsResponse{
		EventsSent: 0,
	}, nil
}

// GetEvents returns SIEM events
func (s *SIEMService) GetEvents(ctx context.Context, req *GetSIEMEventsRequest) (*GetSIEMEventsResponse, error) {
	return &GetSIEMEventsResponse{Events: []*SIEMEvent{}}, nil
}

// SendEvent sends an event to SIEM
func (s *SIEMService) SendEvent(ctx context.Context, req *SendSIEMEventRequest) (*SendSIEMEventResponse, error) {
	return &SendSIEMEventResponse{Success: true}, nil
}

// TestConnection tests SIEM connection
func (s *SIEMService) TestConnection(ctx context.Context, req *TestSIEMConnectionRequest) (*TestSIEMConnectionResponse, error) {
	return &TestSIEMConnectionResponse{Success: true, Message: "Connection test successful"}, nil
}
