// SPDX-License-Identifier: Apache-2.0
//go:build !enterprise

// Package grpc provides a community-edition stub for the SIEM gRPC service.
// The real implementation lives in the enterprise build.

package grpc

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SIEMService is a stub for the community edition that returns Unimplemented
// for all SIEM operations.
type SIEMService struct {
	UnimplementedSIEMServiceServer
}

// NewSIEMService creates a no-op SIEMService in the community edition.
func NewSIEMService(_ SIEMBackend, _ *slog.Logger) *SIEMService {
	return &SIEMService{}
}

// GetConfig returns Unimplemented in the community edition.
func (s *SIEMService) GetConfig(_ context.Context, _ *GetSIEMConfigRequest) (*GetSIEMConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SIEM service is not available in the community build")
}

// GetStats returns Unimplemented in the community edition.
func (s *SIEMService) GetStats(_ context.Context, _ *GetSIEMStatsRequest) (*GetSIEMStatsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SIEM service is not available in the community build")
}

// GetEvents returns Unimplemented in the community edition.
func (s *SIEMService) GetEvents(_ context.Context, _ *GetSIEMEventsRequest) (*GetSIEMEventsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SIEM service is not available in the community build")
}

// SendEvent returns Unimplemented in the community edition.
func (s *SIEMService) SendEvent(_ context.Context, _ *SendSIEMEventRequest) (*SendSIEMEventResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SIEM service is not available in the community build")
}

// TestConnection returns Unimplemented in the community edition.
func (s *SIEMService) TestConnection(_ context.Context, _ *TestSIEMConnectionRequest) (*TestSIEMConnectionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SIEM service is not available in the community build")
}
