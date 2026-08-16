// SPDX-License-Identifier: Apache-2.0
//go:build !enterprise

// Package grpc provides the community-edition SIEM gRPC service.
//
// SIEM integration is an enterprise-tier feature. In the community
// edition, all SIEM RPCs return codes.Unimplemented with a descriptive
// error message. The type and method signatures exist for compilation
// compatibility with the enterprise build.
//
// The enterprise build (pkg/grpc/siem_service.go, build tag: enterprise)
// provides the full gRPC service implementation.

package grpc

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SIEMService implements the SIEM gRPC service. In the community edition,
// all methods return codes.Unimplemented.
type SIEMService struct {
	UnimplementedSIEMServiceServer
}

// NewSIEMService creates a SIEMService. In the community edition, the
// returned service returns Unimplemented for all RPCs.
func NewSIEMService(_ SIEMBackend, _ *slog.Logger) *SIEMService {
	return &SIEMService{}
}

// GetConfig returns Unimplemented in the community edition.
func (s *SIEMService) GetConfig(_ context.Context, _ *GetSIEMConfigRequest) (*GetSIEMConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SIEM service requires enterprise license — see https://aegisgate.dev/pricing")
}

// GetStats returns Unimplemented in the community edition.
func (s *SIEMService) GetStats(_ context.Context, _ *GetSIEMStatsRequest) (*GetSIEMStatsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SIEM service requires enterprise license — see https://aegisgate.dev/pricing")
}

// GetEvents returns Unimplemented in the community edition.
func (s *SIEMService) GetEvents(_ context.Context, _ *GetSIEMEventsRequest) (*GetSIEMEventsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SIEM service requires enterprise license — see https://aegisgate.dev/pricing")
}

// SendEvent returns Unimplemented in the community edition.
func (s *SIEMService) SendEvent(_ context.Context, _ *SendSIEMEventRequest) (*SendSIEMEventResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SIEM service requires enterprise license — see https://aegisgate.dev/pricing")
}

// TestConnection returns Unimplemented in the community edition.
func (s *SIEMService) TestConnection(_ context.Context, _ *TestSIEMConnectionRequest) (*TestSIEMConnectionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SIEM service requires enterprise license — see https://aegisgate.dev/pricing")
}
