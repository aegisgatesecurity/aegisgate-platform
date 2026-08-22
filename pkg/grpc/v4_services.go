// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — gRPC v4.3.1 Pipeline Services (DSAR, LegalHold, ABTest)
// =========================================================================
//
// v4_services.go implements the gRPC service handlers for the three new
// v4.3.1 pipelines. Each follows the same pattern as the existing services:
// a Server interface, an Unimplemented stub, a backend-backed implementation,
// and a RegisterHelper method.
// =========================================================================

package grpc

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ============================================================
// DSAR SERVICE
// ============================================================

// DSARServiceServer is the gRPC server interface for DSAR.
type DSARServiceServer interface {
	Export(context.Context, *DSARExportRequest) (*DSARExportResponse, error)
	Erase(context.Context, *DSAREraseRequest) (*DSAREraseResponse, error)
}

// DSARExportRequest is the request for DSAR export.
type DSARExportRequest struct {
	EntityID string `json:"entity_id"`
}

// DSAREraseRequest is the request for DSAR erase.
type DSAREraseRequest struct {
	EntityID string `json:"entity_id"`
}

// UnimplementedDSARServiceServer returns Unimplemented for all methods.
type UnimplementedDSARServiceServer struct{}

func (*UnimplementedDSARServiceServer) Export(_ context.Context, _ *DSARExportRequest) (*DSARExportResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Export not implemented")
}
func (*UnimplementedDSARServiceServer) Erase(_ context.Context, _ *DSAREraseRequest) (*DSAREraseResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Erase not implemented")
}

// DSARService implements DSARServiceServer using a DSARBackend.
type DSARService struct {
	UnimplementedDSARServiceServer
	backend DSARBackend
	logger  *slog.Logger
}

// NewDSARService creates a new DSARService with the given backend.
func NewDSARService(backend DSARBackend, logger *slog.Logger) *DSARService {
	return &DSARService{backend: backend, logger: logger}
}

// Export exports all data for an entity (GDPR Article 15).
func (s *DSARService) Export(ctx context.Context, req *DSARExportRequest) (*DSARExportResponse, error) {
	if req.EntityID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "entity_id is required")
	}
	resp, err := s.backend.Export(ctx, req.EntityID)
	if err != nil {
		s.logger.Error("gRPC DSAR export failed", "entity_id", req.EntityID, "error", err)
		return nil, status.Errorf(codes.Internal, "export failed: %v", err)
	}
	return resp, nil
}

// Erase deletes all data for an entity (GDPR Article 17).
func (s *DSARService) Erase(ctx context.Context, req *DSAREraseRequest) (*DSAREraseResponse, error) {
	if req.EntityID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "entity_id is required")
	}
	resp, err := s.backend.Erase(ctx, req.EntityID)
	if err != nil {
		if resp != nil && resp.BlockedBy == "legal_hold" {
			return resp, nil
		}
		s.logger.Error("gRPC DSAR erase failed", "entity_id", req.EntityID, "error", err)
		return nil, status.Errorf(codes.Internal, "erase failed: %v", err)
	}
	return resp, nil
}

// ============================================================
// LEGAL HOLD SERVICE
// ============================================================

// LegalHoldServiceServer is the gRPC server interface for Legal Hold.
type LegalHoldServiceServer interface {
	CreateHold(context.Context, *CreateHoldRequest) (*LegalHoldInfo, error)
	ReleaseHold(context.Context, *ReleaseHoldRequest) (*ReleaseHoldResponse, error)
	IsUnderHold(context.Context, *IsUnderHoldRequest) (*IsUnderHoldResponse, error)
	ListHolds(context.Context, *ListHoldsRequest) (*ListHoldsResponse, error)
	GetHold(context.Context, *GetHoldRequest) (*LegalHoldInfo, error)
}

// CreateHoldRequest is the request for creating a legal hold.
type CreateHoldRequest struct {
	EntityID   string `json:"entity_id"`
	EntityType string `json:"entity_type"`
	Reason     string `json:"reason"`
	IssuedBy   string `json:"issued_by"`
}

// ReleaseHoldRequest is the request for releasing a legal hold.
type ReleaseHoldRequest struct {
	HoldID string `json:"hold_id"`
}

// ReleaseHoldResponse is the response for releasing a legal hold.
type ReleaseHoldResponse struct {
	Success bool `json:"success"`
}

// IsUnderHoldRequest is the request for checking if entity is under hold.
type IsUnderHoldRequest struct {
	EntityID string `json:"entity_id"`
}

// IsUnderHoldResponse is the response for the check.
type IsUnderHoldResponse struct {
	UnderHold bool `json:"under_hold"`
}

// ListHoldsRequest is the request for listing all holds.
type ListHoldsRequest struct{}

// ListHoldsResponse is the response containing all holds.
type ListHoldsResponse struct {
	Holds []*LegalHoldInfo `json:"holds"`
}

// GetHoldRequest is the request for getting a single hold.
type GetHoldRequest struct {
	HoldID string `json:"hold_id"`
}

// UnimplementedLegalHoldServiceServer returns Unimplemented for all methods.
type UnimplementedLegalHoldServiceServer struct{}

func (*UnimplementedLegalHoldServiceServer) CreateHold(_ context.Context, _ *CreateHoldRequest) (*LegalHoldInfo, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateHold not implemented")
}
func (*UnimplementedLegalHoldServiceServer) ReleaseHold(_ context.Context, _ *ReleaseHoldRequest) (*ReleaseHoldResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReleaseHold not implemented")
}
func (*UnimplementedLegalHoldServiceServer) IsUnderHold(_ context.Context, _ *IsUnderHoldRequest) (*IsUnderHoldResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsUnderHold not implemented")
}
func (*UnimplementedLegalHoldServiceServer) ListHolds(_ context.Context, _ *ListHoldsRequest) (*ListHoldsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListHolds not implemented")
}
func (*UnimplementedLegalHoldServiceServer) GetHold(_ context.Context, _ *GetHoldRequest) (*LegalHoldInfo, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetHold not implemented")
}

// LegalHoldService implements LegalHoldServiceServer using a LegalHoldBackend.
type LegalHoldService struct {
	UnimplementedLegalHoldServiceServer
	backend LegalHoldBackend
	logger  *slog.Logger
}

// NewLegalHoldService creates a new LegalHoldService.
func NewLegalHoldService(backend LegalHoldBackend, logger *slog.Logger) *LegalHoldService {
	return &LegalHoldService{backend: backend, logger: logger}
}

func (s *LegalHoldService) CreateHold(ctx context.Context, req *CreateHoldRequest) (*LegalHoldInfo, error) {
	if req.EntityID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "entity_id is required")
	}
	return s.backend.CreateHold(ctx, req.EntityID, req.EntityType, req.Reason, req.IssuedBy)
}

func (s *LegalHoldService) ReleaseHold(ctx context.Context, req *ReleaseHoldRequest) (*ReleaseHoldResponse, error) {
	if req.HoldID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "hold_id is required")
	}
	if err := s.backend.ReleaseHold(ctx, req.HoldID); err != nil {
		return nil, status.Errorf(codes.NotFound, "hold not found: %v", err)
	}
	return &ReleaseHoldResponse{Success: true}, nil
}

func (s *LegalHoldService) IsUnderHold(ctx context.Context, req *IsUnderHoldRequest) (*IsUnderHoldResponse, error) {
	under, err := s.backend.IsUnderHold(ctx, req.EntityID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &IsUnderHoldResponse{UnderHold: under}, nil
}

func (s *LegalHoldService) ListHolds(ctx context.Context, _ *ListHoldsRequest) (*ListHoldsResponse, error) {
	holds, err := s.backend.ListHolds(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &ListHoldsResponse{Holds: holds}, nil
}

func (s *LegalHoldService) GetHold(ctx context.Context, req *GetHoldRequest) (*LegalHoldInfo, error) {
	hold, err := s.backend.GetHold(ctx, req.HoldID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	return hold, nil
}

// ============================================================
// A/B TESTING SERVICE
// ============================================================

// ABTestServiceServer is the gRPC server interface for A/B Testing.
type ABTestServiceServer interface {
	CreateTest(context.Context, *ABTestCreateRequest) (*ABTestInfo, error)
	ListTests(context.Context, *ABTestListRequest) (*ABTestListResponse, error)
	StartTest(context.Context, *ABTestActionRequest) (*ABTestActionResponse, error)
	StopTest(context.Context, *ABTestActionRequest) (*ABTestActionResponse, error)
	GetMetrics(context.Context, *ABTestMetricsRequest) (*ABTestMetricsResponse, error)
	AssignVariant(context.Context, *ABTestAssignRequest) (*ABTestAssignResponse, error)
	RecordResult(context.Context, *ABTestResultRequest) (*ABTestResultResponse, error)
}

// ABTestCreateRequest is the request for creating an A/B test.
type ABTestCreateRequest struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Variants    []ABTestVariantInfo `json:"variants"`
}

// ABTestListRequest is the request for listing tests.
type ABTestListRequest struct{}

// ABTestListResponse is the response for listing tests.
type ABTestListResponse struct {
	Tests []*ABTestInfo `json:"tests"`
	Count int32         `json:"count"`
}

// ABTestActionRequest is the request for start/stop actions.
type ABTestActionRequest struct {
	TestID string `json:"test_id"`
}

// ABTestActionResponse is the response for start/stop.
type ABTestActionResponse struct {
	Status string `json:"status"`
	TestID string `json:"test_id"`
}

// ABTestMetricsRequest is the request for getting metrics.
type ABTestMetricsRequest struct {
	TestID string `json:"test_id"`
}

// ABTestMetricsResponse is the response for metrics.
type ABTestMetricsResponse struct {
	Metrics []*ABTestVariantMetrics `json:"metrics"`
}

// ABTestAssignRequest is the request for variant assignment.
type ABTestAssignRequest struct {
	TestID    string `json:"test_id"`
	RequestID string `json:"request_id"`
}

// ABTestAssignResponse is the response for variant assignment.
type ABTestAssignResponse struct {
	Variant string `json:"variant"`
	TestID  string `json:"test_id"`
}

// ABTestResultRequest is the request for recording a result.
type ABTestResultRequest struct {
	TestID        string  `json:"test_id"`
	VariantName   string  `json:"variant_name"`
	Detected      bool    `json:"detected"`
	FalsePositive bool    `json:"false_positive"`
	LatencyMs     float64 `json:"latency_ms"`
}

// ABTestResultResponse is the response for recording a result.
type ABTestResultResponse struct {
	Status string `json:"status"`
}

// UnimplementedABTestServiceServer returns Unimplemented for all methods.
type UnimplementedABTestServiceServer struct{}

func (*UnimplementedABTestServiceServer) CreateTest(_ context.Context, _ *ABTestCreateRequest) (*ABTestInfo, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateTest not implemented")
}
func (*UnimplementedABTestServiceServer) ListTests(_ context.Context, _ *ABTestListRequest) (*ABTestListResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListTests not implemented")
}
func (*UnimplementedABTestServiceServer) StartTest(_ context.Context, _ *ABTestActionRequest) (*ABTestActionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StartTest not implemented")
}
func (*UnimplementedABTestServiceServer) StopTest(_ context.Context, _ *ABTestActionRequest) (*ABTestActionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StopTest not implemented")
}
func (*UnimplementedABTestServiceServer) GetMetrics(_ context.Context, _ *ABTestMetricsRequest) (*ABTestMetricsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetMetrics not implemented")
}
func (*UnimplementedABTestServiceServer) AssignVariant(_ context.Context, _ *ABTestAssignRequest) (*ABTestAssignResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AssignVariant not implemented")
}
func (*UnimplementedABTestServiceServer) RecordResult(_ context.Context, _ *ABTestResultRequest) (*ABTestResultResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RecordResult not implemented")
}

// ABTestService implements ABTestServiceServer using an ABTestBackend.
type ABTestService struct {
	UnimplementedABTestServiceServer
	backend ABTestBackend
	logger  *slog.Logger
}

// NewABTestService creates a new ABTestService.
func NewABTestService(backend ABTestBackend, logger *slog.Logger) *ABTestService {
	return &ABTestService{backend: backend, logger: logger}
}

func (s *ABTestService) CreateTest(ctx context.Context, req *ABTestCreateRequest) (*ABTestInfo, error) {
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "name is required")
	}
	if len(req.Variants) < 2 {
		return nil, status.Errorf(codes.InvalidArgument, "at least 2 variants are required")
	}
	return s.backend.CreateTest(ctx, req.Name, req.Description, req.Variants)
}

func (s *ABTestService) ListTests(ctx context.Context, _ *ABTestListRequest) (*ABTestListResponse, error) {
	tests, err := s.backend.ListTests(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &ABTestListResponse{Tests: tests, Count: int32(len(tests))}, nil
}

func (s *ABTestService) StartTest(ctx context.Context, req *ABTestActionRequest) (*ABTestActionResponse, error) {
	if err := s.backend.StartTest(ctx, req.TestID); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &ABTestActionResponse{Status: "started", TestID: req.TestID}, nil
}

func (s *ABTestService) StopTest(ctx context.Context, req *ABTestActionRequest) (*ABTestActionResponse, error) {
	if err := s.backend.StopTest(ctx, req.TestID); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &ABTestActionResponse{Status: "stopped", TestID: req.TestID}, nil
}

func (s *ABTestService) GetMetrics(ctx context.Context, req *ABTestMetricsRequest) (*ABTestMetricsResponse, error) {
	metrics, err := s.backend.GetMetrics(ctx, req.TestID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	return &ABTestMetricsResponse{Metrics: metrics}, nil
}

func (s *ABTestService) AssignVariant(ctx context.Context, req *ABTestAssignRequest) (*ABTestAssignResponse, error) {
	if req.RequestID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "request_id is required")
	}
	variant, err := s.backend.AssignVariant(ctx, req.TestID, req.RequestID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &ABTestAssignResponse{Variant: variant, TestID: req.TestID}, nil
}

func (s *ABTestService) RecordResult(ctx context.Context, req *ABTestResultRequest) (*ABTestResultResponse, error) {
	if err := s.backend.RecordResult(ctx, req.TestID, req.VariantName, req.Detected, req.FalsePositive, req.LatencyMs); err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &ABTestResultResponse{Status: "recorded"}, nil
}

// ============================================================
// SERVICE DESCRIPTORS
// ============================================================

var (
	DSARService_ServiceDesc = serviceDesc{
		ServiceName: "grpc.DSARService",
		HandlerType: (*DSARServiceServer)(nil),
		Methods: []methodDesc{
			{MethodName: "Export"},
			{MethodName: "Erase"},
		},
	}

	LegalHoldService_ServiceDesc = serviceDesc{
		ServiceName: "grpc.LegalHoldService",
		HandlerType: (*LegalHoldServiceServer)(nil),
		Methods: []methodDesc{
			{MethodName: "CreateHold"},
			{MethodName: "ReleaseHold"},
			{MethodName: "IsUnderHold"},
			{MethodName: "ListHolds"},
			{MethodName: "GetHold"},
		},
	}

	ABTestService_ServiceDesc = serviceDesc{
		ServiceName: "grpc.ABTestService",
		HandlerType: (*ABTestServiceServer)(nil),
		Methods: []methodDesc{
			{MethodName: "CreateTest"},
			{MethodName: "ListTests"},
			{MethodName: "StartTest"},
			{MethodName: "StopTest"},
			{MethodName: "GetMetrics"},
			{MethodName: "AssignVariant"},
			{MethodName: "RecordResult"},
		},
	}
)

// Internal grpc.ServiceDesc objects for v4 service registration.
var (
	_grpcServiceDesc_DSAR = grpc.ServiceDesc{
		ServiceName: DSARService_ServiceDesc.ServiceName,
		HandlerType: (*DSARServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams:     []grpc.StreamDesc{},
	}
	_grpcServiceDesc_LegalHold = grpc.ServiceDesc{
		ServiceName: LegalHoldService_ServiceDesc.ServiceName,
		HandlerType: (*LegalHoldServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams:     []grpc.StreamDesc{},
	}
	_grpcServiceDesc_ABTest = grpc.ServiceDesc{
		ServiceName: ABTestService_ServiceDesc.ServiceName,
		HandlerType: (*ABTestServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams:     []grpc.StreamDesc{},
	}
)

// RegisterHelper methods for v4 services.
func (rh *RegisterHelper) RegisterDSARService(svc DSARServiceServer) {
	rh.Server.RegisterService(&_grpcServiceDesc_DSAR, svc)
}
func (rh *RegisterHelper) RegisterLegalHoldService(svc LegalHoldServiceServer) {
	rh.Server.RegisterService(&_grpcServiceDesc_LegalHold, svc)
}
func (rh *RegisterHelper) RegisterABTestService(svc ABTestServiceServer) {
	rh.Server.RegisterService(&_grpcServiceDesc_ABTest, svc)
}

// Suppress unused import warning when fmt is not used in all build paths.
var _ = fmt.Sprintf
