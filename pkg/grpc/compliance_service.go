// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC Compliance Service Implementation
// =========================================================================

package grpc

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ComplianceService implements ComplianceServiceServer using a ComplianceBackend.
type ComplianceService struct {
	UnimplementedComplianceServiceServer
	backend ComplianceBackend
	logger  *slog.Logger
}

// NewComplianceService creates a new ComplianceService with the given backend.
func NewComplianceService(backend ComplianceBackend, logger *slog.Logger) *ComplianceService {
	return &ComplianceService{backend: backend, logger: logger}
}

// GetFrameworks returns available compliance frameworks.
func (s *ComplianceService) GetFrameworks(ctx context.Context, req *GetFrameworksRequest) (*GetFrameworksResponse, error) {
	frameworks, err := s.backend.GetFrameworks(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get frameworks: %v", err)
	}

	result := make([]*Framework, 0, len(frameworks))
	for _, f := range frameworks {
		result = append(result, &Framework{
			Id:          f.ID,
			Name:        f.Name,
			Description: f.Description,
		})
	}

	return &GetFrameworksResponse{Frameworks: result}, nil
}

// GetStatus returns compliance status.
func (s *ComplianceService) GetStatus(ctx context.Context, req *GetComplianceStatusRequest) (*GetComplianceStatusResponse, error) {
	statusResult, err := s.backend.GetStatus(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get compliance status: %v", err)
	}

	frameworks := make([]*FrameworkStatus, 0, len(statusResult.Frameworks))
	for _, f := range statusResult.Frameworks {
		frameworks = append(frameworks, &FrameworkStatus{
			Framework: f.Framework,
			Status:    f.Status,
			Score:     f.Score,
		})
	}

	return &GetComplianceStatusResponse{
		Overall:    statusResult.OverallStatus,
		Frameworks: frameworks,
	}, nil
}

// RunCheck runs a compliance check.
func (s *ComplianceService) RunCheck(ctx context.Context, req *RunComplianceCheckRequest) (*RunComplianceCheckResponse, error) {
	if req.Framework == "" {
		return nil, status.Errorf(codes.InvalidArgument, "framework is required")
	}

	result, err := s.backend.RunCheck(ctx, req.Framework)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to run compliance check: %v", err)
	}

	var summary *ComplianceSummary
	if result.Summary != nil {
		summary = &ComplianceSummary{
			TotalChecks:   result.Summary.TotalChecks,
			Passed:        result.Summary.Passed,
			Failed:        result.Summary.Failed,
			Warnings:      result.Summary.Warnings,
			NotApplicable: result.Summary.NotApplicable,
			Score:         result.Summary.Score,
		}
	}

	return &RunComplianceCheckResponse{
		Id:        result.ID,
		Framework: result.Framework,
		Status:    result.Status,
		Summary:   summary,
	}, nil
}

// GetFindings returns compliance findings.
func (s *ComplianceService) GetFindings(ctx context.Context, req *GetFindingsRequest) (*GetFindingsResponse, error) {
	findings, err := s.backend.GetFindings(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get findings: %v", err)
	}

	result := make([]*ComplianceFinding, 0, len(findings))
	for _, f := range findings {
		result = append(result, &ComplianceFinding{
			Id:          f.ID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    f.Severity,
			Category:    f.Category,
			Framework:   f.Framework,
			Timestamp:   f.Timestamp,
		})
	}

	return &GetFindingsResponse{Findings: result}, nil
}

// GenerateReport generates a compliance report.
func (s *ComplianceService) GenerateReport(ctx context.Context, req *GenerateReportRequest) (*GenerateReportResponse, error) {
	if req.Framework == "" {
		return nil, status.Errorf(codes.InvalidArgument, "framework is required")
	}

	result, err := s.backend.GenerateReport(ctx, req.Framework)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate report: %v", err)
	}

	var summary *ComplianceSummary
	if result.Summary != nil {
		summary = &ComplianceSummary{
			TotalChecks:   result.Summary.TotalChecks,
			Passed:        result.Summary.Passed,
			Failed:        result.Summary.Failed,
			Warnings:      result.Summary.Warnings,
			NotApplicable: result.Summary.NotApplicable,
			Score:         result.Summary.Score,
		}
	}

	return &GenerateReportResponse{
		Id:        result.ID,
		Framework: result.Framework,
		Timestamp: result.Timestamp,
		Status:    result.Status,
		Summary:   summary,
	}, nil
}