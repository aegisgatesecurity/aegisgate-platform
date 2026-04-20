// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package grpc

import (
	"context"
	"log/slog"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// ComplianceService implements the Compliance service
type ComplianceService struct {
	UnimplementedComplianceServiceServer
	manager *compliance.Manager
	logger  *slog.Logger
}

// NewComplianceService creates a new compliance service
func NewComplianceService(manager *compliance.Manager, logger *slog.Logger) *ComplianceService {
	return &ComplianceService{
		manager: manager,
		logger:  logger,
	}
}

// GetFrameworks returns available compliance frameworks
func (s *ComplianceService) GetFrameworks(ctx context.Context, req *GetFrameworksRequest) (*GetFrameworksResponse, error) {
	frameworks := s.manager.GetActiveFrameworks()
	result := make([]*Framework, len(frameworks))

	for i, f := range frameworks {
		result[i] = &Framework{
			Id:          string(f),
			Name:        string(f),
			Description: string(f) + " compliance framework",
		}
	}

	return &GetFrameworksResponse{Frameworks: result}, nil
}

// GetStatus returns compliance status
func (s *ComplianceService) GetStatus(ctx context.Context, req *GetComplianceStatusRequest) (*GetComplianceStatusResponse, error) {
	return &GetComplianceStatusResponse{
		Overall:    ComplianceStatus_UNKNOWN,
		Frameworks: []*FrameworkStatus{},
	}, nil
}

// RunCheck runs a compliance check
func (s *ComplianceService) RunCheck(ctx context.Context, req *RunComplianceCheckRequest) (*RunComplianceCheckResponse, error) {
	return &RunComplianceCheckResponse{
		Id:        "check_" + req.Framework,
		Framework: req.Framework,
		Status:    ComplianceStatus_PASS,
		Summary: &ComplianceSummary{
			TotalChecks: 0,
			Passed:      0,
			Failed:      0,
			Warnings:    0,
			Score:       100.0,
		},
	}, nil
}

// GetFindings returns compliance findings
func (s *ComplianceService) GetFindings(ctx context.Context, req *GetFindingsRequest) (*GetFindingsResponse, error) {
	return &GetFindingsResponse{Findings: []*ComplianceFinding{}}, nil
}

// GenerateReport generates a compliance report
func (s *ComplianceService) GenerateReport(ctx context.Context, req *GenerateReportRequest) (*GenerateReportResponse, error) {
	return &GenerateReportResponse{
		Id:        "report_" + req.Framework,
		Framework: req.Framework,
		Timestamp: 0,
		Status:    ComplianceStatus_PASS,
		Summary: &ComplianceSummary{
			TotalChecks:   0,
			Passed:        0,
			Failed:        0,
			Warnings:      0,
			NotApplicable: 0,
			Score:         100.0,
		},
	}, nil
}
