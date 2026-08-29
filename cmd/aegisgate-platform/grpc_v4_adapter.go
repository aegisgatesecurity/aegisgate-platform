// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — gRPC v4.3.1 Backend Adapters
//
// grpc_v4_adapter.go adapts the DSAR, LegalHold, and ABTest services
// to the gRPC backend interfaces. This allows the gRPC server to expose
// the new v4.3.1 compliance and testing pipelines.
//
// The adapters map:
//   - DSARBackend.Export → dsar.Service.Export
//   - DSARBackend.Erase → dsar.Service.Erase
//   - LegalHoldBackend.CreateHold → legalhold.Service.CreateHold
//   - LegalHoldBackend.ReleaseHold → legalhold.Service.ReleaseHold
//   - LegalHoldBackend.IsUnderHold → legalhold.Service.IsUnderHold
//   - ABTestBackend.CreateTest → abtest.Service.CreateTest
//   - ABTestBackend.AssignVariant → abtest.Service.AssignVariant
//   - ABTestBackend.RecordResult → abtest.Service.RecordResult

package main

import (
	"context"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/abtest"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/dsar"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/grpc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/legalhold"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/safecast"
)

// ====================================================================
// DSAR Backend Adapter
// ====================================================================

// dsarBackend adapts dsar.Service to the grpc.DSARBackend interface.
type dsarBackend struct {
	svc *dsar.Service
}

// newDSARBackend creates a new DSARBackend adapter from the DSAR Service.
func newDSARBackend(svc *dsar.Service) grpc.DSARBackend {
	return &dsarBackend{svc: svc}
}

func (b *dsarBackend) Export(ctx context.Context, entityID string) (*grpc.DSARExportResponse, error) {
	result, err := b.svc.Export(ctx, entityID)
	if err != nil {
		return nil, err
	}

	// Convert dsar.ExportBundle to grpc.DSARExportResponse
	providers := make(map[string]interface{})
	if result.Providers != nil {
		for name, data := range result.Providers {
			providers[name] = data
		}
	}

	return &grpc.DSARExportResponse{
		EntityID:   result.EntityID,
		ExportedAt: result.ExportedAt.Unix(),
		Providers:  providers,
	}, nil
}

func (b *dsarBackend) Erase(ctx context.Context, entityID string) (*grpc.DSAREraseResponse, error) {
	result, err := b.svc.Erase(ctx, entityID)
	if err != nil {
		return nil, err
	}

	// Convert dsar.EraseResult to grpc.DSAREraseResponse
	providers := make(map[string]int)
	if result.Providers != nil {
		for name, count := range result.Providers {
			providers[name] = count
		}
	}

	return &grpc.DSAREraseResponse{
		EntityID:        result.EntityID,
		ErasedAt:        result.ErasedAt.Unix(),
		RecordsAffected: result.RecordsAffected,
		Providers:       providers,
		BlockedBy:       result.BlockedBy,
	}, nil
}

// ====================================================================
// LegalHold Backend Adapter
// ====================================================================

// legalHoldBackend adapts legalhold.Service to the grpc.LegalHoldBackend interface.
type legalHoldBackend struct {
	svc *legalhold.Service
}

// newLegalHoldBackend creates a new LegalHoldBackend adapter from the LegalHold Service.
func newLegalHoldBackend(svc *legalhold.Service) grpc.LegalHoldBackend {
	return &legalHoldBackend{svc: svc}
}

func (b *legalHoldBackend) CreateHold(ctx context.Context, entityID, entityType, reason, issuedBy string) (*grpc.LegalHoldInfo, error) {
	hold, err := b.svc.CreateHold(ctx, entityID, entityType, reason, issuedBy)
	if err != nil {
		return nil, err
	}

	return &grpc.LegalHoldInfo{
		ID:         hold.ID,
		EntityID:   hold.EntityID,
		EntityType: hold.EntityType,
		Reason:     hold.Reason,
		IssuedBy:   hold.IssuedBy,
		CreatedAt:  hold.CreatedAt.Unix(),
		ReleasedAt: hold.ReleasedAt.Unix(),
	}, nil
}

func (b *legalHoldBackend) ReleaseHold(ctx context.Context, holdID string) error {
	return b.svc.ReleaseHold(ctx, holdID)
}

func (b *legalHoldBackend) IsUnderHold(ctx context.Context, entityID string) (bool, error) {
	return b.svc.IsUnderHold(ctx, entityID), nil
}

func (b *legalHoldBackend) ListHolds(ctx context.Context) ([]*grpc.LegalHoldInfo, error) {
	holds := b.svc.ListHolds(ctx)
	result := make([]*grpc.LegalHoldInfo, 0, len(holds))
	for _, hold := range holds {
		result = append(result, &grpc.LegalHoldInfo{
			ID:         hold.ID,
			EntityID:   hold.EntityID,
			EntityType: hold.EntityType,
			Reason:     hold.Reason,
			IssuedBy:   hold.IssuedBy,
			CreatedAt:  hold.CreatedAt.Unix(),
			ReleasedAt: hold.ReleasedAt.Unix(),
		})
	}
	return result, nil
}

func (b *legalHoldBackend) GetHold(ctx context.Context, holdID string) (*grpc.LegalHoldInfo, error) {
	hold, err := b.svc.GetHold(ctx, holdID)
	if err != nil {
		return nil, err
	}

	return &grpc.LegalHoldInfo{
		ID:         hold.ID,
		EntityID:   hold.EntityID,
		EntityType: hold.EntityType,
		Reason:     hold.Reason,
		IssuedBy:   hold.IssuedBy,
		CreatedAt:  hold.CreatedAt.Unix(),
		ReleasedAt: hold.ReleasedAt.Unix(),
	}, nil
}

// ====================================================================
// ABTest Backend Adapter
// ====================================================================

// abtestBackend adapts abtest.Service to the grpc.ABTestBackend interface.
type abtestBackend struct {
	svc *abtest.Service
}

// newABTestBackend creates a new ABTestBackend adapter from the ABTest Service.
func newABTestBackend(svc *abtest.Service) grpc.ABTestBackend {
	return &abtestBackend{svc: svc}
}

func (b *abtestBackend) CreateTest(ctx context.Context, name, description string, variants []grpc.ABTestVariantInfo) (*grpc.ABTestInfo, error) {
	// Convert grpc.ABTestVariantInfo to abtest.Variant
	abtestVariants := make([]abtest.Variant, 0, len(variants))
	for _, v := range variants {
		abtestVariants = append(abtestVariants, abtest.Variant{
			Name:     v.Name,
			Weight:   int(v.Weight),
			ModelRef: v.ModelRef,
		})
	}

	test, err := b.svc.CreateTest(ctx, name, description, abtestVariants)
	if err != nil {
		return nil, err
	}

	// Convert abtest.Test to grpc.ABTestInfo
	testVariants := make([]grpc.ABTestVariantInfo, 0, len(test.Variants))
	for _, v := range test.Variants {
		testVariants = append(testVariants, grpc.ABTestVariantInfo{
			Name:     v.Name,
			Weight:   safecast.Int32(v.Weight),
			ModelRef: v.ModelRef,
		})
	}

	return &grpc.ABTestInfo{
		ID:          test.ID,
		Name:        test.Name,
		Description: test.Description,
		Variants:    testVariants,
		Status:      string(test.Status),
		CreatedAt:   test.CreatedAt.Unix(),
	}, nil
}

func (b *abtestBackend) ListTests(ctx context.Context) ([]*grpc.ABTestInfo, error) {
	tests := b.svc.ListTests(ctx)
	result := make([]*grpc.ABTestInfo, 0, len(tests))
	for _, test := range tests {
		testVariants := make([]grpc.ABTestVariantInfo, 0, len(test.Variants))
		for _, v := range test.Variants {
			testVariants = append(testVariants, grpc.ABTestVariantInfo{
				Name:     v.Name,
				Weight:   safecast.Int32(v.Weight),
				ModelRef: v.ModelRef,
			})
		}

		result = append(result, &grpc.ABTestInfo{
			ID:          test.ID,
			Name:        test.Name,
			Description: test.Description,
			Variants:    testVariants,
			Status:      string(test.Status),
			CreatedAt:   test.CreatedAt.Unix(),
		})
	}
	return result, nil
}

func (b *abtestBackend) StartTest(ctx context.Context, testID string) error {
	return b.svc.StartTest(ctx, testID)
}

func (b *abtestBackend) StopTest(ctx context.Context, testID string) error {
	return b.svc.StopTest(ctx, testID)
}

func (b *abtestBackend) GetMetrics(ctx context.Context, testID string) ([]*grpc.ABTestVariantMetrics, error) {
	metrics, err := b.svc.GetMetrics(ctx, testID)
	if err != nil {
		return nil, err
	}

	result := make([]*grpc.ABTestVariantMetrics, 0, len(metrics))
	for _, m := range metrics {
		result = append(result, &grpc.ABTestVariantMetrics{
			VariantName:    m.VariantName,
			TotalRequests:  safecast.Int32(m.RequestCount),
			Detections:     safecast.Int32(m.DetectionCount),
			FalsePositives: safecast.Int32(m.FalsePositiveCount),
			AvgLatencyMs:   m.AvgLatencyMs,
		})
	}
	return result, nil
}

func (b *abtestBackend) AssignVariant(ctx context.Context, testID, requestID string) (string, error) {
	return b.svc.AssignVariant(ctx, testID, requestID)
}

func (b *abtestBackend) RecordResult(ctx context.Context, testID, variantName string, detected, falsePositive bool, latencyMs float64) error {
	b.svc.RecordResult(ctx, testID, variantName, detected, falsePositive, latencyMs)
	return nil
}

// Compile-time interface checks.
var (
	_ grpc.DSARBackend      = (*dsarBackend)(nil)
	_ grpc.LegalHoldBackend = (*legalHoldBackend)(nil)
	_ grpc.ABTestBackend    = (*abtestBackend)(nil)
)
