// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — gRPC Backend Interfaces for v4.3.1 Pipelines
// =========================================================================
//
// backends_v4.go defines backend interfaces for the DSAR, Legal Hold,
// and A/B Testing services. These allow the gRPC server to expose the
// new compliance and testing pipelines alongside the existing 7 services.
// =========================================================================

package grpc

import "context"

// ====================================================================
// DSARBackend — GDPR Data Subject Access Requests
// ====================================================================

// DSARBackend is the interface for DSAR operations.
type DSARBackend interface {
	Export(ctx context.Context, entityID string) (*DSARExportResponse, error)
	Erase(ctx context.Context, entityID string) (*DSAREraseResponse, error)
}

// DSARExportResponse is the gRPC response for DSAR export.
type DSARExportResponse struct {
	EntityID   string                 `json:"entity_id"`
	ExportedAt int64                  `json:"exported_at"`
	Providers  map[string]interface{} `json:"providers"`
}

// DSAREraseResponse is the gRPC response for DSAR erase.
type DSAREraseResponse struct {
	EntityID        string         `json:"entity_id"`
	ErasedAt        int64          `json:"erased_at"`
	RecordsAffected int            `json:"records_affected"`
	Providers       map[string]int `json:"providers"`
	BlockedBy       string         `json:"blocked_by,omitempty"`
}

// ====================================================================
// LegalHoldBackend — E-Discovery Compliance
// ====================================================================

// LegalHoldBackend is the interface for legal hold operations.
type LegalHoldBackend interface {
	CreateHold(ctx context.Context, entityID, entityType, reason, issuedBy string) (*LegalHoldInfo, error)
	ReleaseHold(ctx context.Context, holdID string) error
	IsUnderHold(ctx context.Context, entityID string) (bool, error)
	ListHolds(ctx context.Context) ([]*LegalHoldInfo, error)
	GetHold(ctx context.Context, holdID string) (*LegalHoldInfo, error)
}

// LegalHoldInfo represents a legal hold in gRPC responses.
type LegalHoldInfo struct {
	ID         string `json:"id"`
	EntityID   string `json:"entity_id"`
	EntityType string `json:"entity_type"`
	Reason     string `json:"reason"`
	IssuedBy   string `json:"issued_by"`
	CreatedAt  int64  `json:"created_at"`
	ReleasedAt int64  `json:"released_at,omitempty"`
}

// ====================================================================
// ABTestBackend — ML Model A/B Testing
// ====================================================================

// ABTestBackend is the interface for A/B testing operations.
type ABTestBackend interface {
	CreateTest(ctx context.Context, name, description string, variants []ABTestVariantInfo) (*ABTestInfo, error)
	ListTests(ctx context.Context) ([]*ABTestInfo, error)
	StartTest(ctx context.Context, testID string) error
	StopTest(ctx context.Context, testID string) error
	GetMetrics(ctx context.Context, testID string) ([]*ABTestVariantMetrics, error)
	AssignVariant(ctx context.Context, testID, requestID string) (string, error)
	RecordResult(ctx context.Context, testID, variantName string, detected, falsePositive bool, latencyMs float64) error
}

// ABTestVariantInfo defines a variant in a gRPC A/B test.
type ABTestVariantInfo struct {
	Name     string `json:"name"`
	Weight   int32  `json:"weight"`
	ModelRef string `json:"model_ref"`
}

// ABTestInfo represents an A/B test in gRPC responses.
type ABTestInfo struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Variants    []ABTestVariantInfo `json:"variants"`
	Status      string              `json:"status"`
	CreatedAt   int64               `json:"created_at"`
}

// ABTestVariantMetrics holds per-variant metrics in gRPC responses.
type ABTestVariantMetrics struct {
	VariantName    string  `json:"variant_name"`
	TotalRequests  int32   `json:"total_requests"`
	Detections     int32   `json:"detections"`
	FalsePositives int32   `json:"false_positives"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
}
