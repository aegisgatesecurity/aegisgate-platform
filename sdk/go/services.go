// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform Go SDK — Service Methods (v3.6.0)
// =========================================================================
//
// services.go defines every service struct and its methods that map 1:1 to
// the AegisGate v3.6.0 platform API endpoints. All methods accept a
// context.Context as their first parameter for cancellation and deadlines.
// =========================================================================

package aegisgate

import "context"

// service is the common struct embedded by every service.
type service struct {
	client *Client
}

// =========================================================================
// Auth
// =========================================================================

// AuthService handles authentication endpoints.
type AuthService struct{ client *Client }

// Login authenticates a user and returns a token.
// POST /auth/login
func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	var resp LoginResponse
	err := s.client.do(ctx, "POST", "/auth/login", req, &resp)
	return &resp, err
}

// Logout invalidates the current session token.
// POST /auth/logout
func (s *AuthService) Logout(ctx context.Context) error {
	return s.client.do(ctx, "POST", "/auth/logout", nil, nil)
}

// ListUsers returns all registered users.
// GET /auth/users
func (s *AuthService) ListUsers(ctx context.Context) ([]UserInfo, error) {
	var users []UserInfo
	err := s.client.do(ctx, "GET", "/auth/users", nil, &users)
	return users, err
}

// CreateUser creates a new user.
// POST /auth/users
func (s *AuthService) CreateUser(ctx context.Context, req *CreateUserRequest) (*UserInfo, error) {
	var resp UserInfo
	err := s.client.do(ctx, "POST", "/auth/users", req, &resp)
	return &resp, err
}

// =========================================================================
// Compliance
// =========================================================================

// ComplianceService handles compliance endpoints.
type ComplianceService struct{ client *Client }

// Scan runs a compliance scan.
// GET /api/v1/compliance/scan
func (s *ComplianceService) Scan(ctx context.Context) (*ScanReport, error) {
	var resp ScanReport
	err := s.client.do(ctx, "GET", "/api/v1/compliance/scan", nil, &resp)
	return &resp, err
}

// Report returns a compliance report for the given framework.
// GET /api/v1/compliance/report?framework=<framework>
func (s *ComplianceService) Report(ctx context.Context, framework string) (*ComplianceReport, error) {
	path := "/api/v1/compliance/report"
	if framework != "" {
		path += "?framework=" + framework
	}
	var resp ComplianceReport
	err := s.client.do(ctx, "GET", path, nil, &resp)
	return &resp, err
}

// Integrity checks compliance integrity.
// GET /api/v1/compliance/integrity
func (s *ComplianceService) Integrity(ctx context.Context) (*IntegrityResult, error) {
	var resp IntegrityResult
	err := s.client.do(ctx, "GET", "/api/v1/compliance/integrity", nil, &resp)
	return &resp, err
}

// Evidence retrieves compliance evidence.
// GET /api/v1/compliance/evidence
func (s *ComplianceService) Evidence(ctx context.Context) (*EvidenceResult, error) {
	var resp EvidenceResult
	err := s.client.do(ctx, "GET", "/api/v1/compliance/evidence", nil, &resp)
	return &resp, err
}

// =========================================================================
// Trust
// =========================================================================

// TrustService handles trust scoring endpoints.
type TrustService struct{ client *Client }

// Dashboard returns the trust dashboard.
// GET /api/v1/trust/dashboard
func (s *TrustService) Dashboard(ctx context.Context) (*TrustDashboard, error) {
	var resp TrustDashboard
	err := s.client.do(ctx, "GET", "/api/v1/trust/dashboard", nil, &resp)
	return &resp, err
}

// Scores returns all trust scores.
// GET /api/v1/trust/scores
func (s *TrustService) Scores(ctx context.Context) ([]TrustScore, error) {
	var scores []TrustScore
	err := s.client.do(ctx, "GET", "/api/v1/trust/scores", nil, &scores)
	return scores, err
}

// Anomalies returns detected trust anomalies.
// GET /api/v1/trust/anomalies
func (s *TrustService) Anomalies(ctx context.Context) (*TrustAnomalies, error) {
	var resp TrustAnomalies
	err := s.client.do(ctx, "GET", "/api/v1/trust/anomalies", nil, &resp)
	return &resp, err
}

// ComplianceCheck runs a trust compliance check.
// GET /api/v1/trust/compliance
func (s *TrustService) ComplianceCheck(ctx context.Context) (*TrustComplianceResult, error) {
	var resp TrustComplianceResult
	err := s.client.do(ctx, "GET", "/api/v1/trust/compliance", nil, &resp)
	return &resp, err
}

// =========================================================================
// Scan
// =========================================================================

// ScanService handles scanning endpoints.
type ScanService struct{ client *Client }

// Scan initiates a new scan.
// POST /api/v1/scan
func (s *ScanService) Scan(ctx context.Context, req *ScanRequest) (*ScanResult, error) {
	var resp ScanResult
	err := s.client.do(ctx, "POST", "/api/v1/scan", req, &resp)
	return &resp, err
}

// =========================================================================
// Guardrails
// =========================================================================

// GuardrailsService handles guardrails endpoints.
type GuardrailsService struct{ client *Client }

// Check runs a guardrails check.
// GET /api/v1/guardrails
func (s *GuardrailsService) Check(ctx context.Context) (*GuardrailsResult, error) {
	var resp GuardrailsResult
	err := s.client.do(ctx, "GET", "/api/v1/guardrails", nil, &resp)
	return &resp, err
}

// =========================================================================
// Analytics
// =========================================================================

// AnalyticsService handles analytics endpoints.
type AnalyticsService struct{ client *Client }

// Usage returns usage analytics.
// GET /api/v1/analytics/usage
func (s *AnalyticsService) Usage(ctx context.Context) (*AnalyticsUsage, error) {
	var resp AnalyticsUsage
	err := s.client.do(ctx, "GET", "/api/v1/analytics/usage", nil, &resp)
	return &resp, err
}

// Cost returns cost analytics.
// GET /api/v1/analytics/cost
func (s *AnalyticsService) Cost(ctx context.Context) (*AnalyticsCost, error) {
	var resp AnalyticsCost
	err := s.client.do(ctx, "GET", "/api/v1/analytics/cost", nil, &resp)
	return &resp, err
}

// Anomalies returns analytics anomalies.
// GET /api/v1/analytics/anomalies
func (s *AnalyticsService) Anomalies(ctx context.Context) (*AnalyticsAnomalies, error) {
	var resp AnalyticsAnomalies
	err := s.client.do(ctx, "GET", "/api/v1/analytics/anomalies", nil, &resp)
	return &resp, err
}

// Dashboard returns the combined analytics dashboard.
// GET /api/v1/analytics/dashboard
func (s *AnalyticsService) Dashboard(ctx context.Context) (*AnalyticsDashboard, error) {
	var resp AnalyticsDashboard
	err := s.client.do(ctx, "GET", "/api/v1/analytics/dashboard", nil, &resp)
	return &resp, err
}

// =========================================================================
// IOC
// =========================================================================

// IOCService handles Indicator of Compromise endpoints.
type IOCService struct{ client *Client }

// Manifest returns the IOC manifest.
// GET /api/v1/ioc/manifest
func (s *IOCService) Manifest(ctx context.Context) (*IOCManifest, error) {
	var resp IOCManifest
	err := s.client.do(ctx, "GET", "/api/v1/ioc/manifest", nil, &resp)
	return &resp, err
}

// Health returns the IOC system health.
// GET /api/v1/ioc/health
func (s *IOCService) Health(ctx context.Context) (*IOCStatus, error) {
	var resp IOCStatus
	err := s.client.do(ctx, "GET", "/api/v1/ioc/health", nil, &resp)
	return &resp, err
}

// AdminStatus returns the IOC admin status.
// GET /api/v1/ioc/admin/status
func (s *IOCService) AdminStatus(ctx context.Context) (*IOCStatus, error) {
	var resp IOCStatus
	err := s.client.do(ctx, "GET", "/api/v1/ioc/admin/status", nil, &resp)
	return &resp, err
}

// =========================================================================
// SIEM
// =========================================================================

// SIEMService handles SIEM integration endpoints.
type SIEMService struct{ client *Client }

// Status returns the SIEM integration status.
// GET /api/v1/siem/status
func (s *SIEMService) Status(ctx context.Context) (*SIEMStatus, error) {
	var resp SIEMStatus
	err := s.client.do(ctx, "GET", "/api/v1/siem/status", nil, &resp)
	return &resp, err
}

// =========================================================================
// ML
// =========================================================================

// MLService handles ML metrics endpoints.
type MLService struct{ client *Client }

// Metrics returns shadow-mode ML performance metrics.
// GET /api/v1/ml/metrics
func (s *MLService) Metrics(ctx context.Context) (*MLShadowMetrics, error) {
	var resp MLShadowMetrics
	err := s.client.do(ctx, "GET", "/api/v1/ml/metrics", nil, &resp)
	return &resp, err
}

// =========================================================================
// Audit
// =========================================================================

// AuditService handles audit log endpoints.
type AuditService struct{ client *Client }

// Query queries audit log entries.
// GET /api/v1/audit
func (s *AuditService) Query(ctx context.Context) (*AuditQueryResult, error) {
	var resp AuditQueryResult
	err := s.client.do(ctx, "GET", "/api/v1/audit", nil, &resp)
	return &resp, err
}

// =========================================================================
// Policy
// =========================================================================

// PolicyService handles policy endpoints.
type PolicyService struct{ client *Client }

// List returns all policies.
// GET /api/v1/policies
func (s *PolicyService) List(ctx context.Context) ([]Policy, error) {
	var policies []Policy
	err := s.client.do(ctx, "GET", "/api/v1/policies", nil, &policies)
	return policies, err
}

// Get returns a single policy by ID.
// GET /api/v1/policies/{id}
func (s *PolicyService) Get(ctx context.Context, id string) (*Policy, error) {
	var resp Policy
	err := s.client.do(ctx, "GET", "/api/v1/policies/"+id, nil, &resp)
	return &resp, err
}

// =========================================================================
// Cluster
// =========================================================================

// ClusterService handles cluster health endpoints.
type ClusterService struct{ client *Client }

// Health returns cluster health information.
// GET /api/v1/cluster/health
func (s *ClusterService) Health(ctx context.Context) (*ClusterHealth, error) {
	var resp ClusterHealth
	err := s.client.do(ctx, "GET", "/api/v1/cluster/health", nil, &resp)
	return &resp, err
}

// =========================================================================
// Bridge
// =========================================================================

// BridgeService handles bridge endpoints.
type BridgeService struct{ client *Client }

// Status returns the bridge status.
// GET /api/v1/bridge
func (s *BridgeService) Status(ctx context.Context) (*BridgeResult, error) {
	var resp BridgeResult
	err := s.client.do(ctx, "GET", "/api/v1/bridge", nil, &resp)
	return &resp, err
}

// =========================================================================
// Attestation
// =========================================================================

// AttestationService handles attestation endpoints.
type AttestationService struct{ client *Client }

// Verify verifies an attestation offline.
// POST /api/v1/attestation/verify
func (s *AttestationService) Verify(ctx context.Context, req *AttestationRequest) (*AttestationResult, error) {
	var resp AttestationResult
	err := s.client.do(ctx, "POST", "/api/v1/attestation/verify", req, &resp)
	return &resp, err
}

// VerifyOnline verifies an attestation online.
// POST /api/v1/attestation/verify-online
func (s *AttestationService) VerifyOnline(ctx context.Context, req *AttestationRequest) (*AttestationResult, error) {
	var resp AttestationResult
	err := s.client.do(ctx, "POST", "/api/v1/attestation/verify-online", req, &resp)
	return &resp, err
}

// =========================================================================
// AI-BOM
// =========================================================================

// AIBOMService handles AI Bill of Materials endpoints.
type AIBOMService struct{ client *Client }

// Generate generates an AI-BOM.
// POST /api/v1/aibom/generate
func (s *AIBOMService) Generate(ctx context.Context, req *AIBOMRequest) (*AIBOMResult, error) {
	var resp AIBOMResult
	err := s.client.do(ctx, "POST", "/api/v1/aibom/generate", req, &resp)
	return &resp, err
}

// Verify verifies an AI-BOM.
// POST /api/v1/aibom/verify
func (s *AIBOMService) Verify(ctx context.Context, req *AIBOMRequest) (*AIBOMResult, error) {
	var resp AIBOMResult
	err := s.client.do(ctx, "POST", "/api/v1/aibom/verify", req, &resp)
	return &resp, err
}

// =========================================================================
// A2A (Agent-to-Agent)
// =========================================================================

// A2AService handles A2A intent endpoints.
type A2AService struct{ client *Client }

// SignIntent signs an A2A intent.
// POST /api/v1/a2a/intent/sign
func (s *A2AService) SignIntent(ctx context.Context, req *A2AIntentSignRequest) (*A2AIntentResult, error) {
	var resp A2AIntentResult
	err := s.client.do(ctx, "POST", "/api/v1/a2a/intent/sign", req, &resp)
	return &resp, err
}

// VerifyIntent verifies an A2A intent.
// POST /api/v1/a2a/intent/verify
func (s *A2AService) VerifyIntent(ctx context.Context, req *A2AIntentVerifyRequest) (*A2AIntentResult, error) {
	var resp A2AIntentResult
	err := s.client.do(ctx, "POST", "/api/v1/a2a/intent/verify", req, &resp)
	return &resp, err
}

// =========================================================================
// Digest
// =========================================================================

// DigestService handles digest generation and verification.
type DigestService struct{ client *Client }

// Generate generates a digest.
// POST /api/v1/digest/generate
func (s *DigestService) Generate(ctx context.Context, req *DigestGenerateRequest) (*DigestResult, error) {
	var resp DigestResult
	err := s.client.do(ctx, "POST", "/api/v1/digest/generate", req, &resp)
	return &resp, err
}

// Verify verifies a digest.
// POST /api/v1/digest/verify
func (s *DigestService) Verify(ctx context.Context, req *DigestVerifyRequest) (*DigestResult, error) {
	var resp DigestResult
	err := s.client.do(ctx, "POST", "/api/v1/digest/verify", req, &resp)
	return &resp, err
}

// =========================================================================
// Incident
// =========================================================================

// IncidentService handles incident management endpoints.
type IncidentService struct{ client *Client }

// Create creates a new incident.
// POST /api/v1/incidents
func (s *IncidentService) Create(ctx context.Context, req *IncidentCreate) (*Incident, error) {
	var resp Incident
	err := s.client.do(ctx, "POST", "/api/v1/incidents", req, &resp)
	return &resp, err
}

// Get retrieves an incident by ID.
// GET /api/v1/incidents/{id}
func (s *IncidentService) Get(ctx context.Context, id string) (*Incident, error) {
	var resp Incident
	err := s.client.do(ctx, "GET", "/api/v1/incidents/"+id, nil, &resp)
	return &resp, err
}

// Triage triages an incident.
// POST /api/v1/incidents/{id}/triage
func (s *IncidentService) Triage(ctx context.Context, id string, req *IncidentTriage) (*Incident, error) {
	var resp Incident
	err := s.client.do(ctx, "POST", "/api/v1/incidents/"+id+"/triage", req, &resp)
	return &resp, err
}

// Resolve resolves an incident.
// POST /api/v1/incidents/{id}/resolve
func (s *IncidentService) Resolve(ctx context.Context, id string, req *IncidentResolve) (*Incident, error) {
	var resp Incident
	err := s.client.do(ctx, "POST", "/api/v1/incidents/"+id+"/resolve", req, &resp)
	return &resp, err
}

// =========================================================================
// Evaluator
// =========================================================================

// EvaluatorService handles evaluator endpoints.
type EvaluatorService struct{ client *Client }

// Run executes an evaluator run.
// POST /api/v1/evaluator/run
func (s *EvaluatorService) Run(ctx context.Context, req *EvaluatorRunRequest) (*EvaluatorResult, error) {
	var resp EvaluatorResult
	err := s.client.do(ctx, "POST", "/api/v1/evaluator/run", req, &resp)
	return &resp, err
}

// Verify verifies an evaluator result.
// POST /api/v1/evaluator/verify
func (s *EvaluatorService) Verify(ctx context.Context, req *EvaluatorVerifyRequest) (*EvaluatorResult, error) {
	var resp EvaluatorResult
	err := s.client.do(ctx, "POST", "/api/v1/evaluator/verify", req, &resp)
	return &resp, err
}

// =========================================================================
// Persistence
// =========================================================================

// PersistenceService handles persistence endpoints.
type PersistenceService struct{ client *Client }

// Get retrieves persistence data.
// GET /api/v1/persistence
func (s *PersistenceService) Get(ctx context.Context) (*PersistenceResult, error) {
	var resp PersistenceResult
	err := s.client.do(ctx, "GET", "/api/v1/persistence", nil, &resp)
	return &resp, err
}

// =========================================================================
// Certs
// =========================================================================

// CertsService handles certificate endpoints.
type CertsService struct{ client *Client }

// Get retrieves certificate information.
// GET /api/v1/certs
func (s *CertsService) Get(ctx context.Context) (*CertInfo, error) {
	var resp CertInfo
	err := s.client.do(ctx, "GET", "/api/v1/certs", nil, &resp)
	return &resp, err
}

// =========================================================================
// License
// =========================================================================

// LicenseService handles license endpoints.
type LicenseService struct{ client *Client }

// Status returns the current license status.
// GET /api/v1/license/status
func (s *LicenseService) Status(ctx context.Context) (*LicenseStatus, error) {
	var resp LicenseStatus
	err := s.client.do(ctx, "GET", "/api/v1/license/status", nil, &resp)
	return &resp, err
}

// =========================================================================
// SLA
// =========================================================================

// SLAService handles SLA endpoints.
type SLAService struct{ client *Client }

// Get returns SLA information.
// GET /api/v1/sla
func (s *SLAService) Get(ctx context.Context) (*SLAInfo, error) {
	var resp SLAInfo
	err := s.client.do(ctx, "GET", "/api/v1/sla", nil, &resp)
	return &resp, err
}

// =========================================================================
// TSA
// =========================================================================

// TSAService handles Time Stamping Authority endpoints.
type TSAService struct{ client *Client }

// Status returns the TSA status.
// GET /api/v1/tsa/status
func (s *TSAService) Status(ctx context.Context) (*TSAStatus, error) {
	var resp TSAStatus
	err := s.client.do(ctx, "GET", "/api/v1/tsa/status", nil, &resp)
	return &resp, err
}

// =========================================================================
// Health
// =========================================================================

// HealthService handles health check endpoints.
type HealthService struct{ client *Client }

// Get returns the platform health status.
// GET /health
func (s *HealthService) Get(ctx context.Context) (*HealthStatus, error) {
	var resp HealthStatus
	err := s.client.do(ctx, "GET", "/health", nil, &resp)
	return &resp, err
}

// Ready returns the platform readiness status.
// GET /ready
func (s *HealthService) Ready(ctx context.Context) (*HealthStatus, error) {
	var resp HealthStatus
	err := s.client.do(ctx, "GET", "/ready", nil, &resp)
	return &resp, err
}

// =========================================================================
// Version
// =========================================================================

// VersionService handles version endpoints.
type VersionService struct{ client *Client }

// Get returns platform version information.
// GET /version
func (s *VersionService) Get(ctx context.Context) (*VersionInfo, error) {
	var resp VersionInfo
	err := s.client.do(ctx, "GET", "/version", nil, &resp)
	return &resp, err
}