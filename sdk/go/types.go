// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform Go SDK — Request & Response Types (v3.6.0)
// =========================================================================
//
// types.go defines all request and response types for the AegisGate v4.3.3
// platform API. Types are organised by service domain.
// =========================================================================

package aegisgate

import "time"

// =========================================================================
// Health & Version
// =========================================================================

// HealthStatus represents the platform health status.
type HealthStatus struct {
	Status    string            `json:"status"`
	Component map[string]string `json:"component,omitempty"`
	Timestamp string            `json:"timestamp,omitempty"`
}

// VersionInfo represents the platform version information.
type VersionInfo struct {
	Version   string `json:"version"`
	Build     string `json:"build,omitempty"`
	Commit    string `json:"commit,omitempty"`
	GoVersion string `json:"go_version,omitempty"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
}

// =========================================================================
// Auth
// =========================================================================

// LoginRequest is the payload for POST /auth/login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is returned on successful authentication.
type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      UserInfo  `json:"user"`
}

// UserInfo holds basic user information.
type UserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Email    string `json:"email,omitempty"`
}

// CreateUserRequest is the payload for POST /auth/users.
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Email    string `json:"email,omitempty"`
}

// =========================================================================
// Compliance
// =========================================================================

// ScanReport represents a compliance scan report.
type ScanReport struct {
	ID          string          `json:"id"`
	Status      string          `json:"status"`
	Framework   string          `json:"framework"`
	Score       float64         `json:"score"`
	Controls    []ControlResult `json:"controls,omitempty"`
	StartedAt   string          `json:"started_at,omitempty"`
	CompletedAt string          `json:"completed_at,omitempty"`
}

// ControlResult represents a single compliance control check result.
type ControlResult struct {
	ID     string  `json:"id"`
	Status string  `json:"status"`
	Score  float64 `json:"score"`
}

// ComplianceReport represents a detailed compliance report.
type ComplianceReport struct {
	ID          string          `json:"id"`
	Framework   string          `json:"framework"`
	Status      string          `json:"status"`
	Score       float64         `json:"score"`
	Controls    []ControlResult `json:"controls,omitempty"`
	GeneratedAt string          `json:"generated_at,omitempty"`
}

// IntegrityResult represents a compliance integrity check.
type IntegrityResult struct {
	Status   string `json:"status"`
	Checksum string `json:"checksum,omitempty"`
	Message  string `json:"message,omitempty"`
}

// EvidenceResult represents compliance evidence data.
type EvidenceResult struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	Content   string `json:"content,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// =========================================================================
// Trust
// =========================================================================

// TrustScore represents a trust score for an entity.
type TrustScore struct {
	EntityID   string  `json:"entity_id"`
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source,omitempty"`
	Timestamp  string  `json:"timestamp,omitempty"`
}

// TrustDashboard represents the trust dashboard summary.
type TrustDashboard struct {
	OverallScore float64      `json:"overall_score"`
	Scores       []TrustScore `json:"scores,omitempty"`
	UpdatedAt    string       `json:"updated_at,omitempty"`
}

// TrustAnomalies represents detected trust anomalies.
type TrustAnomalies struct {
	Anomalies []TrustAnomaly `json:"anomalies,omitempty"`
	Count     int            `json:"count"`
}

// TrustAnomaly represents a single trust anomaly.
type TrustAnomaly struct {
	ID        string  `json:"id"`
	EntityID  string  `json:"entity_id"`
	Score     float64 `json:"score"`
	Deviation float64 `json:"deviation"`
	Message   string  `json:"message,omitempty"`
	Timestamp string  `json:"timestamp,omitempty"`
}

// TrustComplianceResult represents a trust compliance check.
type TrustComplianceResult struct {
	Compliant bool     `json:"compliant"`
	Issues    []string `json:"issues,omitempty"`
	Score     float64  `json:"score"`
}

// =========================================================================
// Scan
// =========================================================================

// ScanRequest is the payload for POST /api/v1/scan.
type ScanRequest struct {
	Target  string            `json:"target"`
	Type    string            `json:"type,omitempty"`
	Options map[string]string `json:"options,omitempty"`
}

// ScanResult represents a scan result.
type ScanResult struct {
	ID        string            `json:"id"`
	Target    string            `json:"target"`
	Status    string            `json:"status"`
	Findings  []ScanFinding     `json:"findings,omitempty"`
	StartedAt string            `json:"started_at,omitempty"`
	EndedAt   string            `json:"ended_at,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// ScanFinding represents a single scan finding.
type ScanFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Resource    string `json:"resource,omitempty"`
}

// =========================================================================
// Guardrails
// =========================================================================

// GuardrailsResult represents a guardrails check result.
type GuardrailsResult struct {
	Allowed  bool              `json:"allowed"`
	Reason   string            `json:"reason,omitempty"`
	Rules    []string          `json:"rules,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// =========================================================================
// Analytics
// =========================================================================

// AnalyticsUsage represents platform usage analytics.
type AnalyticsUsage struct {
	Period     string                 `json:"period"`
	Requests   int64                  `json:"requests"`
	ByEndpoint map[string]int64       `json:"by_endpoint,omitempty"`
	ByMethod   map[string]int64       `json:"by_method,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// AnalyticsCost represents cost analytics.
type AnalyticsCost struct {
	Period    string             `json:"period"`
	TotalCost float64            `json:"total_cost"`
	Currency  string             `json:"currency,omitempty"`
	Breakdown map[string]float64 `json:"breakdown,omitempty"`
}

// AnalyticsAnomalies represents detected analytics anomalies.
type AnalyticsAnomalies struct {
	Anomalies []Anomaly `json:"anomalies,omitempty"`
	Count     int       `json:"count"`
}

// Anomaly represents a single analytics anomaly.
type Anomaly struct {
	ID        string  `json:"id"`
	Type      string  `json:"type"`
	Severity  string  `json:"severity"`
	Score     float64 `json:"score"`
	Message   string  `json:"message,omitempty"`
	Timestamp string  `json:"timestamp,omitempty"`
}

// AnalyticsDashboard represents a combined analytics dashboard.
type AnalyticsDashboard struct {
	Usage     AnalyticsUsage     `json:"usage"`
	Cost      AnalyticsCost      `json:"cost"`
	Anomalies AnalyticsAnomalies `json:"anomalies"`
	UpdatedAt string             `json:"updated_at,omitempty"`
}

// =========================================================================
// IOC
// =========================================================================

// IOCManifest represents an IOC manifest.
type IOCManifest struct {
	ID        string     `json:"id"`
	Entries   []IOCEntry `json:"entries,omitempty"`
	Version   string     `json:"version,omitempty"`
	Timestamp string     `json:"timestamp,omitempty"`
}

// IOCEntry represents a single IOC entry.
type IOCEntry struct {
	Indicator string `json:"indicator"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Source    string `json:"source,omitempty"`
}

// IOCStatus represents the health status of the IOC system.
type IOCStatus struct {
	Status     string `json:"status"`
	LastSync   string `json:"last_sync,omitempty"`
	EntryCount int    `json:"entry_count"`
}

// =========================================================================
// SIEM
// =========================================================================

// SIEMStatus represents SIEM integration status.
type SIEMStatus struct {
	Connected   bool   `json:"connected"`
	Provider    string `json:"provider,omitempty"`
	LastEventAt string `json:"last_event_at,omitempty"`
	Status      string `json:"status"`
}

// =========================================================================
// ML
// =========================================================================

// MLShadowMetrics represents shadow-mode ML performance metrics.
// Mirrors pkg/ml.ShadowMetrics from the AegisGate platform.
type MLShadowMetrics struct {
	TruePositives     int     `json:"true_positives"`
	TrueNegatives     int     `json:"true_negatives"`
	FalsePositives    int     `json:"false_positives"`
	FalseNegatives    int     `json:"false_negatives"`
	Precision         float64 `json:"precision"`
	Recall            float64 `json:"recall"`
	F1Score           float64 `json:"f1_score"`
	AUROC             float64 `json:"auroc"`
	TotalPredictions  int     `json:"total_predictions"`
	Threshold         float64 `json:"threshold"`
	ModelVersion      string  `json:"model_version"`
	ShadowModeEnabled bool    `json:"shadow_mode_enabled"`
	Timestamp         string  `json:"timestamp,omitempty"`
}

// =========================================================================
// Audit
// =========================================================================

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	ID        string            `json:"id"`
	Action    string            `json:"action"`
	Actor     string            `json:"actor,omitempty"`
	Resource  string            `json:"resource,omitempty"`
	Timestamp string            `json:"timestamp"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// AuditQueryResult represents the result of an audit query.
type AuditQueryResult struct {
	Entries []AuditEntry `json:"entries,omitempty"`
	Total   int          `json:"total"`
	Cursor  string       `json:"cursor,omitempty"`
}

// =========================================================================
// Policy
// =========================================================================

// Policy represents a security policy.
type Policy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Rules       []PolicyRule      `json:"rules,omitempty"`
	Enabled     bool              `json:"enabled"`
	CreatedAt   string            `json:"created_at,omitempty"`
	UpdatedAt   string            `json:"updated_at,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// PolicyRule represents a single rule within a policy.
type PolicyRule struct {
	ID       string `json:"id"`
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Action   string `json:"action,omitempty"`
}

// =========================================================================
// Cluster
// =========================================================================

// ClusterHealth represents cluster health status.
type ClusterHealth struct {
	Status   string                 `json:"status"`
	Nodes    []ClusterNode          `json:"nodes,omitempty"`
	Leader   string                 `json:"leader,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ClusterNode represents a single cluster node.
type ClusterNode struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Role      string `json:"role"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// =========================================================================
// Bridge
// =========================================================================

// BridgeResult represents the bridge status.
type BridgeResult struct {
	Connected bool              `json:"connected"`
	Target    string            `json:"target,omitempty"`
	Status    string            `json:"status"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// =========================================================================
// Attestation
// =========================================================================

// AttestationRequest is the payload for attestation verification.
type AttestationRequest struct {
	Artifact  string            `json:"artifact"`
	PolicyID  string            `json:"policy_id,omitempty"`
	Signature string            `json:"signature,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// AttestationResult represents an attestation verification result.
type AttestationResult struct {
	Valid       bool              `json:"valid"`
	PolicyID    string            `json:"policy_id,omitempty"`
	Claims      map[string]string `json:"claims,omitempty"`
	Certificate string            `json:"certificate,omitempty"`
	Timestamp   string            `json:"timestamp,omitempty"`
}

// =========================================================================
// AI-BOM
// =========================================================================

// AIBOMRequest is the payload for AI-BOM generation.
type AIBOMRequest struct {
	ModelName    string            `json:"model_name"`
	ModelVersion string            `json:"model_version,omitempty"`
	Components   []string          `json:"components,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// AIBOMResult represents an AI Bill of Materials.
type AIBOMResult struct {
	ID          string           `json:"id"`
	ModelName   string           `json:"model_name"`
	Version     string           `json:"version,omitempty"`
	Components  []AIBOMComponent `json:"components,omitempty"`
	GeneratedAt string           `json:"generated_at,omitempty"`
	Checksum    string           `json:"checksum,omitempty"`
}

// AIBOMComponent represents a single component in an AI-BOM.
type AIBOMComponent struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"`
	License string `json:"license,omitempty"`
}

// =========================================================================
// A2A (Agent-to-Agent)
// =========================================================================

// A2AIntentSignRequest is the payload for signing an A2A intent.
type A2AIntentSignRequest struct {
	Intent   string            `json:"intent"`
	AgentID  string            `json:"agent_id"`
	Targets  []string          `json:"targets,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// A2AIntentVerifyRequest is the payload for verifying an A2A intent.
type A2AIntentVerifyRequest struct {
	Intent    string `json:"intent"`
	Signature string `json:"signature"`
	AgentID   string `json:"agent_id"`
}

// A2AIntentResult represents a signed or verified A2A intent.
type A2AIntentResult struct {
	Valid     bool              `json:"valid,omitempty"`
	Intent    string            `json:"intent"`
	AgentID   string            `json:"agent_id"`
	Signature string            `json:"signature,omitempty"`
	Targets   []string          `json:"targets,omitempty"`
	ExpiresAt string            `json:"expires_at,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// =========================================================================
// Digest
// =========================================================================

// DigestGenerateRequest is the payload for digest generation.
type DigestGenerateRequest struct {
	Data      string            `json:"data"`
	Algorithm string            `json:"algorithm,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// DigestVerifyRequest is the payload for digest verification.
type DigestVerifyRequest struct {
	Data      string `json:"data"`
	Digest    string `json:"digest"`
	Algorithm string `json:"algorithm,omitempty"`
}

// DigestResult represents a generated or verified digest.
type DigestResult struct {
	Digest    string `json:"digest"`
	Algorithm string `json:"algorithm"`
	Valid     bool   `json:"valid,omitempty"`
	Data      string `json:"data,omitempty"`
}

// =========================================================================
// Incident
// =========================================================================

// IncidentCreate is the payload for creating an incident.
type IncidentCreate struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Assignee    string            `json:"assignee,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Incident represents an incident.
type Incident struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Severity    string            `json:"severity"`
	Status      string            `json:"status"`
	Assignee    string            `json:"assignee,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	CreatedAt   string            `json:"created_at,omitempty"`
	UpdatedAt   string            `json:"updated_at,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// IncidentTriage is the payload for triaging an incident.
type IncidentTriage struct {
	Priority string `json:"priority"`
	Assignee string `json:"assignee,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// IncidentResolve is the payload for resolving an incident.
type IncidentResolve struct {
	Resolution string `json:"resolution"`
	Notes      string `json:"notes,omitempty"`
}

// =========================================================================
// Evaluator
// =========================================================================

// EvaluatorRunRequest is the payload for running an evaluator.
type EvaluatorRunRequest struct {
	Target   string            `json:"target"`
	PolicyID string            `json:"policy_id,omitempty"`
	Checks   []string          `json:"checks,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// EvaluatorVerifyRequest is the payload for verifying an evaluator result.
type EvaluatorVerifyRequest struct {
	Target    string `json:"target"`
	ResultID  string `json:"result_id"`
	Signature string `json:"signature,omitempty"`
}

// EvaluatorResult represents an evaluator run or verify result.
type EvaluatorResult struct {
	ID        string            `json:"id"`
	Target    string            `json:"target"`
	Status    string            `json:"status"`
	Score     float64           `json:"score,omitempty"`
	Checks    []EvaluatorCheck  `json:"checks,omitempty"`
	Verified  bool              `json:"verified,omitempty"`
	Timestamp string            `json:"timestamp,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// EvaluatorCheck represents a single evaluator check.
type EvaluatorCheck struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// =========================================================================
// Persistence
// =========================================================================

// PersistenceResult represents a persistence query result.
type PersistenceResult struct {
	Key       string            `json:"key"`
	Value     string            `json:"value"`
	Version   string            `json:"version,omitempty"`
	UpdatedAt string            `json:"updated_at,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// =========================================================================
// Certificates
// =========================================================================

// CertInfo represents certificate information.
type CertInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SerialNumber string    `json:"serial_number"`
	Fingerprint  string    `json:"fingerprint,omitempty"`
}

// =========================================================================
// License
// =========================================================================

// LicenseStatus represents the current license status.
type LicenseStatus struct {
	Valid      bool     `json:"valid"`
	Tier       string   `json:"tier,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	Features   []string `json:"features,omitempty"`
	CustomerID string   `json:"customer_id,omitempty"`
}

// TierInfo represents information about a license tier.
type TierInfo struct {
	Name     string         `json:"name"`
	Features []string       `json:"features,omitempty"`
	Limits   map[string]int `json:"limits,omitempty"`
}

// =========================================================================
// SLA
// =========================================================================

// SLAInfo represents SLA information.
type SLAInfo struct {
	Uptime       float64 `json:"uptime"`
	LatencyP50   float64 `json:"latency_p50,omitempty"`
	LatencyP99   float64 `json:"latency_p99,omitempty"`
	TargetUptime float64 `json:"target_uptime,omitempty"`
	Status       string  `json:"status"`
	Period       string  `json:"period,omitempty"`
}

// =========================================================================
// TSA
// =========================================================================

// TSAStatus represents the Time Stamping Authority status.
type TSAStatus struct {
	Available   bool   `json:"available"`
	LastStamp   string `json:"last_stamp,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Status      string `json:"status"`
}

// =========================================================================
// Vendor Risk Types
// =========================================================================

type VendorProfile struct {
	Name      string  `json:"name"`
	Category  string  `json:"category"`
	Score     float64 `json:"score"`
	RiskLevel string  `json:"risk_level"`
}

type VendorAssessment struct {
	ID              string             `json:"id"`
	VendorName      string             `json:"vendor_name"`
	Category        string             `json:"category"`
	OverallScore    float64            `json:"overall_score"`
	RiskLevel       string             `json:"risk_level"`
	Dimensions      map[string]float64 `json:"dimensions"`
	Recommendations []string           `json:"recommendations"`
}

type VendorRiskAssessRequest struct {
	VendorName string `json:"vendor_name"`
	Category   string `json:"category,omitempty"`
}

// =========================================================================
// Policy Engine Types
// =========================================================================

type PolicyInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Framework   string `json:"framework"`
	ControlID   string `json:"control_id"`
	Language    string `json:"language"`
	Description string `json:"description,omitempty"`
}

type PolicyEvaluateRequest struct {
	Request     map[string]any `json:"request,omitempty"`
	Config      map[string]any `json:"config,omitempty"`
	ScanResult  map[string]any `json:"scan_result,omitempty"`
	Environment map[string]any `json:"environment,omitempty"`
	CustomData  map[string]any `json:"custom_data,omitempty"`
}

type PolicyEvaluateResult struct {
	Results []PolicyResult `json:"results"`
}

type PolicyResult struct {
	PolicyID string  `json:"policy_id"`
	Allowed  bool    `json:"allowed"`
	Reason   string  `json:"reason,omitempty"`
	Score    float64 `json:"score"`
}

// =========================================================================
// Evidence Types
// =========================================================================

type EvidenceItem struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Framework   string            `json:"framework"`
	ControlID   string            `json:"control_id"`
	Description string            `json:"description"`
	Status      string            `json:"status"`
	ContentHash string            `json:"content_hash"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type EvidenceCollection struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Framework string         `json:"framework"`
	Items     []EvidenceItem `json:"items"`
	Status    string         `json:"status"`
}

type EvidenceCollectRequest struct {
	Framework string `json:"framework"`
	ControlID string `json:"control_id,omitempty"`
	Type      string `json:"type,omitempty"`
}

type EvidenceVerifyRequest struct {
	ID         string `json:"id"`
	VerifiedBy string `json:"verified_by"`
}

// =========================================================================
// ML A/B Testing Types
// =========================================================================

type ABTestConfig struct {
	ID                  string  `json:"id"`
	Name                string  `json:"name"`
	ChampionModelPath   string  `json:"champion_model_path"`
	ChallengerModelPath string  `json:"challenger_model_path"`
	ChampionVersion     string  `json:"champion_version"`
	ChallengerVersion   string  `json:"challenger_version"`
	TrafficSplitPct     float64 `json:"traffic_split_pct"`
	MinSampleSize       int     `json:"min_sample_size"`
	ConfidenceLevel     float64 `json:"confidence_level"`
}

type ABTestCreateRequest struct {
	Name                string  `json:"name"`
	ChampionModelPath   string  `json:"champion_model_path"`
	ChallengerModelPath string  `json:"challenger_model_path"`
	ChampionVersion     string  `json:"champion_version"`
	ChallengerVersion   string  `json:"challenger_version"`
	TrafficSplitPct     float64 `json:"traffic_split_pct"`
	MinSampleSize       int     `json:"min_sample_size"`
	ConfidenceLevel     float64 `json:"confidence_level"`
}

type ABTestStatusResult struct {
	ID                string         `json:"id"`
	Status            string         `json:"status"`
	ChampionMetrics   ABModelMetrics `json:"champion_metrics"`
	ChallengerMetrics ABModelMetrics `json:"challenger_metrics"`
	SampleSize        int            `json:"sample_size"`
}

type ABModelMetrics struct {
	ModelVersion     string  `json:"model_version"`
	TotalPredictions int     `json:"total_predictions"`
	TruePositives    int     `json:"true_positives"`
	TrueNegatives    int     `json:"true_negatives"`
	FalsePositives   int     `json:"false_positives"`
	FalseNegatives   int     `json:"false_negatives"`
	TPR              float64 `json:"tpr"`
	FPR              float64 `json:"fpr"`
	Precision        float64 `json:"precision"`
	F1Score          float64 `json:"f1_score"`
}

type ABTestResult struct {
	TestID           string  `json:"test_id"`
	Status           string  `json:"status"`
	Winner           string  `json:"winner"`
	ConfidencePValue float64 `json:"confidence_p_value"`
	Recommendation   string  `json:"recommendation"`
}

// =========================================================================
// Evasion Types
// =========================================================================

type EvasionDetectRequest struct {
	Text string `json:"text"`
}

type EvasionDetectResult struct {
	Detected        bool                  `json:"detected"`
	Score           float64               `json:"score"`
	MatchedPatterns []EvasionPatternMatch `json:"matched_patterns"`
}

type EvasionPatternMatch struct {
	Name     string  `json:"name"`
	Category string  `json:"category"`
	Severity float64 `json:"severity"`
}

// =========================================================================
// DSAR (Data Subject Access Request) — GDPR Articles 15-20
// =========================================================================

// dsarExportRequest is the internal request payload for POST /api/v1/dsar/export.
type dsarExportRequest struct {
	EntityID string `json:"entity_id"`
}

// dsarEraseRequest is the internal request payload for POST /api/v1/dsar/erase.
type dsarEraseRequest struct {
	EntityID string `json:"entity_id"`
}

// DSARExportBundle is the structured data export produced by DSAR.
// Implements GDPR Article 15 (right of access) and Article 20 (portability).
type DSARExportBundle struct {
	EntityID   string                 `json:"entity_id"`
	ExportedAt time.Time              `json:"exported_at"`
	Providers  map[string]interface{} `json:"providers"`
}

// DSAREraseResult records the outcome of an erasure request.
// Implements GDPR Article 17 (right to erasure).
type DSAREraseResult struct {
	EntityID        string         `json:"entity_id"`
	ErasedAt        time.Time      `json:"erased_at"`
	RecordsAffected int            `json:"records_affected"`
	Providers       map[string]int `json:"providers"`
	BlockedBy       string         `json:"blocked_by,omitempty"` // "legal_hold" if blocked
}

// =========================================================================
// Legal Hold — E-Discovery Compliance
// =========================================================================

// LegalHold represents a legal hold on a specific entity.
type LegalHold struct {
	ID         string    `json:"id"`
	EntityID   string    `json:"entity_id"`
	EntityType string    `json:"entity_type"`
	Reason     string    `json:"reason"`
	IssuedBy   string    `json:"issued_by"`
	CreatedAt  time.Time `json:"created_at"`
	ReleasedAt time.Time `json:"released_at,omitempty"`
}

// LegalHoldCreateRequest is the payload for POST /api/v1/legal-holds.
type LegalHoldCreateRequest struct {
	EntityID   string `json:"entity_id"`
	EntityType string `json:"entity_type"`
	Reason     string `json:"reason"`
	IssuedBy   string `json:"issued_by"`
}

// =========================================================================
// A/B Testing v4.3.0 — Variant-based ML model testing
// =========================================================================

// ABTestV4Variant defines a variant in an A/B test.
type ABTestV4Variant struct {
	Name     string `json:"name"`
	Weight   int    `json:"weight"`
	ModelRef string `json:"model_ref"`
}

// ABTestV4CreateRequest is the payload for POST /api/v1/abtest/tests.
type ABTestV4CreateRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Variants    []ABTestV4Variant `json:"variants"`
}

// ABTestV4Test represents an A/B test.
type ABTestV4Test struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Variants    []ABTestV4Variant `json:"variants"`
	Status      string            `json:"status"` // "created", "running", "stopped"
	CreatedAt   time.Time         `json:"created_at"`
}

// ABTestV4ListResponse is the response from GET /api/v1/abtest/tests.
type ABTestV4ListResponse struct {
	Tests []*ABTestV4Test `json:"tests"`
	Count int             `json:"count"`
}

// ABTestV4VariantMetrics holds per-variant metrics.
type ABTestV4VariantMetrics struct {
	VariantName    string  `json:"variant_name"`
	TotalRequests  int     `json:"total_requests"`
	Detections     int     `json:"detections"`
	FalsePositives int     `json:"false_positives"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
}

// abTestV4AssignRequest is the internal request payload for assign.
type abTestV4AssignRequest struct {
	RequestID string `json:"request_id"`
}

// ABTestV4ResultRequest is the payload for POST /api/v1/abtest/tests/{id}/result.
type ABTestV4ResultRequest struct {
	VariantName   string  `json:"variant_name"`
	Detected      bool    `json:"detected"`
	FalsePositive bool    `json:"false_positive"`
	LatencyMs     float64 `json:"latency_ms"`
}
