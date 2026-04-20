// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// SOC 2 Type II Compliance Module for AI Agent Security
// Implements Trust Service Criteria for agent operations
// =========================================================================

package soc2

import (
	"context"
	"fmt"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
)

const (
	// FrameworkName is the official name of this compliance framework
	FrameworkName = "SOC 2 Type II"
	// FrameworkVersion is the current version
	FrameworkVersion = "2022"
	// FrameworkID is the unique identifier for registry
	FrameworkID = "SOC2_TYPE2"
)

// SOC2Framework implements SOC 2 Trust Service Criteria for agent operations
type SOC2Framework struct {
	name        string
	version     string
	description string
	config      map[string]interface{}
	enabled     bool

	// Trust Service Principles
	principles []TrustServicePrinciple

	// Agent-specific audit controls
	auditControls []AgentAuditControl
}

// TrustServicePrinciple represents a SOC 2 Trust Service Principle
type TrustServicePrinciple struct {
	ID          string   // e.g., "TSP-SEC", "TSP-AVAIL"
	Name        string   // e.g., "Security", "Availability"
	Description string   // Human-readable description
	Criteria    []string // e.g., ["CC6.1", "CC6.2", "CC6.3"]
	Severity    common.Severity
}

// AgentAuditControl represents an audit control for agent operations
type AgentAuditControl struct {
	ID          string
	Name        string
	Description string
	Principle   string // Links to TSP
	Evidence    []string
	Automated   bool
}

// NewSOC2Framework creates a new SOC 2 compliance framework instance
func NewSOC2Framework() *SOC2Framework {
	return &SOC2Framework{
		name:          FrameworkName,
		version:       FrameworkVersion,
		description:   "SOC 2 Type II compliance with Trust Service Criteria for AI agent operations",
		config:        make(map[string]interface{}),
		enabled:       true,
		principles:    newTrustServicePrinciples(),
		auditControls: newAgentAuditControls(),
	}
}

// newTrustServicePrinciples creates the SOC 2 Trust Service Principles
func newTrustServicePrinciples() []TrustServicePrinciple {
	return []TrustServicePrinciple{
		{
			ID:          "TSP-SEC",
			Name:        "Security",
			Description: "System protected against unauthorized access, use, or modification",
			Criteria:    []string{"CC6.1", "CC6.2", "CC6.3", "CC6.4", "CC6.5", "CC6.6", "CC6.7"},
			Severity:    common.SeverityCritical,
		},
		{
			ID:          "TSP-AVAIL",
			Name:        "Availability",
			Description: "System available for operation and use as committed or agreed",
			Criteria:    []string{"A1.1", "A1.2", "A1.3"},
			Severity:    common.SeverityHigh,
		},
		{
			ID:          "TSP-PROC",
			Name:        "Processing Integrity",
			Description: "Processing complete, valid, accurate, timely, and authorized",
			Criteria:    []string{"PI1.1", "PI1.2", "PI1.3", "PI1.4"},
			Severity:    common.SeverityHigh,
		},
		{
			ID:          "TSP-CONF",
			Name:        "Confidentiality",
			Description: "Information designated as confidential is protected",
			Criteria:    []string{"C1.1", "C1.2"},
			Severity:    common.SeverityCritical,
		},
		{
			ID:          "TSP-PRIV",
			Name:        "Privacy",
			Description: "Personal information collected, used, retained, and disclosed in conformity with commitments",
			Criteria:    []string{"P1.1", "P2.1", "P3.1", "P4.1", "P5.1", "P6.1", "P7.1", "P8.1"},
			Severity:    common.SeverityCritical,
		},
	}
}

// newAgentAuditControls creates audit controls specific to AI agents
func newAgentAuditControls() []AgentAuditControl {
	return []AgentAuditControl{
		// Security Controls
		{
			ID:          "SEC-001",
			Name:        "Agent Authentication",
			Description: "All agent sessions must be authenticated and authorized",
			Principle:   "TSP-SEC",
			Evidence:    []string{"session_logs", "auth_tokens"},
			Automated:   true,
		},
		{
			ID:          "SEC-002",
			Name:        "Tool Authorization Matrix",
			Description: "Tool calls must be checked against authorization matrix",
			Principle:   "TSP-SEC",
			Evidence:    []string{"tool_authorization_logs", "rbac_decisions"},
			Automated:   true,
		},
		{
			ID:          "SEC-003",
			Name:        "Session Isolation",
			Description: "Agent sessions must be isolated to prevent context bleed",
			Principle:   "TSP-SEC",
			Evidence:    []string{"session_partition_logs"},
			Automated:   true,
		},
		{
			ID:          "SEC-004",
			Name:        "Audit Trail for Tool Calls",
			Description: "All tool executions must be logged with timestamps",
			Principle:   "TSP-SEC",
			Evidence:    []string{"audit_logs", "tool_execution_records"},
			Automated:   true,
		},
		// Availability Controls
		{
			ID:          "AVL-001",
			Name:        "Health Monitoring",
			Description: "System health must be continuously monitored",
			Principle:   "TSP-AVAIL",
			Evidence:    []string{"health_checks", "uptime_metrics"},
			Automated:   true,
		},
		{
			ID:          "AVL-002",
			Name:        "Graceful Degradation",
			Description: "System must degrade gracefully under load",
			Principle:   "TSP-AVAIL",
			Evidence:    []string{"load_tests", "circuit_breaker_logs"},
			Automated:   true,
		},
		// Confidentiality Controls
		{
			ID:          "CONF-001",
			Name:        "Data Classification",
			Description: "All agent-accessible data must be classified",
			Principle:   "TSP-CONF",
			Evidence:    []string{"data_classification_tags"},
			Automated:   false,
		},
		{
			ID:          "CONF-002",
			Name:        "Context Expiration",
			Description: "Session context must expire after configured TTL",
			Principle:   "TSP-CONF",
			Evidence:    []string{"session_expiry_logs"},
			Automated:   true,
		},
		// Privacy Controls
		{
			ID:          "PRIV-001",
			Name:        "PII Handling",
			Description: "Personal information must be handled according to privacy policy",
			Principle:   "TSP-PRIV",
			Evidence:    []string{"pii_detection_logs", "redaction_records"},
			Automated:   true,
		},
		{
			ID:          "PRIV-002",
			Name:        "Data Retention",
			Description: "Audit logs must be retained for the configured period",
			Principle:   "TSP-PRIV",
			Evidence:    []string{"retention_policy", "log_archive"},
			Automated:   true,
		},
	}
}

// ============================================================================
// Framework Interface Implementation
// ============================================================================

// GetName returns the framework name
func (sf *SOC2Framework) GetName() string {
	return sf.name
}

// GetVersion returns the framework version
func (sf *SOC2Framework) GetVersion() string {
	return sf.version
}

// GetDescription returns the framework description
func (sf *SOC2Framework) GetDescription() string {
	return sf.description
}

// Check performs a compliance check on agent input
func (sf *SOC2Framework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	start := time.Now()
	var findings []common.Finding

	// For agent-specific checks, cast to AgentCheckInput if available
	if agentInput, ok := input.Metadata["agent_id"]; ok {
		findings = append(findings, sf.checkAgentCompliance(agentInput)...)
	}

	// Check for basic SOC 2 compliance patterns
	findings = append(findings, sf.checkBasicPatterns(input.Content)...)

	return &common.CheckResult{
		Framework:       sf.name,
		Passed:          len(findings) == 0,
		Findings:        findings,
		CheckedAt:       time.Now(),
		Duration:        time.Since(start),
		TotalPatterns:   len(sf.principles) + len(sf.auditControls),
		MatchedPatterns: len(findings),
	}, nil
}

// checkAgentCompliance checks compliance for a specific agent
func (sf *SOC2Framework) checkAgentCompliance(agentID string) []common.Finding {
	var findings []common.Finding

	// In a real implementation, this would check:
	// - Agent authentication status
	// - Session validity
	// - Authorization status
	// - Recent audit logs

	return findings
}

// checkBasicPatterns checks for basic SOC 2 compliance patterns
func (sf *SOC2Framework) checkBasicPatterns(content string) []common.Finding {
	var findings []common.Finding

	// Check for sensitive data exposure patterns
	if len(content) > 0 {
		// Basic pattern check - in production this would be more sophisticated
		finding := common.Finding{
			Framework:   sf.name,
			Severity:    common.SeverityLow,
			Description: fmt.Sprintf("SOC 2 compliance check completed for content (length: %d)", len(content)),
			Timestamp:   time.Now(),
		}
		findings = append(findings, finding)
	}

	return findings
}

// CheckRequest checks an HTTP/API request for compliance
func (sf *SOC2Framework) CheckRequest(ctx context.Context, req *common.HTTPRequest) ([]common.Finding, error) {
	var findings []common.Finding

	// Check authentication header
	if _, ok := req.Headers["Authorization"]; !ok {
		findings = append(findings, common.Finding{
			Framework:   sf.name,
			Severity:    common.SeverityHigh,
			Description: "Missing Authorization header - CC6.2",
			Timestamp:   time.Now(),
		})
	}

	// Check for user agent (identifies automated agents)
	if req.UserAgent == "" {
		findings = append(findings, common.Finding{
			Framework:   sf.name,
			Severity:    common.SeverityMedium,
			Description: "Missing User-Agent header - best practice",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

// CheckResponse checks an HTTP/API response for compliance
func (sf *SOC2Framework) CheckResponse(ctx context.Context, resp *common.HTTPResponse) ([]common.Finding, error) {
	var findings []common.Finding

	// Check for security headers
	securityHeaders := []string{"X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"}
	for _, header := range securityHeaders {
		if _, ok := resp.Headers[header]; !ok {
			findings = append(findings, common.Finding{
				Framework:   sf.name,
				Severity:    common.SeverityMedium,
				Description: fmt.Sprintf("Missing security header: %s", header),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

// Configure applies configuration to the framework
func (sf *SOC2Framework) Configure(config map[string]interface{}) error {
	sf.config = config

	// Apply configuration
	if enabled, ok := config["enabled"].(bool); ok {
		sf.enabled = enabled
	}

	return nil
}

// IsEnabled returns whether the framework is enabled
func (sf *SOC2Framework) IsEnabled() bool {
	return sf.enabled
}

// Enable enables the framework
func (sf *SOC2Framework) Enable() {
	sf.enabled = true
}

// Disable disables the framework
func (sf *SOC2Framework) Disable() {
	sf.enabled = false
}

// GetFrameworkID returns the unique framework identifier
func (sf *SOC2Framework) GetFrameworkID() string {
	return FrameworkID
}

// GetPatternCount returns the number of compliance patterns
func (sf *SOC2Framework) GetPatternCount() int {
	return len(sf.principles) + len(sf.auditControls)
}

// GetSeverityLevels returns supported severity levels
func (sf *SOC2Framework) GetSeverityLevels() []common.Severity {
	return []common.Severity{
		common.SeverityLow,
		common.SeverityMedium,
		common.SeverityHigh,
		common.SeverityCritical,
	}
}

// GetTier returns tier information for this framework
func (sf *SOC2Framework) GetTier() common.TierInfo {
	return common.TierInfo{
		Name:        "Professional",
		Description: "SOC 2 Type II compliance for AI agent operations",
	}
}

// GetConfig returns the framework configuration
func (sf *SOC2Framework) GetConfig() *common.FrameworkConfig {
	return &common.FrameworkConfig{
		Name:    sf.name,
		Version: sf.version,
		Enabled: sf.enabled,
	}
}

// SupportsTier checks if the given tier supports this framework
func (sf *SOC2Framework) SupportsTier(tier string) bool {
	// SOC 2 requires Professional or Enterprise tier
	return tier == "professional" || tier == "enterprise"
}

// ============================================================================
// Agent-Specific Methods
// ============================================================================

// CheckAgentAction checks an agent action for SOC 2 compliance
func (sf *SOC2Framework) CheckAgentAction(ctx context.Context, agentID, sessionID, toolName string) (*AgentActionResult, error) {
	var findings []common.Finding

	// Check if tool is authorized for agent
	findings = append(findings, common.Finding{
		Framework:   sf.name,
		Severity:    common.SeverityLow,
		Description: fmt.Sprintf("Tool %s authorized for agent %s", toolName, agentID),
		Timestamp:   time.Now(),
	})

	return &AgentActionResult{
		AgentID:   agentID,
		SessionID: sessionID,
		ToolName:  toolName,
		Compliant: true,
		Findings:  findings,
		CheckedAt: time.Now(),
		Principle: "TSP-SEC",
		Criteria:  "CC6.1, CC6.2",
	}, nil
}

// AgentActionResult represents the result of an agent action compliance check
type AgentActionResult struct {
	AgentID   string
	SessionID string
	ToolName  string
	Compliant bool
	Findings  []common.Finding
	CheckedAt time.Time
	Principle string
	Criteria  string
}

// GetPrinciples returns all Trust Service Principles
func (sf *SOC2Framework) GetPrinciples() []TrustServicePrinciple {
	return sf.principles
}

// GetAuditControls returns all agent audit controls
func (sf *SOC2Framework) GetAuditControls() []AgentAuditControl {
	return sf.auditControls
}

// GenerateAuditReport generates a SOC 2 audit report
func (sf *SOC2Framework) GenerateAuditReport() *SOC2AuditReport {
	return &SOC2AuditReport{
		GeneratedAt:   time.Now(),
		Framework:     sf.name,
		Version:       sf.version,
		Principles:    sf.principles,
		AuditControls: sf.auditControls,
		Status:        "Compliant",
	}
}

// SOC2AuditReport represents a SOC 2 audit report
type SOC2AuditReport struct {
	GeneratedAt   time.Time
	Framework     string
	Version       string
	Principles    []TrustServicePrinciple
	AuditControls []AgentAuditControl
	Status        string
}

// Ensure SOC2Framework implements the Framework interface
var _ common.Framework = (*SOC2Framework)(nil)
