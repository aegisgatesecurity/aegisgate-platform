// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package compliance provides compliance checking capabilities for AegisGate
// Implements MITRE ATLAS, NIST AI RMF, OWASP, GDPR, HIPAA, PCI-DSS, SOC2, and ISO 42001
package compliance

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Framework represents a compliance framework identifier.
type Framework string

// Compliance frameworks
const (
	// FrameworkNIST1500 is the NIST AI Risk Management Framework.
	FrameworkNIST1500 Framework = "NIST.AI-1.500"
	// FrameworkATLAS is the MITRE ATLAS framework.
	FrameworkATLAS Framework = "ATLAS"
	// FrameworkSOC2 is the SOC 2 framework.
	FrameworkSOC2 Framework = "SOC2"
	// FrameworkGDPR is the GDPR framework.
	FrameworkGDPR Framework = "GDPR"
	// FrameworkHIPAA is the HIPAA framework.
	FrameworkHIPAA Framework = "HIPAA"
	// FrameworkPCIDSS is the PCI-DSS framework.
	FrameworkPCIDSS Framework = "PCI-DSS"
	// FrameworkOWASP is the OWASP framework.
	FrameworkOWASP Framework = "OWASP"
	// FrameworkISO27001 is the ISO 27001 framework.
	FrameworkISO27001 Framework = "ISO27001"
	// FrameworkISO42001 is the ISO/IEC 42001 framework.
	FrameworkISO42001 Framework = "ISO/IEC 42001"
)

// Severity levels for findings
type Severity string

// Severity aliases for backward compatibility with submodules using old naming
const (
	// SeverityCritical indicates critical severity level.
	SeverityCritical Severity = "Critical"
	// SeverityHigh indicates high severity level.
	SeverityHigh Severity = "High"
	// SeverityMedium indicates medium severity level.
	SeverityMedium Severity = "Medium"
	// SeverityLow indicates low severity level.
	SeverityLow Severity = "Low"
	// SeverityInfo indicates informational severity level.
	SeverityInfo Severity = "Info"
)

// ControlSeverity is an alias for backward compatibility
type ControlSeverity = Severity

// Finding represents a compliance finding
type Finding struct {
	ID          string    `json:"id"`
	Framework   Framework `json:"framework"`
	Technique   string    `json:"technique"`
	Severity    Severity  `json:"severity"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Match       string    `json:"match,omitempty"`
	Context     string    `json:"context,omitempty"`
	Position    int       `json:"position,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Block       bool      `json:"block,omitempty"`
	Pattern     string    `json:"pattern,omitempty"`
}

// Result represents the outcome of a compliance check.
type Result struct {
	Passed            bool              `json:"passed"`
	Findings          []Finding         `json:"findings"`
	FrameworksChecked []Framework       `json:"frameworks_checked"`
	CheckedAt         time.Time         `json:"checked_at"`
	Duration          time.Duration     `json:"duration"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// Manager handles compliance operations.
type Manager struct {
	config        *Config
	frameworks    map[Framework]FrameworkChecker
	patterns      map[Framework][]*Pattern
	mu            sync.RWMutex
	tierManager   *TierManager
	reportHistory []Result
}

// Config holds compliance manager configuration
type Config struct {
	EnableAtlas     bool `json:"enable_atlas"`
	EnableNIST1500  bool `json:"enable_nist_1500"`
	EnableOWASP     bool `json:"enable_owasp"`
	EnableGDPR      bool `json:"enable_gdpr"`
	EnableHIPAA     bool `json:"enable_hipaa"`
	EnablePCIDSS    bool `json:"enable_pci_dss"`
	EnableSOC2      bool `json:"enable_soc2"`
	EnableISO42001  bool `json:"enable_iso_42001"`
	ContextLines    int  `json:"context_lines"`
	StrictMode      bool `json:"strict_mode"`
	BlockOnCritical bool `json:"block_on_critical"`
}

// Pattern represents a detection pattern
type Pattern struct {
	ID          string    `json:"id"`
	Technique   string    `json:"technique"`
	Framework   Framework `json:"framework"`
	Regex       *regexp.Regexp
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Block       bool     `json:"block"`
}

// FrameworkChecker interface for framework-specific checking
type FrameworkChecker interface {
	Check(content string) ([]Finding, error)
	GetName() Framework
	GetPatterns() []*Pattern
}

// NewManager creates a new compliance manager
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	mgr := &Manager{
		config:      config,
		frameworks:  make(map[Framework]FrameworkChecker),
		patterns:    make(map[Framework][]*Pattern),
		tierManager: NewTierManager(),
	}

	// Register frameworks based on config
	if config.EnableAtlas {
		atlas := NewATLASFramework(config.ContextLines)
		mgr.frameworks[FrameworkATLAS] = atlas
		mgr.patterns[FrameworkATLAS] = atlas.GetPatterns()
	}

	return mgr, nil
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		EnableAtlas:     true,
		EnableNIST1500:  true,
		EnableOWASP:     true,
		EnableGDPR:      false,
		EnableHIPAA:     false,
		EnablePCIDSS:    false,
		EnableSOC2:      false,
		EnableISO42001:  false,
		ContextLines:    3,
		StrictMode:      false,
		BlockOnCritical: true,
	}
}

// Check performs compliance checking against all enabled frameworks
func (m *Manager) Check(content string, direction string) (*Result, error) {
	startTime := time.Now()
	result := &Result{
		Passed:            true,
		Findings:          []Finding{},
		FrameworksChecked: []Framework{},
		CheckedAt:         startTime,
		Metadata:          map[string]string{"direction": direction},
	}

	// Use write lock because we also modify reportHistory
	m.mu.Lock()
	defer m.mu.Unlock()

	for framework, checker := range m.frameworks {
		result.FrameworksChecked = append(result.FrameworksChecked, framework)

		findings, err := checker.Check(content)
		if err != nil {
			return nil, fmt.Errorf("framework %s check failed: %w", framework, err)
		}

		result.Findings = append(result.Findings, findings...)

		// Update passed status
		blocked := false
		for _, f := range findings {
			if f.Block && f.Severity == SeverityCritical {
				blocked = true
			}
		}
		if blocked {
			result.Passed = false
		}
	}

	result.Duration = time.Since(startTime)

	// Add to history
	m.reportHistory = append(m.reportHistory, *result)
	if len(m.reportHistory) > 100 {
		m.reportHistory = m.reportHistory[len(m.reportHistory)-100:]
	}

	return result, nil
}

// CheckFramework checks content against a specific framework
func (m *Manager) CheckFramework(content string, framework Framework) (*Result, error) {
	startTime := time.Now()
	result := &Result{
		Passed:            true,
		Findings:          []Finding{},
		FrameworksChecked: []Framework{},
		CheckedAt:         startTime,
	}

	m.mu.RLock()
	checker, ok := m.frameworks[framework]
	m.mu.RUnlock()

	if !ok {
		// FAIL-CLOSED: An unregistered framework means we CANNOT verify compliance.
		// Returning Passed=true for an unregistered framework is dangerous —
		// it would allow content to pass compliance checks that were never actually run.
		result.Passed = false
		result.FrameworksChecked = []Framework{}
		result.Metadata = map[string]string{"reason": fmt.Sprintf("framework %s not enabled — compliance cannot be verified", framework)}
		return result, fmt.Errorf("framework %s not enabled — compliance cannot be verified", framework)
	}

	findings, err := checker.Check(content)
	if err != nil {
		return nil, fmt.Errorf("framework %s check failed: %w", framework, err)
	}

	result.Findings = findings
	result.FrameworksChecked = []Framework{framework}
	result.Duration = time.Since(startTime)
	result.Passed = len(findings) == 0

	return result, nil
}

// GetFindingsByTechnique returns findings for a specific technique
func (m *Manager) GetFindingsByTechnique(technique string) []Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var findings []Finding
	for _, f := range m.reportHistory {
		for _, finding := range f.Findings {
			if finding.Technique == technique {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

// GetFindingsBySeverity returns findings filtered by severity
func (m *Manager) GetFindingsBySeverity(severity Severity) []Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var findings []Finding
	for _, r := range m.reportHistory {
		for _, f := range r.Findings {
			if f.Severity == severity {
				findings = append(findings, f)
			}
		}
	}
	return findings
}

// GetActiveFrameworks returns list of active frameworks
func (m *Manager) GetActiveFrameworks() []Framework {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var frameworks []Framework
	for f := range m.frameworks {
		frameworks = append(frameworks, f)
	}
	return frameworks
}

// GenerateReport generates a compliance report
func (m *Manager) GenerateReport() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	report := map[string]interface{}{
		"generated_at":          time.Now(),
		"active_frameworks":     len(m.frameworks),
		"total_findings":        0,
		"findings_by_severity":  map[string]int{},
		"findings_by_framework": map[string]int{},
	}

	severityCounts := map[Severity]int{}
	frameworkCounts := map[Framework]int{}

	for _, r := range m.reportHistory {
		report["total_findings"] = report["total_findings"].(int) + len(r.Findings)
		for _, f := range r.Findings {
			severityCounts[f.Severity]++
			frameworkCounts[f.Framework]++
		}
	}

	// Convert to string keys for JSON
	sevStr := make(map[string]int)
	for k, v := range severityCounts {
		sevStr[string(k)] = v
	}
	report["findings_by_severity"] = sevStr

	fwStr := make(map[string]int)
	for k, v := range frameworkCounts {
		fwStr[string(k)] = v
	}
	report["findings_by_framework"] = fwStr

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// GetStatus returns current compliance status
func (m *Manager) GetStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := map[string]interface{}{
		"enabled_frameworks": make([]string, 0),
		"total_patterns":     0,
		"recent_findings":    0,
	}

	for f := range m.frameworks {
		status["enabled_frameworks"] = append(status["enabled_frameworks"].([]string), string(f))
		status["total_patterns"] = status["total_patterns"].(int) + len(m.patterns[f])
	}

	if len(m.reportHistory) > 0 {
		status["recent_findings"] = len(m.reportHistory[len(m.reportHistory)-1].Findings)
	}

	return status
}

// AddCustomPattern adds a custom detection pattern
func (m *Manager) AddCustomPattern(pattern *Pattern) error {
	if pattern == nil || pattern.Regex == nil {
		return fmt.Errorf("invalid pattern")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Add to appropriate framework
	if patterns, ok := m.patterns[pattern.Framework]; ok {
		m.patterns[pattern.Framework] = append(patterns, pattern)
	}

	return nil
}

// DetectFrameworks auto-detects relevant frameworks based on content
func (m *Manager) DetectFrameworks(content string) []Framework {
	var detected []Framework
	contentLower := strings.ToLower(content)

	// Healthcare indicators
	healthcareKeywords := []string{"patient", "diagnosis", "treatment", "medical", "health", "prescription", "physician"}
	if containsAny(contentLower, healthcareKeywords) {
		detected = append(detected, FrameworkHIPAA)
	}

	// Financial indicators
	financialKeywords := []string{"payment", "credit card", "bank", "transaction", "invoice", "billing", "account number"}
	if containsAny(contentLower, financialKeywords) {
		detected = append(detected, FrameworkPCIDSS)
	}

	// EU personal data indicators
	gdprKeywords := []string{"name", "email", "address", "phone", "ip address", "cookie", "consent", "personal data"}
	if containsAny(contentLower, gdprKeywords) {
		detected = append(detected, FrameworkGDPR)
	}

	// AI/LLM indicators (ATLAS)
	aiKeywords := []string{"prompt", "model", "chat", "assistant", "ai", "llm", "gpt", "token", "completion"}
	if containsAny(contentLower, aiKeywords) {
		detected = append(detected, FrameworkATLAS)
	}

	return detected
}

// GetReportHistory returns compliance report history
func (m *Manager) GetReportHistory(limit int) []Result {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit > len(m.reportHistory) || limit <= 0 {
		return m.reportHistory
	}
	return m.reportHistory[len(m.reportHistory)-limit:]
}

// ClearHistory clears compliance report history
func (m *Manager) ClearHistory() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reportHistory = []Result{}
}

// ExportFindings exports findings in various formats
func (m *Manager) ExportFindings(format string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch format {
	case "json":
		data, err := json.MarshalIndent(m.reportHistory, "", "  ")
		if err != nil {
			return "", err
		}
		return string(data), nil
	case "csv":
		var sb strings.Builder
		sb.WriteString("Framework,Technique,Severity,Category,Description,Timestamp\n")
		for _, r := range m.reportHistory {
			for _, f := range r.Findings {
				sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s\n",
					f.Framework, f.Technique, f.Severity, f.Category, f.Description, f.Timestamp.Format(time.RFC3339)))
			}
		}
		return sb.String(), nil
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

// containsAny checks if any keyword exists in content
func containsAny(content string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(content, kw) {
			return true
		}
	}
	return false
}

// String returns string representation of severity
func (s Severity) String() string {
	return string(s)
}

// String returns string representation of framework
func (f Framework) String() string {
	return string(f)
}

// Requirement represents a compliance requirement (stub for compatibility)
type Requirement struct {
	ID          string
	Name        string
	Description string
	Severity    Severity
	Framework   Framework
	Patterns    []Pattern
}

// ComplianceManager is an alias for Manager (for backward compatibility)
type ComplianceManager = Manager

// Report represents a compliance assessment report.
type Report struct {
	Summary    string
	Findings   []Finding
	Frameworks []Framework
	Timestamp  time.Time
}

// ComplianceReport is an alias for Report (for backward compatibility)
type ComplianceReport = Report

// ComplianceResult is an alias for Result (for backward compatibility)
type ComplianceResult = Result

// NewNIST1500Framework returns a stub (NIST framework not fully implemented)
func NewNIST1500Framework() FrameworkChecker {
	return nil
}

// NewOWASPFramework returns a stub (OWASP framework not fully implemented)
func NewOWASPFramework() FrameworkChecker {
	return nil
}

// AtlasTestResult represents the result of an ATLAS compliance test
type AtlasTestResult struct {
	Blocked   bool
	Detected  bool
	Technique string
	Pattern   string
	Score     float64
}

// AtlasManager interface for ATLAS framework management
type AtlasManager interface {
	Check(content string) ([]Finding, error)
	GetPatterns() []*Pattern
}

// NewAtlas returns a new ATLAS framework instance (backward compatible with 0 args)
func NewAtlas(args ...int) *ATLASFramework {
	contextLines := 0
	if len(args) > 0 {
		contextLines = args[0]
	}
	return NewATLASFramework(contextLines)
}
