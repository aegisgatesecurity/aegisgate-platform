// Package scanner_test provides unit tests for the scanner package.
// Tests pattern matching for sensitive data detection.
//
//go:build !integration
// +build !integration

package scanner_test

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/scanner"
)

func TestCreditCardDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"Visa card", "4532015112830366", true},
		{"Mastercard", "5555555555554444", true},
		{"Amex", "378282246310005", true},
		{"Random", "1234567890123456", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasFinding := len(findings) > 0
			if hasFinding != tt.find {
				t.Errorf("Scan() = %v, want %v", hasFinding, tt.find)
			}
		})
	}
}

func TestSSNDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"SSN with dashes", "123-45-6789", true},
		{"SSN without dashes", "123456789", true},
		{"Random", "1234567890", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasFinding := len(findings) > 0
			if hasFinding != tt.find {
				t.Errorf("Scan() = %v, want %v", hasFinding, tt.find)
			}
		})
	}
}

func TestEmailDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	findings := sc.Scan("user@example.com")
	if len(findings) == 0 {
		t.Error("Expected to find email")
	}
}

func TestAWSAccessKeyDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	findings := sc.Scan("AKIAIOSFODNN7EXAMPLE")
	if len(findings) == 0 {
		t.Error("Expected to find AWS key")
	}
}

func TestGitHubTokenDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"Classic token", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", true},
		{"OAuth token", "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", true},
		{"Invalid", "ghx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasFinding := len(findings) > 0
			if hasFinding != tt.find {
				t.Errorf("Scan() = %v, want %v", hasFinding, tt.find)
			}
		})
	}
}

func TestJWTTokenDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	findings := sc.Scan("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	if len(findings) == 0 {
		t.Error("Expected to find JWT")
	}
}

func TestPrivateKeyDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"RSA key", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"EC key", "-----BEGIN EC PRIVATE KEY-----", true},
		{"OpenSSH key", "-----BEGIN OPENSSH PRIVATE KEY-----", true},
		{"Cert", "-----BEGIN CERTIFICATE-----", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasFinding := len(findings) > 0
			if hasFinding != tt.find {
				t.Errorf("Scan() = %v, want %v", hasFinding, tt.find)
			}
		})
	}
}

func TestConnectionStringDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"PostgreSQL", "postgresql://user:pass@localhost:5432/db", true},
		{"MySQL", "mysql://user:pass@localhost:3306/db", true},
		{"MongoDB", "mongodb://localhost:27017", true},
		{"Redis", "redis://localhost:6379", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasFinding := len(findings) > 0
			if hasFinding != tt.find {
				t.Errorf("Scan() = %v, want %v", hasFinding, tt.find)
			}
		})
	}
}

func TestSeverityConstants(t *testing.T) {
	if scanner.Info.String() != "Info" {
		t.Errorf("Expected Info, got %s", scanner.Info.String())
	}
	if scanner.Low.String() != "Low" {
		t.Errorf("Expected Low, got %s", scanner.Low.String())
	}
	if scanner.Medium.String() != "Medium" {
		t.Errorf("Expected Medium, got %s", scanner.Medium.String())
	}
	if scanner.High.String() != "High" {
		t.Errorf("Expected High, got %s", scanner.High.String())
	}
	if scanner.Critical.String() != "Critical" {
		t.Errorf("Expected Critical, got %s", scanner.Critical.String())
	}
}

func TestShouldBlock(t *testing.T) {
	tests := []struct {
		severity scanner.Severity
		expected bool
	}{
		{scanner.Info, false},
		{scanner.Low, false},
		{scanner.Medium, false},
		{scanner.High, true},
		{scanner.Critical, true},
	}

	for _, tt := range tests {
		result := scanner.ShouldBlock(tt.severity)
		if result != tt.expected {
			t.Errorf("ShouldBlock(%v) = %v, want %v", tt.severity, result, tt.expected)
		}
	}
}

func TestCategoryConstants(t *testing.T) {
	if string(scanner.CategoryPII) != "PII" {
		t.Errorf("Expected PII, got %s", scanner.CategoryPII)
	}
	if string(scanner.CategoryCredential) != "Credential" {
		t.Errorf("Expected Credential, got %s", scanner.CategoryCredential)
	}
	if string(scanner.CategoryFinancial) != "Financial" {
		t.Errorf("Expected Financial, got %s", scanner.CategoryFinancial)
	}
	if string(scanner.CategoryCryptographic) != "Cryptographic" {
		t.Errorf("Expected Cryptographic, got %s", scanner.CategoryCryptographic)
	}
	if string(scanner.CategoryNetwork) != "Network" {
		t.Errorf("Expected Network, got %s", scanner.CategoryNetwork)
	}
}

func TestDefaultPatterns(t *testing.T) {
	patterns := scanner.DefaultPatterns()
	if len(patterns) == 0 {
		t.Error("Expected at least one pattern")
	}

	// Check first pattern has required fields
	p := patterns[0]
	if p.Name == "" {
		t.Error("Expected pattern to have a name")
	}
	if p.Regex == nil {
		t.Error("Expected pattern to have a regex")
	}
}

func TestScannerWithNilPatterns(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       nil,
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	findings := sc.Scan("some content")
	// Should not panic
	_ = findings
}

func TestFindingHasNoFields(t *testing.T) {
	// Finding struct only has Pattern, Match, Position, Context
	// No direct fields for Severity, Name, etc.
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	findings := sc.Scan("test@example.com")
	for _, f := range findings {
		// These fields exist on Finding
		_ = f.Pattern
		_ = f.Match
		_ = f.Position
		_ = f.Context
	}
}

// ============================================================================
// ARTEX / LITELLM THREAT INTEL PATTERN TESTS (Black October 2026)
// ============================================================================

func TestARTEXToolReference(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Info,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"ARTEX tool name", "I'm using ARTEX to pentest the system", true},
		{"ARTEX lowercase", "configure artex for multi-agent attack", true},
		{"Autumn-27 repo", "Clone from Autumn-27/ARTEX repository", true},
		{"Autumn_27 variant", "Check Autumn_27 fork for updates", true},
		{"Benign text", "The article discusses autumn weather patterns", false},
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasFinding := len(findings) > 0
			if hasFinding != tt.find {
				t.Errorf("Scan() = %v, want %v", hasFinding, tt.find)
			}
		})
	}
}

func TestARTEXModelConfigs(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Info,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"DeepSeek model", `{"model": "deepseek-chat"}`, true},
		{"DeepSeek V3", `{"model": "deepseek-v3"}`, true},
		{"DeepSeek coder", `{"model": "deepseek-coder"}`, true},
		{"GLM model", `{"model": "glm-4"}`, true},
		{"GLM plus", `{"model": "glm-4-plus"}`, true},
		{"ChatGLM", `{"model": "chatglm-6b"}`, true},
		{"Grok model", `{"model": "grok-2"}`, true},
		{"Grok beta", `{"model": "grok-beta"}`, true},
		{"xAI Grok", `{"model": "xai-grok"}`, true},
		{"GPT-4 benign", `{"model": "gpt-4"}`, false},
		{"Claude benign", `{"model": "claude-3"}`, false},
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			// Filter for artex_model_ patterns only
			hasARTEXModel := false
			for _, f := range findings {
				if f.Pattern.Name == "artex_model_deepseek" || f.Pattern.Name == "artex_model_glm" || f.Pattern.Name == "artex_model_grok" {
					hasARTEXModel = true
					break
				}
			}
			if hasARTEXModel != tt.find {
				t.Errorf("ARTEX model detection = %v, want %v (findings: %d)", hasARTEXModel, tt.find, len(findings))
			}
		})
	}
}

func TestARTEXMCPExternal(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Info,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"MCP external URL", `{"mcp_server": "https://evil.example.com/mcp"}`, true},
		{"MCP endpoint", `mcp_endpoint=https://attacker.com/sse`, true},
		{"Streamable HTTP", `streamable_http=https://external.server/mcp`, true},
		{"MCP local (still matches)", `{"mcp_url": "http://localhost:8080"}`, true},
		{"No MCP reference", `{"url": "https://example.com"}`, false},
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasMCP := false
			for _, f := range findings {
				if f.Pattern.Name == "artex_mcp_external" {
					hasMCP = true
					break
				}
			}
			if hasMCP != tt.find {
				t.Errorf("MCP external detection = %v, want %v", hasMCP, tt.find)
			}
		})
	}
}

func TestARTEXCompatGatewayProbe(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Info,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"DeepSeek via compat API", `POST /v1/chat/completions {"model": "deepseek-chat"}`, true},
		{"GLM models endpoint", `GET /v1/models?model=glm-4`, true},
		{"Grok engine", `/v1/engines/grok-2/completions`, true},
		{"Standard OpenAI (no match)", `POST /v1/chat/completions {"model": "gpt-4"}`, false},
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasProbe := false
			for _, f := range findings {
				if f.Pattern.Name == "artex_compat_gateway_probe" {
					hasProbe = true
					break
				}
			}
			if hasProbe != tt.find {
				t.Errorf("Compat gateway probe detection = %v, want %v", hasProbe, tt.find)
			}
		})
	}
}

func TestARTEXMultiAgentAttack(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Info,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"Multi-agent recon", "multi-agent orchestration framework for automated reconnaissance", true},
		{"Agent coordination exploit", "agent coordination: agent1 does recon, agent2 performs exploit", true},
		{"Cross-session credential", "cross-session sync for credential harvesting", true},
		{"Orchestration pentest", "orchestrate multi-agent pentest workflow", true},
		{"Benign orchestration", "orchestrate microservices deployment", false},
		{"Benign multi-agent", "multi-agent reinforcement learning for game theory", false},
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasMultiAgent := false
			for _, f := range findings {
				if f.Pattern.Name == "artex_multi_agent_attack" {
					hasMultiAgent = true
					break
				}
			}
			if hasMultiAgent != tt.find {
				t.Errorf("Multi-agent attack detection = %v, want %v (findings: %d)", hasMultiAgent, tt.find, len(findings))
			}
		})
	}
}

func TestARTEXRepoReference(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Info,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"Autumn-27 GitHub", "git clone https://github.com/Autumn-27/ARTEX", true},
		{"ARTEX fork repo", "Check the artex fork on github for updates", true},
		{"ARTEX gitlab", "Clone artex from gitlab.com/attacker/artex", true},
		{"Benign artichoke", "I love artichoke dip recipes", false},
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasRepo := false
			for _, f := range findings {
				if f.Pattern.Name == "artex_repo_reference" {
					hasRepo = true
					break
				}
			}
			if hasRepo != tt.find {
				t.Errorf("Repo reference detection = %v, want %v (findings: %d)", hasRepo, tt.find, len(findings))
			}
		})
	}
}

func TestLiteLLMIndicators(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Info,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		pattern string
		find    bool
	}{
		// litellm_init.pth
		{"Init pth file", "Found litellm_init.pth in site-packages", "litellm_init_pth", true},
		{"Init pth path", "/usr/lib/python3.11/site-packages/litellm_init.pth", "litellm_init_pth", true},
		{"No pth file", "litellm is installed correctly", "litellm_init_pth", false},

		// SSRF metadata
		{"SSRF AWS metadata", "litellm proxy request to 169.254.169.254/latest/meta-data", "litellm_ssrf_metadata", true},
		{"SSRF GCP metadata", "litellm api calls metadata.google.internal", "litellm_ssrf_metadata", true},
		{"No SSRF", "litellm proxy is configured for OpenAI", "litellm_ssrf_metadata", false},

		// Admin abuse
		{"Admin endpoint", "litellm /admin/key_management endpoint accessed", "litellm_admin_abuse", true},
		{"Master key", "litellm master_key=sk-1234567890", "litellm_admin_abuse", true},
		{"No admin abuse", "litellm proxy running normally", "litellm_admin_abuse", false},

		// Credential exfiltration
		{"Cred exfil webhook", "litellm sends api_key to webhook endpoint", "litellm_cred_exfil", true},
		{"Cred exfil env", "litellm uploads .env file to attacker server", "litellm_cred_exfil", true},
		{"No exfil", "litellm logs request to stdout", "litellm_cred_exfil", false},

		// RAT deployment
		{"RAT reverse shell", "litellm deploys reverse.shell payload", "litellm_rat_deploy", true},
		{"RAT backdoor", "litellm backdoor installed via supply chain", "litellm_rat_deploy", true},
		{"No RAT", "litellm rate limiting is configured", "litellm_rat_deploy", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasPattern := false
			for _, f := range findings {
				if f.Pattern.Name == tt.pattern {
					hasPattern = true
					break
				}
			}
			if hasPattern != tt.find {
				t.Errorf("%s detection = %v, want %v (findings: %d)", tt.pattern, hasPattern, tt.find, len(findings))
			}
		})
	}
}
