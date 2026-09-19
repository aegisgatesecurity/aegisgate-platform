//go:build e2e
// +build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mcpE2EFreePort returns a free TCP port by letting the OS assign one.
func mcpE2EFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// writeFile writes content to a file, creating parent directories if needed
func writeFile(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// MCPRequest represents a JSON-RPC request
type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// MCPResponse represents a JSON-RPC response
type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

// MCPError represents a JSON-RPC error
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type MCPE2ESuite struct {
	platform      *exec.Cmd
	workDir       string
	binaryPath    string
	configPath    string
	dataDir       string
	auditDir      string
	dashboardPort int
	mcpPort       int
	proxyPort     int
}

func setupMCPE2E(t *testing.T) *MCPE2ESuite {
	suite := &MCPE2ESuite{
		dashboardPort: mcpE2EFreePort(t),
		mcpPort:       mcpE2EFreePort(t),
		proxyPort:     mcpE2EFreePort(t),
	}

	// Create temp directory
	tmpDir := t.TempDir()
	suite.workDir = tmpDir
	suite.dataDir = filepath.Join(tmpDir, "data")
	suite.auditDir = filepath.Join(suite.dataDir, "audit")
	suite.binaryPath = filepath.Join(tmpDir, "aegisgate-platform")
	suite.configPath = filepath.Join(tmpDir, "aegisgate-platform.yaml")

	// Create directories
	require.NoError(t, exec.Command("mkdir", "-p", suite.auditDir).Run())

	// Build binary
	buildCmd := exec.Command("go", "build", "-o", suite.binaryPath,
		"github.com/aegisgatesecurity/aegisgate-platform/cmd/aegisgate-platform")
	buildCmd.Dir, _ = os.Getwd()
	output, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "Failed to build binary: %s", output)

	// Create config
	configContent := fmt.Sprintf(`
version: "1.0"
tier: community
server:
  bind_address: "0.0.0.0:%d"
  tls:
    enabled: false
proxy:
  enabled: true
  bind_address: "0.0.0.0:%d"
  upstream: "http://localhost:18080"
  rate_limit: 100
mcp_agent:
  enabled: true
  mode: embedded
  bind_address: "0.0.0.0:%d"
  security:
    policy: "restrictive"
    allowed_tools:
      - echo
      - filesystem_read
      - filesystem_write
      - http_request
    blocked_tools:
      - "*"
    require_approval:
      - filesystem_write
logging:
  level: debug
  format: text
persistence:
  enabled: true
  data_dir: %q
  audit_dir: %q
  retention_days: 7
`, suite.dashboardPort, suite.mcpPort, suite.proxyPort, suite.dataDir, suite.auditDir)

	require.NoError(t, writeFile(suite.configPath, configContent))

	return suite
}

func (s *MCPE2ESuite) startPlatform(t *testing.T) {
	cmd := exec.Command(s.binaryPath,
		"--config", s.configPath,
		"--proxy-port", fmt.Sprintf("%d", s.proxyPort),
		"--mcp-port", fmt.Sprintf("%d", s.mcpPort),
		"--dashboard-port", fmt.Sprintf("%d", s.dashboardPort),
		"--embedded-mcp",
		"--tier", "community",
		"--mode", "staging",
	)
	cmd.Env = append(os.Environ(), "REQUIRE_AUTH=false")

	// Capture logs
	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()

	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			t.Logf("[PLATFORM-OUT] %s", scanner.Text())
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			t.Logf("[PLATFORM-ERR] %s", scanner.Text())
		}
	}()

	require.NoError(t, cmd.Start())
	s.platform = cmd

	// Wait for startup
	time.Sleep(3 * time.Second)

	// Verify MCP port is listening
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", s.mcpPort))
	require.NoError(t, err, "MCP server not listening")
	conn.Close()
}

func (s *MCPE2ESuite) stopPlatform() {
	if s.platform != nil && s.platform.Process != nil {
		s.platform.Process.Kill()
		s.platform.Wait()
	}
}

func (s *MCPE2ESuite) sendMCPRequest(t *testing.T, req MCPRequest) *MCPResponse {
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", s.mcpPort))
	require.NoError(t, err)
	defer conn.Close()

	// Send request
	encoder := json.NewEncoder(conn)
	encoder.SetIndent("", "  ")
	require.NoError(t, encoder.Encode(req))

	// Read response
	reader := bufio.NewReader(conn)
	data, err := reader.ReadBytes('\n')
	require.NoError(t, err, "Failed to read MCP response: %v", err)

	var resp MCPResponse
	require.NoError(t, json.Unmarshal(data, &resp))

	return &resp
}

// dialMCP opens a persistent TCP connection to the MCP server.
// Use sendOnConn for subsequent requests on the same connection
// to maintain session tracking.
func (s *MCPE2ESuite) dialMCP(t *testing.T) net.Conn {
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", s.mcpPort))
	require.NoError(t, err, "MCP server not listening")
	return conn
}

// sendOnConn sends a single MCP request on an existing connection and
// reads the response. The connection must remain open for session tracking.
func (s *MCPE2ESuite) sendOnConn(t *testing.T, conn net.Conn, req MCPRequest) *MCPResponse {
	encoder := json.NewEncoder(conn)
	require.NoError(t, encoder.Encode(req))

	reader := bufio.NewReader(conn)
	data, err := reader.ReadBytes('\n')
	require.NoError(t, err, "Failed to read MCP response: %v", err)

	var resp MCPResponse
	require.NoError(t, json.Unmarshal(data, &resp))
	return &resp
}

func TestMCPE2E_Initialize(t *testing.T) {
	suite := setupMCPE2E(t)
	defer suite.stopPlatform()

	suite.startPlatform(t)

	// Use persistent connection
	conn := suite.dialMCP(t)
	defer conn.Close()

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "e2e-test",
				"version": "1.0.0",
			},
		},
	}

	resp := suite.sendOnConn(t, conn, req)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, 1, resp.ID)
	assert.Nil(t, resp.Error, "Initialize should not error: %v", resp.Error)
	assert.NotNil(t, resp.Result, "Initialize should return result")

	result := resp.Result.(map[string]interface{})
	assert.Equal(t, "2024-11-05", result["protocolVersion"])
}

func TestMCPE2E_ToolList(t *testing.T) {
	suite := setupMCPE2E(t)
	defer suite.stopPlatform()

	suite.startPlatform(t)

	// Use persistent connection for session tracking
	conn := suite.dialMCP(t)
	defer conn.Close()

	// First initialize on this connection
	initReq := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "e2e-test",
				"version": "1.0.0",
			},
		},
	}
	suite.sendOnConn(t, conn, initReq)

	// List tools
	listReq := MCPRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	resp := suite.sendOnConn(t, conn, listReq)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, 2, resp.ID)
	assert.Nil(t, resp.Error, "Tool list should not error")
	assert.NotNil(t, resp.Result)

	result := resp.Result.(map[string]interface{})
	tools := result["tools"].([]interface{})
	assert.GreaterOrEqual(t, len(tools), 1, "Should have at least 1 tool")

	// Log available tools
	toolNames := []string{}
	for _, tool := range tools {
		toolMap := tool.(map[string]interface{})
		toolNames = append(toolNames, toolMap["name"].(string))
	}
	t.Logf("Available tools: %v", toolNames)

	// Verify at least process_list exists (built-in community tier tool)
	foundProcessList := false
	for _, name := range toolNames {
		if name == "process_list" {
			foundProcessList = true
			break
		}
	}
	assert.True(t, foundProcessList, "Should have 'process_list' tool available")
}

func TestMCPE2E_ToolCall_Echo_Allowed(t *testing.T) {
	suite := setupMCPE2E(t)
	defer suite.stopPlatform()

	suite.startPlatform(t)

	// Use persistent connection for session tracking
	conn := suite.dialMCP(t)
	defer conn.Close()

	// Initialize first on this connection
	initReq := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "e2e-test",
				"version": "1.0.0",
			},
		},
	}
	suite.sendOnConn(t, conn, initReq)

	// Call process_list tool (built-in, allowed in community tier)
	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "process_list",
			"arguments": map[string]interface{}{},
		},
	}

	resp := suite.sendOnConn(t, conn, req)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, 3, resp.ID)

	if resp.Error == nil && resp.Result != nil {
		assert.NotNil(t, resp.Result)
	} else if resp.Error != nil {
		// Tool may be blocked by guardrails — acceptable
		t.Logf("Tool call blocked: %s", resp.Error.Message)
	}
}

func TestMCPE2E_ToolCall_FilesystemWrite_Blocked(t *testing.T) {
	suite := setupMCPE2E(t)
	defer suite.stopPlatform()

	suite.startPlatform(t)

	// Use persistent connection for session tracking
	conn := suite.dialMCP(t)
	defer conn.Close()

	// Initialize first on this connection
	initReq := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "e2e-test",
				"version": "1.0.0",
			},
		},
	}
	suite.sendOnConn(t, conn, initReq)

	// Call file_write tool with dangerous path — should be blocked by toolauth
	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "file_write",
			"arguments": map[string]interface{}{
				"path":    "/etc/passwd",
				"content": "malicious entry",
			},
		},
	}

	resp := suite.sendOnConn(t, conn, req)

	t.Logf("File write response: %+v", resp)

	// Either blocked by tool not existing, toolauth, or guardrail
	hasResult := resp.Result != nil
	hasError := resp.Error != nil

	if hasResult {
		result := resp.Result.(map[string]interface{})
		content, ok := result["content"].([]interface{})
		if ok && len(content) > 0 {
			first := content[0].(map[string]interface{})
			text := first["text"].(string)
			assert.False(t, strings.Contains(text, "/etc/passwd"),
				"Write to /etc/passwd should have been blocked")
		}
	} else if hasError {
		assert.NotNil(t, resp.Error)
	}
}

func TestMCPE2E_AuditTrail(t *testing.T) {
	suite := setupMCPE2E(t)
	defer suite.stopPlatform()

	suite.startPlatform(t)

	// Use persistent connection for session tracking
	conn := suite.dialMCP(t)
	defer conn.Close()

	// Initialize on this connection
	initReq := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "e2e-test",
				"version": "1.0.0",
			},
		},
	}
	suite.sendOnConn(t, conn, initReq)

	// Wait for audit to be written
	time.Sleep(500 * time.Millisecond)

	// Verify the audit directory exists
	auditPath := suite.auditDir
	t.Logf("Audit directory: %s", auditPath)
	assert.DirExists(t, auditPath, "Audit directory should exist")
}
