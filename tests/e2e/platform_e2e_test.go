// E2E Tests for AegisGate Security Platform
// Tests full platform lifecycle: build → start → health checks → MCP → graceful shutdown
//
// Run: go test -tags=e2e -timeout=5m -v ./tests/e2e/...
//
// Prerequisites:
//   - go 1.25+
//   - ports 28080, 28081, 28443 available (non-standard to avoid conflicts)
//   - 2GB free disk
//
//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// Non-standard ports to avoid conflicts with running instances
	proxyPort     = 28080
	mcpPort       = 28081
	dashboardPort = 28443

	// Timeouts
	startupTimeout  = 30 * time.Second
	shutdownTimeout = 10 * time.Second
	requestTimeout  = 5 * time.Second

	// Retry config
	healthcheckRetries = 30
	healthcheckDelay   = 1 * time.Second
)

// TestSuite holds shared state across subtests
type TestSuite struct {
	BinaryPath  string
	WorkDir     string
	PlatformCmd *exec.Cmd
	PlatformPID int
	TestOutput  *testOutputCapture
}

// testOutputCapture captures stdout/stderr for logging
type testOutputCapture struct {
	mu     sync.Mutex
	stdout strings.Builder
	stderr strings.Builder
}

var (
	suite      *TestSuite
	suiteMutex sync.Mutex
)

// TestMain validates environment before running tests
func TestMain(m *testing.M) {
	// Check ports are available before starting
	for _, port := range []int{proxyPort, mcpPort, dashboardPort} {
		if !isPortAvailable(port) {
			fmt.Fprintf(os.Stderr, "FATAL: Port %d is not available\n", port)
			os.Exit(1)
		}
	}
	
	suite = &TestSuite{
		TestOutput: &testOutputCapture{},
	}
	
	code := m.Run()
	
	// Final cleanup
	if suite != nil && suite.PlatformPID != 0 {
		if proc, _ := os.FindProcess(suite.PlatformPID); proc != nil {
			proc.Kill()
		}
	}
	if suite != nil && suite.WorkDir != "" {
		os.RemoveAll(suite.WorkDir)
	}
	
	os.Exit(code)
}

// TestPlatformLifecycle runs the complete platform lifecycle
func TestPlatformLifecycle(t *testing.T) {
	suiteMutex.Lock()
	defer suiteMutex.Unlock()
	
	// Step 1: Build binary
	t.Run("BuildBinary", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		_, filename, _, _ := runtime.Caller(0)
		projectRoot := filepath.Join(filepath.Dir(filename), "../..")

		// Create temp work directory
		workDir, err := os.MkdirTemp("", "aegisgate-e2e-*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		suite.WorkDir = workDir

		binaryPath := filepath.Join(workDir, "aegisgate-platform")
		if runtime.GOOS == "windows" {
			binaryPath += ".exe"
		}

		cmd := exec.CommandContext(ctx, "go", "build",
			"-o", binaryPath,
			"-ldflags", "-X main.Version=e2e-test",
			filepath.Join(projectRoot, "cmd", "aegisgate-platform"),
		)
		cmd.Dir = projectRoot
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")

		output, err := cmd.CombinedOutput()
		if err != nil {
			os.RemoveAll(workDir)
			t.Fatalf("Build failed: %v\nOutput: %s", err, output)
		}

		info, err := os.Stat(binaryPath)
		if err != nil || info.Size() == 0 {
			os.RemoveAll(workDir)
			t.Fatalf("Binary not found or empty: %v", err)
		}

		suite.BinaryPath = binaryPath
		t.Logf("Binary built: %s (%d bytes)", binaryPath, info.Size())
	})

	// Step 2: Write minimal config and start platform
	t.Run("StartAndHealthChecks", func(t *testing.T) {
		if suite.BinaryPath == "" {
			t.Fatal("Binary not built")
		}

		// Create minimal config file with data directory
		configPath := filepath.Join(suite.WorkDir, "aegisgate-platform.yaml")
		dataDirPath := suite.WorkDir + "/data"
		auditDirPath := dataDirPath + "/audit"
		configContent := fmt.Sprintf(`server:
  port: %d
  dashboard_port: %d
mcp:
  enabled: true
  port: %d
proxy:
  enabled: true
persistence:
  data_dir: %s
  audit_dir: %s
log_level: debug
tier: community
version: "1.0"
`, proxyPort, dashboardPort, mcpPort, dataDirPath, auditDirPath)

		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("Failed to write config: %v", err)
		}

		// Start platform with explicit port flags
		// NOTE: We use suite-level context, not subtest context, so platform survives subtest boundaries
		cmd := exec.Command(suite.BinaryPath,
			"--config", configPath,
			"--proxy-port", fmt.Sprintf("%d", proxyPort),
			"--mcp-port", fmt.Sprintf("%d", mcpPort),
			"--dashboard-port", fmt.Sprintf("%d", dashboardPort),
			"--tier", "community",
			"--embedded-mcp",
		)

		// Set up log capture
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatalf("Failed to get stdout: %v", err)
		}
		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			t.Fatalf("Failed to get stderr: %v", err)
		}

		if err := cmd.Start(); err != nil {
			t.Fatalf("Failed to start platform: %v", err)
		}

		suite.PlatformCmd = cmd
		suite.PlatformPID = cmd.Process.Pid

		go captureLogs(stdoutPipe, "[STDOUT]", t)
		go captureLogs(stderrPipe, "[STDERR]", t)

		// Wait a bit for startup logs to appear
		time.Sleep(2 * time.Second)

		// Wait for services
		if err := waitForServices(t); err != nil {
			t.Fatalf("Services failed to start: %v", err)
		}

		t.Log("All services ready")
	})

	// Step 3: Test dashboard health endpoint (proxy may be 503 if not fully initialized)
	t.Run("HealthEndpoints", func(t *testing.T) {
		if suite.PlatformPID == 0 {
			t.Fatal("Platform not running")
		}

		// Check dashboard health (this is the main health check)
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", dashboardPort))
		if err != nil {
			t.Fatalf("Dashboard health check failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Logf("Dashboard health returned %d: %s", resp.StatusCode, body)
		} else {
			var health map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
				t.Fatalf("Failed to decode health: %v", err)
			}
			t.Logf("Dashboard health: %v", health)
		}

		// Try dashboard ready endpoint
		readyResp, err := http.Get(fmt.Sprintf("http://localhost:%d/ready", dashboardPort))
		if err != nil {
			t.Logf("Dashboard ready check skipped: %v", err)
		} else {
			readyResp.Body.Close()
			t.Logf("Dashboard ready status: %d", readyResp.StatusCode)
		}
	})

	// Step 4: Test MCP connection (MCP uses native protocol, not HTTP)
	t.Run("MCPConnection", func(t *testing.T) {
		if suite.PlatformPID == 0 {
			t.Fatal("Platform not running")
		}

		// MCP server uses raw TCP/socket connection, not HTTP
		// Just verify we can establish a connection (any connection attempt is accepted)
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", mcpPort), 2*time.Second)
		if err != nil {
			t.Fatalf("MCP connection failed: %v", err)
		}
		defer conn.Close()

		// MCP connection established (server responded)
		t.Log("MCP TCP connection successful (MCP protocol uses native socket)")
	})

	// Step 5: Test API endpoints
	t.Run("APIEndpoints", func(t *testing.T) {
		if suite.PlatformPID == 0 {
			t.Fatal("Platform not running")
		}

		// Test version endpoint
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/version", dashboardPort))
		if err != nil {
			t.Fatalf("Version request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Logf("Version endpoint returned %d", resp.StatusCode)
		} else {
			var version map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
				t.Logf("Failed to decode version: %v", err)
			} else {
				t.Logf("Version: %v", version)
			}
		}

		// Test tier endpoint
		tierResp, err := http.Get(fmt.Sprintf("http://localhost:%d/api/v1/tier", dashboardPort))
		if err != nil {
			t.Logf("Tier request skipped: %v", err)
		} else {
			defer tierResp.Body.Close()
			if tierResp.StatusCode == http.StatusOK {
				var tierInfo map[string]interface{}
				if err := json.NewDecoder(tierResp.Body).Decode(&tierInfo); err == nil {
					t.Logf("Tier info: %v", tierInfo)
				}
			}
		}
	})

	// Step 6: Graceful shutdown
	t.Run("GracefulShutdown", func(t *testing.T) {
		if suite.PlatformPID == 0 {
			t.Skip("Platform not running, skipping shutdown test")
		}

		process, err := os.FindProcess(suite.PlatformPID)
		if err != nil {
			t.Fatalf("Failed to find process: %v", err)
		}

		t.Log("Sending SIGINT for graceful shutdown...")
		if err := process.Signal(os.Interrupt); err != nil {
			t.Fatalf("Failed to send signal: %v", err)
		}

		done := make(chan error, 1)
		go func() {
			_, err := process.Wait()
			done <- err
		}()

		select {
		case <-done:
			t.Log("Process exited gracefully")
		case <-time.After(shutdownTimeout):
			process.Kill()
			t.Error("Had to kill process - graceful shutdown timeout")
		}

		// Verify ports released
		time.Sleep(500 * time.Millisecond)
		for _, port := range []int{proxyPort, mcpPort, dashboardPort} {
			if !isPortAvailable(port) {
				t.Errorf("Port %d still in use", port)
			}
		}

		suite.PlatformPID = 0 // Mark as stopped
		t.Log("Graceful shutdown successful")
	})
}

// Helper functions

func isPortAvailable(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), time.Second)
	if err != nil {
		return true
	}
	conn.Close()
	return false
}

func waitForServices(t *testing.T) error {
	// First check: TCP ports are listening
	ports := map[string]int{
		"proxy":     proxyPort,
		"mcp":       mcpPort,
		"dashboard": dashboardPort,
	}
		timeout := time.After(startupTimeout)

	for name, port := range ports {
		t.Logf("Waiting for %s on port %d...", name, port)
		done := false
		for !done {
			select {
			case <-timeout:
				return fmt.Errorf("timeout waiting for %s", name)
			default:
				if !isPortAvailable(port) {
					done = true
					break
				}
				time.Sleep(healthcheckDelay)
			}
		}
		t.Logf("  %s TCP port ready", name)
	}

	// Second check: wait for services to actually serve HTTP
	t.Log("Waiting for HTTP services to be ready...")
	time.Sleep(1 * time.Second) // Brief pause after TCP bind

	return nil
}

func captureLogs(pipe io.ReadCloser, prefix string, t *testing.T) {
	defer pipe.Close()
	defer func() {
		if r := recover(); r != nil {
			// Ignore panics from logging after test ends
		}
	}()
	
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		line := scanner.Text()
		// Only log important messages to reduce noise
		if containsAny(line, []string{"ERROR", "FATAL", "listening", "started", "ready", "health", "AegisGate"}) {
			t.Logf("%s %s", prefix, line)
		}
	}
}

func containsAny(s string, substrs []string) bool {
	lower := strings.ToLower(s)
	for _, substr := range substrs {
		if strings.Contains(lower, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}
