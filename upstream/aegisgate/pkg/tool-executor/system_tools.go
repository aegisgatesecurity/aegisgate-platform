// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGuard Security
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// System tools for process, memory, network, and system information.
// =========================================================================

package toolexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ============================================================================
// PROCESS LIST EXECUTOR
// ============================================================================

// ProcessListExecutor returns a list of running processes
type ProcessListExecutor struct{}

// NewProcessListExecutor creates a new process list executor
func NewProcessListExecutor() *ProcessListExecutor {
	return &ProcessListExecutor{}
}

// Name returns the tool name
func (e *ProcessListExecutor) Name() string {
	return "process_list"
}

// Execute returns a list of running processes
func (e *ProcessListExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("powershell", "-NoProfile", "-Command",
			`Get-Process | Select-Object -First 50 | ForEach-Object { 
				@{ PID = $_.Id; Name = $_.ProcessName; CPU = $_.CPU; Memory = $_.WorkingSet64 } | ConvertTo-Json -Compress
			}`)
	case "linux", "darwin":
		cmd = exec.Command("ps", "aux")
	default:
		return nil, errors.New("unsupported operating system")
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		return nil, errors.New("process list timeout")
	case err := <-done:
		if err != nil {
			return nil, errors.New("failed to get process list: " + stderr.String())
		}

		switch runtime.GOOS {
		case "windows":
			return parseWindowsProcessList(stdout.String()), nil
		default:
			return parseUnixProcessList(stdout.String()), nil
		}
	}
}

// Validate checks parameters (no parameters required)
func (e *ProcessListExecutor) Validate(params map[string]interface{}) error {
	return nil
}

// Timeout returns the execution timeout
func (e *ProcessListExecutor) Timeout() time.Duration {
	return 30 * time.Second
}

// RiskLevel returns the risk level
func (e *ProcessListExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *ProcessListExecutor) Description() string {
	return "List running processes on the system"
}

func parseWindowsProcessList(output string) []map[string]interface{} {
	var processes []map[string]interface{}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var proc map[string]interface{}
		if err := json.Unmarshal([]byte(line), &proc); err == nil {
			processes = append(processes, proc)
		}
	}

	if len(processes) == 0 {
		return []map[string]interface{}{}
	}
	return processes
}

func parseUnixProcessList(output string) []map[string]interface{} {
	var processes []map[string]interface{}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 11 {
			processes = append(processes, map[string]interface{}{
				"user":     parts[0],
				"pid":      parts[1],
				"cpu":      parts[2],
				"mem":      parts[3],
				"vsz":      parts[4],
				"rss":      parts[5],
				"tty":      parts[6],
				"stat":     parts[7],
				"start":    parts[8],
				"time":     parts[9],
				"command":  strings.Join(parts[10:], " "),
			})
		}
	}

	if len(processes) == 0 {
		return []map[string]interface{}{}
	}
	return processes
}

// ============================================================================
// MEMORY STATS EXECUTOR
// ============================================================================

// MemoryStatsExecutor returns memory statistics
type MemoryStatsExecutor struct{}

// NewMemoryStatsExecutor creates a new memory stats executor
func NewMemoryStatsExecutor() *MemoryStatsExecutor {
	return &MemoryStatsExecutor{}
}

// Name returns the tool name
func (e *MemoryStatsExecutor) Name() string {
	return "memory_stats"
}

// Execute returns memory statistics
func (e *MemoryStatsExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("powershell", "-NoProfile", "-Command",
			`$os = Get-CimInstance Win32_OperatingSystem; 
			@{ Total = $os.TotalVisibleMemorySize * 1024; 
			   Available = $os.FreePhysicalMemory * 1024;
			   Used = ($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) * 1024;
			   PercentUsed = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 2)
			} | ConvertTo-Json -Compress`)
	case "linux":
		cmd = exec.Command("bash", "-c", `cat /proc/meminfo | awk '/MemTotal/{t=$2} /MemAvailable/{a=$2} END {printf "{\"total\":%d,\"available\":%d,\"used\":%d,\"percentUsed\":%.2f}", t*1024, a*1024, (t-a)*1024, ((t-a)/t)*100}"'`)
	case "darwin":
		cmd = exec.Command("bash", "-c", `sysctl -n hw.memsize && vm_stat`)
	default:
		return nil, errors.New("unsupported operating system")
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		return nil, errors.New("memory stats timeout")
	case err := <-done:
		if err != nil {
			return getGoMemoryStats(), nil
		}

		switch runtime.GOOS {
		case "windows", "linux":
			var stats map[string]interface{}
			if err := json.Unmarshal(stdout.Bytes(), &stats); err == nil {
				return stats, nil
			}
		case "darwin":
			return parseDarwinMemoryStats(stdout.String()), nil
		}

		return getGoMemoryStats(), nil
	}
}

// Validate checks parameters (no parameters required)
func (e *MemoryStatsExecutor) Validate(params map[string]interface{}) error {
	return nil
}

// Timeout returns the execution timeout
func (e *MemoryStatsExecutor) Timeout() time.Duration {
	return 15 * time.Second
}

// RiskLevel returns the risk level
func (e *MemoryStatsExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *MemoryStatsExecutor) Description() string {
	return "Get system memory statistics"
}

func getGoMemoryStats() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return map[string]interface{}{
		"total":       memStats.Alloc,
		"used":        memStats.Alloc,
		"available":   memStats.Sys - memStats.Alloc,
		"system":      memStats.Sys,
		"heapAlloc":   memStats.HeapAlloc,
		"heapSys":     memStats.HeapSys,
		"numGC":       memStats.NumGC,
		"goroutines":  runtime.NumGoroutine(),
	}
}

func parseDarwinMemoryStats(output string) map[string]interface{} {
	return map[string]interface{}{
		"platform": "darwin",
		"raw":      output,
	}
}

// ============================================================================
// NETWORK CONNECTIONS EXECUTOR
// ============================================================================

// NetworkConnectionsExecutor returns network connection information
type NetworkConnectionsExecutor struct{}

// NewNetworkConnectionsExecutor creates a new network connections executor
func NewNetworkConnectionsExecutor() *NetworkConnectionsExecutor {
	return &NetworkConnectionsExecutor{}
}

// Name returns the tool name
func (e *NetworkConnectionsExecutor) Name() string {
	return "network_connections"
}

// Execute returns network connection information
func (e *NetworkConnectionsExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	protocol := ""
	if p, ok := params["protocol"].(string); ok {
		protocol = strings.ToLower(p)
	}

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		protoFlag := "-p all"
		if protocol == "tcp" {
			protoFlag = "-p tcp"
		} else if protocol == "udp" {
			protoFlag = "-p udp"
		}
		cmd = exec.Command("netstat", protoFlag, "-n")
	case "linux":
		protoFlag := "-tuln"
		if protocol == "tcp" {
			protoFlag = "-tln"
		} else if protocol == "udp" {
			protoFlag = "-uln"
		}
		cmd = exec.Command("netstat", protoFlag)
	case "darwin":
		cmd = exec.Command("netstat", "-an")
	default:
		return nil, errors.New("unsupported operating system")
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		return nil, errors.New("network connections timeout")
	case err := <-done:
		if err != nil {
			return nil, errors.New("failed to get network connections: " + stderr.String())
		}

		return parseNetworkConnections(stdout.String(), runtime.GOOS), nil
	}
}

// Validate checks parameters
func (e *NetworkConnectionsExecutor) Validate(params map[string]interface{}) error {
	protocol, ok := params["protocol"].(string)
	if ok && protocol != "" {
		protocol = strings.ToLower(protocol)
		if protocol != "tcp" && protocol != "udp" && protocol != "all" {
			return errors.New("protocol must be 'tcp', 'udp', or 'all'")
		}
	}
	return nil
}

// Timeout returns the execution timeout
func (e *NetworkConnectionsExecutor) Timeout() time.Duration {
	return 20 * time.Second
}

// RiskLevel returns the risk level
func (e *NetworkConnectionsExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *NetworkConnectionsExecutor) Description() string {
	return "List active network connections"
}

func parseNetworkConnections(output, osName string) map[string]interface{} {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var tcpConnections, udpConnections []map[string]interface{}
	tcpCount, udpCount := 0, 0

	for i, line := range lines {
		if i == 0 {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		proto := parts[0]
		if strings.HasPrefix(proto, "tcp") {
			tcpCount++
			if len(tcpConnections) < 50 {
				tcpConnections = append(tcpConnections, map[string]interface{}{
					"protocol": proto,
					"local":    parts[len(parts)-4],
					"remote":   parts[len(parts)-3],
					"state":    parts[len(parts)-1],
				})
			}
		} else if strings.HasPrefix(proto, "udp") {
			udpCount++
			if len(udpConnections) < 50 {
				udpConnections = append(udpConnections, map[string]interface{}{
					"protocol": proto,
					"local":    parts[len(parts)-2],
				})
			}
		}
	}

	return map[string]interface{}{
		"tcp_count":          tcpCount,
		"udp_count":          udpCount,
		"tcp_connections":    tcpConnections,
		"udp_connections":    udpConnections,
		"platform":           osName,
	}
}

// ============================================================================
// SYSTEM INFO EXECUTOR
// ============================================================================

// SystemInfoExecutor returns system information
type SystemInfoExecutor struct{}

// NewSystemInfoExecutor creates a new system info executor
func NewSystemInfoExecutor() *SystemInfoExecutor {
	return &SystemInfoExecutor{}
}

// Name returns the tool name
func (e *SystemInfoExecutor) Name() string {
	return "system_info"
}

// Execute returns comprehensive system information
func (e *SystemInfoExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	info := map[string]interface{}{
		"hostname":     getHostname(),
		"platform":    runtime.GOOS,
		"arch":         runtime.GOARCH,
		"num_cpu":      runtime.NumCPU(),
		"go_version":   runtime.Version(),
		"go_routines":  runtime.NumGoroutine(),
		"memory_alloc": memStats.Alloc,
		"memory_sys":   memStats.Sys,
		"heap_alloc":   memStats.HeapAlloc,
		"heap_sys":     memStats.HeapSys,
		"gc_count":     memStats.NumGC,
	}

	switch runtime.GOOS {
	case "windows":
		addWindowsSystemInfo(info)
	case "linux":
		addLinuxSystemInfo(info)
	case "darwin":
		addDarwinSystemInfo(info)
	}

	return info, nil
}

// Validate checks parameters (no parameters required)
func (e *SystemInfoExecutor) Validate(params map[string]interface{}) error {
	return nil
}

// Timeout returns the execution timeout
func (e *SystemInfoExecutor) Timeout() time.Duration {
	return 15 * time.Second
}

// RiskLevel returns the risk level
func (e *SystemInfoExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *SystemInfoExecutor) Description() string {
	return "Get detailed system information"
}

func getHostname() string {
	cmd := exec.Command("hostname")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Run()
	return strings.TrimSpace(stdout.String())
}

func addWindowsSystemInfo(info map[string]interface{}) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`$cs = Get-CimInstance Win32_ComputerSystem; 
		$os = Get-CimInstance Win32_OperatingSystem;
		@{ Manufacturer = $cs.Manufacturer; Model = $cs.Model; OSName = $os.Caption; OSVersion = $os.Version } | ConvertTo-Json -Compress`)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Run()

	var sysInfo map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &sysInfo); err == nil {
		for k, v := range sysInfo {
			info[k] = v
		}
	}
}

func addLinuxSystemInfo(info map[string]interface{}) {
	cmd := exec.Command("bash", "-c", `if [ -f /etc/os-release ]; then source /etc/os-release && echo $NAME $VERSION_ID; fi`)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Run()
	osInfo := strings.TrimSpace(stdout.String())
	if osInfo != "" {
		info["os_info"] = osInfo
	}

	cmd = exec.Command("uptime", "-p")
	stdout.Reset()
	cmd.Stdout = &stdout
	cmd.Run()
	info["uptime"] = strings.TrimSpace(stdout.String())

	cmd = exec.Command("cat", "/proc/loadavg")
	stdout.Reset()
	cmd.Stdout = &stdout
	cmd.Run()
	loadAvg := strings.Fields(strings.TrimSpace(stdout.String()))
	if len(loadAvg) >= 3 {
		info["load_average"] = map[string]interface{}{
			"1min":  loadAvg[0],
			"5min":  loadAvg[1],
			"15min": loadAvg[2],
		}
	}
}

func addDarwinSystemInfo(info map[string]interface{}) {
	cmd := exec.Command("sysctl", "-n", "hw.model")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Run()
	info["hw_model"] = strings.TrimSpace(stdout.String())

	cmd = exec.Command("sw_vers")
	stdout.Reset()
	cmd.Stdout = &stdout
	cmd.Run()
	info["os_details"] = strings.TrimSpace(stdout.String())
}
