// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Security Scanner Interface
// =========================================================================
//
// Scanner interface for security scanning services. The platform
// supports both local processing and remote scanners (AegisGuard MCP).
//
// Architecture:
//   - scanner.go:           Scanner interface, ScanRequest, ScanResponse types
//   - aegisguard_mcp.go:    AegisGuardMCPScanner (remote scanner using MCP
//                          protocol, JSON-RPC over TCP) — used when AegisGuard
//                          runs as a separate process
//
// The Scanner interface has 4 methods:
//   - Scan(ctx, request) (*ScanResponse, error):  process a request
//   - Health() error:                              health status
//   - Stats() (*StatsResponse, error):             statistics (RPS, P95/P99 latency)
//   - Close() error:                               cleanup resources
//
// Wire protocol (AegisGuardMCPScanner):
//   - JSON-RPC 2.0 over TCP (port 8081 by default)
//   - Reuses the same MCP transport as the MCP server (one less protocol)
//   - Default timeout: 30 seconds (configurable via ScannerConfig)
//
// In standalone mode (--embedded-mcp), the platform uses the local
// AegisGuard bridge (pkg/bridge) instead of this scanner. The scanner
// is only used when AegisGuard is deployed as a separate process.
//
// Related packages:
//   - pkg/bridge:  unified LLM bridge (re-exports the AegisGuard types)
//   - pkg/proxy:   HTTP proxy that calls the scanner for every request/response
//
// =========================================================================

package scanner
