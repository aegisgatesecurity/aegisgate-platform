// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Event Logging and Ring Buffer
// =========================================================================
//
// Structured event recording and the global in-memory ring buffer that
// backs the compliance evidence pipeline. The recorder is the bridge
// between the event-emitting subsystems (HTTP proxy, MCP server, A2A,
// ACP, ANP, response scans, anomaly scores) and the SIEM integration
// layer + IOC store + compliance evidence packages.
//
// Components:
//   - recorder.go:        package-level default recorder (singleton, similar to log.Default())
//   - auditring.go:       thread-safe ring buffer (MPSC, fixed capacity)
//   - framework_refs.go:  hot-path-safe cache mapping (Type, ThreatType, Pattern)
//                         to cross-framework reference IDs (MITRE ATLAS, NIST AI RMF,
//                         OWASP LLM, CWE, CVE). Bridges pkg/logging to pkg/compliance
//                         without creating a circular import.
//   - rfc5424.go:         RFC 5424 compliant syslog output (for SIEM integration)
//
// Threading model:
//   - Init  -> called once from main.go at startup
//   - Record -> callable from any goroutine, lock-free fast path
//   - GetDefault -> read-only
//   - Stop  -> called once from main.go at shutdown
//
// Pattern: similar to Go stdlib log.Default() — a package-level
// recorder is set once at process startup (in main.go) and then used
// by any subsystem that wants to record events. This avoids threading
// a *RingBuffer through every constructor in the codebase.
//
// =========================================================================

package logging
