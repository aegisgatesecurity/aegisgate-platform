// Package sandbox provides feed-level sandboxing capabilities for AegisGate's threat intelligence feeds.
//
// ## Overview
//
// The sandbox package implements comprehensive isolation for feed processing with the following capabilities:
//
// - **Feed-Specific Sandboxing**: Each feed gets its own dedicated sandbox environment
// - **Resource Management**: Configurable resource quotas and limits
// - **Security Isolation**: Strict security boundaries between sandboxes
// - **Monitoring**: Real-time sandbox monitoring and audit logging
// - **Lifecycle Management**: Create, configure, start, stop, and destroy sandboxes
//
// ## Architecture
//
// The sandbox system implements:
//
// - Sandbox container system for feed isolation
// - Feed-specific sandbox policies
// - Resource quota enforcement
// - Security boundary enforcement
// - Audit logging for compliance
//
// ## Integration
//
// - pkg/sandbox: Core sandbox services
// - pkg/sandbox/internal: Internal implementation details
//
// ## Testing
//
// - pkg/sandbox/sandbox_test.go: Unit tests
// - pkg/sandbox/integration_test.go: Integration tests
//
// ## Documentation
//
// - docs/sandbox/architecture.md: Architecture design document
// - docs/sandbox/implementation.md: Implementation guide
//
// ## Version
//
// - Current Version: v0.20.0 (in development)
// - Next Step: Sandbox container system implementation

package sandbox
