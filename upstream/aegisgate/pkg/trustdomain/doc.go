// Package trustdomain provides feed-specific trust domain management for the AegisGate AI Security Gateway.
//
// This package implements trust domain isolation, feed-specific trust policies,
// and validation engines to prevent cascade failures across threat feeds.
//
// Main Features:
//   - Feed-specific trust domain creation and management
//   - Trust domain isolation to prevent cross-feed contamination
//   - Feed-specific trust anchor management
//   - Validation engine for certificate and signature verification
//   - Lifecycle management for trust domains
//   - Audit logging for trust domain operations
package trustdomain
