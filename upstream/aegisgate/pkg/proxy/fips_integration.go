// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Copyright 2024 AegisGate
// FIPS-Compliant Proxy Configuration
//
// This module integrates enhanced cryptographic operations into the proxy
// for FIPS compliance.

package proxy

import (
	"crypto/tls"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/crypto/enhanced"
)

// ProxyTLSConfig holds TLS configuration for the proxy
type ProxyTLSConfig struct {
	// Enable FIPS mode
	FIPSMode bool

	// Minimum TLS version
	MinTLSVersion uint16

	// Client certificate required
	RequireClientCert bool

	// Allowed cipher suites
	CipherSuites []uint16
}

// DefaultProxyTLSConfig returns default TLS configuration for proxy
func DefaultProxyTLSConfig() *ProxyTLSConfig {
	return &ProxyTLSConfig{
		FIPSMode:          false,
		MinTLSVersion:     tls.VersionTLS12,
		RequireClientCert: false,
		CipherSuites:      enhanced.GetFIPSCipherSuites(),
	}
}

// GetTLSConfig returns a TLS config for the proxy
func (p *ProxyTLSConfig) GetTLSConfig() *tls.Config {
	cfg := &tls.Config{
		MinVersion:               p.MinTLSVersion,
		PreferServerCipherSuites: true,
		ClientAuth:               tls.NoClientCert,
	}

	if p.FIPSMode {
		cfg.CipherSuites = enhanced.GetFIPSCipherSuites()
	} else if len(p.CipherSuites) > 0 {
		cfg.CipherSuites = p.CipherSuites
	}

	return cfg
}

// GetClientTLSConfig returns client TLS configuration
func GetClientTLSConfig() *tls.Config {
	return enhanced.GetSecureTLSConfig()
}

// ProxyMetrics holds proxy performance metrics
type ProxyMetrics struct {
	// Request counts
	TotalRequests   int64
	BlockedRequests int64
	AllowedRequests int64

	// Latency
	AvgLatency time.Duration
	P99Latency time.Duration

	// TLS metrics
	TLSVersions  map[string]int64
	CipherSuites map[string]int64

	// Connection metrics
	ActiveConnections int64
	TotalConnections  int64
}

// NewProxyMetrics creates new proxy metrics
func NewProxyMetrics() *ProxyMetrics {
	return &ProxyMetrics{
		TLSVersions:  make(map[string]int64),
		CipherSuites: make(map[string]int64),
	}
}

// RecordTLSVersion records a TLS version usage
func (m *ProxyMetrics) RecordTLSVersion(version string) {
	m.TLSVersions[version]++
}

// RecordCipherSuite records a cipher suite usage
func (m *ProxyMetrics) RecordCipherSuite(suite string) {
	m.CipherSuites[suite]++
}
