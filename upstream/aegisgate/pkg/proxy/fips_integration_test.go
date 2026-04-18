// Copyright 2024 AegisGate
// FIPS Integration Tests

package proxy

import (
	"crypto/tls"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/crypto/fips"
)

func TestProxyTLSConfig(t *testing.T) {
	cfg := DefaultProxyTLSConfig()
	if cfg == nil {
		t.Fatal("Expected config, got nil")
	}

	tlsCfg := cfg.GetTLSConfig()
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected TLS 1.2 minimum, got %d", tlsCfg.MinVersion)
	}
}

func TestProxyTLSConfigFIPSMode(t *testing.T) {
	cfg := &ProxyTLSConfig{
		FIPSMode:      true,
		MinTLSVersion: tls.VersionTLS12,
	}

	fips.Configure(fips.Level140_2)
	defer fips.Configure(fips.LevelNone)

	tlsCfg := cfg.GetTLSConfig()

	if len(tlsCfg.CipherSuites) == 0 {
		t.Error("Expected FIPS cipher suites")
	}
}

func TestClientTLSConfig(t *testing.T) {
	cfg := GetClientTLSConfig()

	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("Expected TLS 1.2 minimum, got %d", cfg.MinVersion)
	}
}

func TestProxyMetrics(t *testing.T) {
	metrics := NewProxyMetrics()

	if metrics == nil {
		t.Fatal("Expected metrics")
	}

	metrics.RecordTLSVersion("1.3")
	metrics.RecordCipherSuite("ECDHE-RSA-AES256-GCM-SHA384")

	if metrics.TLSVersions["1.3"] != 1 {
		t.Errorf("Expected 1 TLS 1.3 recording, got %d", metrics.TLSVersions["1.3"])
	}
}
