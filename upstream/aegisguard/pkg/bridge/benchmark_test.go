// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================

package bridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// BenchmarkGatewayProxy measures the performance of the bridge gateway proxy
func BenchmarkGatewayProxy(b *testing.B) {
	// Setup mock AegisGate server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"response": "success"}`))
	}))
	defer mockServer.Close()

	// Create gateway
	config := &Config{
		AegisGateURL:  mockServer.URL,
		Timeout:       30 * time.Second,
		Enabled:       true,
		MaxRetries:    3,
		RetryInterval: 500 * time.Millisecond,
		SkipTLSVerify: true,
		DefaultTarget: "https://api.openai.com",
	}

	gateway, err := NewGateway(config)
	require.NoError(b, err)
	defer gateway.Close()

	// Benchmark proxy performance
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gateway.RouteLLMCall(context.Background(), &LLMRequest{
			RequestID: "test-request",
			AgentID:   "test-agent",
			SessionID: "test-session",
			TargetURL: mockServer.URL,
			Method:    http.MethodGet,
			Body:      []byte(`{"test": "data"}`),
		})
		require.NoError(b, err)
	}
}

// BenchmarkGatewayProxyWithPassThrough measures the performance with pass-through mode
func BenchmarkGatewayProxyWithPassThrough(b *testing.B) {
	// Setup mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"response": "success"}`))
	}))
	defer mockServer.Close()

	// Create gateway with bridge disabled (pass-through mode)
	config := &Config{
		AegisGateURL:  mockServer.URL,
		Timeout:       30 * time.Second,
		Enabled:       false, // Pass-through mode
		MaxRetries:    3,
		RetryInterval: 500 * time.Millisecond,
		SkipTLSVerify: true,
		DefaultTarget: mockServer.URL,
	}

	gateway, err := NewGateway(config)
	require.NoError(b, err)
	defer gateway.Close()

	// Benchmark pass-through performance
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gateway.RouteLLMCall(context.Background(), &LLMRequest{
			RequestID: "test-request",
			Method:    http.MethodGet,
			TargetURL: mockServer.URL,
		})
		require.NoError(b, err)
	}
}

// BenchmarkGatewayProxyWithoutCache measures the performance without any caching
func BenchmarkGatewayProxyWithoutCache(b *testing.B) {
	// Setup mock AegisGate server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"response": "success"}`))
	}))
	defer mockServer.Close()

	// Create gateway
	config := &Config{
		AegisGateURL:  mockServer.URL,
		Timeout:       30 * time.Second,
		Enabled:       true,
		MaxRetries:    3,
		RetryInterval: 500 * time.Millisecond,
		SkipTLSVerify: true,
		DefaultTarget: "https://api.openai.com",
	}

	gateway, err := NewGateway(config)
	require.NoError(b, err)
	defer gateway.Close()

	// Benchmark proxy performance without cache
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gateway.RouteLLMCall(context.Background(), &LLMRequest{
			RequestID: "test-request",
			AgentID:   "test-agent",
			SessionID: "test-session",
			TargetURL: mockServer.URL,
			Method:    http.MethodPost,
			Body:      []byte(`{"prompt": "test prompt", "max_tokens": 100}`),
		})
		require.NoError(b, err)
	}
}

// BenchmarkStatsRecording measures the performance of stats recording
func BenchmarkStatsRecording(b *testing.B) {
	// Setup mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"response": "success"}`))
	}))
	defer mockServer.Close()

	// Create gateway
	config := &Config{
		AegisGateURL:  mockServer.URL,
		Timeout:       30 * time.Second,
		Enabled:       false,
		MaxRetries:    3,
		RetryInterval: 500 * time.Millisecond,
		SkipTLSVerify: true,
		DefaultTarget: mockServer.URL,
	}

	gateway, err := NewGateway(config)
	require.NoError(b, err)
	defer gateway.Close()

	// Benchmark stats recording
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gateway.RouteLLMCall(context.Background(), &LLMRequest{
			RequestID: "test-request",
		})
		_ = gateway.GetStats()
	}
}

// BenchmarkConcurrentGatewayRequests measures performance under concurrent load
func BenchmarkConcurrentGatewayRequests(b *testing.B) {
	// Setup mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"response": "success"}`))
	}))
	defer mockServer.Close()

	// Create gateway
	config := &Config{
		AegisGateURL:  mockServer.URL,
		Timeout:       30 * time.Second,
		Enabled:       false,
		MaxRetries:    3,
		RetryInterval: 500 * time.Millisecond,
		SkipTLSVerify: true,
		DefaultTarget: mockServer.URL,
	}

	gateway, err := NewGateway(config)
	require.NoError(b, err)
	defer gateway.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = gateway.RouteLLMCall(context.Background(), &LLMRequest{
				RequestID: "test-request",
				Method:    http.MethodGet,
			})
		}
	})
}

// BenchmarkGatewayHealthCheck measures the performance of health check operations
func BenchmarkGatewayHealthCheck(b *testing.B) {
	// Setup mock health server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	config := &Config{
		AegisGateURL:  mockServer.URL,
		Timeout:       30 * time.Second,
		Enabled:       false,
		MaxRetries:    3,
		RetryInterval: 500 * time.Millisecond,
		SkipTLSVerify: true,
		DefaultTarget: "https://api.openai.com",
	}

	gateway, err := NewGateway(config)
	require.NoError(b, err)
	defer gateway.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gateway.isAegisGateReachable(context.Background())
	}
}
