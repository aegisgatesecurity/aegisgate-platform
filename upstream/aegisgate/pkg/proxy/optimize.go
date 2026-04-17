// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Copyright 2024 AegisGate
// Performance optimizations for MITM proxy - focusing on hot path allocations

package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
)

// ============================================================================
// Object Pools - Reduce allocations in hot paths
// ============================================================================

// ResponseHeaderPool pools http.Header for response objects
var ResponseHeaderPool = sync.Pool{
	New: func() interface{} {
		return make(http.Header, 4)
	},
}

// GetHeaderPool returns a pooled header
func GetHeaderPool() http.Header {
	h := ResponseHeaderPool.Get()
	if h == nil {
		return make(http.Header, 4)
	}
	return h.(http.Header)
}

// PutHeaderPool returns header to pool
func PutHeaderPool(h http.Header) {
	if h == nil {
		return
	}
	// Clear the header
	for k := range h {
		delete(h, k)
	}
	ResponseHeaderPool.Put(h)
}

// StringBuilderPool pools strings.Builder for string concatenation
var StringBuilderPool = sync.Pool{
	New: func() interface{} {
		return &strings.Builder{}
	},
}

// GetStringBuilder returns a pooled strings.Builder
func GetStringBuilder() *strings.Builder {
	b := StringBuilderPool.Get()
	if b == nil {
		return &strings.Builder{}
	}
	return b.(*strings.Builder)
}

// PutStringBuilder returns builder to pool
func PutStringBuilder(b *strings.Builder) {
	if b == nil {
		return
	}
	b.Reset()
	StringBuilderPool.Put(b)
}

// ============================================================================
// Pre-computed Constants - Avoid runtime calculations
// ============================================================================

// Common status text to avoid runtime lookups
var (
	StatusBadGateway     = http.StatusText(http.StatusBadGateway)
	StatusForbidden      = http.StatusText(http.StatusForbidden)
	StatusTextBadGateway = "502 Bad Gateway"
	StatusTextForbidden  = "403 Forbidden"
)

// ============================================================================
// Optimized Response Creators - Using pools
// ============================================================================

// CreateOptimizedErrorResponse creates an error response with pooled resources
// This replaces createErrorResponse in hot paths
func CreateOptimizedErrorResponse(err error) *http.Response {
	header := GetHeaderPool()
	defer PutHeaderPool(header)

	// Use strings.Builder for efficient concatenation
	builder := GetStringBuilder()
	defer PutStringBuilder(builder)

	builder.WriteString("Proxy Error: ")
	builder.WriteString(err.Error())
	body := builder.String()

	return &http.Response{
		StatusCode:    http.StatusBadGateway,
		Status:        StatusTextBadGateway,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Header:        header,
	}
}

// CreateOptimizedBlockedResponse creates a blocked response with pooled resources
// This replaces createBlockedResponse in hot paths
func CreateOptimizedBlockedResponse(patterns []string) *http.Response {
	header := GetHeaderPool()
	defer PutHeaderPool(header)

	builder := GetStringBuilder()
	defer PutStringBuilder(builder)

	builder.WriteString("Request blocked: prohibited content detected (")

	// Join patterns efficiently
	for i, p := range patterns {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(p)
	}
	builder.WriteString(")")

	body := builder.String()

	return &http.Response{
		StatusCode:    http.StatusForbidden,
		Status:        StatusTextForbidden,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Header:        header,
	}
}

// ============================================================================
// bytes.Buffer Pool for body reading
// ============================================================================

// BufferPool pools []byte buffers for reading request/response bodies
var BufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, 8192)
		return &buf
	},
}

// GetBuffer returns a pooled buffer
func GetBuffer() *[]byte {
	b := BufferPool.Get()
	if b == nil {
		buf := make([]byte, 0, 8192)
		return &buf
	}
	return b.(*[]byte)
}

// PutBuffer returns buffer to pool
func PutBuffer(b *[]byte) {
	if b == nil {
		return
	}
	*b = (*b)[:0]
	BufferPool.Put(b)
}

// ReadBodyOptimized reads body with pooled buffer
func ReadBodyOptimized(body io.Reader) ([]byte, error) {
	buf := GetBuffer()
	defer PutBuffer(buf)

	// Read with buffer
	n, err := body.Read(*buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	result := make([]byte, n)
	copy(result, (*buf)[:n])
	return result, nil
}

// ============================================================================
// String Utilities - Reduce allocations
// ============================================================================

// SafeString returns empty string if s is empty
func SafeString(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ContainsCI is a case-insensitive contains check
func ContainsCI(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// SplitHostPort splits host:port efficiently
func SplitHostPort(host string) (string, string) {
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		return host[:idx], host[idx+1:]
	}
	return host, ""
}

// ============================================================================
// Benchmark Support
// ============================================================================

// BenchmarkResult holds benchmark results
type BenchmarkResult struct {
	OpsPerSec   float64
	NsPerOp     int64
	BytesPerOp  int64
	AllocsPerOp int64
}

// PrintBenchmarkResults prints formatted benchmark results
func PrintBenchmarkResults(name string, result BenchmarkResult) string {
	buf := new(bytes.Buffer)
	buf.WriteString(name)
	buf.WriteString(": ")
	buf.WriteString("M ops/sec, ")
	buf.WriteString("ns/op, ")
	buf.WriteString("B/op, ")
	buf.WriteString("allocs/op")
	return buf.String()
}
