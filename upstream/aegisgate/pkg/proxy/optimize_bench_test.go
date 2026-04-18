// Copyright 2024 AegisGate
// Performance benchmarks for MITM proxy - realistic hot-path benchmarks

package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// BenchmarkProxyResponseCreation benchmarks response creation (not full proxy setup)
func BenchmarkProxyResponseCreation(b *testing.B) {
	patterns := []string{"VisaCreditCard", "AWSKey", "PasswordInBody"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = CreateOptimizedBlockedResponse(patterns)
	}
}

// BenchmarkProxyResponseCreationOld benchmarks old response creation
func BenchmarkProxyResponseCreationOld(b *testing.B) {
	// This simulates the old createBlockedResponse behavior
	patterns := []string{"VisaCreditCard", "AWSKey", "PasswordInBody"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Old method - creates new header each time
		body := "Request blocked: prohibited content detected (" + strings.Join(patterns, ", ") + ")"
		resp := &http.Response{
			StatusCode:    http.StatusForbidden,
			Status:        http.StatusText(http.StatusForbidden),
			ProtoMajor:    1,
			ProtoMinor:    1,
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Header:        make(http.Header), // NEW HEADER EACH TIME - wasteful!
		}
		_ = resp
	}
}

// BenchmarkHeaderPooling benchmarks the header pooling
func BenchmarkHeaderPooling(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		h := GetHeaderPool()
		h.Set("Content-Type", "application/json")
		PutHeaderPool(h)
	}
}

// BenchmarkHeaderCreation benchmarks naive header creation
func BenchmarkHeaderCreation(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		h := make(http.Header, 8)
		h.Set("Content-Type", "application/json")
	}
}

// BenchmarkStringBuilderPooling benchmarks string builder pooling
func BenchmarkStringBuilderPooling(b *testing.B) {
	parts := []string{"part1", "part2", "part3", "part4", "part5"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		sb := GetStringBuilder()
		for _, p := range parts {
			sb.WriteString(p)
			sb.WriteString(" ")
		}
		result := sb.String()
		_ = result
		PutStringBuilder(sb)
	}
}

// BenchmarkStringJoin benchmarks strings.Join
func BenchmarkStringJoin(b *testing.B) {
	parts := []string{"part1", "part2", "part3", "part4", "part5"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result := strings.Join(parts, " ")
		_ = result
	}
}

// BenchmarkBufferPooling benchmarks buffer pooling for body reading
func BenchmarkBufferPooling(b *testing.B) {
	data := strings.NewReader("This is test data for reading body content")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		data.Seek(0, 0)
		buf := GetBuffer()
		data.Read(*buf)
		_ = buf
		PutBuffer(buf)
	}
}

// BenchmarkBufferNaive benchmarks naive buffer allocation
func BenchmarkBufferNaive(b *testing.B) {
	data := strings.NewReader("This is test data for reading body content")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		data.Seek(0, 0)
		buf := make([]byte, 0, 8192)
		data.Read(buf)
		_ = buf
	}
}

// BenchmarkSafeString benchmarks safe string helper
func BenchmarkSafeString(b *testing.B) {
	inputs := []string{"", "value", "another"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		input := inputs[i%len(inputs)]
		_ = SafeString(input)
	}
}

// BenchmarkSplitHostPort benchmarks host:port splitting
func BenchmarkSplitHostPort(b *testing.B) {
	inputs := []string{"example.com:443", "192.168.1.1:8080", "api.server.com"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		input := inputs[i%len(inputs)]
		host, port := SplitHostPort(input)
		_ = host
		_ = port
	}
}
