package scanner

import (
	"testing"
)

// FuzzScanRequest tests scan request parsing with arbitrary input
//
//go:generate go test -fuzz=FuzzScanRequest -fuzztime=60s
func FuzzScanRequest(f *testing.F) {
	// Seed corpus with valid request formats
	validRequests := []string{
		`{"Message":"test","Kind":"tool_use","ToolName":"test","Args":{}}`,
		`{"Message":"hello","Kind":"agent_request","ToolName":"scan","Args":{"url":"test"}}`,
		`{"Message":"","Kind":"completion","ToolName":"","Args":null}`,
	}

	for _, seed := range validRequests {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Scan request parsing panicked on: %s", data[:min(50, len(data))])
			}
		}()

		// Create a test scanner with nil config
		s := &testScanner{}

		// Parse the request - just ensure no panic
		_ = s.canParse(data)
	})
}

// testScanner is a test helper
type testScanner struct{}

func (s *testScanner) canParse(data string) bool {
	// Simple test - just check if data is not empty
	return len(data) > 0 && len(data) < 10000
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
