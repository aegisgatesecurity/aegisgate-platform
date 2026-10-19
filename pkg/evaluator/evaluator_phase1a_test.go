// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

func TestPhase1aNewResponseGuardScanner_NilGuard(t *testing.T) {
	s := NewResponseGuardScanner(nil)
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.Name() != "ResponseGuard" {
		t.Fatalf("expected name 'ResponseGuard', got %s", s.Name())
	}
}

func TestPhase1aNewResponseGuardScanner_WithGuard(t *testing.T) {
	guard := response.NewResponseGuard()
	s := NewResponseGuardScanner(guard)
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestPhase1aResponseGuardScanner_Scan_CleanText(t *testing.T) {
	s := NewResponseGuardScanner(nil)
	record := SXCRecord{ID: "test-1", Text: "hello world", ExpectedLabel: 0}
	det, err := s.Scan(context.Background(), record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if det == nil {
		t.Fatal("expected non-nil detection")
	}
}

func TestPhase1aResponseGuardScanner_Scan_MaliciousText(t *testing.T) {
	s := NewResponseGuardScanner(nil)
	record := SXCRecord{ID: "test-2", Text: "my API key is AKIAIOSFODNN7EXAMPLE", ExpectedLabel: 1}
	det, err := s.Scan(context.Background(), record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if det == nil {
		t.Fatal("expected non-nil detection")
	}
}

func TestPhase1aShortFingerprint_NoPrefix(t *testing.T) {
	result := shortFingerprint("abcdef0123456789abcdef")
	if len(result) > 16 {
		t.Fatalf("expected max 16 chars, got %d", len(result))
	}
}

func TestPhase1aShortFingerprint_ShortInput(t *testing.T) {
	result := shortFingerprint("short")
	if result != "short" {
		t.Fatalf("expected 'short', got %s", result)
	}
}

func TestPhase1aShortFingerprint_WithPrefix(t *testing.T) {
	result := shortFingerprint("sha256:abcdef0123456789abcdef0123456789")
	if len(result) > 16 {
		t.Fatalf("expected max 16 chars, got %d", len(result))
	}
}

func TestPhase1aShortFingerprint_EmptyInput(t *testing.T) {
	result := shortFingerprint("")
	if result != "" {
		t.Fatalf("expected empty string, got %s", result)
	}
}

func TestPhase1aParseRunResult_ValidJSON(t *testing.T) {
	payload := []byte(`{"scanner":"test","total_records":10,"detected":5}`)
	result, err := ParseRunResult(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPhase1aParseRunResult_InvalidJSON(t *testing.T) {
	payload := []byte(`{invalid json}`)
	_, err := ParseRunResult(payload)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestPhase1aParseRunResult_EmptyPayload(t *testing.T) {
	_, err := ParseRunResult([]byte{})
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}
