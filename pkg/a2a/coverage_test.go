package a2a

import (
	"testing"
)

func TestA2AErrorCodes(t *testing.T) {
	codes := []string{
		A2A_ERR_AUTH,
		A2A_ERR_AUTH_NO_CERT,
		A2A_ERR_AUTH_MISSING_CN,
		A2A_ERR_LICENSE_MISSING,
		A2A_ERR_LICENSE_INVALID,
		A2A_ERR_RATE_LIMITED,
		A2A_ERR_INTEGRITY_MISSING,
		A2A_ERR_INTEGRITY_INVALID,
		A2A_ERR_INTEGRITY_MALFORMED,
		A2A_ERR_CAP_MISSING,
		A2A_ERR_CAP_DENIED,
		A2A_ERR_CAP_UNKNOWN_AGENT,
		A2A_ERR_CAP_CHECK_FAILED,
		A2A_ERR_INTERNAL,
	}

	if len(codes) != 14 {
		t.Errorf("Expected 14 error codes, got %d", len(codes))
	}

	for _, code := range codes {
		if code == "" {
			t.Error("Error code should not be empty")
		}
		if len(code) < 10 {
			t.Error("Error code should be descriptive")
		}
	}
}

func TestA2AErrorCodePrefixes(t *testing.T) {
	codes := []string{
		A2A_ERR_AUTH,
		A2A_ERR_LICENSE_MISSING,
		A2A_ERR_RATE_LIMITED,
		A2A_ERR_INTEGRITY_MISSING,
		A2A_ERR_CAP_MISSING,
		A2A_ERR_INTERNAL,
	}

	for _, code := range codes {
		if len(code) < 5 {
			t.Error("Error code too short")
		}
	}
}

func TestA2AErrorCodeUniqueness(t *testing.T) {
	codeMap := make(map[string]bool)
	codes := []string{
		A2A_ERR_AUTH, A2A_ERR_AUTH_NO_CERT, A2A_ERR_AUTH_MISSING_CN,
		A2A_ERR_LICENSE_MISSING, A2A_ERR_LICENSE_INVALID, A2A_ERR_RATE_LIMITED,
		A2A_ERR_INTEGRITY_MISSING, A2A_ERR_INTEGRITY_INVALID, A2A_ERR_INTEGRITY_MALFORMED,
		A2A_ERR_CAP_MISSING, A2A_ERR_CAP_DENIED, A2A_ERR_CAP_UNKNOWN_AGENT,
		A2A_ERR_CAP_CHECK_FAILED, A2A_ERR_INTERNAL,
	}

	for _, code := range codes {
		if codeMap[code] {
			t.Errorf("Duplicate error code: %s", code)
		}
		codeMap[code] = true
	}
}
