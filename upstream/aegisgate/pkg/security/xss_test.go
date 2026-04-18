package security

import (
	"testing"
)

func TestStripTags(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain text",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "with paragraph",
			input:    "<p>Hello</p>",
			expected: "Hello",
		},
		{
			name:     "with script",
			input:    "<script>alert('xss')</script>",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripTags(tt.input)
			if result != tt.expected {
				t.Errorf("StripTags(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeHTML(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "basic html",
			input: "<div><p>Test</p></div>",
		},
		{
			name:  "with script",
			input: "<div><script>alert('xss')</script></div>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeHTML(tt.input)
			if result == "" && tt.input != "" {
				t.Logf("SanitizeHTML(%q) returned empty", tt.input)
			}
		})
	}
}
