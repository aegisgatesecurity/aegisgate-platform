// Package tool-executor - SSRF protection tests
package toolexecutor

import (
	"net"
	"testing"
)

func TestValidateURL_SSRF_BlocksPrivateIPs(t *testing.T) {
	tools := NewWebTools(nil, 0) // No allowlist — allow all public

	blockedURLs := []string{
		"http://127.0.0.1/",
		"http://127.0.0.1:8080/admin",
		"http://localhost/",
		"http://localhost:3000/",
		"http://10.0.0.1/",
		"http://10.255.255.255/",
		"http://172.16.0.1/",
		"http://172.31.255.255/",
		"http://192.168.1.1/",
		"http://192.168.0.100:8080/",
		"http://169.254.169.254/latest/meta-data/", // AWS metadata
		"http://metadata.google.internal/",         // GCP metadata
		"http://metadata.aws.internal/",            // AWS metadata alias
		"http://metadata.azure.com/",               // Azure metadata
		"http://0.0.0.0/",
		"http://[::1]/",
		"http://[fe80::1]/",
		"http://[fc00::1]/", // IPv6 ULA
	}

	for _, u := range blockedURLs {
		t.Run("blocked_"+u, func(t *testing.T) {
			err := tools.validateURL(u)
			if err == nil {
				t.Errorf("expected URL %s to be blocked, but it was allowed", u)
			}
		})
	}
}

func TestValidateURL_SSRF_AllowsPublicDomains(t *testing.T) {
	tools := NewWebTools(nil, 0) // No allowlist — allow all public

	allowedURLs := []string{
		"https://example.com/",
		"https://api.github.com/v1",
		"http://93.184.216.34/", // example.com's actual IP
		"https://registry.npmjs.org/",
	}

	for _, u := range allowedURLs {
		t.Run("allowed_"+u, func(t *testing.T) {
			err := tools.validateURL(u)
			if err != nil {
				t.Errorf("expected URL %s to be allowed, got error: %v", u, err)
			}
		})
	}
}

func TestValidateURL_SSRF_BlocksNonHTTPScheme(t *testing.T) {
	tools := NewWebTools(nil, 0)

	blockedSchemes := []string{
		"file:///etc/passwd",
		"ftp://example.com/",
		"gopher://localhost:6379/",
		"dict://localhost:11211/",
		"ldap://localhost:389/",
		"javascript:alert(1)",
	}

	for _, u := range blockedSchemes {
		t.Run("blocked_scheme_"+u, func(t *testing.T) {
			err := tools.validateURL(u)
			if err == nil {
				t.Errorf("expected scheme for URL %s to be blocked", u)
			}
		})
	}
}

func TestValidateURL_SSRF_AlllistEnforced(t *testing.T) {
	tools := NewWebTools([]string{"example.com", "api.github.com"}, 0)

	tests := []struct {
		url     string
		allowed bool
	}{
		{"https://example.com/", true},
		{"https://api.github.com/v1", true},
		{"https://sub.example.com/path", true}, // subdomain of allowlisted
		{"https://evil.com/", false},
		{"https://example.com.evil.com/", false}, // not a real subdomain
		{"https://notexample.com/", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := tools.validateURL(tt.url)
			if tt.allowed && err != nil {
				t.Errorf("expected %s to be allowed, got: %v", tt.url, err)
			}
			if !tt.allowed && err == nil {
				t.Errorf("expected %s to be blocked, but it was allowed", tt.url)
			}
		})
	}
}

func TestValidateURL_SSRF_BlocksMetadataHostnames(t *testing.T) {
	tools := NewWebTools(nil, 0)

	metadataHosts := []string{
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://metadata.aws.internal/",
		"http://metadata.azure.com/",
		"http://sub.metadata.google.internal/",
	}

	for _, u := range metadataHosts {
		t.Run("metadata_"+u, func(t *testing.T) {
			err := tools.validateURL(u)
			if err == nil {
				t.Errorf("expected metadata endpoint %s to be blocked", u)
			}
		})
	}
}

func TestValidateURL_SSRF_EmptyAndInvalid(t *testing.T) {
	tools := NewWebTools(nil, 0)

	invalidURLs := []string{
		"",
		"not-a-url",
		"https://",
		"http://",
		"://",
	}

	for _, u := range invalidURLs {
		t.Run("invalid_"+u, func(t *testing.T) {
			err := tools.validateURL(u)
			if err == nil {
				t.Errorf("expected %q to return error", u)
			}
		})
	}
}

func TestIsPrivateOrBlockedIP(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false}, // outside private range
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"169.254.0.1", true},
		{"0.0.0.0", true},
		{"::1", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"8.8.8.8", false},                            // public DNS
		{"93.184.216.34", false},                      // example.com
		{"2606:2800:220:1:248:1893:25c8:1946", false}, // public IPv6
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %s", tt.ip)
			}
			result := isPrivateOrBlockedIP(ip)
			if result != tt.blocked {
				t.Errorf("isPrivateOrBlockedIP(%s) = %v, want %v", tt.ip, result, tt.blocked)
			}
		})
	}
}

func TestIsPrivateOrBlockedIP_Nil(t *testing.T) {
	if !isPrivateOrBlockedIP(nil) {
		t.Error("nil IP should be blocked")
	}
}
