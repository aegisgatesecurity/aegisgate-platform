// SPDX-License-Identifier: Apache-2.0
package toolexecutor

import (
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		blocked  bool
	}{
		// Loopback
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.2", "127.0.0.2", true},
		{"::1", "::1", true},

		// Private RFC 1918
		{"10.0.0.1", "10.0.0.1", true},
		{"10.255.255.255", "10.255.255.255", true},
		{"172.16.0.1", "172.16.0.1", true},
		{"172.31.255.255", "172.31.255.255", true},
		{"192.168.1.1", "192.168.1.1", true},
		{"192.168.0.0", "192.168.0.0", true},

		// Link-local (cloud metadata)
		{"169.254.169.254", "169.254.169.254", true},
		{"169.254.0.1", "169.254.0.1", true},

		// Unspecified
		{"0.0.0.0", "0.0.0.0", true},
		{"::", "::", true},

		// IPv6 unique-local
		{"fc00::1", "fc00::1", true},
		{"fd00::1", "fd00::1", true},

		// IPv6 link-local
		{"fe80::1", "fe80::1", true},

		// Public IPs should NOT be blocked
		{"8.8.8.8", "8.8.8.8", false},
		{"1.1.1.1", "1.1.1.1", false},
		{"172.32.0.1", "172.32.0.1", false}, // just outside 172.16/12
		{"169.255.0.1", "169.255.0.1", false}, // not link-local
		{"2606:4700:4700::1111", "2606:4700:4700::1111", false}, // public IPv6
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			result := isBlockedIP(ip)
			if result != tt.blocked {
				t.Errorf("isBlockedIP(%s) = %v, want %v", tt.ip, result, tt.blocked)
			}
		})
	}
}

func TestIsBlockedIP_IPv4MappedIPv6(t *testing.T) {
	// ::ffff:127.0.0.1 is an IPv4-mapped IPv6 address for loopback
	ip := net.ParseIP("::ffff:127.0.0.1")
	if ip == nil {
		t.Fatal("failed to parse IPv4-mapped IPv6 address")
	}
	if !isBlockedIP(ip) {
		t.Error("expected ::ffff:127.0.0.1 to be blocked (IPv4-mapped loopback)")
	}
}

func TestSSRFControl_RejectsInternalIP(t *testing.T) {
	// ssrfControl should reject internal IPs
	err := ssrfControl("tcp", "127.0.0.1:443", nil)
	if err == nil {
		t.Error("expected ssrfControl to reject 127.0.0.1:443")
	}

	err = ssrfControl("tcp", "169.254.169.254:80", nil)
	if err == nil {
		t.Error("expected ssrfControl to reject 169.254.169.254:80 (cloud metadata)")
	}

	err = ssrfControl("tcp", "10.0.0.1:80", nil)
	if err == nil {
		t.Error("expected ssrfControl to reject 10.0.0.1:80")
	}
}

func TestSSRFControl_AllowsPublicIP(t *testing.T) {
	err := ssrfControl("tcp", "8.8.8.8:443", nil)
	if err != nil {
		t.Errorf("expected ssrfControl to allow 8.8.8.8:443, got: %v", err)
	}

	err = ssrfControl("tcp", "1.1.1.1:443", nil)
	if err != nil {
		t.Errorf("expected ssrfControl to allow 1.1.1.1:443, got: %v", err)
	}
}

func TestSSRFControl_InvalidAddress(t *testing.T) {
	// Should error on unparseable address
	err := ssrfControl("tcp", "not-an-address", nil)
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestSSRFSafeDialerCreation(t *testing.T) {
	d := newSSRFSafeDialer(30 * 1e9) // 30s timeout in nanoseconds
	if d == nil {
		t.Fatal("expected non-nil dialer")
	}
	if d.Dialer == nil {
		t.Fatal("expected non-nil embedded Dialer")
	}
	if d.Dialer.Control == nil {
		t.Error("expected Control function to be set")
	}
}