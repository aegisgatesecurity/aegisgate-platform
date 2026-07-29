// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — SIEM Package Tests
// =========================================================================

package siem

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/siem"
)

func TestNewManager_NilUpstream(t *testing.T) {
	m := NewManager(nil, nil)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.IsStarted() {
		t.Error("Manager should not be started initially")
	}
}

func TestManager_StartStop_NilUpstream(t *testing.T) {
	m := NewManager(nil, nil)
	m.Start()
	if !m.IsStarted() {
		t.Error("Manager should be started after Start()")
	}
	m.Stop()
	if m.IsStarted() {
		t.Error("Manager should not be started after Stop()")
	}
}

func TestManager_Uptime(t *testing.T) {
	m := NewManager(nil, nil)
	up := m.Uptime()
	if up != 0 {
		t.Errorf("Uptime before start should be 0, got %v", up)
	}

	m.Start()
	time.Sleep(10 * time.Millisecond)
	up = m.Uptime()
	if up == 0 {
		t.Error("Uptime after start should be > 0")
	}
	if up > 5*time.Second {
		t.Errorf("Uptime too large: %v", up)
	}

	m.Stop()
}

func TestManager_Send_NilUpstream(t *testing.T) {
	m := NewManager(nil, nil)
	err := m.Send(context.Background(), &siem.Event{})
	if err == nil {
		t.Error("Send on nil upstream should return error")
	}
}

func TestManager_SendBatch_NilUpstream(t *testing.T) {
	m := NewManager(nil, nil)
	err := m.SendBatch(context.Background(), []*siem.Event{{}})
	if err == nil {
		t.Error("SendBatch on nil upstream should return error")
	}
}

func TestManager_Stats_NilUpstream(t *testing.T) {
	m := NewManager(nil, nil)
	stats := m.Stats()
	if stats == nil {
		t.Fatal("Stats should not return nil even with nil upstream")
	}
}

func TestManager_HealthCheck_NilUpstream(t *testing.T) {
	m := NewManager(nil, nil)
	health := m.HealthCheck()
	if health == nil {
		t.Fatal("HealthCheck should not return nil")
	}
	if health.Started {
		t.Error("Health check should show not started")
	}
	if health.Uptime != 0 {
		t.Errorf("Health check uptime should be 0, got %v", health.Uptime)
	}
}

func TestManager_HealthCheck_Started(t *testing.T) {
	m := NewManager(nil, nil)
	m.Start()
	time.Sleep(10 * time.Millisecond)

	health := m.HealthCheck()
	if !health.Started {
		t.Error("Health check should show started")
	}
	if health.Uptime == 0 {
		t.Error("Health check uptime should be > 0")
	}

	m.Stop()
}

func TestConfigFromPlatform_Defaults(t *testing.T) {
	cfg := PlatformSIEMConfig{
		Source:      "aegisgate",
		Environment: "production",
	}

	result := ConfigFromPlatform(cfg)
	if result.Global.AppName != "aegisgate" {
		t.Errorf("AppName = %q, want %q", result.Global.AppName, "aegisgate")
	}
	if result.Global.Environment != "production" {
		t.Errorf("Environment = %q, want %q", result.Global.Environment, "production")
	}
}

func TestConfigFromPlatform_WithPlatforms(t *testing.T) {
	cfg := PlatformSIEMConfig{
		Source:      "aegisgate",
		Environment: "staging",
		Platforms: []PlatformSIEMTarget{
			{
				Type:     "splunk",
				Enabled:  true,
				Endpoint: "https://splunk.example.com:8088",
				Format:   "json",
				APIKey:   "secret-key-123",
			},
			{
				Type:     "elastic",
				Enabled:  true,
				Endpoint: "https://elastic.example.com:9200",
				Format:   "ecs",
			},
		},
	}

	result := ConfigFromPlatform(cfg)
	if len(result.Platforms) != 2 {
		t.Fatalf("Platforms count = %d, want 2", len(result.Platforms))
	}
	if string(result.Platforms[0].Platform) != "splunk" {
		t.Errorf("Platform[0] = %q, want splunk", result.Platforms[0].Platform)
	}
	if result.Platforms[0].Endpoint != "https://splunk.example.com:8088" {
		t.Errorf("Platform[0] Endpoint = %q", result.Platforms[0].Endpoint)
	}
	if result.Platforms[0].Auth.Type != "api_key" {
		t.Errorf("Platform[0] Auth.Type = %q, want api_key", result.Platforms[0].Auth.Type)
	}
}

func TestHealthStatus_Fields(t *testing.T) {
	hs := &HealthStatus{
		Started:   true,
		Uptime:    5 * time.Minute,
		Platforms: 3,
	}
	if !hs.Started {
		t.Error("Started should be true")
	}
	if hs.Platforms != 3 {
		t.Errorf("Platforms = %d, want 3", hs.Platforms)
	}
}
