package mcpserver

import (
	"testing"
	"time"
)

func TestEmbeddedServer_Handler(t *testing.T) {
	s := NewEmbeddedServer(nil)
	if s == nil {
		t.Fatal("Server should not be nil")
	}
	handler := s.Handler()
	if handler == nil {
		t.Error("Handler should not be nil")
	}
}

func TestConfig_AllFields(t *testing.T) {
	cfg := &Config{
		Address:      "localhost:9090",
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  10 * time.Minute,
	}
	if cfg.Address != "localhost:9090" {
		t.Error("Address should be localhost:9090")
	}
	if cfg.ReadTimeout != 60*time.Second {
		t.Error("ReadTimeout should be 60s")
	}
}

func TestConfig_DefaultValues(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Address != ":8081" {
		t.Error("Default address should be :8081")
	}
	if cfg.ReadTimeout != 30*time.Second {
		t.Error("Default read timeout should be 30s")
	}
	if cfg.WriteTimeout != 30*time.Second {
		t.Error("Default write timeout should be 30s")
	}
	if cfg.IdleTimeout != 5*time.Minute {
		t.Error("Default idle timeout should be 5m")
	}
}

func TestNewEmbeddedServer_WithValidConfig(t *testing.T) {
	cfg := &Config{
		Address:      ":9999",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	s := NewEmbeddedServer(cfg)
	if s == nil {
		t.Fatal("Server should not be nil")
	}
}
