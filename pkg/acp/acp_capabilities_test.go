// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - ACP Capabilities Tests

package acp

import (
	"testing"
)

func TestNewCapabilityEnforcer(t *testing.T) {
	enforcer := NewCapabilityEnforcer()
	if enforcer == nil {
		t.Fatal("Expected non-nil enforcer")
	}
	if enforcer.capabilities == nil {
		t.Error("Expected capabilities map to be initialized")
	}
}

func TestAllowCapability(t *testing.T) {
	enforcer := NewCapabilityEnforcer()
	enforcer.Allow("user1", "terminal.execute")
	if !enforcer.Check("user1", "terminal.execute") {
		t.Error("Expected terminal.execute to be allowed for user1")
	}
}

func TestDisallowCapability(t *testing.T) {
	enforcer := NewCapabilityEnforcer()
	enforcer.Allow("user1", "terminal.execute")
	enforcer.Disallow("user1", "terminal.execute")
	if enforcer.Check("user1", "terminal.execute") {
		t.Error("Expected terminal.execute to be disallowed for user1")
	}
}

func TestCheckUnknownIdentity(t *testing.T) {
	enforcer := NewCapabilityEnforcer()
	// Unknown identity should return defaultAllowed (false)
	if enforcer.Check("unknown", "terminal.execute") {
		t.Error("Unknown identity should not have capability by default")
	}
}

func TestCheckCapabilityNotSet(t *testing.T) {
	enforcer := NewCapabilityEnforcer()
	enforcer.Allow("user1", "fs.read")
	// Different capability should return default
	if enforcer.Check("user1", "fs.write") {
		t.Error("fs.write should not be allowed for user1")
	}
}

func TestGetCapabilities(t *testing.T) {
	enforcer := NewCapabilityEnforcer()
	enforcer.Allow("user1", "fs.read")
	enforcer.Allow("user1", "fs.write")
	caps := enforcer.GetCapabilities("user1")
	if len(caps) != 2 {
		t.Errorf("Expected 2 capabilities, got %d", len(caps))
	}
}

func TestGetCapabilitiesEmpty(t *testing.T) {
	enforcer := NewCapabilityEnforcer()
	caps := enforcer.GetCapabilities("unknown")
	if caps != nil && len(caps) != 0 {
		t.Errorf("Expected nil or empty for unknown identity, got %v", caps)
	}
}

func TestClear(t *testing.T) {
	enforcer := NewCapabilityEnforcer()
	enforcer.Allow("user1", "fs.read")
	enforcer.Clear("user1")
	caps := enforcer.GetCapabilities("user1")
	if caps != nil && len(caps) != 0 {
		t.Error("Expected empty capabilities after clear")
	}
}

func TestMultipleIdentities(t *testing.T) {
	enforcer := NewCapabilityEnforcer()
	enforcer.Allow("user1", "fs.read")
	enforcer.Allow("user2", "fs.write")

	if !enforcer.Check("user1", "fs.read") {
		t.Error("user1 should have fs.read")
	}
	if !enforcer.Check("user2", "fs.write") {
		t.Error("user2 should have fs.write")
	}
	if enforcer.Check("user1", "fs.write") {
		t.Error("user1 should not have fs.write")
	}
}

func TestConcurrentAccess(t *testing.T) {
	enforcer := NewCapabilityEnforcer()
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id string) {
			enforcer.Allow(id, "terminal.execute")
			enforcer.Check(id, "terminal.execute")
			done <- true
		}("user" + string(rune('0'+i)))
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestCommonCapabilities(t *testing.T) {
	enforcer := NewCapabilityEnforcer()
	enforcer.Allow("admin", CapabilityExecuteTerminal)
	enforcer.Allow("dev", CapabilityReadFile)
	enforcer.Allow("dev", CapabilityWriteFile)

	if !enforcer.Check("admin", CapabilityExecuteTerminal) {
		t.Error("admin should have terminal capability")
	}
	if !enforcer.Check("dev", CapabilityReadFile) {
		t.Error("dev should have read capability")
	}
}
