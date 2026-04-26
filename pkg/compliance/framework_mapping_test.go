// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"testing"
)

// TestComplianceFactoryMethods tests the framework factory methods
func TestComplianceFactoryMethods(t *testing.T) {
	t.Run("NewNIST1500Framework", func(t *testing.T) {
		// Just call it - may return nil
		_ = NewNIST1500Framework()
	})

	t.Run("NewOWASPFramework", func(t *testing.T) {
		_ = NewOWASPFramework()
	})

	t.Run("NewAtlas", func(t *testing.T) {
		_ = NewAtlas()
	})

	t.Run("AddCustomPattern nil", func(t *testing.T) {
		manager, _ := NewManager(nil)
		err := manager.AddCustomPattern(nil)
		if err == nil {
			t.Error("AddCustomPattern should fail with nil pattern")
		}
	})
}

// TestFrameworkMappingMethods tests framework_mapping.go methods
func TestFrameworkMappingMethods(t *testing.T) {
	mapping := NewFrameworkMapping()

	t.Run("AddMapping", func(t *testing.T) {
		mapping.AddMapping("test-control", []string{"T1001"}, "mitigates", 0.8, "Test mapping")
	})

	t.Run("GetTechniquesForControl", func(t *testing.T) {
		techniques := mapping.GetTechniquesForControl("test-control")
		if techniques == nil {
			t.Error("GetTechniquesForControl should return nil, not nil slice")
		}
	})

	t.Run("GetMappingsForControl", func(t *testing.T) {
		mappings := mapping.GetMappingsForControl("test-control")
		if mappings == nil {
			t.Error("GetMappingsForControl should return nil, not nil slice")
		}
	})

	t.Run("GenerateUnifiedReport", func(t *testing.T) {
		report := mapping.GenerateUnifiedReport(nil)
		if report == nil {
			t.Error("GenerateUnifiedReport should not return nil")
		}
	})

	t.Run("AddOWASPMapping", func(t *testing.T) {
		mapping.AddOWASPMapping("OWASP-1", []string{"T1001"}, "detects", 0.9, "OWASP mapping")
	})

	t.Run("AddNIST1500Mapping", func(t *testing.T) {
		mapping.AddNIST1500Mapping("NIST-1", []string{"T1001"}, []string{"OWASP-1"}, []string{}, "mitigates", 0.85, "NIST mapping")
	})

	t.Run("ToJSON", func(t *testing.T) {
		json, err := mapping.ToJSON()
		if err != nil {
			t.Errorf("ToJSON failed: %v", err)
		}
		if json == "" {
			t.Error("ToJSON returned empty string")
		}
	})
}
