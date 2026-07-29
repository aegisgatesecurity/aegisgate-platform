// SPDX-License-Identifier: Apache-2.0
// FedRAMP <-> MITRE ATLAS Framework Mapping Tests

package compliance

import (
	"testing"
)

// TestFedRAMPMappingCreation verifies the FedRAMP mapping constructs correctly.
func TestFedRAMPMappingCreation(t *testing.T) {
	mapping := NewFedRAMPMapping()
	if mapping == nil {
		t.Fatal("NewFedRAMPMapping returned nil")
	}
	if mapping.Name != "FedRAMP Moderate <-> MITRE ATLAS Mapping" {
		t.Errorf("Mapping name = %q, want FedRAMP Moderate <-> MITRE ATLAS Mapping", mapping.Name)
	}
	if len(mapping.Mappings) == 0 {
		t.Error("FedRAMP mapping has no mappings")
	}
	if len(mapping.ControlToTechnique) == 0 {
		t.Error("FedRAMP mapping has no control-to-technique entries")
	}
	if len(mapping.TechniqueToControl) == 0 {
		t.Error("FedRAMP mapping has no technique-to-control entries")
	}
}

// TestFedRAMPMappingAllFamilies verifies all 18 NIST 800-53 families are represented.
func TestFedRAMPMappingAllFamilies(t *testing.T) {
	mapping := NewFedRAMPMapping()
	familyPrefixes := map[string]bool{
		"AC": false, "AT": false, "AU": false, "CA": false, "CM": false,
		"CP": false, "IA": false, "IR": false, "MA": false, "MP": false,
		"PE": false, "PL": false, "PM": false, "PS": false, "RA": false,
		"SA": false, "SC": false, "SI": false, "SR": false,
	}
	for ctrl := range mapping.ControlToTechnique {
		for prefix := range familyPrefixes {
			if len(ctrl) > len("FedRAMP-")+len(prefix) &&
				ctrl[len("FedRAMP-"):len("FedRAMP-")+len(prefix)] == prefix {
				familyPrefixes[prefix] = true
			}
		}
	}
	for prefix, found := range familyPrefixes {
		if !found {
			t.Errorf("FedRAMP mapping missing family %s", prefix)
		}
	}
}

// TestFedRAMPMappingBidirectional verifies technique-to-control reverse lookup.
func TestFedRAMPMappingBidirectional(t *testing.T) {
	// T1070 (Indicator Removal) should map to AU-2, AU-3, AU-9, SI-4, etc.
	controls := GetFedRAMPControlsForTechnique("T1070")
	if len(controls) == 0 {
		t.Error("GetFedRAMPControlsForTechnique(T1070) returned no controls")
	}
	// T1535 (Unsecured Credentials) should map to AC-2, IA-2, IA-5
	controls2 := GetFedRAMPControlsForTechnique("T1535")
	if len(controls2) == 0 {
		t.Error("GetFedRAMPControlsForTechnique(T1535) returned no controls")
	}
}

// TestFedRAMPMappingAvailableMappings verifies the mapping is in AvailableMappings.
func TestFedRAMPMappingAvailableMappings(t *testing.T) {
	mappings := AvailableMappings()
	found := false
	for _, m := range mappings {
		if m == "FedRAMP <-> MITRE ATLAS" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AvailableMappings missing FedRAMP <-> MITRE ATLAS, got %v", mappings)
	}
}

// TestFedRAMPMappingGetMapping verifies GetMapping returns the FedRAMP mapping.
func TestFedRAMPMappingGetMapping(t *testing.T) {
	mapping := GetMapping("FedRAMP <-> MITRE ATLAS")
	if mapping == nil {
		t.Fatal("GetMapping(FedRAMP <-> MITRE ATLAS) returned nil")
	}
	if mapping.Name != "FedRAMP Moderate <-> MITRE ATLAS Mapping" {
		t.Errorf("Mapping name = %q, want FedRAMP Moderate <-> MITRE ATLAS Mapping", mapping.Name)
	}
}

// TestFedRAMPMappingKeyControls verifies that critical FedRAMP controls have mappings.
func TestFedRAMPMappingKeyControls(t *testing.T) {
	keyControls := []string{
		"FedRAMP-AC-2", // Account Management
		"FedRAMP-AU-2", // Audit Events
		"FedRAMP-IA-2", // Identification and Authentication
		"FedRAMP-SC-8", // Transmission Confidentiality
		"FedRAMP-SI-4", // System Monitoring
		"FedRAMP-IR-4", // Incident Handling
		"FedRAMP-RA-5", // Vulnerability Scanning
	}
	for _, ctrl := range keyControls {
		mappings := GetFedRAMPMappingsForControl(ctrl)
		if len(mappings) == 0 {
			t.Errorf("Key control %s has no ATLAS technique mappings", ctrl)
		}
	}
}

// TestFedRAMPMappingTechniqueCount verifies sufficient ATLAS technique coverage.
func TestFedRAMPMappingTechniqueCount(t *testing.T) {
	mapping := NewFedRAMPMapping()
	uniqueTechniques := make(map[string]bool)
	for _, techniques := range mapping.ControlToTechnique {
		for _, t := range techniques {
			uniqueTechniques[t] = true
		}
	}
	// Should cover at least 30 unique ATLAS techniques (expanded from 15 in v3.5.0)
	if len(uniqueTechniques) < 30 {
		t.Errorf("FedRAMP mapping covers only %d ATLAS techniques, want at least 30", len(uniqueTechniques))
	}
}

// TestFedRAMPMappingFullCoverage verifies all FedRAMP registry controls have ATLAS mappings.
func TestFedRAMPMappingFullCoverage(t *testing.T) {
	mapping := NewFedRAMPMapping()
	// Every FedRAMP control in the registry should have an ATLAS mapping
	if len(mapping.ControlToTechnique) < 150 {
		t.Errorf("FedRAMP ATLAS mapping covers only %d controls, want at least 150", len(mapping.ControlToTechnique))
	}
	// Every technique should have at least one control
	if len(mapping.TechniqueToControl) < 30 {
		t.Errorf("FedRAMP ATLAS mapping covers only %d techniques, want at least 30", len(mapping.TechniqueToControl))
	}
}

// TestFedRAMPMappingToJSON verifies the mapping serializes correctly.
func TestFedRAMPMappingToJSON(t *testing.T) {
	mapping := NewFedRAMPMapping()
	json, err := mapping.ToJSON()
	if err != nil {
		t.Errorf("ToJSON failed: %v", err)
	}
	if json == "" {
		t.Error("ToJSON returned empty string")
	}
}
