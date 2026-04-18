// Package threatintel provides comprehensive tests for threat intelligence functionality.
package threatintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Types Tests
// ============================================================================

func TestSTIXTypeConstants(t *testing.T) {
	types := []STIXType{
		STIXTypeIndicator,
		STIXTypeAttackPattern,
		STIXTypeThreatActor,
		STIXTypeMalware,
		STIXTypeVulnerability,
		STIXTypeReport,
		STIXTypeRelationship,
		STIXTypeDomainName,
		STIXTypeIPv4Addr,
		STIXTypeIPv6Addr,
		STIXTypeURL,
		STIXTypeFile,
		STIXTypeEmailAddr,
		STIXTypeBundle,
	}

	for _, st := range types {
		if string(st) == "" {
			t.Errorf("STIXType constant should not be empty")
		}
	}
}

func TestIndicatorPatternTypeConstants(t *testing.T) {
	types := []IndicatorPatternType{
		PatternTypeSTIX,
		PatternTypeSNORT,
		PatternTypeSuricata,
		PatternTypeSigma,
		PatternTypeYARA,
	}

	for _, pt := range types {
		if string(pt) == "" {
			t.Errorf("IndicatorPatternType constant should not be empty")
		}
	}
}

func TestIndicatorTypeConstants(t *testing.T) {
	types := []IndicatorType{
		IndicatorTypeMaliciousActivity,
		IndicatorTypeAnomalousActivity,
		IndicatorTypeAttribution,
		IndicatorTypeUnknown,
		IndicatorTypeBenign,
		IndicatorTypeCompromised,
	}

	for _, it := range types {
		if string(it) == "" {
			t.Errorf("IndicatorType constant should not be empty")
		}
	}
}

func TestRelationshipTypeConstants(t *testing.T) {
	types := []RelationshipType{
		RelationshipTypeRelatedTo,
		RelationshipTypeIndicates,
		RelationshipTypeUses,
		RelationshipTypeTargets,
		RelationshipTypeAttributedTo,
	}

	for _, rt := range types {
		if string(rt) == "" {
			t.Errorf("RelationshipType constant should not be empty")
		}
	}
}

// ============================================================================
// Indicator Tests
// ============================================================================

func TestNewIndicator(t *testing.T) {
	id, err := GenerateSTIXID(STIXTypeIndicator)
	if err != nil {
		t.Fatalf("Failed to generate ID: %v", err)
	}

	indicator := NewIndicator(id, "[ipv4-addr:value = '192.168.1.1']", PatternTypeSTIX)

	if indicator.Type != STIXTypeIndicator {
		t.Errorf("Expected type %s, got %s", STIXTypeIndicator, indicator.Type)
	}
	if indicator.Pattern != "[ipv4-addr:value = '192.168.1.1']" {
		t.Errorf("Unexpected pattern: %s", indicator.Pattern)
	}
	if indicator.PatternType != PatternTypeSTIX {
		t.Errorf("Expected pattern type %s, got %s", PatternTypeSTIX, indicator.PatternType)
	}
	if indicator.SpecVersion != "2.1" {
		t.Errorf("Expected spec version 2.1, got %s", indicator.SpecVersion)
	}
	if indicator.Created.IsZero() {
		t.Error("Created should be set")
	}
}

func TestIndicatorJSON(t *testing.T) {
	id, _ := GenerateSTIXID(STIXTypeIndicator)
	indicator := NewIndicator(id, "[domain-name:value = 'malicious.example.com']", PatternTypeSTIX)
	indicator.Name = "Malicious Domain"
	indicator.Description = "Domain associated with malware distribution"
	indicator.IndicatorTypes = []IndicatorType{IndicatorTypeMaliciousActivity}
	indicator.Confidence = 85
	indicator.Labels = []string{"malware", "c2"}

	data, err := json.Marshal(indicator)
	if err != nil {
		t.Fatalf("Failed to marshal indicator: %v", err)
	}

	var parsed Indicator
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal indicator: %v", err)
	}

	if parsed.Name != indicator.Name {
		t.Errorf("Expected name %s, got %s", indicator.Name, parsed.Name)
	}
	if parsed.Confidence != indicator.Confidence {
		t.Errorf("Expected confidence %d, got %d", indicator.Confidence, parsed.Confidence)
	}
	if len(parsed.Labels) != 2 {
		t.Errorf("Expected 2 labels, got %d", len(parsed.Labels))
	}
}

// ============================================================================
// Attack Pattern Tests
// ============================================================================

func TestNewAttackPattern(t *testing.T) {
	id, err := GenerateSTIXID(STIXTypeAttackPattern)
	if err != nil {
		t.Fatalf("Failed to generate ID: %v", err)
	}

	ap := NewAttackPattern(id, "Spear Phishing")
	ap.Description = "Spear phishing attack technique"
	ap.KillChainPhases = []KillChainPhase{
		{KillChainName: "mitre-attack", PhaseName: "initial-access"},
	}

	if ap.Type != STIXTypeAttackPattern {
		t.Errorf("Expected type %s, got %s", STIXTypeAttackPattern, ap.Type)
	}
	if ap.Name != "Spear Phishing" {
		t.Errorf("Expected name 'Spear Phishing', got %s", ap.Name)
	}
	if len(ap.KillChainPhases) != 1 {
		t.Errorf("Expected 1 kill chain phase, got %d", len(ap.KillChainPhases))
	}
}

// ============================================================================
// Threat Actor Tests
// ============================================================================

func TestNewThreatActor(t *testing.T) {
	id, err := GenerateSTIXID(STIXTypeThreatActor)
	if err != nil {
		t.Fatalf("Failed to generate ID: %v", err)
	}

	ta := NewThreatActor(id, "APT28")
	ta.Description = "Russian state-sponsored threat actor"
	ta.ThreatActorTypes = []ThreatActorType{ThreatActorTypeNationState}
	ta.Aliases = []string{"Fancy Bear", "Sofacy"}
	ta.ResourceLevel = "state-sponsored"
	ta.PrimaryMotivation = "espionage"

	if ta.Type != STIXTypeThreatActor {
		t.Errorf("Expected type %s, got %s", STIXTypeThreatActor, ta.Type)
	}
	if ta.Name != "APT28" {
		t.Errorf("Expected name 'APT28', got %s", ta.Name)
	}
	if len(ta.ThreatActorTypes) != 1 {
		t.Errorf("Expected 1 threat actor type, got %d", len(ta.ThreatActorTypes))
	}
}

// ============================================================================
// Malware Tests
// ============================================================================

func TestNewMalware(t *testing.T) {
	id, err := GenerateSTIXID(STIXTypeMalware)
	if err != nil {
		t.Fatalf("Failed to generate ID: %v", err)
	}

	malware := NewMalware(id, "Emotet", true)
	malware.Description = "Banking trojan"
	malware.MalwareTypes = []MalwareType{MalwareTypeTrojan}
	malware.Aliases = []string{"Heodo", "Geodo"}
	malware.Capabilities = []string{"stealth", "persistence", "lateral-movement"}

	if malware.Type != STIXTypeMalware {
		t.Errorf("Expected type %s, got %s", STIXTypeMalware, malware.Type)
	}
	if malware.Name != "Emotet" {
		t.Errorf("Expected name 'Emotet', got %s", malware.Name)
	}
	if !malware.IsFamily {
		t.Error("Malware should be marked as family")
	}
	if len(malware.MalwareTypes) != 1 {
		t.Errorf("Expected 1 malware type, got %d", len(malware.MalwareTypes))
	}
}

// ============================================================================
// Relationship Tests
// ============================================================================

func TestNewRelationship(t *testing.T) {
	relID, _ := GenerateSTIXID(STIXTypeRelationship)
	indID, _ := GenerateSTIXID(STIXTypeIndicator)
	taID, _ := GenerateSTIXID(STIXTypeThreatActor)

	rel := NewRelationship(relID, RelationshipTypeIndicates, indID, taID)
	rel.Description = "Indicator attributed to threat actor"

	if rel.Type != STIXTypeRelationship {
		t.Errorf("Expected type %s, got %s", STIXTypeRelationship, rel.Type)
	}
	if rel.RelationshipType != RelationshipTypeIndicates {
		t.Errorf("Expected relationship type %s, got %s", RelationshipTypeIndicates, rel.RelationshipType)
	}
	if rel.SourceRef != indID {
		t.Errorf("Expected source ref %s, got %s", indID, rel.SourceRef)
	}
	if rel.TargetRef != taID {
		t.Errorf("Expected target ref %s, got %s", taID, rel.TargetRef)
	}
}

// ============================================================================
// Report Tests
// ============================================================================

func TestNewReport(t *testing.T) {
	id, _ := GenerateSTIXID(STIXTypeReport)
	indID, _ := GenerateSTIXID(STIXTypeIndicator)

	report := NewReport(id, "Threat Intelligence Report", time.Now())
	report.Description = "Monthly threat intelligence report"
	report.ReportTypes = []string{"threat-report"}
	report.ObjectRefs = []string{indID}

	if report.Type != STIXTypeReport {
		t.Errorf("Expected type %s, got %s", STIXTypeReport, report.Type)
	}
	if report.Name != "Threat Intelligence Report" {
		t.Errorf("Unexpected name: %s", report.Name)
	}
	if len(report.ObjectRefs) != 1 {
		t.Errorf("Expected 1 object ref, got %d", len(report.ObjectRefs))
	}
}

// ============================================================================
// Observable Tests
// ============================================================================

func TestNewIPv4Address(t *testing.T) {
	id, _ := GenerateSTIXID(STIXTypeIPv4Addr)
	obs := NewIPv4Address(id, "192.168.1.1")

	if obs.Type != STIXTypeIPv4Addr {
		t.Errorf("Expected type %s, got %s", STIXTypeIPv4Addr, obs.Type)
	}
	if obs.Value != "192.168.1.1" {
		t.Errorf("Expected value '192.168.1.1', got %s", obs.Value)
	}
}

func TestNewIPv6Address(t *testing.T) {
	id, _ := GenerateSTIXID(STIXTypeIPv6Addr)
	obs := NewIPv6Address(id, "2001:db8::1")

	if obs.Type != STIXTypeIPv6Addr {
		t.Errorf("Expected type %s, got %s", STIXTypeIPv6Addr, obs.Type)
	}
	if obs.Value != "2001:db8::1" {
		t.Errorf("Expected value '2001:db8::1', got %s", obs.Value)
	}
}

func TestNewDomainName(t *testing.T) {
	id, _ := GenerateSTIXID(STIXTypeDomainName)
	obs := NewDomainName(id, "malicious.example.com")

	if obs.Type != STIXTypeDomainName {
		t.Errorf("Expected type %s, got %s", STIXTypeDomainName, obs.Type)
	}
	if obs.Value != "malicious.example.com" {
		t.Errorf("Expected value 'malicious.example.com', got %s", obs.Value)
	}
}

func TestNewURL(t *testing.T) {
	id, _ := GenerateSTIXID(STIXTypeURL)
	obs := NewURL(id, "https://malicious.example.com/payload.exe")

	if obs.Type != STIXTypeURL {
		t.Errorf("Expected type %s, got %s", STIXTypeURL, obs.Type)
	}
	if obs.Value != "https://malicious.example.com/payload.exe" {
		t.Errorf("Unexpected value: %s", obs.Value)
	}
}

func TestNewFile(t *testing.T) {
	id, _ := GenerateSTIXID(STIXTypeFile)
	hashes := FileHash{
		MD5:    "d41d8cd98f00b204e9800998ecf8427e",
		SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	obs := NewFile(id, hashes)
	obs.Name = "malware.exe"
	obs.Size = 1024

	if obs.Type != STIXTypeFile {
		t.Errorf("Expected type %s, got %s", STIXTypeFile, obs.Type)
	}
	if obs.Hashes.MD5 != hashes.MD5 {
		t.Errorf("Expected MD5 %s, got %s", hashes.MD5, obs.Hashes.MD5)
	}
	if obs.Name != "malware.exe" {
		t.Errorf("Expected name 'malware.exe', got %s", obs.Name)
	}
}

func TestNewEmailAddress(t *testing.T) {
	id, _ := GenerateSTIXID(STIXTypeEmailAddr)
	obs := NewEmailAddress(id, "attacker@example.com")

	if obs.Type != STIXTypeEmailAddr {
		t.Errorf("Expected type %s, got %s", STIXTypeEmailAddr, obs.Type)
	}
	if obs.Value != "attacker@example.com" {
		t.Errorf("Expected value 'attacker@example.com', got %s", obs.Value)
	}
}

// ============================================================================
// Bundle Tests
// ============================================================================

func TestNewBundle(t *testing.T) {
	id, _ := GenerateSTIXID(STIXTypeBundle)
	bundle := NewBundle(id)

	if bundle.Type != STIXTypeBundle {
		t.Errorf("Expected type %s, got %s", STIXTypeBundle, bundle.Type)
	}
	if bundle.ID == "" {
		t.Error("Bundle ID should not be empty")
	}
	if bundle.Objects == nil {
		t.Error("Bundle objects should be initialized")
	}
}

func TestBundleAddObject(t *testing.T) {
	bundleID, _ := GenerateSTIXID(STIXTypeBundle)
	bundle := NewBundle(bundleID)

	indID, _ := GenerateSTIXID(STIXTypeIndicator)
	indicator := NewIndicator(indID, "[ipv4-addr:value = '10.0.0.1']", PatternTypeSTIX)

	err := bundle.AddObject(indicator)
	if err != nil {
		t.Fatalf("Failed to add object: %v", err)
	}

	if len(bundle.Objects) != 1 {
		t.Errorf("Expected 1 object, got %d", len(bundle.Objects))
	}
}

func TestBundleMarshal(t *testing.T) {
	bundleID, _ := GenerateSTIXID(STIXTypeBundle)
	bundle := NewBundle(bundleID)

	indID, _ := GenerateSTIXID(STIXTypeIndicator)
	indicator := NewIndicator(indID, "[ipv4-addr:value = '10.0.0.1']", PatternTypeSTIX)
	indicator.Name = "Test Indicator"

	bundle.AddObject(indicator)

	data, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatalf("Failed to marshal bundle: %v", err)
	}

	if !strings.Contains(string(data), `"type":"bundle"`) {
		t.Error("Bundle should contain type field")
	}
	// The pattern is stored in the indicator and gets JSON encoded
	// Check for the pattern value with proper escaping for JSON
	if !strings.Contains(string(data), "10.0.0.1") {
		t.Error("Bundle should contain indicator pattern value")
	}
}

// ============================================================================
// STIX Builder Tests
// ============================================================================

func TestNewSTIXBuilder(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{
		Confidence: 80,
	})

	if builder == nil {
		t.Fatal("Builder should not be nil")
	}
	if builder.confidence != 80 {
		t.Errorf("Expected confidence 80, got %d", builder.confidence)
	}
	if builder.identity == nil {
		t.Error("Default identity should be created")
	}
}

func TestGenerateIndicator(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{
		Confidence: 90,
	})

	indicator, err := builder.GenerateIndicator(
		"[domain-name:value = 'malicious.example.com']",
		IndicatorOptions{
			Name:           "Malicious Domain",
			Description:    "Domain used for C2",
			IndicatorTypes: []IndicatorType{IndicatorTypeMaliciousActivity},
			Labels:         []string{"c2", "malware"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to generate indicator: %v", err)
	}

	if indicator.Name != "Malicious Domain" {
		t.Errorf("Expected name 'Malicious Domain', got %s", indicator.Name)
	}
	if indicator.Confidence != 90 {
		t.Errorf("Expected confidence 90, got %d", indicator.Confidence)
	}
	if len(indicator.Labels) != 2 {
		t.Errorf("Expected 2 labels, got %d", len(indicator.Labels))
	}
}

func TestGenerateIPIndicator(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	indicator, observable, err := builder.GenerateIPIndicator("192.168.1.100", IndicatorOptions{
		Name:        "Malicious IP",
		Description: "IP associated with scanning activity",
	})
	if err != nil {
		t.Fatalf("Failed to generate IP indicator: %v", err)
	}

	if indicator == nil {
		t.Fatal("Indicator should not be nil")
	}
	if observable == nil {
		t.Fatal("Observable should not be nil")
	}
	if observable.Value != "192.168.1.100" {
		t.Errorf("Expected IP '192.168.1.100', got %s", observable.Value)
	}
	if observable.Type != STIXTypeIPv4Addr {
		t.Errorf("Expected type %s, got %s", STIXTypeIPv4Addr, observable.Type)
	}
}

func TestGenerateIPv6Indicator(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	indicator, observable, err := builder.GenerateIPIndicator("2001:db8::1", IndicatorOptions{})
	if err != nil {
		t.Fatalf("Failed to generate IPv6 indicator: %v", err)
	}

	if observable.Type != STIXTypeIPv6Addr {
		t.Errorf("Expected type %s, got %s", STIXTypeIPv6Addr, observable.Type)
	}
	if !strings.Contains(indicator.Pattern, "ipv6-addr") {
		t.Error("Pattern should contain ipv6-addr")
	}
}

func TestGenerateDomainIndicator(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	indicator, observable, err := builder.GenerateDomainIndicator("evil.example.com", IndicatorOptions{
		Name: "Malicious Domain",
	})
	if err != nil {
		t.Fatalf("Failed to generate domain indicator: %v", err)
	}

	if observable.Value != "evil.example.com" {
		t.Errorf("Expected domain 'evil.example.com', got %s", observable.Value)
	}
	if !strings.Contains(indicator.Pattern, "domain-name") {
		t.Error("Pattern should contain domain-name")
	}
}

func TestGenerateURLIndicator(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	indicator, observable, err := builder.GenerateURLIndicator("https://evil.example.com/payload", IndicatorOptions{
		Name: "Malicious URL",
	})
	if err != nil {
		t.Fatalf("Failed to generate URL indicator: %v", err)
	}

	if observable.Value != "https://evil.example.com/payload" {
		t.Errorf("Unexpected URL: %s", observable.Value)
	}
	if !strings.Contains(indicator.Pattern, "url:value") {
		t.Error("Pattern should contain url:value")
	}
}

func TestGenerateFileHashIndicator(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	hashes := FileHash{
		MD5:    "d41d8cd98f00b204e9800998ecf8427e",
		SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	indicator, observable, err := builder.GenerateFileHashIndicator(hashes, IndicatorOptions{
		Name: "Malware Hash",
	})
	if err != nil {
		t.Fatalf("Failed to generate file hash indicator: %v", err)
	}

	if observable.Hashes.MD5 != hashes.MD5 {
		t.Errorf("Expected MD5 %s, got %s", hashes.MD5, observable.Hashes.MD5)
	}
	if !strings.Contains(indicator.Pattern, "MD5") {
		t.Error("Pattern should contain MD5")
	}
	if !strings.Contains(indicator.Pattern, "SHA-256") {
		t.Error("Pattern should contain SHA-256")
	}
}

func TestGenerateAttackPattern(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	mitre := &MITREMapping{
		Tactic:      "Initial Access",
		TacticID:    "TA0001",
		Technique:   "Spear Phishing",
		TechniqueID: "T1566",
	}

	ap, err := builder.GenerateAttackPattern(AttackPatternOptions{
		Name:  "Spear Phishing",
		MITRE: mitre,
	})
	if err != nil {
		t.Fatalf("Failed to generate attack pattern: %v", err)
	}

	if ap.Name != "Spear Phishing" {
		t.Errorf("Expected name 'Spear Phishing', got %s", ap.Name)
	}
	if len(ap.KillChainPhases) == 0 {
		t.Error("Expected kill chain phases from MITRE mapping")
	}
	if len(ap.ExternalReferences) == 0 {
		t.Error("Expected external references from MITRE mapping")
	}
}

func TestGenerateThreatActor(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{Confidence: 75})

	ta, err := builder.GenerateThreatActor(ThreatActorOptions{
		Name:              "APT29",
		Types:             []ThreatActorType{ThreatActorTypeNationState},
		Aliases:           []string{"Cozy Bear"},
		ResourceLevel:     "state-sponsored",
		PrimaryMotivation: "espionage",
	})
	if err != nil {
		t.Fatalf("Failed to generate threat actor: %v", err)
	}

	if ta.Name != "APT29" {
		t.Errorf("Expected name 'APT29', got %s", ta.Name)
	}
	if ta.Confidence != 75 {
		t.Errorf("Expected confidence 75, got %d", ta.Confidence)
	}
}

func TestGenerateMalware(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	malware, err := builder.GenerateMalware(MalwareOptions{
		Name:         "Ryuk",
		IsFamily:     false,
		Types:        []MalwareType{MalwareTypeRansomware},
		Aliases:      []string{"REvil"},
		Capabilities: []string{"encryption", "lateral-movement"},
	})
	if err != nil {
		t.Fatalf("Failed to generate malware: %v", err)
	}

	if malware.Name != "Ryuk" {
		t.Errorf("Expected name 'Ryuk', got %s", malware.Name)
	}
	if malware.IsFamily {
		t.Error("Malware should not be marked as family")
	}
}

func TestGenerateRelationship(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{Confidence: 85})

	indID, _ := GenerateSTIXID(STIXTypeIndicator)
	taID, _ := GenerateSTIXID(STIXTypeThreatActor)

	rel, err := builder.GenerateRelationship(RelationshipOptions{
		Type:        RelationshipTypeIndicates,
		SourceRef:   indID,
		TargetRef:   taID,
		Description: "Indicator associated with threat actor",
	})
	if err != nil {
		t.Fatalf("Failed to generate relationship: %v", err)
	}

	if rel.RelationshipType != RelationshipTypeIndicates {
		t.Errorf("Expected relationship type %s, got %s", RelationshipTypeIndicates, rel.RelationshipType)
	}
	if rel.SourceRef != indID {
		t.Error("Source ref mismatch")
	}
	if rel.TargetRef != taID {
		t.Error("Target ref mismatch")
	}
	if rel.Confidence != 85 {
		t.Errorf("Expected confidence 85, got %d", rel.Confidence)
	}
}

func TestGenerateSTIXBundle(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{
		Confidence: 80,
	})

	// Generate some objects
	builder.GenerateIPIndicator("10.0.0.1", IndicatorOptions{Name: "IP 1"})
	builder.GenerateIPIndicator("10.0.0.2", IndicatorOptions{Name: "IP 2"})
	builder.GenerateDomainIndicator("evil.example.com", IndicatorOptions{Name: "Domain"})

	bundle, err := builder.GenerateSTIXBundle(STIXBundleOptions{IncludeIdentity: true})
	if err != nil {
		t.Fatalf("Failed to generate bundle: %v", err)
	}

	if bundle.Type != STIXTypeBundle {
		t.Errorf("Expected type %s, got %s", STIXTypeBundle, bundle.Type)
	}
	if len(bundle.Objects) == 0 {
		t.Error("Bundle should contain objects")
	}
}

// ============================================================================
// Pattern Builder Tests
// ============================================================================

func TestPatternBuilder(t *testing.T) {
	pattern := NewPatternBuilder().
		IPv4Match("192.168.1.1").
		And().
		DomainMatch("malicious.example.com").
		Build()

	if pattern == "" {
		t.Error("Pattern should not be empty")
	}
	if !strings.Contains(pattern, "ipv4-addr:value = '192.168.1.1'") {
		t.Error("Pattern should contain IPv4 match")
	}
	if !strings.Contains(pattern, "domain-name:value = 'malicious.example.com'") {
		t.Error("Pattern should contain domain match")
	}
}

func TestPatternBuilderOr(t *testing.T) {
	// Build pattern: [ipv4-addr:value = '192.168.1.1'] OR [ipv4-addr:value = '192.168.1.2']
	pattern := NewPatternBuilder().
		IPv4Match("192.168.1.1").
		Or().
		IPv4Match("192.168.1.2").
		Build()

	// With the new implementation, OR should create a pattern like:
	// ([ipv4-addr:value = '192.168.1.1'] OR [ipv4-addr:value = '192.168.1.2'])
	if !strings.Contains(pattern, "([") || !strings.Contains(pattern, "OR") {
		t.Errorf("Pattern should contain OR operator, got: %s", pattern)
	}
}

func TestPatternBuilderFileHash(t *testing.T) {
	pattern := NewPatternBuilder().
		FileHashMD5("d41d8cd98f00b204e9800998ecf8427e").
		Build()

	if !strings.Contains(pattern, "MD5 = 'd41d8cd98f00b204e9800998ecf8427e'") {
		t.Error("Pattern should contain MD5 hash")
	}
}

// ============================================================================
// SIEM Event Conversion Tests
// ============================================================================

func TestConvertSIEMEvent(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	event := &SIEMEvent{
		ID:        "event-001",
		Timestamp: time.Now(),
		Source:    "aegisgate",
		Category:  "threat",
		Type:      "blocked_request",
		Severity:  "high",
		Message:   "Malicious IP detected",
		Entities: []SIEMEntity{
			{Type: "source_ip", Value: "192.168.1.100"},
			{Type: "destination_ip", Value: "10.0.0.1"},
		},
		MITRE: &MITREMapping{
			Tactic:      "Initial Access",
			Technique:   "Spear Phishing",
			TechniqueID: "T1566",
		},
	}

	objects, err := builder.ConvertSIEMEvent(event)
	if err != nil {
		t.Fatalf("Failed to convert SIEM event: %v", err)
	}

	if len(objects) < 2 {
		t.Errorf("Expected at least 2 objects, got %d", len(objects))
	}
}

func TestConvertSIEMEventWithMalware(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	event := &SIEMEvent{
		ID:        "event-002",
		Timestamp: time.Now(),
		Source:    "aegisgate",
		Category:  "malware",
		Type:      "malware_detected",
		Severity:  "critical",
		Message:   "Ryuk ransomware detected",
		Entities: []SIEMEntity{
			{Type: "malware_name", Value: "Ryuk"},
			{Type: "source_ip", Value: "192.168.1.50"},
		},
	}

	objects, err := builder.ConvertSIEMEvent(event)
	if err != nil {
		t.Fatalf("Failed to convert SIEM event: %v", err)
	}

	// Should have IP indicator and malware object
	var hasIP, hasMalware bool
	for _, obj := range objects {
		switch obj.GetType() {
		case STIXTypeIPv4Addr, STIXTypeIndicator:
			hasIP = true
		case STIXTypeMalware:
			hasMalware = true
		}
	}

	if !hasIP {
		t.Error("Expected IP indicator in objects")
	}
	if !hasMalware {
		t.Error("Expected malware object in objects")
	}
}

// ============================================================================
// Validation Tests
// ============================================================================

func TestValidateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"255.255.255.255", true},
		{"256.1.1.1", false},
		{"abc", false},
		{"", false},
	}

	for _, tt := range tests {
		result := ValidateIP(tt.ip)
		if result != tt.expected {
			t.Errorf("ValidateIP(%s): expected %v, got %v", tt.ip, tt.expected, result)
		}
	}
}

func TestValidateIPv4(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"2001:db8::1", false},
		{"10.0.0.1", true},
		{"abc", false},
	}

	for _, tt := range tests {
		result := ValidateIPv4(tt.ip)
		if result != tt.expected {
			t.Errorf("ValidateIPv4(%s): expected %v, got %v", tt.ip, tt.expected, result)
		}
	}
}

func TestValidateIPv6(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"2001:db8::1", true},
		{"::1", true},
		{"192.168.1.1", false},
		{"abc", false},
	}

	for _, tt := range tests {
		result := ValidateIPv6(tt.ip)
		if result != tt.expected {
			t.Errorf("ValidateIPv6(%s): expected %v, got %v", tt.ip, tt.expected, result)
		}
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"a-b-c.com", true},
		{"", false},
		{"-invalid.com", false},
		{"invalid-.com", false},
	}

	for _, tt := range tests {
		result := ValidateDomain(tt.domain)
		if result != tt.expected {
			t.Errorf("ValidateDomain(%s): expected %v, got %v", tt.domain, tt.expected, result)
		}
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com", true},
		{"http://example.com/path", true},
		{"ftp://files.example.com", true},
		{"example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		result := ValidateURL(tt.url)
		if result != tt.expected {
			t.Errorf("ValidateURL(%s): expected %v, got %v", tt.url, tt.expected, result)
		}
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
	}{
		{"user@example.com", true},
		{"user.name@example.com", true},
		{"user+tag@example.com", true},
		{"invalid", false},
		{"@example.com", false},
		{"user@", false},
	}

	for _, tt := range tests {
		result := ValidateEmail(tt.email)
		if result != tt.expected {
			t.Errorf("ValidateEmail(%s): expected %v, got %v", tt.email, tt.expected, result)
		}
	}
}

func TestValidateHashes(t *testing.T) {
	// MD5
	if !ValidateMD5("d41d8cd98f00b204e9800998ecf8427e") {
		t.Error("Valid MD5 hash should pass validation")
	}
	if ValidateMD5("invalid") {
		t.Error("Invalid MD5 hash should fail validation")
	}

	// SHA1
	if !ValidateSHA1("da39a3ee5e6b4b0d3255bfef95601890afd80709") {
		t.Error("Valid SHA1 hash should pass validation")
	}
	if ValidateSHA1("invalid") {
		t.Error("Invalid SHA1 hash should fail validation")
	}

	// SHA256
	if !ValidateSHA256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
		t.Error("Valid SHA256 hash should pass validation")
	}
	if ValidateSHA256("invalid") {
		t.Error("Invalid SHA256 hash should fail validation")
	}

	// SHA512
	validSHA512 := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	if !ValidateSHA512(validSHA512) {
		t.Error("Valid SHA512 hash should pass validation")
	}
	if ValidateSHA512("invalid") {
		t.Error("Invalid SHA512 hash should fail validation")
	}
}

// ============================================================================
// CEF/LEEF Conversion Tests
// ============================================================================

func TestConvertToCEF(t *testing.T) {
	event := &SIEMEvent{
		ID:        "cef-test",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Source:    "aegisgate",
		Category:  "threat",
		Type:      "blocked_request",
		Severity:  "critical",
		Message:   "SQL injection attempt blocked",
		Entities: []SIEMEntity{
			{Type: "source_ip", Value: "192.168.1.100"},
			{Type: "destination_ip", Value: "10.0.0.1"},
		},
		MITRE: &MITREMapping{
			TacticID:    "TA0001",
			TechniqueID: "T1190",
		},
	}

	cef := ConvertToCEF(event)

	if !strings.Contains(cef, "CEF:0") {
		t.Error("CEF should start with header")
	}
	if !strings.Contains(cef, "AegisGate") {
		t.Error("CEF should contain vendor")
	}
	if !strings.Contains(cef, "blocked_request") {
		t.Error("CEF should contain event type")
	}
	if !strings.Contains(cef, "src=192.168.1.100") {
		t.Error("CEF should contain source IP")
	}
}

func TestConvertToLEEF(t *testing.T) {
	event := &SIEMEvent{
		ID:        "leef-test",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Source:    "aegisgate",
		Category:  "authentication",
		Type:      "auth_failure",
		Severity:  "medium",
		Message:   "Authentication failure detected",
		Entities: []SIEMEntity{
			{Type: "source_ip", Value: "192.168.1.50"},
			{Type: "source_user", Value: "admin"},
		},
	}

	leef := ConvertToLEEF(event)

	if !strings.Contains(leef, "LEEF:2.0") {
		t.Error("LEEF should start with header")
	}
	if !strings.Contains(leef, "AegisGate") {
		t.Error("LEEF should contain vendor")
	}
	if !strings.Contains(leef, "auth_failure") {
		t.Error("LEEF should contain event type")
	}
	if !strings.Contains(leef, "src=192.168.1.50") {
		t.Error("LEEF should contain source IP")
	}
}

// ============================================================================
// MITRE Mapping Tests
// ============================================================================

func TestMITREMappingToKillChainPhases(t *testing.T) {
	mitre := &MITREMapping{
		Tactic:      "Initial Access",
		TacticID:    "TA0001",
		Technique:   "Exploit Public-Facing Application",
		TechniqueID: "T1190",
	}

	phases := mitre.ToKillChainPhases()

	if len(phases) == 0 {
		t.Error("Expected kill chain phases")
	}
	if phases[0].KillChainName != "mitre-attack" {
		t.Errorf("Expected kill chain name 'mitre-attack', got %s", phases[0].KillChainName)
	}
}

func TestMITREMappingToExternalReferences(t *testing.T) {
	mitre := &MITREMapping{
		TechniqueID: "T1190",
		Technique:   "Exploit Public-Facing Application",
	}

	refs := mitre.ToExternalReferences()

	if len(refs) == 0 {
		t.Error("Expected external references")
	}
	if refs[0].SourceName != "mitre-attack" {
		t.Errorf("Expected source name 'mitre-attack', got %s", refs[0].SourceName)
	}
	if refs[0].ExternalID != "T1190" {
		t.Errorf("Expected external ID 'T1190', got %s", refs[0].ExternalID)
	}
}

// ============================================================================
// TAXII Types Tests
// ============================================================================

func TestTAXIIDiscovery(t *testing.T) {
	discovery := TAXIIDiscovery{
		Title:       "Test TAXII Server",
		Description: "Test server for unit tests",
		Contact:     "security@aegisgatesecurity.ioexample.com",
		APIRoots:    []string{"https://taxii.example.com/api1/"},
	}

	data, err := json.Marshal(discovery)
	if err != nil {
		t.Fatalf("Failed to marshal discovery: %v", err)
	}

	var parsed TAXIIDiscovery
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal discovery: %v", err)
	}

	if parsed.Title != discovery.Title {
		t.Errorf("Title mismatch")
	}
}

func TestTAXIICollection(t *testing.T) {
	collection := TAXIICollection{
		ID:          "collection-001",
		Title:       "Threat Intelligence",
		Description: "Collection of threat indicators",
		CanRead:     true,
		CanWrite:    true,
		MediaTypes:  []string{"application/stix+json;version=2.1"},
	}

	if collection.ID != "collection-001" {
		t.Errorf("Expected ID 'collection-001', got %s", collection.ID)
	}
	if !collection.CanRead || !collection.CanWrite {
		t.Error("Collection should be readable and writable")
	}
}

func TestTAXIIConfig(t *testing.T) {
	config := DefaultTAXIIConfig()

	if config.ServerURL != "" {
		t.Error("Default server URL should be empty")
	}
	if config.AuthType != "basic" {
		t.Errorf("Expected auth type 'basic', got %s", config.AuthType)
	}
	if !config.Retry.Enabled {
		t.Error("Retry should be enabled by default")
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", config.Timeout)
	}
}

// ============================================================================
// Mock TAXII Server Tests
// ============================================================================

func TestTAXIIClientDiscovery(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/taxii2/" {
			w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
			json.NewEncoder(w).Encode(TAXIIDiscovery{
				Title:    "Test TAXII Server",
				APIRoots: []string{"http://" + r.Host + "/api1/"},
			})
		}
	}))
	defer server.Close()

	config := DefaultTAXIIConfig()
	config.ServerURL = server.URL
	config.DiscoveryURL = server.URL + "/taxii2/"
	config.TLS.Enabled = false

	client, err := NewTAXIIClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	discovery, err := client.Discovery(ctx)
	if err != nil {
		t.Fatalf("Discovery failed: %v", err)
	}

	if discovery.Title != "Test TAXII Server" {
		t.Errorf("Unexpected title: %s", discovery.Title)
	}
}

func TestTAXIIClientGetCollections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/collections") {
			w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
			json.NewEncoder(w).Encode(TAXIICollections{
				Collections: []TAXIICollection{
					{ID: "col-1", Title: "Collection 1", CanRead: true, CanWrite: true},
					{ID: "col-2", Title: "Collection 2", CanRead: true, CanWrite: false},
				},
			})
		}
	}))
	defer server.Close()

	config := DefaultTAXIIConfig()
	config.ServerURL = server.URL
	config.TLS.Enabled = false

	client, err := NewTAXIIClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	collections, err := client.GetCollections(ctx, server.URL)
	if err != nil {
		t.Fatalf("GetCollections failed: %v", err)
	}

	if len(collections.Collections) != 2 {
		t.Errorf("Expected 2 collections, got %d", len(collections.Collections))
	}
}

func TestTAXIIClientGetObjects(t *testing.T) {
	bundleID, _ := GenerateSTIXID(STIXTypeBundle)
	bundle := NewBundle(bundleID)

	indID, _ := GenerateSTIXID(STIXTypeIndicator)
	indicator := NewIndicator(indID, "[ipv4-addr:value = '10.0.0.1']", PatternTypeSTIX)
	bundle.AddObject(indicator)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/objects") {
			w.Header().Set("Content-Type", "application/stix+json;version=2.1")
			json.NewEncoder(w).Encode(bundle)
		}
	}))
	defer server.Close()

	config := DefaultTAXIIConfig()
	config.ServerURL = server.URL
	config.TLS.Enabled = false

	client, err := NewTAXIIClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	result, _, err := client.GetObjects(ctx, server.URL, "collection-1", nil)
	if err != nil {
		t.Fatalf("GetObjects failed: %v", err)
	}

	if result.Type != STIXTypeBundle {
		t.Errorf("Expected bundle type, got %s", result.Type)
	}
}

// ============================================================================
// Exporter Tests
// ============================================================================

func TestExporterConfig(t *testing.T) {
	config := DefaultExportConfig()

	if config.Format != "stix" {
		t.Errorf("Expected format 'stix', got %s", config.Format)
	}
	if !config.IncludeIdentity {
		t.Error("IncludeIdentity should be true by default")
	}
	if config.MaxObjectsPerFile != 10000 {
		t.Errorf("Expected max 10000 objects, got %d", config.MaxObjectsPerFile)
	}
}

func TestExportToSTIXWriter(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})
	_, _, err := builder.GenerateIPIndicator("192.168.1.1", IndicatorOptions{Name: "Test IP"})
	if err != nil {
		t.Fatalf("Failed to generate IP indicator: %v", err)
	}
	_, _, err = builder.GenerateDomainIndicator("evil.example.com", IndicatorOptions{Name: "Test Domain"})
	if err != nil {
		t.Fatalf("Failed to generate domain indicator: %v", err)
	}

	exporter := NewExporter(ExporterOptions{
		Config:  DefaultExportConfig(),
		Builder: builder,
	})

	objects := builder.GetObjects()

	var buf strings.Builder
	err = exporter.ExportToSTIXWriter(context.Background(), objects, &buf)
	if err != nil {
		t.Fatalf("ExportToSTIXWriter failed: %v", err)
	}

	output := buf.String()
	// Check that the output contains the expected data
	if !strings.Contains(output, "type") {
		t.Error("Output should contain type field")
	}
}

func TestExportToJSON(t *testing.T) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})
	ind, _, err := builder.GenerateIPIndicator("10.0.0.1", IndicatorOptions{Name: "Test"})
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	exporter := NewExporter(ExporterOptions{
		Config: ExportConfig{
			Format: "json",
		},
	})

	objects := []STIXObject{ind}

	var buf strings.Builder
	err = exporter.ExportToSTIXWriter(context.Background(), objects, &buf)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Output should not be empty")
	}
}

func TestFilterObjects(t *testing.T) {
	// Create some indicators with different confidence levels
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	ind1, _, err := builder.GenerateIPIndicator("10.0.0.1", IndicatorOptions{
		Name:       "High Confidence",
		Confidence: 90,
		Labels:     []string{"malware", "c2"},
	})
	if err != nil {
		t.Fatalf("Failed to generate indicator 1: %v", err)
	}

	ind2, _, err := builder.GenerateIPIndicator("10.0.0.2", IndicatorOptions{
		Name:       "Low Confidence",
		Confidence: 30,
		Labels:     []string{"suspicious"},
	})
	if err != nil {
		t.Fatalf("Failed to generate indicator 2: %v", err)
	}

	exporter := NewExporter(ExporterOptions{
		Config: ExportConfig{
			Format:        "stix",
			MinConfidence: 50,
			Labels:        []string{"malware"},
		},
	})

	objects := []STIXObject{ind1, ind2}
	filtered := exporter.filterObjects(objects)

	if len(filtered) != 1 {
		t.Errorf("Expected 1 object after filtering, got %d", len(filtered))
	}
}

// ============================================================================
// Error Tests
// ============================================================================

func TestError(t *testing.T) {
	err := NewError("test_op", "test message", true, nil)

	if err.Operation != "test_op" {
		t.Errorf("Expected operation 'test_op', got %s", err.Operation)
	}
	if !err.Retryable {
		t.Error("Error should be retryable")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "test_op") {
		t.Error("Error string should contain operation")
	}
}

func TestErrorWithCause(t *testing.T) {
	cause := context.DeadlineExceeded
	err := NewError("test_op", "timeout", true, cause)

	if err.Unwrap() != cause {
		t.Error("Unwrap should return cause")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "context deadline exceeded") {
		t.Error("Error string should contain cause")
	}
}

func TestTAXIIError(t *testing.T) {
	taxiiErr := &TAXIIError{
		Title:       "Not Found",
		Description: "Collection not found",
		ErrorCode:   404,
	}

	if taxiiErr.Error() != "Not Found: Collection not found" {
		t.Errorf("Unexpected error string: %s", taxiiErr.Error())
	}
	if taxiiErr.IsRetryable() {
		t.Error("404 error should not be retryable")
	}

	retryableErr := &TAXIIError{
		Title:       "Rate Limited",
		Description: "Too many requests",
		ErrorCode:   429,
	}

	if !retryableErr.IsRetryable() {
		t.Error("429 error should be retryable")
	}
}

// ============================================================================
// STIX ID Tests
// ============================================================================

func TestGenerateSTIXID(t *testing.T) {
	id1, err := GenerateSTIXID(STIXTypeIndicator)
	if err != nil {
		t.Fatalf("Failed to generate ID: %v", err)
	}

	if !strings.HasPrefix(id1, "indicator--") {
		t.Errorf("ID should start with 'indicator--', got %s", id1)
	}

	// Verify uniqueness
	id2, _ := GenerateSTIXID(STIXTypeIndicator)
	if id1 == id2 {
		t.Error("IDs should be unique")
	}
}

func TestParseSTIXID(t *testing.T) {
	id, _ := GenerateSTIXID(STIXTypeIndicator)
	stixType, uuid, err := ParseSTIXID(id)

	if err != nil {
		t.Fatalf("Failed to parse ID: %v", err)
	}

	if stixType != STIXTypeIndicator {
		t.Errorf("Expected type %s, got %s", STIXTypeIndicator, stixType)
	}
	if uuid == "" {
		t.Error("UUID should not be empty")
	}
}

func TestSTIXIDGenerator(t *testing.T) {
	gen := NewSTIXIDGenerator(STIXTypeMalware)

	id1, err := gen.Generate()
	if err != nil {
		t.Fatalf("Failed to generate ID: %v", err)
	}

	id2, _ := gen.Generate()

	if !strings.HasPrefix(id1, "malware--") {
		t.Errorf("ID should start with 'malware--', got %s", id1)
	}
	if id1 == id2 {
		t.Error("IDs should be unique")
	}
}

// ============================================================================
// Content Range Tests
// ============================================================================

func TestTAXIIContentRange(t *testing.T) {
	cr := &TAXIIContentRange{
		Start: 0,
		End:   99,
		Total: 1000,
	}

	str := cr.String()
	if str == "" {
		t.Error("String representation should not be empty")
	}
}

// ============================================================================
// Rate Limiter Tests
// ============================================================================

func TestTAXIIRateLimiter(t *testing.T) {
	rl := NewTAXIIRateLimiter(10)
	defer rl.Stop()

	ctx := context.Background()

	// Should be able to get a token immediately
	err := rl.Wait(ctx)
	if err != nil {
		t.Errorf("Should be able to get token: %v", err)
	}
}

func TestTAXIIRateLimiterTimeout(t *testing.T) {
	rl := NewTAXIIRateLimiter(1) // Only 1 token per second
	defer rl.Stop()

	// Use up the token
	rl.Wait(context.Background())

	// Try to get another with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := rl.Wait(ctx)
	if err == nil {
		t.Error("Should have timed out waiting for token")
	}
}

// ============================================================================
// Export Manager Tests
// ============================================================================

func TestExportManager(t *testing.T) {
	em := NewExportManager()

	if em == nil {
		t.Fatal("Export manager should not be nil")
	}

	builder := NewSTIXBuilder(STIXBuilderOptions{})
	exporter := NewExporter(ExporterOptions{Builder: builder})
	config := DefaultExportConfig()

	em.AddExporter("test", exporter, config)

	retrieved := em.GetExporter("test")
	if retrieved == nil {
		t.Error("Should be able to retrieve exporter")
	}

	em.RemoveExporter("test")
	retrieved = em.GetExporter("test")
	if retrieved != nil {
		t.Error("Exporter should be removed")
	}
}

// ============================================================================
// Hash and Utility Tests
// ============================================================================

func TestComputeHash(t *testing.T) {
	data := []byte("test data")
	hash := ComputeHash(data)

	if hash == "" {
		t.Error("Hash should not be empty")
	}
	if len(hash) != 64 { // SHA256 produces 64 hex characters
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}

	// Same data should produce same hash
	hash2 := ComputeHash(data)
	if hash != hash2 {
		t.Error("Same data should produce same hash")
	}
}

func TestGenerateExportFilename(t *testing.T) {
	filename := GenerateExportFilename("stix", "threat-intel")

	if !strings.HasPrefix(filename, "threat-intel-") {
		t.Errorf("Filename should start with prefix: %s", filename)
	}
	if !strings.HasSuffix(filename, ".json") {
		t.Errorf("Filename should end with .json: %s", filename)
	}

	csvFilename := GenerateExportFilename("csv", "")
	if !strings.HasSuffix(csvFilename, ".csv") {
		t.Errorf("CSV filename should end with .csv: %s", csvFilename)
	}
}

func TestValidateExport(t *testing.T) {
	// Valid STIX bundle
	bundleID, _ := GenerateSTIXID(STIXTypeBundle)
	bundle := NewBundle(bundleID)
	data, _ := json.Marshal(bundle)

	err := ValidateExport(data, "stix")
	if err != nil {
		t.Errorf("Valid STIX bundle should pass: %v", err)
	}

	// Invalid JSON
	err = ValidateExport([]byte("not json"), "stix")
	if err == nil {
		t.Error("Invalid JSON should fail validation")
	}

	// Valid CSV
	err = ValidateExport([]byte("header1,header2\nvalue1,value2"), "csv")
	if err != nil {
		t.Errorf("Valid CSV should pass: %v", err)
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkGenerateIndicator(b *testing.B) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = builder.GenerateIndicator(
			"[ipv4-addr:value = '192.168.1.1']",
			IndicatorOptions{Name: "Benchmark Indicator"},
		)
	}
}

func BenchmarkGenerateIPIndicator(b *testing.B) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = builder.GenerateIPIndicator("192.168.1.1", IndicatorOptions{})
	}
}

func BenchmarkBundleMarshal(b *testing.B) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	for i := 0; i < 100; i++ {
		builder.GenerateIPIndicator("10.0.0.1", IndicatorOptions{})
	}

	bundle, _ := builder.GenerateSTIXBundle(STIXBundleOptions{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = MarshalBundle(bundle)
	}
}

func BenchmarkConvertSIEMEvent(b *testing.B) {
	builder := NewSTIXBuilder(STIXBuilderOptions{})

	event := &SIEMEvent{
		ID:        "event-001",
		Timestamp: time.Now(),
		Source:    "aegisgate",
		Category:  "threat",
		Type:      "blocked_request",
		Severity:  "high",
		Message:   "Malicious IP detected",
		Entities: []SIEMEntity{
			{Type: "source_ip", Value: "192.168.1.100"},
			{Type: "destination_ip", Value: "10.0.0.1"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = builder.ConvertSIEMEvent(event)
	}
}

func BenchmarkValidateIP(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateIP("192.168.1.1")
	}
}

func BenchmarkGenerateSTIXID(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSTIXID(STIXTypeIndicator)
	}
}
