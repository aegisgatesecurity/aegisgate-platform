// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package threatintel provides STIX 2.1 object generation and serialization.
package threatintel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// STIX Builder
// ============================================================================

// STIXBuilder builds STIX bundles from security events.
// It maintains state for identity and marking definitions.
type STIXBuilder struct {
	mu sync.RWMutex

	// Identity for the STIX objects
	identity *Identity
	// Marking definitions
	markingDefinitions []string
	// Confidence level for generated objects
	confidence int
	// Created objects
	objects []STIXObject
	// ID generators for each type
	idGenerators map[STIXType]*STIXIDGenerator
	// Pattern format preference
	defaultPatternType IndicatorPatternType
	// MITRE ATT&CK mapping
	mitreMapping map[string]*MITREMapping
}

// STIXBuilderOptions contains options for creating a STIX builder.
type STIXBuilderOptions struct {
	// Identity for the STIX objects
	Identity *Identity
	// Marking definitions
	MarkingDefinitions []string
	// Confidence level (0-100)
	Confidence int
	// Default pattern type
	DefaultPatternType IndicatorPatternType
}

// NewSTIXBuilder creates a new STIX builder.
func NewSTIXBuilder(opts STIXBuilderOptions) *STIXBuilder {
	identity := opts.Identity
	if identity == nil {
		id, _ := NewSTIXIDGenerator(STIXTypeIdentity).Generate()
		identity = NewIdentity(id, "AegisGate AI Security Gateway", IdentityClassOrganization)
		identity.Description = "Automated threat intelligence generation"
	}

	if opts.DefaultPatternType == "" {
		opts.DefaultPatternType = PatternTypeSTIX
	}

	builder := &STIXBuilder{
		identity:           identity,
		markingDefinitions: opts.MarkingDefinitions,
		confidence:         opts.Confidence,
		objects:            []STIXObject{},
		idGenerators:       make(map[STIXType]*STIXIDGenerator),
		defaultPatternType: opts.DefaultPatternType,
		mitreMapping:       make(map[string]*MITREMapping),
	}

	// Initialize ID generators for all types
	for _, stixType := range []STIXType{
		STIXTypeIndicator, STIXTypeAttackPattern, STIXTypeThreatActor,
		STIXTypeMalware, STIXTypeVulnerability, STIXTypeRelationship,
		STIXTypeReport, STIXTypeObservedData, STIXTypeSighting,
		STIXTypeDomainName, STIXTypeIPv4Addr, STIXTypeIPv6Addr,
		STIXTypeURL, STIXTypeFile, STIXTypeEmailAddr, STIXTypeMACAddr,
		STIXTypeBundle,
	} {
		builder.idGenerators[stixType] = NewSTIXIDGenerator(stixType)
	}

	return builder
}

// generateID generates a new STIX ID for the given type.
func (b *STIXBuilder) generateID(stixType STIXType) (string, error) {
	gen, ok := b.idGenerators[stixType]
	if !ok {
		gen = NewSTIXIDGenerator(stixType)
		b.idGenerators[stixType] = gen
	}
	return gen.Generate()
}

// AddObject adds a STIX object to the builder.
func (b *STIXBuilder) AddObject(obj STIXObject) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects = append(b.objects, obj)
}

// GetObjects returns all added objects.
func (b *STIXBuilder) GetObjects() []STIXObject {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.objects
}

// Clear removes all objects.
func (b *STIXBuilder) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects = []STIXObject{}
}

// SetConfidence sets the confidence level.
func (b *STIXBuilder) SetConfidence(confidence int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.confidence = confidence
}

// SetIdentity sets the identity.
func (b *STIXBuilder) SetIdentity(identity *Identity) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.identity = identity
}

// ============================================================================
// Indicator Generation
// ============================================================================

// IndicatorOptions contains options for indicator generation.
type IndicatorOptions struct {
	// Name for the indicator
	Name string
	// Description of the indicator
	Description string
	// Indicator types
	IndicatorTypes []IndicatorType
	// Pattern type override
	PatternType IndicatorPatternType
	// Valid from timestamp
	ValidFrom time.Time
	// Valid until timestamp
	ValidUntil time.Time
	// Kill chain phases
	KillChainPhases []KillChainPhase
	// MITRE ATT&CK mapping
	MITRE *MITREMapping
	// Labels for the indicator
	Labels []string
	// Confidence override
	Confidence int
}

// GenerateIndicator generates a STIX indicator from a pattern.
func (b *STIXBuilder) GenerateIndicator(pattern string, opts IndicatorOptions) (*Indicator, error) {
	id, err := b.generateID(STIXTypeIndicator)
	if err != nil {
		return nil, err
	}

	patternType := opts.PatternType
	if patternType == "" {
		patternType = b.defaultPatternType
	}

	now := time.Now().UTC()
	validFrom := opts.ValidFrom
	if validFrom.IsZero() {
		validFrom = now
	}

	indicator := NewIndicator(id, pattern, patternType)
	indicator.Name = opts.Name
	indicator.Description = opts.Description
	indicator.IndicatorTypes = opts.IndicatorTypes
	indicator.ValidFrom = validFrom
	indicator.ValidUntil = opts.ValidUntil
	indicator.KillChainPhases = opts.KillChainPhases
	indicator.Labels = opts.Labels
	indicator.CreatedByRef = b.identity.ID

	if b.confidence > 0 {
		indicator.Confidence = b.confidence
	}
	if opts.Confidence > 0 {
		indicator.Confidence = opts.Confidence
	}

	if len(b.markingDefinitions) > 0 {
		indicator.ObjectMarkingRefs = b.markingDefinitions
	}

	// Add MITRE ATT&CK references
	if opts.MITRE != nil {
		indicator.ExternalReferences = opts.MITRE.ToExternalReferences()
		if len(indicator.KillChainPhases) == 0 {
			indicator.KillChainPhases = opts.MITRE.ToKillChainPhases()
		}
	}

	b.AddObject(indicator)
	return indicator, nil
}

// GenerateIPIndicator generates an indicator for an IP address.
func (b *STIXBuilder) GenerateIPIndicator(ip string, opts IndicatorOptions) (*Indicator, *IPv4Address, error) {
	// Generate the IP observable
	obsID, err := b.generateID(STIXTypeIPv4Addr)
	if err != nil {
		return nil, nil, err
	}
	observable := NewIPv4Address(obsID, ip)

	// Determine if IPv4 or IPv6
	var pattern string
	if strings.Contains(ip, ":") {
		observable.Type = STIXTypeIPv6Addr
		pattern = fmt.Sprintf("[ipv6-addr:value = '%s']", ip)
	} else {
		pattern = fmt.Sprintf("[ipv4-addr:value = '%s']", ip)
	}

	// Generate the indicator
	indicator, err := b.GenerateIndicator(pattern, opts)
	if err != nil {
		return nil, nil, err
	}

	b.AddObject(observable)
	return indicator, observable, nil
}

// GenerateDomainIndicator generates an indicator for a domain.
func (b *STIXBuilder) GenerateDomainIndicator(domain string, opts IndicatorOptions) (*Indicator, *DomainName, error) {
	// Generate the domain observable
	obsID, err := b.generateID(STIXTypeDomainName)
	if err != nil {
		return nil, nil, err
	}
	observable := NewDomainName(obsID, domain)

	// Generate the pattern
	pattern := fmt.Sprintf("[domain-name:value = '%s']", domain)

	// Generate the indicator
	indicator, err := b.GenerateIndicator(pattern, opts)
	if err != nil {
		return nil, nil, err
	}

	b.AddObject(observable)
	return indicator, observable, nil
}

// GenerateURLIndicator generates an indicator for a URL.
func (b *STIXBuilder) GenerateURLIndicator(urlStr string, opts IndicatorOptions) (*Indicator, *URL, error) {
	// Generate the URL observable
	obsID, err := b.generateID(STIXTypeURL)
	if err != nil {
		return nil, nil, err
	}
	observable := NewURL(obsID, urlStr)

	// Generate the pattern (escape special characters in URL)
	escaped := strings.ReplaceAll(urlStr, "'", "\\'")
	pattern := fmt.Sprintf("[url:value = '%s']", escaped)

	// Generate the indicator
	indicator, err := b.GenerateIndicator(pattern, opts)
	if err != nil {
		return nil, nil, err
	}

	b.AddObject(observable)
	return indicator, observable, nil
}

// GenerateFileHashIndicator generates an indicator for file hashes.
func (b *STIXBuilder) GenerateFileHashIndicator(hashes FileHash, opts IndicatorOptions) (*Indicator, *File, error) {
	// Generate the file observable
	obsID, err := b.generateID(STIXTypeFile)
	if err != nil {
		return nil, nil, err
	}
	observable := NewFile(obsID, hashes)

	// Build the pattern with available hashes
	var patterns []string
	if hashes.MD5 != "" {
		patterns = append(patterns, fmt.Sprintf("[file:hashes.MD5 = '%s']", hashes.MD5))
	}
	if hashes.SHA1 != "" {
		patterns = append(patterns, fmt.Sprintf("[file:hashes.'SHA-1' = '%s']", hashes.SHA1))
	}
	if hashes.SHA256 != "" {
		patterns = append(patterns, fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", hashes.SHA256))
	}
	if hashes.SHA512 != "" {
		patterns = append(patterns, fmt.Sprintf("[file:hashes.'SHA-512' = '%s']", hashes.SHA512))
	}

	if len(patterns) == 0 {
		return nil, nil, NewError("generate_file_hash_indicator", "at least one hash required", false, nil)
	}

	// Join patterns with OR
	pattern := strings.Join(patterns, " OR ")

	// Generate the indicator
	indicator, err := b.GenerateIndicator(pattern, opts)
	if err != nil {
		return nil, nil, err
	}

	b.AddObject(observable)
	return indicator, observable, nil
}

// GenerateEmailIndicator generates an indicator for an email address.
func (b *STIXBuilder) GenerateEmailIndicator(email string, opts IndicatorOptions) (*Indicator, *EmailAddress, error) {
	// Generate the email observable
	obsID, err := b.generateID(STIXTypeEmailAddr)
	if err != nil {
		return nil, nil, err
	}
	observable := NewEmailAddress(obsID, email)

	// Generate the pattern
	pattern := fmt.Sprintf("[email-addr:value = '%s']", email)

	// Generate the indicator
	indicator, err := b.GenerateIndicator(pattern, opts)
	if err != nil {
		return nil, nil, err
	}

	b.AddObject(observable)
	return indicator, observable, nil
}

// ============================================================================
// Attack Pattern Generation
// ============================================================================

// AttackPatternOptions contains options for attack pattern generation.
type AttackPatternOptions struct {
	// Name of the attack pattern
	Name string
	// Description
	Description string
	// MITRE ATT&CK mapping
	MITRE *MITREMapping
	// Kill chain phases
	KillChainPhases []KillChainPhase
	// Labels
	Labels []string
	// Aliases
	Aliases []string
	// Abstraction level
	AbstractionLevel string
}

// GenerateAttackPattern generates a STIX attack pattern.
func (b *STIXBuilder) GenerateAttackPattern(opts AttackPatternOptions) (*AttackPattern, error) {
	id, err := b.generateID(STIXTypeAttackPattern)
	if err != nil {
		return nil, err
	}

	attackPattern := NewAttackPattern(id, opts.Name)
	attackPattern.Description = opts.Description
	attackPattern.KillChainPhases = opts.KillChainPhases
	attackPattern.Labels = opts.Labels
	attackPattern.Aliases = opts.Aliases
	attackPattern.AbstractionLevel = opts.AbstractionLevel
	attackPattern.CreatedByRef = b.identity.ID

	if len(b.markingDefinitions) > 0 {
		attackPattern.ObjectMarkingRefs = b.markingDefinitions
	}

	// Add MITRE ATT&CK references
	if opts.MITRE != nil {
		attackPattern.ExternalReferences = opts.MITRE.ToExternalReferences()
		if len(attackPattern.KillChainPhases) == 0 {
			attackPattern.KillChainPhases = opts.MITRE.ToKillChainPhases()
		}
	}

	b.AddObject(attackPattern)
	return attackPattern, nil
}

// GenerateAttackPatternFromMITRE generates an attack pattern from MITRE ATT&CK.
func (b *STIXBuilder) GenerateAttackPatternFromMITRE(techniqueID, techniqueName string, tactics []string) (*AttackPattern, error) {
	mitre := &MITREMapping{
		Technique:   techniqueName,
		TechniqueID: techniqueID,
		Tactics:     tactics,
	}

	return b.GenerateAttackPattern(AttackPatternOptions{
		Name:  techniqueName,
		MITRE: mitre,
	})
}

// ============================================================================
// Threat Actor Generation
// ============================================================================

// ThreatActorOptions contains options for threat actor generation.
type ThreatActorOptions struct {
	// Name of the threat actor
	Name string
	// Description
	Description string
	// Threat actor types
	Types []ThreatActorType
	// Aliases
	Aliases []string
	// Goals
	Goals []string
	// Resource level
	ResourceLevel string
	// Primary motivation
	PrimaryMotivation string
	// Sophistication level
	Sophistication string
	// Labels
	Labels []string
	// Confidence
	Confidence int
}

// GenerateThreatActor generates a STIX threat actor.
func (b *STIXBuilder) GenerateThreatActor(opts ThreatActorOptions) (*ThreatActor, error) {
	id, err := b.generateID(STIXTypeThreatActor)
	if err != nil {
		return nil, err
	}

	threatActor := NewThreatActor(id, opts.Name)
	threatActor.Description = opts.Description
	threatActor.ThreatActorTypes = opts.Types
	threatActor.Aliases = opts.Aliases
	threatActor.Goals = opts.Goals
	threatActor.ResourceLevel = opts.ResourceLevel
	threatActor.PrimaryMotivation = opts.PrimaryMotivation
	threatActor.Sophistication = opts.Sophistication
	threatActor.Labels = opts.Labels
	threatActor.CreatedByRef = b.identity.ID

	if b.confidence > 0 {
		threatActor.Confidence = b.confidence
	}
	if opts.Confidence > 0 {
		threatActor.Confidence = opts.Confidence
	}

	if len(b.markingDefinitions) > 0 {
		threatActor.ObjectMarkingRefs = b.markingDefinitions
	}

	b.AddObject(threatActor)
	return threatActor, nil
}

// ============================================================================
// Malware Generation
// ============================================================================

// MalwareOptions contains options for malware generation.
type MalwareOptions struct {
	// Name of the malware family
	Name string
	// Description
	Description string
	// Malware types
	Types []MalwareType
	// Is this a family?
	IsFamily bool
	// Aliases
	Aliases []string
	// Kill chain phases
	KillChainPhases []KillChainPhase
	// Capabilities
	Capabilities []string
	// Labels
	Labels []string
}

// GenerateMalware generates a STIX malware object.
func (b *STIXBuilder) GenerateMalware(opts MalwareOptions) (*Malware, error) {
	id, err := b.generateID(STIXTypeMalware)
	if err != nil {
		return nil, err
	}

	malware := NewMalware(id, opts.Name, opts.IsFamily)
	malware.Description = opts.Description
	malware.MalwareTypes = opts.Types
	malware.Aliases = opts.Aliases
	malware.KillChainPhases = opts.KillChainPhases
	malware.Capabilities = opts.Capabilities
	malware.Labels = opts.Labels
	malware.CreatedByRef = b.identity.ID

	if len(b.markingDefinitions) > 0 {
		malware.ObjectMarkingRefs = b.markingDefinitions
	}

	b.AddObject(malware)
	return malware, nil
}

// ============================================================================
// Relationship Generation
// ============================================================================

// RelationshipOptions contains options for relationship generation.
type RelationshipOptions struct {
	// Relationship type
	Type RelationshipType
	// Description
	Description string
	// Source reference
	SourceRef string
	// Target reference
	TargetRef string
	// Start time
	StartTime time.Time
	// Stop time
	StopTime time.Time
	// Kill chain phases
	KillChainPhases []KillChainPhase
	// Confidence
	Confidence int
}

// GenerateRelationship generates a STIX relationship.
func (b *STIXBuilder) GenerateRelationship(opts RelationshipOptions) (*Relationship, error) {
	id, err := b.generateID(STIXTypeRelationship)
	if err != nil {
		return nil, err
	}

	relationship := NewRelationship(id, opts.Type, opts.SourceRef, opts.TargetRef)
	relationship.Description = opts.Description
	relationship.StartTime = opts.StartTime
	relationship.StopTime = opts.StopTime
	relationship.KillChainPhases = opts.KillChainPhases
	relationship.CreatedByRef = b.identity.ID

	if b.confidence > 0 {
		relationship.Confidence = b.confidence
	}
	if opts.Confidence > 0 {
		relationship.Confidence = opts.Confidence
	}

	if len(b.markingDefinitions) > 0 {
		relationship.ObjectMarkingRefs = b.markingDefinitions
	}

	b.AddObject(relationship)
	return relationship, nil
}

// LinkIndicatorToThreatActor creates a relationship linking an indicator to a threat actor.
func (b *STIXBuilder) LinkIndicatorToThreatActor(indicatorID, threatActorID string, description string) (*Relationship, error) {
	return b.GenerateRelationship(RelationshipOptions{
		Type:        RelationshipTypeIndicates,
		SourceRef:   indicatorID,
		TargetRef:   threatActorID,
		Description: description,
	})
}

// LinkIndicatorToMalware creates a relationship linking an indicator to malware.
func (b *STIXBuilder) LinkIndicatorToMalware(indicatorID, malwareID string, description string) (*Relationship, error) {
	return b.GenerateRelationship(RelationshipOptions{
		Type:        RelationshipTypeIndicates,
		SourceRef:   indicatorID,
		TargetRef:   malwareID,
		Description: description,
	})
}

// LinkMalwareToAttackPattern creates a relationship linking malware to an attack pattern.
func (b *STIXBuilder) LinkMalwareToAttackPattern(malwareID, attackPatternID string, description string) (*Relationship, error) {
	return b.GenerateRelationship(RelationshipOptions{
		Type:        RelationshipTypeUses,
		SourceRef:   malwareID,
		TargetRef:   attackPatternID,
		Description: description,
	})
}

// LinkThreatActorToMalware creates a relationship linking a threat actor to malware.
func (b *STIXBuilder) LinkThreatActorToMalware(threatActorID, malwareID string, description string) (*Relationship, error) {
	return b.GenerateRelationship(RelationshipOptions{
		Type:        RelationshipTypeUses,
		SourceRef:   threatActorID,
		TargetRef:   malwareID,
		Description: description,
	})
}

// ============================================================================
// Report Generation
// ============================================================================

// ReportOptions contains options for report generation.
type ReportOptions struct {
	// Name of the report
	Name string
	// Description
	Description string
	// Report types
	Types []string
	// Published date
	Published time.Time
	// Object references
	ObjectRefs []string
	// Labels
	Labels []string
	// Confidence
	Confidence int
}

// GenerateReport generates a STIX report.
func (b *STIXBuilder) GenerateReport(opts ReportOptions) (*Report, error) {
	id, err := b.generateID(STIXTypeReport)
	if err != nil {
		return nil, err
	}

	published := opts.Published
	if published.IsZero() {
		published = time.Now().UTC()
	}

	report := NewReport(id, opts.Name, published)
	report.Description = opts.Description
	report.ReportTypes = opts.Types
	report.ObjectRefs = opts.ObjectRefs
	report.Labels = opts.Labels
	report.CreatedByRef = b.identity.ID

	if b.confidence > 0 {
		report.Confidence = b.confidence
	}
	if opts.Confidence > 0 {
		report.Confidence = opts.Confidence
	}

	if len(b.markingDefinitions) > 0 {
		report.ObjectMarkingRefs = b.markingDefinitions
	}

	b.AddObject(report)
	return report, nil
}

// ============================================================================
// Bundle Generation
// ============================================================================

// STIXBundleOptions contains options for bundle generation.
type STIXBundleOptions struct {
	// Include identity in bundle
	IncludeIdentity bool
	// Custom bundle ID
	ID string
}

// GenerateSTIXBundle generates a STIX bundle from all added objects.
func (b *STIXBuilder) GenerateSTIXBundle(opts STIXBundleOptions) (*Bundle, error) {
	bundleID := opts.ID
	if bundleID == "" {
		var err error
		bundleID, err = b.generateID(STIXTypeBundle)
		if err != nil {
			return nil, err
		}
	}

	bundle := NewBundle(bundleID)

	// Add identity if requested
	if opts.IncludeIdentity && b.identity != nil {
		if err := bundle.AddObject(b.identity); err != nil {
			return nil, err
		}
	}

	// Add all objects
	for _, obj := range b.objects {
		if err := bundle.AddObject(obj); err != nil {
			return nil, err
		}
	}

	return bundle, nil
}

// ============================================================================
// SIEM Event Conversion
// ============================================================================

// SIEMEvent represents a security event from a SIEM system.
// This mirrors the siem.Event type for compatibility.
type SIEMEvent struct {
	// Unique identifier
	ID string
	// Timestamp
	Timestamp time.Time
	// Source platform
	Source string
	// Event category
	Category string
	// Event type
	Type string
	// Severity
	Severity string
	// Human-readable message
	Message string
	// Raw event data
	Raw map[string]interface{}
	// Additional attributes
	Attributes map[string]string
	// Related entities
	Entities []SIEMEntity
	// MITRE ATT&CK mapping
	MITRE *MITREMapping
	// Compliance mappings
	Compliance []ComplianceMapping
}

// SIEMEntity represents a related entity in a SIEM event.
type SIEMEntity struct {
	Type  string
	ID    string
	Name  string
	Value string
}

// ComplianceMapping maps events to compliance frameworks.
type ComplianceMapping struct {
	Framework string
	Control   string
	Section   string
}

// ConvertSIEMEvent converts a SIEM event to STIX objects.
func (b *STIXBuilder) ConvertSIEMEvent(event *SIEMEvent) ([]STIXObject, error) {
	var objects []STIXObject

	// Extract indicator types from event attributes
	indicatorType := inferIndicatorType(event.Category, event.Type)

	// Process entities and generate observables/indicators
	for _, entity := range event.Entities {
		switch entity.Type {
		case "ip", "source_ip", "destination_ip", "src_ip", "dst_ip":
			indicator, obs, err := b.GenerateIPIndicator(entity.Value, IndicatorOptions{
				Name:           fmt.Sprintf("Indicators for %s: %s", entity.Type, entity.Value),
				Description:    event.Message,
				IndicatorTypes: []IndicatorType{indicatorType},
				MITRE:          event.MITRE,
				Labels:         []string{event.Source, event.Category, event.Type},
			})
			if err != nil {
				return nil, err
			}
			objects = append(objects, indicator, obs)

		case "domain", "hostname", "source_domain", "destination_domain":
			indicator, obs, err := b.GenerateDomainIndicator(entity.Value, IndicatorOptions{
				Name:           fmt.Sprintf("Domain indicator: %s", entity.Value),
				Description:    event.Message,
				IndicatorTypes: []IndicatorType{indicatorType},
				MITRE:          event.MITRE,
				Labels:         []string{event.Source, event.Category, event.Type},
			})
			if err != nil {
				return nil, err
			}
			objects = append(objects, indicator, obs)

		case "url", "uri":
			indicator, obs, err := b.GenerateURLIndicator(entity.Value, IndicatorOptions{
				Name:           fmt.Sprintf("URL indicator: %s", entity.Value),
				Description:    event.Message,
				IndicatorTypes: []IndicatorType{indicatorType},
				MITRE:          event.MITRE,
				Labels:         []string{event.Source, event.Category, event.Type},
			})
			if err != nil {
				return nil, err
			}
			objects = append(objects, indicator, obs)

		case "email", "email_address", "sender_email", "recipient_email":
			indicator, obs, err := b.GenerateEmailIndicator(entity.Value, IndicatorOptions{
				Name:           fmt.Sprintf("Email indicator: %s", entity.Value),
				Description:    event.Message,
				IndicatorTypes: []IndicatorType{indicatorType},
				MITRE:          event.MITRE,
				Labels:         []string{event.Source, event.Category, event.Type},
			})
			if err != nil {
				return nil, err
			}
			objects = append(objects, indicator, obs)

		case "file_hash", "hash", "md5", "sha1", "sha256":
			hashes := parseFileHashes(entity.Type, entity.Value)
			if hashes.HasAny() {
				indicator, obs, err := b.GenerateFileHashIndicator(hashes, IndicatorOptions{
					Name:           "File hash indicator",
					Description:    event.Message,
					IndicatorTypes: []IndicatorType{indicatorType},
					MITRE:          event.MITRE,
					Labels:         []string{event.Source, event.Category, event.Type},
				})
				if err != nil {
					return nil, err
				}
				objects = append(objects, indicator, obs)
			}

		case "malware_name", "malware_family":
			malware, err := b.GenerateMalware(MalwareOptions{
				Name:     entity.Value,
				IsFamily: true,
				Labels:   []string{event.Source, event.Category},
			})
			if err != nil {
				return nil, err
			}
			objects = append(objects, malware)
		}
	}

	// Generate attack pattern if MITRE ATT&CK mapping exists
	if event.MITRE != nil && event.MITRE.TechniqueID != "" {
		attackPattern, err := b.GenerateAttackPattern(AttackPatternOptions{
			Name:  event.MITRE.Technique,
			MITRE: event.MITRE,
		})
		if err != nil {
			return nil, err
		}
		objects = append(objects, attackPattern)
	}

	return objects, nil
}

// inferIndicatorType determines indicator type from event category and type.
func inferIndicatorType(category, eventType string) IndicatorType {
	switch category {
	case "threat", "malware", "intrusion":
		return IndicatorTypeMaliciousActivity
	case "anomaly", "anomalous_activity":
		return IndicatorTypeAnomalousActivity
	case "attribution", "threat_actor":
		return IndicatorTypeAttribution
	case "benign", "whitelist":
		return IndicatorTypeBenign
	case "compromised", "incident":
		return IndicatorTypeCompromised
	default:
		return IndicatorTypeUnknown
	}
}

// parseFileHashes parses file hashes from entity data.
func parseFileHashes(hashType, value string) FileHash {
	var hashes FileHash

	switch strings.ToLower(hashType) {
	case "md5":
		if len(value) == 32 {
			hashes.MD5 = value
		}
	case "sha1":
		if len(value) == 40 {
			hashes.SHA1 = value
		}
	case "sha256":
		if len(value) == 64 {
			hashes.SHA256 = value
		}
	case "sha512":
		if len(value) == 128 {
			hashes.SHA512 = value
		}
	}

	// Try to detect hash type by length
	if hashes == (FileHash{}) && value != "" {
		switch len(value) {
		case 32:
			hashes.MD5 = value
		case 40:
			hashes.SHA1 = value
		case 64:
			hashes.SHA256 = value
		case 128:
			hashes.SHA512 = value
		}
	}

	return hashes
}

// ============================================================================
// Observable Generation
// ============================================================================

// GenerateObservable generates a STIX observable from an entity.
func (b *STIXBuilder) GenerateObservable(entityType, value string) (interface{}, error) {
	switch entityType {
	case "ip", "ipv4":
		id, err := b.generateID(STIXTypeIPv4Addr)
		if err != nil {
			return nil, err
		}
		return NewIPv4Address(id, value), nil

	case "ipv6":
		id, err := b.generateID(STIXTypeIPv6Addr)
		if err != nil {
			return nil, err
		}
		return NewIPv6Address(id, value), nil

	case "domain", "hostname":
		id, err := b.generateID(STIXTypeDomainName)
		if err != nil {
			return nil, err
		}
		return NewDomainName(id, value), nil

	case "url", "uri":
		id, err := b.generateID(STIXTypeURL)
		if err != nil {
			return nil, err
		}
		return NewURL(id, value), nil

	case "email", "email_address":
		id, err := b.generateID(STIXTypeEmailAddr)
		if err != nil {
			return nil, err
		}
		return NewEmailAddress(id, value), nil

	case "mac":
		id, err := b.generateID(STIXTypeMACAddr)
		if err != nil {
			return nil, err
		}
		return NewMACAddress(id, value), nil

	default:
		return nil, NewError("generate_observable", "unknown entity type: "+entityType, false, nil)
	}
}

// ============================================================================
// Pattern Generation
// ============================================================================

// PatternBuilder helps build STIX indicator patterns.
type PatternBuilder struct {
	comparisons []string
	qualifiers  []string
	operators   []string
}

// NewPatternBuilder creates a new pattern builder.
func NewPatternBuilder() *PatternBuilder {
	return &PatternBuilder{
		comparisons: []string{},
		qualifiers:  []string{},
		operators:   []string{},
	}
}

// IPv4Match adds an IPv4 address match to the pattern.
func (p *PatternBuilder) IPv4Match(value string) *PatternBuilder {
	p.comparisons = append(p.comparisons, fmt.Sprintf("[ipv4-addr:value = '%s']", escapePatternValue(value)))
	return p
}

// IPv6Match adds an IPv6 address match to the pattern.
func (p *PatternBuilder) IPv6Match(value string) *PatternBuilder {
	p.comparisons = append(p.comparisons, fmt.Sprintf("[ipv6-addr:value = '%s']", escapePatternValue(value)))
	return p
}

// DomainMatch adds a domain name match to the pattern.
func (p *PatternBuilder) DomainMatch(value string) *PatternBuilder {
	p.comparisons = append(p.comparisons, fmt.Sprintf("[domain-name:value = '%s']", escapePatternValue(value)))
	return p
}

// URLMatch adds a URL match to the pattern.
func (p *PatternBuilder) URLMatch(value string) *PatternBuilder {
	p.comparisons = append(p.comparisons, fmt.Sprintf("[url:value = '%s']", escapePatternValue(value)))
	return p
}

// EmailMatch adds an email address match to the pattern.
func (p *PatternBuilder) EmailMatch(value string) *PatternBuilder {
	p.comparisons = append(p.comparisons, fmt.Sprintf("[email-addr:value = '%s']", escapePatternValue(value)))
	return p
}

// FileHashMD5 adds an MD5 file hash match to the pattern.
func (p *PatternBuilder) FileHashMD5(value string) *PatternBuilder {
	p.comparisons = append(p.comparisons, fmt.Sprintf("[file:hashes.MD5 = '%s']", value))
	return p
}

// FileHashSHA1 adds an SHA-1 file hash match to the pattern.
func (p *PatternBuilder) FileHashSHA1(value string) *PatternBuilder {
	p.comparisons = append(p.comparisons, fmt.Sprintf("[file:hashes.'SHA-1' = '%s']", value))
	return p
}

// FileHashSHA256 adds an SHA-256 file hash match to the pattern.
func (p *PatternBuilder) FileHashSHA256(value string) *PatternBuilder {
	p.comparisons = append(p.comparisons, fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", value))
	return p
}

// FileHashSHA512 adds an SHA-512 file hash match to the pattern.
func (p *PatternBuilder) FileHashSHA512(value string) *PatternBuilder {
	p.comparisons = append(p.comparisons, fmt.Sprintf("[file:hashes.'SHA-512' = '%s']", value))
	return p
}

// FileNameMatch adds a file name match to the pattern.
func (p *PatternBuilder) FileNameMatch(value string) *PatternBuilder {
	p.comparisons = append(p.comparisons, fmt.Sprintf("[file:name = '%s']", escapePatternValue(value)))
	return p
}

// And marks the next comparison to be ANDed with the previous one.
func (p *PatternBuilder) And() *PatternBuilder {
	p.operators = append(p.operators, "AND")
	return p
}

// Or marks the next comparison to be ORed with the previous one.
func (p *PatternBuilder) Or() *PatternBuilder {
	p.operators = append(p.operators, "OR")
	return p
}

// FollowedBy adds a FOLLOWED BY qualifier.
func (p *PatternBuilder) FollowedBy(comparison string) *PatternBuilder {
	p.qualifiers = append(p.qualifiers, fmt.Sprintf(" FOLLOWEDBY %s", comparison))
	return p
}

// Repeat adds a repeat qualifier.
func (p *PatternBuilder) Repeat(count int) *PatternBuilder {
	p.qualifiers = append(p.qualifiers, fmt.Sprintf(" REPEATS %d TIMES", count))
	return p
}

// Within adds a time window qualifier.
func (p *PatternBuilder) Within(duration time.Duration) *PatternBuilder {
	p.qualifiers = append(p.qualifiers, fmt.Sprintf(" WITHIN %s", duration.String()))
	return p
}

// Build returns the final pattern string.
func (p *PatternBuilder) Build() string {
	if len(p.comparisons) == 0 {
		return ""
	}

	if len(p.comparisons) == 1 {
		pattern := p.comparisons[0]
		for _, q := range p.qualifiers {
			pattern += q
		}
		return pattern
	}

	// Build pattern using operators
	pattern := p.comparisons[0]
	for i, op := range p.operators {
		if i+1 < len(p.comparisons) {
			if op == "OR" {
				pattern = "(" + pattern + " OR " + p.comparisons[i+1] + ")"
			} else {
				pattern = pattern + " AND " + p.comparisons[i+1]
			}
		}
	}
	// Handle case where we have more comparisons than operators (default AND join remaining)
	for i := len(p.operators) + 1; i < len(p.comparisons); i++ {
		pattern = pattern + " AND " + p.comparisons[i]
	}

	for _, q := range p.qualifiers {
		pattern += q
	}
	return pattern
}

// escapePatternValue escapes special characters in pattern values.
func escapePatternValue(value string) string {
	// Escape single quotes and backslashes
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "'", "\\'")
	return value
}

// ============================================================================
// CEF Pattern Format
// ============================================================================

// ConvertToCEF converts a SIEM event to CEF format pattern.
func ConvertToCEF(event *SIEMEvent) string {
	var builder strings.Builder

	// CEF Header
	builder.WriteString("CEF:0|AegisGate|AI Security Gateway|1.0|")
	builder.WriteString(cefEscape(event.Type))
	builder.WriteString("|")
	builder.WriteString(cefEscape(event.Message))
	builder.WriteString("|")
	builder.WriteString(cefSeverity(event.Severity))
	builder.WriteString("|")

	// Extensions
	ext := make([]string, 0, 10)
	ext = append(ext, fmt.Sprintf("rt=%d", event.Timestamp.Unix()))
	ext = append(ext, fmt.Sprintf("category=%s", event.Category))
	ext = append(ext, fmt.Sprintf("source=%s", event.Source))

	for _, entity := range event.Entities {
		switch entity.Type {
		case "source_ip", "src_ip":
			ext = append(ext, fmt.Sprintf("src=%s", entity.Value))
		case "destination_ip", "dst_ip":
			ext = append(ext, fmt.Sprintf("dst=%s", entity.Value))
		case "source_domain", "src_domain":
			ext = append(ext, fmt.Sprintf("sdomain=%s", entity.Value))
		case "destination_domain", "dst_domain":
			ext = append(ext, fmt.Sprintf("ddomain=%s", entity.Value))
		case "source_user", "src_user", "user":
			ext = append(ext, fmt.Sprintf("suser=%s", entity.Value))
		case "destination_user", "dst_user":
			ext = append(ext, fmt.Sprintf("duser=%s", entity.Value))
		}
	}

	if event.MITRE != nil {
		if event.MITRE.TechniqueID != "" {
			ext = append(ext, fmt.Sprintf("cs1=%s", event.MITRE.TechniqueID))
			ext = append(ext, "cs1Label=MitreTechnique")
		}
		if event.MITRE.TacticID != "" {
			ext = append(ext, fmt.Sprintf("cs2=%s", event.MITRE.TacticID))
			ext = append(ext, "cs2Label=MitreTactic")
		}
	}

	builder.WriteString(strings.Join(ext, " "))

	return builder.String()
}

// cefEscape escapes characters for CEF format.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "=", "\\=")
	return s
}

// cefSeverity converts severity to CEF severity (0-10).
func cefSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "10"
	case "high":
		return "8"
	case "medium":
		return "6"
	case "low":
		return "4"
	default:
		return "2"
	}
}

// ============================================================================
// LEEF Pattern Format
// ============================================================================

// ConvertToLEEF converts a SIEM event to LEEF format.
func ConvertToLEEF(event *SIEMEvent) string {
	var builder strings.Builder

	// LEEF Header
	builder.WriteString("LEEF:2.0|AegisGate|AI Security Gateway|1.0|")
	builder.WriteString(leefEscape(event.Type))
	builder.WriteString("|")

	// Extensions
	ext := make([]string, 0, 10)
	ext = append(ext, fmt.Sprintf("devTime=%s", event.Timestamp.Format(time.RFC3339)))
	ext = append(ext, fmt.Sprintf("sev=%s", event.Severity))
	ext = append(ext, fmt.Sprintf("cat=%s", event.Category))
	ext = append(ext, fmt.Sprintf("eventName=%s", event.Message))

	for _, entity := range event.Entities {
		switch entity.Type {
		case "source_ip", "src_ip":
			ext = append(ext, fmt.Sprintf("src=%s", entity.Value))
		case "destination_ip", "dst_ip":
			ext = append(ext, fmt.Sprintf("dst=%s", entity.Value))
		case "source_user", "src_user", "user":
			ext = append(ext, fmt.Sprintf("usrName=%s", entity.Value))
		}
	}

	builder.WriteString(strings.Join(ext, "\t"))

	return builder.String()
}

// leefEscape escapes characters for LEEF format.
func leefEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "=", "\\=")
	return s
}

// ============================================================================
// Utilities
// ============================================================================

// ValidateIP validates an IP address.
func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ValidateIPv4 validates an IPv4 address.
func ValidateIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

// ValidateIPv6 validates an IPv6 address.
func ValidateIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

// ValidateDomain validates a domain name.
func ValidateDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	domainRegex := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	return domainRegex.MatchString(domain)
}

// ValidateURL validates a URL.
func ValidateURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

// ValidateEmail validates an email address.
func ValidateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ValidateMD5 validates an MD5 hash.
func ValidateMD5(hash string) bool {
	if len(hash) != 32 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ValidateSHA1 validates a SHA-1 hash.
func ValidateSHA1(hash string) bool {
	if len(hash) != 40 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ValidateSHA256 validates a SHA-256 hash.
func ValidateSHA256(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ValidateSHA512 validates a SHA-512 hash.
func ValidateSHA512(hash string) bool {
	if len(hash) != 128 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// generateRandomUUID generates a random UUID v4.
func generateRandomUUID() (string, error) {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		return "", err
	}

	// Set version (4) and variant bits
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant 1

	return hex.EncodeToString(uuid), nil
}

// GenerateSTIXID generates a STIX-compliant ID.
func GenerateSTIXID(stixType STIXType) (string, error) {
	uuid, err := generateRandomUUID()
	if err != nil {
		return "", err
	}
	return string(stixType) + "--" + uuid, nil
}

// ParseSTIXID parses a STIX ID into its type and UUID components.
func ParseSTIXID(id string) (stixType STIXType, uuid string, err error) {
	parts := strings.SplitN(id, "--", 2)
	if len(parts) != 2 {
		return "", "", NewError("parse_stix_id", "invalid STIX ID format", false, nil)
	}
	return STIXType(parts[0]), parts[1], nil
}

// ContextKey represents a key for context values.
type contextKey string

const (
	// ContextKeyBuilder is the context key for the STIX builder.
	ContextKeyBuilder contextKey = "stix_builder"
)

// WithBuilder returns a context with a STIX builder.
func WithBuilder(ctx context.Context, builder *STIXBuilder) context.Context {
	return context.WithValue(ctx, ContextKeyBuilder, builder)
}

// BuilderFromContext returns the STIX builder from context.
func BuilderFromContext(ctx context.Context) *STIXBuilder {
	if builder, ok := ctx.Value(ContextKeyBuilder).(*STIXBuilder); ok {
		return builder
	}
	return nil
}

// MarshalSTIX marshals a STIX object to JSON.
func MarshalSTIX(obj STIXObject) ([]byte, error) {
	return json.Marshal(obj)
}

// MarshalSTIXIndent marshals a STIX object to indented JSON.
func MarshalSTIXIndent(obj STIXObject) ([]byte, error) {
	return json.MarshalIndent(obj, "", "  ")
}

// MarshalBundle marshals a STIX bundle to JSON.
func MarshalBundle(bundle *Bundle) ([]byte, error) {
	return json.Marshal(bundle)
}

// MarshalBundleIndent marshals a STIX bundle to indented JSON.
func MarshalBundleIndent(bundle *Bundle) ([]byte, error) {
	return json.MarshalIndent(bundle, "", "  ")
}
