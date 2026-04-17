// Package threatintel provides STIX 2.1 and TAXII 2.1 threat intelligence
// integration for the AegisGate AI Security Gateway. It supports generating,
// exporting, and sharing threat intelligence in standardized formats.
//
// Features:
//   - STIX 2.1 object generation from SIEM events
//   - TAXII 2.1 protocol client for threat intel exchange
//   - Multiple export formats (STIX, JSON, CSV, MISP)
//   - MITRE ATT&CK framework mapping
//   - Support for indicators, attack patterns, threat actors, malware
//   - Observable generation for network and file artifacts
//   - Relationship management between STIX objects
package threatintel

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// STIX 2.1 Core Types
// ============================================================================

// STIXType represents the type of a STIX object.
type STIXType string

const (
	// STIX Domain Objects (SDOs)
	STIXTypeIndicator      STIXType = "indicator"
	STIXTypeAttackPattern  STIXType = "attack-pattern"
	STIXTypeThreatActor    STIXType = "threat-actor"
	STIXTypeMalware        STIXType = "malware"
	STIXTypeVulnerability  STIXType = "vulnerability"
	STIXTypeTool           STIXType = "tool"
	STIXTypeReport         STIXType = "report"
	STIXTypeIntrusionSet   STIXType = "intrusion-set"
	STIXTypeCampaign       STIXType = "campaign"
	STIXTypeCourseOfAction STIXType = "course-of-action"
	STIXTypeIdentity       STIXType = "identity"
	STIXTypeLocation       STIXType = "location"
	STIXTypeNote           STIXType = "note"
	STIXTypeOpinion        STIXType = "opinion"
	STIXTypeObservedData   STIXType = "observed-data"

	// STIX Cyber Observable Objects (SCOs)
	STIXTypeDomainName         STIXType = "domain-name"
	STIXTypeIPv4Addr           STIXType = "ipv4-addr"
	STIXTypeIPv6Addr           STIXType = "ipv6-addr"
	STIXTypeURL                STIXType = "url"
	STIXTypeFile               STIXType = "file"
	STIXTypeEmailAddr          STIXType = "email-addr"
	STIXTypeMACAddr            STIXType = "mac-addr"
	STIXTypeMutex              STIXType = "mutex"
	STIXTypeProcess            STIXType = "process"
	STIXTypeSoftware           STIXType = "software"
	STIXTypeUserAgent          STIXType = "user-agent"
	STIXTypeWindowsRegistryKey STIXType = "windows-registry-key"
	STIXTypeX509Certificate    STIXType = "x509-certificate"

	// STIX Relationship Objects
	STIXTypeRelationship STIXType = "relationship"
	STIXTypeSighting     STIXType = "sighting"

	// Bundle
	STIXTypeBundle STIXType = "bundle"
)

// IndicatorPatternType represents the type of indicator pattern.
type IndicatorPatternType string

const (
	PatternTypeSTIX     IndicatorPatternType = "stix"
	PatternTypeSNORT    IndicatorPatternType = "snort"
	PatternTypeSuricata IndicatorPatternType = "suricata"
	PatternTypeSigma    IndicatorPatternType = "sigma"
	PatternTypeYARA     IndicatorPatternType = "yara"
	PatternTypePcre     IndicatorPatternType = "pcre"
	PatternTypeSigmaAny IndicatorPatternType = "sigma-any"
)

// IndicatorType represents the type of threat indicator.
type IndicatorType string

const (
	IndicatorTypeMaliciousActivity IndicatorType = "malicious-activity"
	IndicatorTypeAnomalousActivity IndicatorType = "anomalous-activity"
	IndicatorTypeAttribution       IndicatorType = "attribution"
	IndicatorTypeUnknown           IndicatorType = "unknown"
	IndicatorTypeBenign            IndicatorType = "benign"
	IndicatorTypeCompromised       IndicatorType = "compromised"
)

// ThreatActorType represents the type of threat actor.
type ThreatActorType string

const (
	ThreatActorTypeNationState    ThreatActorType = "nation-state"
	ThreatActorTypeCrimeSyndicate ThreatActorType = "crime-syndicate"
	ThreatActorTypeHacker         ThreatActorType = "hacker"
	ThreatActorTypeInsider        ThreatActorType = "insider"
	ThreatActorTypeUnknown        ThreatActorType = "unknown"
)

// MalwareType represents the type of malware.
type MalwareType string

const (
	MalwareTypeVirus       MalwareType = "virus"
	MalwareTypeWorm        MalwareType = "worm"
	MalwareTypeTrojan      MalwareType = "trojan"
	MalwareTypeRansomware  MalwareType = "ransomware"
	MalwareTypeSpyware     MalwareType = "spyware"
	MalwareTypeAdware      MalwareType = "adware"
	MalwareTypeBackdoor    MalwareType = "backdoor"
	MalwareTypeRootkit     MalwareType = "rootkit"
	MalwareTypeBotnet      MalwareType = "botnet"
	MalwareTypeCryptominer MalwareType = "cryptominer"
	MalwareTypeKeylogger   MalwareType = "keylogger"
	MalwareTypeDropper     MalwareType = "dropper"
	MalwareTypeLoader      MalwareType = "loader"
)

// RelationshipType represents the type of STIX relationship.
type RelationshipType string

const (
	RelationshipTypeRelatedTo        RelationshipType = "related-to"
	RelationshipTypeIndicates        RelationshipType = "indicates"
	RelationshipTypeUses             RelationshipType = "uses"
	RelationshipTypeTargets          RelationshipType = "targets"
	RelationshipTypeAttributedTo     RelationshipType = "attributed-to"
	RelationshipTypeCompromises      RelationshipType = "compromises"
	RelationshipTypeDelivers         RelationshipType = "delivers"
	RelationshipTypeDownloads        RelationshipType = "downloads"
	RelationshipTypeExploits         RelationshipType = "exploits"
	RelationshipTypeHas              RelationshipType = "has"
	RelationshipTypeHosts            RelationshipType = "hosts"
	RelationshipTypeOriginatesFrom   RelationshipType = "originates-from"
	RelationshipTypeOwns             RelationshipType = "owns"
	RelationshipTypePartOf           RelationshipType = "part-of"
	RelationshipTypeVariantOf        RelationshipType = "variant-of"
	RelationshipTypeCommunicatesWith RelationshipType = "communicates-with"
	RelationshipTypeConsistsOf       RelationshipType = "consists-of"
	RelationshipTypeControls         RelationshipType = "controls"
	RelationshipTypeCreatedBy        RelationshipType = "created-by"
	RelationshipTypeDerivedFrom      RelationshipType = "derived-from"
	RelationshipTypeDuplicateOf      RelationshipType = "duplicate-of"
	RelationshipTypeDetects          RelationshipType = "detects"
	RelationshipTypeImpersonates     RelationshipType = "impersonates"
	RelationshipTypeInvestigates     RelationshipType = "investigates"
	RelationshipTypeLocatedAt        RelationshipType = "located-at"
	RelationshipTypeMitigates        RelationshipType = "mitigates"
	RelationshipTypeRemediates       RelationshipType = "remediates"
	RelationshipTypeRevokedBy        RelationshipType = "revoked-by"
	RelationshipTypeSubtechniqueOf   RelationshipType = "subtechnique-of"
)

// ============================================================================
// STIX Object Base
// ============================================================================

// STIXObject is the base interface for all STIX objects.
type STIXObject interface {
	GetID() string
	GetType() STIXType
	GetCreated() time.Time
	GetModified() time.Time
}

// BaseObject contains fields common to all STIX Domain Objects.
type BaseObject struct {
	// Type identifies the type of STIX Object
	Type STIXType `json:"type"`
	// ID is the unique identifier (UUIDv4 with type prefix)
	ID string `json:"id"`
	// Created is the creation timestamp
	Created time.Time `json:"created"`
	// Modified is the last modification timestamp
	Modified time.Time `json:"modified,omitempty"`
	// SpecVersion is the STIX specification version (always "2.1")
	SpecVersion string `json:"spec_version,omitempty"`
	// ObjectMarkingRefs contains marking definitions for this object
	ObjectMarkingRefs []string `json:"object_marking_refs,omitempty"`
	// GranularMarkings contains granular marking definitions
	GranularMarkings []GranularMarking `json:"granular_markings,omitempty"`
	// Defanged indicates whether the object has been defanged
	Defanged bool `json:"defanged,omitempty"`
	// Extensions contains custom extensions
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// GetID returns the object ID.
func (b *BaseObject) GetID() string {
	return b.ID
}

// GetType returns the object type.
func (b *BaseObject) GetType() STIXType {
	return b.Type
}

// GetCreated returns the creation timestamp.
func (b *BaseObject) GetCreated() time.Time {
	return b.Created
}

// GetModified returns the modification timestamp.
func (b *BaseObject) GetModified() time.Time {
	return b.Modified
}

// GranularMarking defines granular markings for specific properties.
type GranularMarking struct {
	MarkingRef string   `json:"marking_ref"`
	Selectors  []string `json:"selectors"`
}

// ExternalReference references external sources.
type ExternalReference struct {
	SourceName  string            `json:"source_name"`
	Description string            `json:"description,omitempty"`
	URL         string            `json:"url,omitempty"`
	ExternalID  string            `json:"external_id,omitempty"`
	Hashes      map[string]string `json:"hashes,omitempty"`
}

// KillChainPhase represents a phase in a kill chain.
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// ============================================================================
// Indicator
// ============================================================================

// Indicator represents a STIX Indicator Object.
// Indicators contain patterns that can be used to detect suspicious activity.
type Indicator struct {
	BaseObject
	// Name is a human-readable name
	Name string `json:"name,omitempty"`
	// Description provides more details
	Description string `json:"description,omitempty"`
	// IndicatorTypes categorizes the indicator
	IndicatorTypes []IndicatorType `json:"indicator_types,omitempty"`
	// Pattern is the detection pattern
	Pattern string `json:"pattern"`
	// PatternType specifies the pattern language
	PatternType IndicatorPatternType `json:"pattern_type"`
	// PatternVersion specifies the version of the pattern language
	PatternVersion string `json:"pattern_version,omitempty"`
	// ValidFrom is when the indicator is valid from
	ValidFrom time.Time `json:"valid_from"`
	// ValidUntil is when the indicator is no longer valid
	ValidUntil time.Time `json:"valid_until,omitempty"`
	// KillChainPhases maps to MITRE ATT&CK phases
	KillChainPhases []KillChainPhase `json:"kill_chain_phases,omitempty"`
	// CreatedByRef references the identity that created this
	CreatedByRef string `json:"created_by_ref,omitempty"`
	// Confidence in the indicator (0-100)
	Confidence int `json:"confidence,omitempty"`
	// Labels for tagging
	Labels []string `json:"labels,omitempty"`
	// ExternalReferences to external sources
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	// ObjectMarkingRefs references marking definitions
	ObjectMarkingRefs []string `json:"object_marking_refs,omitempty"`
	// Types of the indicator (for observable-based patterns)
	Types []string `json:"types,omitempty"`
}

// NewIndicator creates a new Indicator with defaults.
func NewIndicator(id, pattern string, patternType IndicatorPatternType) *Indicator {
	now := time.Now().UTC()
	return &Indicator{
		BaseObject: BaseObject{
			Type:        STIXTypeIndicator,
			ID:          id,
			Created:     now,
			Modified:    now,
			SpecVersion: "2.1",
		},
		Pattern:     pattern,
		PatternType: patternType,
		ValidFrom:   now,
	}
}

// ============================================================================
// Attack Pattern
// ============================================================================

// AttackPattern represents a STIX Attack Pattern Object.
// Attack patterns describe adversarial behavior patterns (MITRE ATT&CK techniques).
type AttackPattern struct {
	BaseObject
	// Name of the attack pattern
	Name string `json:"name"`
	// Description of the attack pattern
	Description string `json:"description,omitempty"`
	// KillChainPhases maps to MITRE ATT&CK techniques
	KillChainPhases []KillChainPhase `json:"kill_chain_phases,omitempty"`
	// ExternalReferences references MITRE ATT&CK IDs
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	// AbstractionLevel for the attack pattern
	AbstractionLevel string `json:"abstraction_level,omitempty"`
	// CreatedByRef references the identity that created this
	CreatedByRef string `json:"created_by_ref,omitempty"`
	// Confidence in the attack pattern
	Confidence int `json:"confidence,omitempty"`
	// Labels for tagging
	Labels []string `json:"labels,omitempty"`
	// Aliases for this attack pattern
	Aliases []string `json:"aliases,omitempty"`
}

// NewAttackPattern creates a new AttackPattern.
func NewAttackPattern(id, name string) *AttackPattern {
	now := time.Now().UTC()
	return &AttackPattern{
		BaseObject: BaseObject{
			Type:        STIXTypeAttackPattern,
			ID:          id,
			Created:     now,
			Modified:    now,
			SpecVersion: "2.1",
		},
		Name: name,
	}
}

// ============================================================================
// Threat Actor
// ============================================================================

// ThreatActor represents a STIX Threat Actor Object.
// Threat actors are individuals, groups, or organizations believed to be malicious.
type ThreatActor struct {
	BaseObject
	// Name of the threat actor
	Name string `json:"name"`
	// Description of the threat actor
	Description string `json:"description,omitempty"`
	// ThreatActorTypes categorizes the actor
	ThreatActorTypes []ThreatActorType `json:"threat_actor_types,omitempty"`
	// Aliases for this threat actor
	Aliases []string `json:"aliases,omitempty"`
	// FirstSeen timestamp
	FirstSeen time.Time `json:"first_seen,omitempty"`
	// LastSeen timestamp
	LastSeen time.Time `json:"last_seen,omitempty"`
	// Goals of the threat actor
	Goals []string `json:"goals,omitempty"`
	// ResourceLevel of the actor
	ResourceLevel string `json:"resource_level,omitempty"`
	// PrimaryMotivation of the actor
	PrimaryMotivation string `json:"primary_motivation,omitempty"`
	// SecondaryMotivations of the actor
	SecondaryMotivations []string `json:"secondary_motivations,omitempty"`
	// Sophistication level
	Sophistication string `json:"sophistication,omitempty"`
	// KillChainPhases associated with the actor
	KillChainPhases []KillChainPhase `json:"kill_chain_phases,omitempty"`
	// ExternalReferences to external sources
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	// CreatedByRef references the identity that created this
	CreatedByRef string `json:"created_by_ref,omitempty"`
	// Confidence in the threat actor attribution
	Confidence int `json:"confidence,omitempty"`
	// Labels for tagging
	Labels []string `json:"labels,omitempty"`
}

// NewThreatActor creates a new ThreatActor.
func NewThreatActor(id, name string) *ThreatActor {
	now := time.Now().UTC()
	return &ThreatActor{
		BaseObject: BaseObject{
			Type:        STIXTypeThreatActor,
			ID:          id,
			Created:     now,
			Modified:    now,
			SpecVersion: "2.1",
		},
		Name: name,
	}
}

// ============================================================================
// Malware
// ============================================================================

// Malware represents a STIX Malware Object.
// Malware describes malicious software and its characteristics.
type Malware struct {
	BaseObject
	// Name of the malware family
	Name string `json:"name"`
	// Description of the malware
	Description string `json:"description,omitempty"`
	// MalwareTypes categorizes the malware
	MalwareTypes []MalwareType `json:"malware_types,omitempty"`
	// IsFamily indicates if this represents a malware family
	IsFamily bool `json:"is_family"`
	// Aliases for this malware
	Aliases []string `json:"aliases,omitempty"`
	// KillChainPhases associated with the malware
	KillChainPhases []KillChainPhase `json:"kill_chain_phases,omitempty"`
	// FirstSeen timestamp
	FirstSeen time.Time `json:"first_seen,omitempty"`
	// LastSeen timestamp
	LastSeen time.Time `json:"last_seen,omitempty"`
	// OperatingSystemRefs for which the malware is designed
	OperatingSystemRefs []string `json:"operating_system_refs,omitempty"`
	// ArchitectureExecutionEnvs for which the malware is designed
	ArchitectureExecutionEnvs []string `json:"architecture_execution_envs,omitempty"`
	// ImplementationLanguages used to create the malware
	ImplementationLanguages []string `json:"implementation_languages,omitempty"`
	// Capabilities of the malware
	Capabilities []string `json:"capabilities,omitempty"`
	// ExternalReferences to external sources
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	// CreatedByRef references the identity that created this
	CreatedByRef string `json:"created_by_ref,omitempty"`
	// Confidence in the malware attribution
	Confidence int `json:"confidence,omitempty"`
	// Labels for tagging
	Labels []string `json:"labels,omitempty"`
}

// NewMalware creates a new Malware object.
func NewMalware(id, name string, isFamily bool) *Malware {
	now := time.Now().UTC()
	return &Malware{
		BaseObject: BaseObject{
			Type:        STIXTypeMalware,
			ID:          id,
			Created:     now,
			Modified:    now,
			SpecVersion: "2.1",
		},
		Name:     name,
		IsFamily: isFamily,
	}
}

// ============================================================================
// Vulnerability
// ============================================================================

// Vulnerability represents a STIX Vulnerability Object.
type Vulnerability struct {
	BaseObject
	// Name of the vulnerability
	Name string `json:"name"`
	// Description of the vulnerability
	Description string `json:"description,omitempty"`
	// ExternalReferences (CVE IDs, etc.)
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	// CreatedByRef references the identity that created this
	CreatedByRef string `json:"created_by_ref,omitempty"`
	// Confidence in the vulnerability assessment
	Confidence int `json:"confidence,omitempty"`
	// Labels for tagging
	Labels []string `json:"labels,omitempty"`
}

// NewVulnerability creates a new Vulnerability.
func NewVulnerability(id, name string) *Vulnerability {
	now := time.Now().UTC()
	return &Vulnerability{
		BaseObject: BaseObject{
			Type:        STIXTypeVulnerability,
			ID:          id,
			Created:     now,
			Modified:    now,
			SpecVersion: "2.1",
		},
		Name: name,
	}
}

// ============================================================================
// Relationship
// ============================================================================

// Relationship represents a STIX Relationship Object.
// Relationships link two STIX objects together.
type Relationship struct {
	BaseObject
	// RelationshipType describes the relationship
	RelationshipType RelationshipType `json:"relationship_type"`
	// SourceRef is the source object reference
	SourceRef string `json:"source_ref"`
	// TargetRef is the target object reference
	TargetRef string `json:"target_ref"`
	// Description of the relationship
	Description string `json:"description,omitempty"`
	// StartTime when the relationship is valid from
	StartTime time.Time `json:"start_time,omitempty"`
	// StopTime when the relationship is valid until
	StopTime time.Time `json:"stop_time,omitempty"`
	// KillChainPhases associated with the relationship
	KillChainPhases []KillChainPhase `json:"kill_chain_phases,omitempty"`
	// ExternalReferences to external sources
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	// CreatedByRef references the identity that created this
	CreatedByRef string `json:"created_by_ref,omitempty"`
	// Confidence in the relationship
	Confidence int `json:"confidence,omitempty"`
}

// NewRelationship creates a new Relationship.
func NewRelationship(id string, relType RelationshipType, sourceRef, targetRef string) *Relationship {
	now := time.Now().UTC()
	return &Relationship{
		BaseObject: BaseObject{
			Type:        STIXTypeRelationship,
			ID:          id,
			Created:     now,
			Modified:    now,
			SpecVersion: "2.1",
		},
		RelationshipType: relType,
		SourceRef:        sourceRef,
		TargetRef:        targetRef,
	}
}

// ============================================================================
// Report
// ============================================================================

// Report represents a STIX Report Object.
// Reports are collections of STIX objects related to a specific topic.
type Report struct {
	BaseObject
	// Name of the report
	Name string `json:"name"`
	// Description of the report
	Description string `json:"description,omitempty"`
	// ReportTypes categorizes the report
	ReportTypes []string `json:"report_types,omitempty"`
	// Published timestamp
	Published time.Time `json:"published"`
	// ObjectRefs references to objects in this report
	ObjectRefs []string `json:"object_refs"`
	// ExternalReferences to external sources
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	// CreatedByRef references the identity that created this
	CreatedByRef string `json:"created_by_ref,omitempty"`
	// Confidence in the report
	Confidence int `json:"confidence,omitempty"`
	// Labels for tagging
	Labels []string `json:"labels,omitempty"`
}

// NewReport creates a new Report.
func NewReport(id, name string, published time.Time) *Report {
	now := time.Now().UTC()
	return &Report{
		BaseObject: BaseObject{
			Type:        STIXTypeReport,
			ID:          id,
			Created:     now,
			Modified:    now,
			SpecVersion: "2.1",
		},
		Name:       name,
		Published:  published,
		ObjectRefs: []string{},
	}
}

// ============================================================================
// Identity
// ============================================================================

// Identity represents a STIX Identity Object.
// Identities represent individuals, organizations, or groups.
type Identity struct {
	BaseObject
	// Name of the identity
	Name string `json:"name"`
	// Description of the identity
	Description string `json:"description,omitempty"`
	// IdentityClass categorizes the identity
	IdentityClass string `json:"identity_class"`
	// Sectors the identity belongs to
	Sectors []string `json:"sectors,omitempty"`
	// ContactInformation for the identity
	ContactInformation string `json:"contact_information,omitempty"`
	// ExternalReferences to external sources
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	// CreatedByRef references the identity that created this
	CreatedByRef string `json:"created_by_ref,omitempty"`
	// Labels for tagging
	Labels []string `json:"labels,omitempty"`
}

// NewIdentity creates a new Identity.
func NewIdentity(id, name, identityClass string) *Identity {
	now := time.Now().UTC()
	return &Identity{
		BaseObject: BaseObject{
			Type:        STIXTypeIdentity,
			ID:          id,
			Created:     now,
			Modified:    now,
			SpecVersion: "2.1",
		},
		Name:          name,
		IdentityClass: identityClass,
	}
}

// Identity classes
const (
	IdentityClassIndividual   = "individual"
	IdentityClassGroup        = "group"
	IdentityClassOrganization = "organization"
	IdentityClassClass        = "class"
	IdentityClassUnknown      = "unknown"
)

// ============================================================================
// Observable Objects (SCOs)
// ============================================================================

// Observable represents a STIX Cyber Observable Object.
// These describe observable characteristics of network and system activity.
type Observable struct {
	// Type identifies the type of observable
	Type STIXType `json:"type"`
	// ID is the observable object ID
	ID string `json:"id,omitempty"`
	// SpecVersion is the STIX spec version
	SpecVersion string `json:"spec_version,omitempty"`
	// ObjectMarkingRefs for marking definitions
	ObjectMarkingRefs []string `json:"object_marking_refs,omitempty"`
	// GranularMarkings for granular markings
	GranularMarkings []GranularMarking `json:"granular_markings,omitempty"`
	// Defanged indicates if the object is defanged
	Defanged bool `json:"defanged,omitempty"`
	// Extensions contains custom extensions
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// DomainName represents a STIX Domain Name Object.
type DomainName struct {
	Type        STIXType `json:"type"`
	ID          string   `json:"id,omitempty"`
	SpecVersion string   `json:"spec_version,omitempty"`
	// Value is the domain name
	Value string `json:"value"`
	// ResolvesToRefs are IP addresses this resolves to
	ResolvesToRefs []string `json:"resolves_to_refs,omitempty"`
}

// NewDomainName creates a new DomainName observable.
func NewDomainName(id, value string) *DomainName {
	return &DomainName{
		Type:        STIXTypeDomainName,
		ID:          id,
		SpecVersion: "2.1",
		Value:       value,
	}
}

// GetID returns the identifier.
func (d *DomainName) GetID() string { return d.ID }

// GetType returns the STIX type.
func (d *DomainName) GetType() STIXType { return d.Type }

// GetCreated returns the creation timestamp (zero time for observables).
func (d *DomainName) GetCreated() time.Time { return time.Time{} }

// GetModified returns the modification timestamp (zero time for observables).
func (d *DomainName) GetModified() time.Time { return time.Time{} }

// IPv4Address represents a STIX IPv4 Address Object.
type IPv4Address struct {
	Type        STIXType `json:"type"`
	ID          string   `json:"id,omitempty"`
	SpecVersion string   `json:"spec_version,omitempty"`
	// Value is the IPv4 address
	Value string `json:"value"`
	// ResolvesToRefs are domain names that resolve to this IP
	ResolvesToRefs []string `json:"resolves_to_refs,omitempty"`
	// BelongsToRefs are ASNs this IP belongs to
	BelongsToRefs []string `json:"belongs_to_refs,omitempty"`
}

// NewIPv4Address creates a new IPv4Address observable.
func NewIPv4Address(id, value string) *IPv4Address {
	return &IPv4Address{
		Type:        STIXTypeIPv4Addr,
		ID:          id,
		SpecVersion: "2.1",
		Value:       value,
	}
}

// GetID returns the identifier.
func (a *IPv4Address) GetID() string { return a.ID }

// GetType returns the STIX type.
func (a *IPv4Address) GetType() STIXType { return a.Type }

// GetCreated returns the creation timestamp (zero time for observables).
func (a *IPv4Address) GetCreated() time.Time { return time.Time{} }

// GetModified returns the modification timestamp (zero time for observables).
func (a *IPv4Address) GetModified() time.Time { return time.Time{} }

// IPv6Address represents a STIX IPv6 Address Object.
type IPv6Address struct {
	Type        STIXType `json:"type"`
	ID          string   `json:"id,omitempty"`
	SpecVersion string   `json:"spec_version,omitempty"`
	// Value is the IPv6 address
	Value string `json:"value"`
	// ResolvesToRefs are domain names that resolve to this IP
	ResolvesToRefs []string `json:"resolves_to_refs,omitempty"`
}

// NewIPv6Address creates a new IPv6Address observable.
func NewIPv6Address(id, value string) *IPv6Address {
	return &IPv6Address{
		Type:        STIXTypeIPv6Addr,
		ID:          id,
		SpecVersion: "2.1",
		Value:       value,
	}
}

// GetID returns the identifier.
func (a *IPv6Address) GetID() string { return a.ID }

// GetType returns the STIX type.
func (a *IPv6Address) GetType() STIXType { return a.Type }

// GetCreated returns the creation timestamp (zero time for observables).
func (a *IPv6Address) GetCreated() time.Time { return time.Time{} }

// GetModified returns the modification timestamp (zero time for observables).
func (a *IPv6Address) GetModified() time.Time { return time.Time{} }

// URL represents a STIX URL Object.
type URL struct {
	Type        STIXType `json:"type"`
	ID          string   `json:"id,omitempty"`
	SpecVersion string   `json:"spec_version,omitempty"`
	// Value is the URL
	Value string `json:"value"`
}

// GetID returns the identifier.
func (u *URL) GetID() string { return u.ID }

// GetType returns the STIX type.
func (u *URL) GetType() STIXType { return u.Type }

// GetCreated returns the creation timestamp (zero time for observables).
func (u *URL) GetCreated() time.Time { return time.Time{} }

// GetModified returns the modification timestamp (zero time for observables).
func (u *URL) GetModified() time.Time { return time.Time{} }

// NewURL creates a new URL observable.
func NewURL(id, value string) *URL {
	return &URL{
		Type:        STIXTypeURL,
		ID:          id,
		SpecVersion: "2.1",
		Value:       value,
	}
}

// FileHash represents file hash information.
type FileHash struct {
	// MD5 hash
	MD5 string `json:"MD5,omitempty"`
	// SHA-1 hash
	SHA1 string `json:"SHA-1,omitempty"`
	// SHA-256 hash
	SHA256 string `json:"SHA-256,omitempty"`
	// SHA-512 hash
	SHA512 string `json:"SHA-512,omitempty"`
	// SSDEEP fuzzy hash
	SSDEEP string `json:"SSDEEP,omitempty"`
}

// HasAny returns true if any hash is set.
func (h FileHash) HasAny() bool {
	return h.MD5 != "" || h.SHA1 != "" || h.SHA256 != "" || h.SHA512 != "" || h.SSDEEP != ""
}

// File represents a STIX File Object.
type File struct {
	Type        STIXType `json:"type"`
	ID          string   `json:"id,omitempty"`
	SpecVersion string   `json:"spec_version,omitempty"`
	// Hashes contains file hashes
	Hashes FileHash `json:"hashes,omitempty"`
	// Size in bytes
	Size int64 `json:"size,omitempty"`
	// Name of the file
	Name string `json:"name,omitempty"`
	// NameEnc is the encoding of the name
	NameEnc string `json:"name_enc,omitempty"`
	// MagicNumberHex is the magic number in hex
	MagicNumberHex string `json:"magic_number_hex,omitempty"`
	// Mime type
	MimeType string `json:"mime_type,omitempty"`
	// ContainsRefs references embedded objects
	ContainsRefs []string `json:"contains_refs,omitempty"`
	// Content is the content of the file
	Content string `json:"content,omitempty"`
}

// NewFile creates a new File observable.
func NewFile(id string, hashes FileHash) *File {
	return &File{
		Type:        STIXTypeFile,
		ID:          id,
		SpecVersion: "2.1",
		Hashes:      hashes,
	}
}

// GetID returns the identifier.
func (f *File) GetID() string { return f.ID }

// GetType returns the STIX type.
func (f *File) GetType() STIXType { return f.Type }

// GetCreated returns the creation timestamp (zero time for observables).
func (f *File) GetCreated() time.Time { return time.Time{} }

// GetModified returns the modification timestamp (zero time for observables).
func (f *File) GetModified() time.Time { return time.Time{} }

// EmailAddress represents a STIX Email Address Object.
type EmailAddress struct {
	Type        STIXType `json:"type"`
	ID          string   `json:"id,omitempty"`
	SpecVersion string   `json:"spec_version,omitempty"`
	// Value is the email address
	Value string `json:"value"`
	// DisplayName is the human-readable name
	DisplayName string `json:"display_name,omitempty"`
	// BelongsToRefs references identities this email belongs to
	BelongsToRefs []string `json:"belongs_to_ref,omitempty"`
}

// NewEmailAddress creates a new EmailAddress observable.
func NewEmailAddress(id, value string) *EmailAddress {
	return &EmailAddress{
		Type:        STIXTypeEmailAddr,
		ID:          id,
		SpecVersion: "2.1",
		Value:       value,
	}
}

// GetID returns the identifier.
func (e *EmailAddress) GetID() string { return e.ID }

// GetType returns the STIX type.
func (e *EmailAddress) GetType() STIXType { return e.Type }

// GetCreated returns the creation timestamp (zero time for observables).
func (e *EmailAddress) GetCreated() time.Time { return time.Time{} }

// GetModified returns the modification timestamp (zero time for observables).
func (e *EmailAddress) GetModified() time.Time { return time.Time{} }

// MACAddress represents a STIX MAC Address Object.
type MACAddress struct {
	Type        STIXType `json:"type"`
	ID          string   `json:"id,omitempty"`
	SpecVersion string   `json:"spec_version,omitempty"`
	// Value is the MAC address
	Value string `json:"value"`
}

// GetID returns the identifier.
func (m *MACAddress) GetID() string { return m.ID }

// GetType returns the STIX type.
func (m *MACAddress) GetType() STIXType { return m.Type }

// GetCreated returns the creation timestamp (zero time for observables).
func (m *MACAddress) GetCreated() time.Time { return time.Time{} }

// GetModified returns the modification timestamp (zero time for observables).
func (m *MACAddress) GetModified() time.Time { return time.Time{} }

// NewMACAddress creates a new MACAddress observable.
func NewMACAddress(id, value string) *MACAddress {
	return &MACAddress{
		Type:        STIXTypeMACAddr,
		ID:          id,
		SpecVersion: "2.1",
		Value:       value,
	}
}

// Bundle represents a STIX Bundle - a collection of STIX objects.
type Bundle struct {
	// Type is always "bundle"
	Type STIXType `json:"type"`
	// ID is the bundle identifier
	ID string `json:"id"`
	// Objects contains the STIX objects in this bundle
	Objects []json.RawMessage `json:"objects"`
	// SpecVersion is the STIX specification version
	SpecVersion string `json:"spec_version,omitempty"`
}

// NewBundle creates a new STIX Bundle.
func NewBundle(id string) *Bundle {
	return &Bundle{
		Type:        STIXTypeBundle,
		ID:          id,
		SpecVersion: "2.1",
		Objects:     []json.RawMessage{},
	}
}

// AddObject adds a STIX object to the bundle.
func (b *Bundle) AddObject(obj STIXObject) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	b.Objects = append(b.Objects, data)
	return nil
}

// AddRawObject adds a raw JSON object to the bundle.
func (b *Bundle) AddRawObject(data json.RawMessage) {
	b.Objects = append(b.Objects, data)
}

// ============================================================================
// Sighting
// ============================================================================

// Sighting represents a STIX Sighting Object.
// Sighting indicates that a STIX object was observed.
type Sighting struct {
	BaseObject
	// FirstSeen timestamp
	FirstSeen time.Time `json:"first_seen,omitempty"`
	// LastSeen timestamp
	LastSeen time.Time `json:"last_seen,omitempty"`
	// Count of sightings
	Count int `json:"count,omitempty"`
	// SightingOfRef is the object that was sighted
	SightingOfRef string `json:"sighting_of_ref"`
	// ObservedDataRefs references observed data objects
	ObservedDataRefs []string `json:"observed_data_refs,omitempty"`
	// WhereSightedRefs references locations where sighted
	WhereSightedRefs []string `json:"where_sighted_refs,omitempty"`
	// Summary indicates if this is a summary sighting
	Summary bool `json:"summary,omitempty"`
	// Description of the sighting
	Description string `json:"description,omitempty"`
	// ExternalReferences to external sources
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	// CreatedByRef references the identity that created this
	CreatedByRef string `json:"created_by_ref,omitempty"`
}

// NewSighting creates a new Sighting.
func NewSighting(id, sightingOfRef string) *Sighting {
	now := time.Now().UTC()
	return &Sighting{
		BaseObject: BaseObject{
			Type:        STIXTypeSighting,
			ID:          id,
			Created:     now,
			Modified:    now,
			SpecVersion: "2.1",
		},
		SightingOfRef: sightingOfRef,
	}
}

// ============================================================================
// Observed Data
// ============================================================================

// ObservedData represents a STIX Observed Data Object.
type ObservedData struct {
	BaseObject
	// FirstObserved timestamp
	FirstObserved time.Time `json:"first_observed"`
	// LastObserved timestamp
	LastObserved time.Time `json:"last_observed"`
	// Number of times observed
	NumberObserved int `json:"number_observed"`
	// Objects contains the observed objects
	Objects map[string]interface{} `json:"objects"`
	// ObjectRefs references to observed objects
	ObjectRefs []string `json:"object_refs,omitempty"`
	// ExternalReferences to external sources
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	// CreatedByRef references the identity that created this
	CreatedByRef string `json:"created_by_ref,omitempty"`
}

// NewObservedData creates a new ObservedData.
func NewObservedData(id string, firstObserved, lastObserved time.Time, numberObserved int) *ObservedData {
	now := time.Now().UTC()
	return &ObservedData{
		BaseObject: BaseObject{
			Type:        STIXTypeObservedData,
			ID:          id,
			Created:     now,
			Modified:    now,
			SpecVersion: "2.1",
		},
		FirstObserved:  firstObserved,
		LastObserved:   lastObserved,
		NumberObserved: numberObserved,
		Objects:        make(map[string]interface{}),
	}
}

// ============================================================================
// TAXII 2.1 Types
// ============================================================================

// TAXIIDiscovery represents a TAXII Discovery Response.
type TAXIIDiscovery struct {
	// Title of the TAXII server
	Title string `json:"title"`
	// Description of the TAXII server
	Description string `json:"description,omitempty"`
	// Contact email or information
	Contact string `json:"contact,omitempty"`
	// Default value for a default collection
	Default string `json:"default,omitempty"`
	// APIRoots available on this server
	APIRoots []string `json:"api_roots,omitempty"`
}

// TAXIIAPIRoot represents a TAXII API Root.
type TAXIIAPIRoot struct {
	// MaxContentSize is the maximum content size in bytes
	MaxContentSize int64 `json:"max_content_length"`
	// Description of the API root
	Description string `json:"description,omitempty"`
	// Title of the API root
	Title string `json:"title,omitempty"`
	// Versions supported STIX versions
	Versions []string `json:"versions"`
	// MaxRange is the maximum range for partial content requests
	MaxRange int `json:"max_range,omitempty"`
}

// TAXIICollection represents a TAXII Collection.
type TAXIICollection struct {
	// ID of the collection
	ID string `json:"id"`
	// Title of the collection
	Title string `json:"title"`
	// Description of the collection
	Description string `json:"description,omitempty"`
	// CanRead indicates if objects can be read
	CanRead bool `json:"can_read"`
	// CanWrite indicates if objects can be written
	CanWrite bool `json:"can_write"`
	// MediaTypes supported by the collection
	MediaTypes []string `json:"media_types,omitempty"`
}

// TAXIICollections represents a list of collections.
type TAXIICollections struct {
	// Collections in this list
	Collections []TAXIICollection `json:"collections"`
}

// TAXIIManifestEntry represents an entry in a collection manifest.
type TAXIIManifestEntry struct {
	// ID of the object
	ID string `json:"id"`
	// DateAdded to the collection
	DateAdded time.Time `json:"date_added"`
	// Version of the object
	Version string `json:"version"`
	// MediaTypes for this object
	MediaTypes []string `json:"media_types,omitempty"`
}

// TAXIIManifest represents a collection manifest.
type TAXIIManifest struct {
	// Objects in the manifest
	Objects []TAXIIManifestEntry `json:"objects"`
}

// TAXIIGetObjectsRequest represents a request to get objects from a collection.
type TAXIIGetObjectsRequest struct {
	// AddedAfter filters objects added after this time
	AddedAfter time.Time `json:"added_after,omitempty"`
	// IDs filters by specific object IDs
	IDs []string `json:"ids,omitempty"`
	// Types filters by object types
	Types []string `json:"types,omitempty"`
	// Versions specifies which versions to retrieve
	Versions []string `json:"versions,omitempty"`
	// Match specifies property matching criteria
	Match map[string]interface{} `json:"match,omitempty"`
}

// TAXIIEnvelopes represents a TAXII envelope containing STIX objects.
type TAXIIEnvelopes struct {
	// Objects in this envelope
	Objects []json.RawMessage `json:"objects"`
}

// TAXIISession represents an active TAXII session.
type TAXIISession struct {
	// SessionID is the unique session identifier
	SessionID string `json:"session_id"`
	// ServerURL is the TAXII server URL
	ServerURL string `json:"server_url"`
	// Username for the session
	Username string `json:"username,omitempty"`
	// Token for authentication
	Token string `json:"token,omitempty"`
	// ExpiresAt is when the session expires
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// TAXIIContentRange represents a Content-Range header for partial responses.
type TAXIIContentRange struct {
	// Start is the starting index
	Start int `json:"start"`
	// End is the ending index
	End int `json:"end"`
	// Total is the total number of objects
	Total int `json:"total"`
}

// ParseTAXIIContentRange parses a Content-Range header.
func ParseTAXIIContentRange(header string) (*TAXIIContentRange, error) {
	// Format: items 0-99/1000
	var cr TAXIIContentRange
	_, err := cr.Parse(header)
	return &cr, err
}

// Parse parses a Content-Range header string.
func (cr *TAXIIContentRange) Parse(header string) (int, error) {
	// Format: items 0-99/1000
	if header == "" {
		return 0, nil
	}
	n, err := cr.UnmarshalText([]byte(header))
	return n, err
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (cr *TAXIIContentRange) UnmarshalText(data []byte) (int, error) {
	// Parse "items start-end/total" format
	var start, end, total int
	n, err := parseContentRange(string(data), &start, &end, &total)
	if err != nil {
		return 0, err
	}
	cr.Start = start
	cr.End = end
	cr.Total = total
	return n, nil
}

// MarshalText implements encoding.TextMarshaler.
func (cr *TAXIIContentRange) MarshalText() ([]byte, error) {
	return []byte(cr.String()), nil
}

// String returns the Content-Range header string.
func (cr *TAXIIContentRange) String() string {
	if cr.Total == 0 {
		return ""
	}
	return formatContentRange(cr.Start, cr.End, cr.Total)
}

// Helper functions for Content-Range parsing
func parseContentRange(s string, start, end, total *int) (int, error) {
	// Parse "items start-end/total" format
	if len(s) < 7 || s[:6] != "items " {
		return 0, nil
	}
	rest := s[6:]
	n, err := parseRange(rest, start, end, total)
	return n, err
}

func parseRange(s string, start, end, total *int) (int, error) {
	// Parse "items start-end/total" format
	// Example: "items 0-99/1000"
	parts := strings.Split(s, " ")
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid content-range format: %s", s)
	}

	rangePart := parts[len(parts)-1]
	// Parse "start-end/total"
	rangeParts := strings.Split(rangePart, "/")
	if len(rangeParts) != 2 {
		return 0, fmt.Errorf("invalid range format: %s", rangePart)
	}

	totalStr := rangeParts[1]
	startEndParts := strings.Split(rangeParts[0], "-")
	if len(startEndParts) != 2 {
		return 0, fmt.Errorf("invalid start-end format: %s", rangeParts[0])
	}

	var err error
	*start, err = strconv.Atoi(startEndParts[0])
	if err != nil {
		return 0, fmt.Errorf("invalid start: %w", err)
	}

	*end, err = strconv.Atoi(startEndParts[1])
	if err != nil {
		return 0, fmt.Errorf("invalid end: %w", err)
	}

	*total, err = strconv.Atoi(totalStr)
	if err != nil {
		return 0, fmt.Errorf("invalid total: %w", err)
	}

	return *end - *start + 1, nil
}

func formatContentRange(start, end, total int) string {
	return fmt.Sprintf("items %d-%d/%d", start, end, total)
}

// ============================================================================
// Error Types
// ============================================================================

// Error represents a threat intelligence error.
type Error struct {
	Operation string `json:"operation"`
	Message   string `json:"message"`
	Code      int    `json:"code,omitempty"`
	Retryable bool   `json:"retryable"`
	Cause     error  `json:"-"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Cause != nil {
		return e.Operation + ": " + e.Message + ": " + e.Cause.Error()
	}
	return e.Operation + ": " + e.Message
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error {
	return e.Cause
}

// NewError creates a new threat intelligence error.
func NewError(operation, message string, retryable bool, cause error) *Error {
	return &Error{
		Operation: operation,
		Message:   message,
		Retryable: retryable,
		Cause:     cause,
	}
}

// TAXIIError represents a TAXII error response.
type TAXIIError struct {
	Title           string              `json:"title"`
	Description     string              `json:"description,omitempty"`
	ErrorCode       int                 `json:"error_code,omitempty"`
	ExternalDetails string              `json:"external_details,omitempty"`
	HTTPHeaders     map[string][]string `json:"-"`
}

// Error implements the error interface.
func (e *TAXIIError) Error() string {
	return e.Title + ": " + e.Description
}

// IsRetryable returns true if the error is retryable.
func (e *TAXIIError) IsRetryable() bool {
	return e.ErrorCode == 429 || (e.ErrorCode >= 500 && e.ErrorCode < 600)
}

// ============================================================================
// MITRE ATT&CK Mapping
// ============================================================================

// MITREMapping maps events to MITRE ATT&CK framework.
type MITREMapping struct {
	Tactic         string   `json:"tactic,omitempty"`
	TacticID       string   `json:"tactic_id,omitempty"`
	Technique      string   `json:"technique,omitempty"`
	TechniqueID    string   `json:"technique_id,omitempty"`
	SubTechnique   string   `json:"sub_technique,omitempty"`
	SubTechniqueID string   `json:"sub_technique_id,omitempty"`
	Tactics        []string `json:"tactics,omitempty"`
	Techniques     []string `json:"techniques,omitempty"`
}

// ToKillChainPhases converts MITRE mapping to STIX kill chain phases.
func (m *MITREMapping) ToKillChainPhases() []KillChainPhase {
	phases := []KillChainPhase{}

	if m.Tactic != "" && m.TacticID != "" {
		phases = append(phases, KillChainPhase{
			KillChainName: "mitre-attack",
			PhaseName:     m.Tactic,
		})
	}

	for _, tactic := range m.Tactics {
		phases = append(phases, KillChainPhase{
			KillChainName: "mitre-attack",
			PhaseName:     tactic,
		})
	}

	return phases
}

// ToExternalReferences converts MITRE mapping to external references.
func (m *MITREMapping) ToExternalReferences() []ExternalReference {
	refs := []ExternalReference{}

	if m.TechniqueID != "" {
		refs = append(refs, ExternalReference{
			SourceName:  "mitre-attack",
			ExternalID:  m.TechniqueID,
			Description: m.Technique,
			URL:         "https://attack.mitre.org/techniques/" + m.TechniqueID,
		})
	}

	if m.SubTechniqueID != "" {
		refs = append(refs, ExternalReference{
			SourceName:  "mitre-attack",
			ExternalID:  m.SubTechniqueID,
			Description: m.SubTechnique,
			URL:         "https://attack.mitre.org/techniques/" + m.SubTechniqueID,
		})
	}

	return refs
}

// ============================================================================
// STIX ID Generation
// ============================================================================

// STIXIDGenerator generates STIX-compliant IDs.
type STIXIDGenerator struct {
	prefix string
}

// NewSTIXIDGenerator creates a new ID generator for a STIX type.
func NewSTIXIDGenerator(stixType STIXType) *STIXIDGenerator {
	return &STIXIDGenerator{
		prefix: string(stixType),
	}
}

// Generate creates a new STIX ID.
func (g *STIXIDGenerator) Generate() (string, error) {
	uuid, err := generateUUID()
	if err != nil {
		return "", err
	}
	return g.prefix + "--" + uuid, nil
}

// generateUUID generates a random UUID v4.
func generateUUID() (string, error) {
	return generateRandomUUID()
}
