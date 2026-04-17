// Package common provides shared types and interfaces for compliance frameworks
package common

import "time"

// Control represents a security or compliance control
type Control struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description" yaml:"description"`
	Category    string            `json:"category" yaml:"category"`
	SubCategory string            `json:"sub_category" yaml:"sub_category"`
	Severity    string            `json:"severity" yaml:"severity"` // critical, high, medium, low
	Status      string            `json:"status" yaml:"status"`     // implemented, planned, not_applicable
	Metadata    map[string]string `json:"metadata" yaml:"metadata"`
}

// ControlSet represents a collection of controls
type ControlSet struct {
	Framework   string    `json:"framework" yaml:"framework"`
	Version     string    `json:"version" yaml:"version"`
	PublishedAt time.Time `json:"published_at" yaml:"published_at"`
	Controls    []Control `json:"controls" yaml:"controls"`
}

// ControlStatus represents the status of a control implementation
type ControlStatus struct {
	ControlID   string    `json:"control_id" yaml:"control_id"`
	Status      string    `json:"status" yaml:"status"`
	Notes       string    `json:"notes" yaml:"notes"`
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`
}

// Mapping represents a cross-reference between frameworks
type Mapping struct {
	SourceFramework string `json:"source_framework" yaml:"source_framework"`
	SourceControl   string `json:"source_control" yaml:"source_control"`
	TargetFramework string `json:"target_framework" yaml:"target_framework"`
	TargetControl   string `json:"target_control" yaml:"target_control"`
	Relationship    string `json:"relationship" yaml:"relationship"` // equivalent, partial, broader, narrower
}

// Threat represents an AI-specific threat
type Threat struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	Category    string   `json:"category" yaml:"category"`
	Mitigations []string `json:"mitigations" yaml:"mitigations"`
}

// Assessment represents a compliance assessment result
type Assessment struct {
	Framework      string          `json:"framework" yaml:"framework"`
	Timestamp      time.Time       `json:"timestamp" yaml:"timestamp"`
	OverallScore   float64         `json:"overall_score" yaml:"overall_score"`
	ControlResults []ControlResult `json:"control_results" yaml:"control_results"`
}

// ControlResult represents the result of assessing a single control
type ControlResult struct {
	ControlID  string   `json:"control_id" yaml:"control_id"`
	Status     string   `json:"status" yaml:"status"`
	Score      float64  `json:"score" yaml:"score"`
	Evidence   string   `json:"evidence" yaml:"evidence"`
	Exceptions []string `json:"exceptions" yaml:"exceptions"`
}

// Importer defines the interface for compliance framework importers
type Importer interface {
	Import(data []byte) (*ControlSet, error)
	Validate() error
}

// Exporter defines the interface for compliance framework exporters
type Exporter interface {
	Export(set *ControlSet) ([]byte, error)
}

// Validator defines the interface for compliance validation
type Validator interface {
	Validate(framework string, controls []Control) (*Assessment, error)
}
