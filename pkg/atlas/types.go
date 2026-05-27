package atlas

import "time"

// Config holds ATLAS detector configuration
type Config struct {
	EnableNetworkScanning      bool
	EnablePersistenceDetection bool
	EnableC2Detection          bool
	EnableImpactDetection      bool
	AlertOnHighSeverity        bool
}

func DefaultConfig() *Config {
	return &Config{
		EnableNetworkScanning:      true,
		EnablePersistenceDetection: true,
		EnableC2Detection:          true,
		EnableImpactDetection:      true,
		AlertOnHighSeverity:        true,
	}
}

// DetectionResult holds detection results
type DetectionResult struct {
	TechniqueID string
	Technique   string
	Tactic      string
	Alert       bool
	Severity    string
	Reason      string
	Mitigation  string
	Metadata    map[string]string
	Timestamp   time.Time
}

// APIRequest represents an API request
type APIRequest struct {
	AgentID   string
	SessionID string
	Endpoint  string
	Content   string
	Headers   map[string]string
}

// NetworkActivity represents network activity
type NetworkActivity struct {
	SourceIP string
	DestIP   string
	DestPort int
}
