package attestation

import (
	"time"
)

// Framework represents a compliance framework
type Framework string

const (
	FrameworkGDPR    Framework = "gdpr"
	FrameworkHIPAA   Framework = "hipaa"
	FrameworkSOC2    Framework = "soc2"
	FrameworkPCIDSS  Framework = "pci-dss"
	FrameworkISO27001 Framework = "iso27001"
	FrameworkEUAI    Framework = "eu-ai-act"
)

// Attestation represents a cryptographic compliance attestation
type Attestation struct {
	ID              string           `json:"id"`
	AgentID         string           `json:"agentId"`
	ContractID      string           `json:"contractId"`
	Frameworks      []Framework      `json:"frameworks"`
	IssuedAt        time.Time        `json:"issuedAt"`
	ExpiresAt       time.Time        `json:"expiresAt"`
	Statements      []Statement      `json:"statements"`
	Signature       []byte           `json:"signature"`
	SignerPublicKey []byte           `json:"signerPublicKey"`
}

// Statement represents a single attestation statement
type Statement struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Passed      bool              `json:"passed"`
	Details     string            `json:"details,omitempty"`
}

// AttestationRequest contains parameters for creating an attestation
type AttestationRequest struct {
	AgentID     string      `json:"agentId"`
	Frameworks  []Framework `json:"frameworks"`
	ValidFor    time.Duration `json:"validFor"`
}

// AttestationResult contains the result of attestation verification
type AttestationResult struct {
	Valid          bool      `json:"valid"`
	AgentID        string    `json:"agentId"`
	Frameworks     []Framework `json:"frameworks"`
	IssuedAt       time.Time `json:"issuedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	StatementsPass int       `json:"statementsPass"`
	StatementsFail int       `json:"statementsFail"`
	VerifiedAt     time.Time `json:"verifiedAt"`
	Errors         []string  `json:"errors,omitempty"`
}

// ComplianceStatus represents overall compliance status
type ComplianceStatus struct {
	Framework     Framework `json:"framework"`
	Score         float64  `json:"score"`
	ControlsPass  int      `json:"controlsPass"`
	ControlsFail  int      `json:"controlsFail"`
	ControlsTotal int      `json:"controlsTotal"`
	LastAudit     time.Time `json:"lastAudit"`
	NextAudit     time.Time `json:"nextAudit"`
	Compliant     bool      `json:"compliant"`
}

// Config contains attestation configuration
type Config struct {
	SigningKey   []byte       `json:"signingKey"`
	ValidityDays int          `json:"validityDays"`
	Frameworks   []Framework  `json:"frameworks"`
}
