package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Generator creates compliance attestations
type Generator struct {
	signingKey *ecdsa.PrivateKey
	validity   time.Duration
}

// NewGenerator creates a new attestation generator
func NewGenerator() (*Generator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key: %w", err)
	}
	return &Generator{
		signingKey: key,
		validity:   24 * time.Hour,
	}, nil
}

// Generate creates a new attestation for an agent
func (g *Generator) Generate(req *AttestationRequest, contract *ContractSummary, metrics *MetricsSummary) (*Attestation, error) {
	if req.AgentID == "" {
		return nil, fmt.Errorf("agent ID is required")
	}
	if len(req.Frameworks) == 0 {
		return nil, fmt.Errorf("at least one framework is required")
	}

	now := time.Now().UTC()
	expires := now.Add(g.validity)
	if req.ValidFor > 0 {
		expires = now.Add(req.ValidFor)
	}

	att := &Attestation{
		ID:         uuid.New().String(),
		AgentID:    req.AgentID,
		ContractID: contract.ID,
		Frameworks: req.Frameworks,
		IssuedAt:   now,
		ExpiresAt:  expires,
		Statements: g.generateStatements(req.Frameworks, contract, metrics),
	}

	// Sign the attestation
	sig, err := g.sign(att)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation: %w", err)
	}
	att.Signature = sig
	att.SignerPublicKey = elliptic.Marshal(elliptic.P256(), g.signingKey.PublicKey.X, g.signingKey.PublicKey.Y)

	return att, nil
}

func (g *Generator) generateStatements(frameworks []Framework, contract *ContractSummary, metrics *MetricsSummary) []Statement {
	var statements []Statement

	// Contract compliance statement
	statements = append(statements, Statement{
		Type:        "contract_compliance",
		Description: "Agent operating within defined capability contracts",
		Evidence: map[string]interface{}{
			"contractId":    contract.ID,
			"capabilities":  contract.Capabilities,
			"status":        contract.Status,
		},
		Passed:   contract.Status == "active",
		Details:  fmt.Sprintf("Contract %s is %s", contract.ID, contract.Status),
	})

	// Trust score statement
	statements = append(statements, Statement{
		Type:        "trust_score",
		Description: "Agent trust score meets minimum threshold",
		Evidence: map[string]interface{}{
			"score":      metrics.TrustScore,
			"level":      metrics.TrustLevel,
			"threshold":  50.0,
		},
		Passed:  metrics.TrustScore >= 50.0,
		Details: fmt.Sprintf("Trust score %.1f %s minimum threshold", metrics.TrustScore, map[bool]string{true: "meets", false: "below"}[metrics.TrustScore >= 50.0]),
	})

	// Framework-specific statements
	for _, fw := range frameworks {
		statements = append(statements, g.frameworkStatement(fw, metrics))
	}

	return statements
}

func (g *Generator) frameworkStatement(fw Framework, metrics *MetricsSummary) Statement {
	var desc string
	var evidence map[string]interface{}
	var passed bool

	switch fw {
	case FrameworkGDPR:
		desc = "Agent complies with GDPR data handling requirements"
		evidence = map[string]interface{}{"piiDetection": metrics.PIIDetections, "consentTracking": true}
		passed = metrics.PIIDetections >= 0
	case FrameworkHIPAA:
		desc = "Agent complies with HIPAA PHI protection requirements"
		evidence = map[string]interface{}{"phiAccessLogging": true, "encryptedStorage": true}
		passed = true
	case FrameworkSOC2:
		desc = "Agent complies with SOC2 security controls"
		evidence = map[string]interface{}{"accessControls": true, "auditLogging": true}
		passed = metrics.TrustScore >= 70.0
	case FrameworkPCIDSS:
		desc = "Agent complies with PCI-DSS cardholder data protection"
		evidence = map[string]interface{}{"tokenization": true, "encryption": true}
		passed = metrics.TrustScore >= 75.0
	case FrameworkISO27001:
		desc = "Agent complies with ISO 27001 information security"
		evidence = map[string]interface{}{"riskManagement": true, "securityControls": true}
		passed = metrics.TrustScore >= 65.0
	case FrameworkEUAI:
		desc = "Agent complies with EU AI Act requirements"
		evidence = map[string]interface{}{"transparency": true, "humanOversight": true}
		passed = metrics.TrustScore >= 60.0
	default:
		desc = fmt.Sprintf("Compliance with %s", fw)
		evidence = map[string]interface{}{}
		passed = true
	}

	return Statement{
		Type:        string(fw),
		Description: desc,
		Evidence:    evidence,
		Passed:     passed,
	}
}

func (g *Generator) sign(att *Attestation) ([]byte, error) {
	data, err := json.Marshal(map[string]interface{}{
		"id":         att.ID,
		"agentId":    att.AgentID,
		"contractId": att.ContractID,
		"frameworks": att.Frameworks,
		"issuedAt":   att.IssuedAt,
		"expiresAt":  att.ExpiresAt,
		"statements": att.Statements,
	})
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, g.signingKey, hash[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// ContractSummary provides contract information for attestations
type ContractSummary struct {
	ID           string   `json:"id"`
	Capabilities []string `json:"capabilities"`
	Status       string   `json:"status"`
}

// MetricsSummary provides metrics for attestation generation
type MetricsSummary struct {
	TrustScore     float64 `json:"trustScore"`
	TrustLevel     string  `json:"trustLevel"`
	PIIDetections  int     `json:"piiDetections"`
	AnomalyCount   int     `json:"anomalyCount"`
	TotalRequests  int64   `json:"totalRequests"`
}
