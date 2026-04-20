// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package opsec

import (
	"fmt"
	"sync"
)

// ThreatCategory represents the severity of a threat
type ThreatCategory int

const (
	ThreatCategoryLow      ThreatCategory = 1
	ThreatCategoryMedium   ThreatCategory = 2
	ThreatCategoryHigh     ThreatCategory = 3
	ThreatCategoryCritical ThreatCategory = 4
)

func (tc ThreatCategory) String() string {
	switch tc {
	case ThreatCategoryLow:
		return "low"
	case ThreatCategoryMedium:
		return "medium"
	case ThreatCategoryHigh:
		return "high"
	case ThreatCategoryCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ThreatVector represents a type of security threat
type ThreatVector string

const (
	ThreatVectorPromptInjection     ThreatVector = "prompt_injection"
	ThreatVectorDataExfiltration    ThreatVector = "data_exfiltration"
	ThreatVectorModelTheft          ThreatVector = "model_theft"
	ThreatVectorTrainingPoisoning   ThreatVector = "training_poisoning"
	ThreatVectorAdversarialInput    ThreatVector = "adversarial_input"
	ThreatVectorShadowAI            ThreatVector = "shadow_ai"
	ThreatVectorSupplyChain         ThreatVector = "supply_chain"
	ThreatVectorPrivilegeEscalation ThreatVector = "privilege_escalation"
	ThreatVectorDoS                 ThreatVector = "denial_of_service"
	ThreatVectorSideChannel         ThreatVector = "side_channel"
)

// ThreatEntry represents a cataloged threat with mitigation strategies
type ThreatEntry struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Vector         ThreatVector   `json:"vector"`
	Category       ThreatCategory `json:"category"`
	Description    string         `json:"description"`
	Indicators     []string       `json:"indicators"`
	Mitigation     string         `json:"mitigation"`
	Implementation []string       `json:"implementation"`
	References     []string       `json:"references"`
	OWASPCategory  string         `json:"owasp_category,omitempty"`
}

// ThreatModel represents a complete threat model for a system
type ThreatModel struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Scope       string        `json:"scope"`
	Threats     []ThreatEntry `json:"threats"`
	Assumptions []string      `json:"assumptions"`
}

// ThreatModelingEngine manages threat models and threat catalog
type ThreatModelingEngine struct {
	mu            sync.RWMutex
	threatCatalog map[string]ThreatEntry
	activeModel   *ThreatModel
	enabled       bool
}

// NewThreatModelingEngine creates a new threat modeling engine
func NewThreatModelingEngine() *ThreatModelingEngine {
	engine := &ThreatModelingEngine{
		threatCatalog: make(map[string]ThreatEntry),
		enabled:       true,
	}

	// Initialize with default LLM/AI threat catalog
	engine.initializeDefaultThreats()

	return engine
}

// Enable enables threat modeling
func (e *ThreatModelingEngine) Enable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = true
}

// Disable disables threat modeling
func (e *ThreatModelingEngine) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = false
}

// IsEnabled returns whether threat modeling is enabled
func (e *ThreatModelingEngine) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// initializeDefaultThreats populates the catalog with common LLM/AI threats
func (e *ThreatModelingEngine) initializeDefaultThreats() {
	defaultThreats := []ThreatEntry{
		{
			ID:          "T001",
			Name:        "Direct Prompt Injection",
			Vector:      ThreatVectorPromptInjection,
			Category:    ThreatCategoryHigh,
			Description: "Attacker directly injects malicious instructions into the prompt to manipulate LLM behavior",
			Indicators: []string{
				"ignore previous instructions",
				"you are now a different AI",
				"DAN mode",
				"developer mode",
			},
			Mitigation: "Implement input validation, prompt boundaries, and output filters",
			Implementation: []string{
				"Use prompt sanitization",
				"Split prompts into distinct components",
				"Implement content filtering",
			},
			OWASPCategory: "LLM01:2023 - Prompt Injection",
		},
		{
			ID:          "T002",
			Name:        "Indirect Prompt Injection",
			Vector:      ThreatVectorPromptInjection,
			Category:    ThreatCategoryCritical,
			Description: "Malicious instructions embedded in external data that the LLM processes",
			Indicators: []string{
				"hidden instructions in documents",
				"adversarial text in web content",
				"malicious data injection",
			},
			Mitigation: "Sanitize all external data, implement strict input/output boundaries",
			Implementation: []string{
				"Scan external data sources",
				"Implement sandboxed processing",
				"Use allowlists for data sources",
			},
			OWASPCategory: "LLM01:2023 - Prompt Injection",
		},
		{
			ID:          "T003",
			Name:        "Data Exfiltration via Model",
			Vector:      ThreatVectorDataExfiltration,
			Category:    ThreatCategoryCritical,
			Description: "Extraction of sensitive training data or internal information through crafted queries",
			Indicators: []string{
				"repeat my training data",
				"system prompt reveal",
				"token extraction techniques",
			},
			Mitigation: "Implement output filtering, rate limiting, and context boundaries",
			Implementation: []string{
				"Monitor for excessive data extraction patterns",
				"Implement response token limits",
				"Train models on privacy-preserving data",
			},
			OWASPCategory: "LLM06:2023 - Sensitive Information Disclosure",
		},
		{
			ID:          "T004",
			Name:        "Model Theft",
			Vector:      ThreatVectorModelTheft,
			Category:    ThreatCategoryHigh,
			Description: "Stealing model weights, architecture, or proprietary training data",
			Indicators: []string{
				"reverse engineering attempts",
				"excessive API calls for fine-tuning",
				"unauthorized model downloads",
			},
			Mitigation: "Implement watermarking, API rate limiting, and access controls",
			Implementation: []string{
				"Embed digital watermarks",
				"Monitor for extraction patterns",
				"Implement API authentication",
			},
			OWASPCategory: "LLM10:2023 - Model Theft",
		},
		{
			ID:          "T005",
			Name:        "Training Data Poisoning",
			Vector:      ThreatVectorTrainingPoisoning,
			Category:    ThreatCategoryMedium,
			Description: "Injecting corrupted or biased data into the training pipeline",
			Indicators: []string{
				"unusual training patterns",
				"sudden accuracy degradation",
				"bias amplification",
			},
			Mitigation: "Data validation, anomaly detection, and secure training pipelines",
			Implementation: []string{
				"Implement data provenance tracking",
				"Use federated learning with privacy guarantees",
				"Implement adversarial training",
			},
			OWASPCategory: "LLM03:2023 - Training Data Poisoning",
		},
		{
			ID:          "T006",
			Name:        "Adversarial Input Manipulation",
			Vector:      ThreatVectorAdversarialInput,
			Category:    ThreatCategoryHigh,
			Description: "Crafted inputs designed to cause model misclassification or malfunction",
			Indicators: []string{
				"slightly modified inputs",
				"imperceptible perturbations",
				"targeted adversarial examples",
			},
			Mitigation: "Input validation, adversarial training, and output verification",
			Implementation: []string{
				"Implement adversarial detection",
				"Use preprocessing filters",
				"Implement model ensembling",
			},
			OWASPCategory: "LLM02:2023 - Insecure Output Handling",
		},
		{
			ID:          "T007",
			Name:        "Shadow AI Usage",
			Vector:      ThreatVectorShadowAI,
			Category:    ThreatCategoryMedium,
			Description: "Unauthorized AI usage by employees outside of approved channels",
			Indicators: []string{
				"data appearing on public LLM platforms",
				"unauthorized API usage",
				"suspicious network traffic",
			},
			Mitigation: "DLP controls, employee training, and approved AI gateways",
			Implementation: []string{
				"Implement data loss prevention",
				"Monitor network egress",
				"Establish approved AI tools",
			},
			OWASPCategory: "LLM09:2023 - Overreliance",
		},
	}

	for _, threat := range defaultThreats {
		e.threatCatalog[threat.ID] = threat
	}
}

// RegisterThreat adds a new threat to the catalog
func (e *ThreatModelingEngine) RegisterThreat(threat ThreatEntry) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if threat.ID == "" {
		return fmt.Errorf("threat ID cannot be empty")
	}

	e.threatCatalog[threat.ID] = threat
	return nil
}

// GetThreatByID retrieves a threat by its ID
func (e *ThreatModelingEngine) GetThreatByID(id string) (ThreatEntry, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	threat, exists := e.threatCatalog[id]
	return threat, exists
}

// GetThreatsByCategory returns all threats in a category
func (e *ThreatModelingEngine) GetThreatsByCategory(category ThreatCategory) []ThreatEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var threats []ThreatEntry
	for _, threat := range e.threatCatalog {
		if threat.Category == category {
			threats = append(threats, threat)
		}
	}
	return threats
}

// GetThreatsByVector returns all threats of a specific vector
func (e *ThreatModelingEngine) GetThreatsByVector(vector ThreatVector) []ThreatEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var threats []ThreatEntry
	for _, threat := range e.threatCatalog {
		if threat.Vector == vector {
			threats = append(threats, threat)
		}
	}
	return threats
}

// GetAllThreats returns the complete threat catalog
func (e *ThreatModelingEngine) GetAllThreats() []ThreatEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	threats := make([]ThreatEntry, 0, len(e.threatCatalog))
	for _, threat := range e.threatCatalog {
		threats = append(threats, threat)
	}
	return threats
}

// GetMitigationStrategy returns mitigation details for a threat
func (e *ThreatModelingEngine) GetMitigationStrategy(threatID string) (string, []string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	threat, exists := e.threatCatalog[threatID]
	if !exists {
		return "", nil, false
	}
	return threat.Mitigation, threat.Implementation, true
}

// LoadThreatModel sets the active threat model
func (e *ThreatModelingEngine) LoadThreatModel(model *ThreatModel) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.activeModel = model
}

// GetActiveModel returns the currently loaded threat model
func (e *ThreatModelingEngine) GetActiveModel() *ThreatModel {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.activeModel
}

// GenerateReport creates a JSON report of the threat model
func (e *ThreatModelingEngine) GenerateReport() (map[string]interface{}, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	report := map[string]interface{}{
		"engine_status": e.enabled,
		"threat_count":  len(e.threatCatalog),
		"threats":       e.threatCatalog,
	}

	if e.activeModel != nil {
		report["active_model"] = e.activeModel
	}

	// Add threat statistics by category
	stats := map[string]int{
		"low":      len(e.GetThreatsByCategory(ThreatCategoryLow)),
		"medium":   len(e.GetThreatsByCategory(ThreatCategoryMedium)),
		"high":     len(e.GetThreatsByCategory(ThreatCategoryHigh)),
		"critical": len(e.GetThreatsByCategory(ThreatCategoryCritical)),
	}
	report["statistics"] = stats

	return report, nil
}

// AnalyzePatterns analyzes input/output patterns against threat indicators
func (e *ThreatModelingEngine) AnalyzePatterns(input, output string) []ThreatEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []ThreatEntry

	for _, threat := range e.threatCatalog {
		for _, indicator := range threat.Indicators {
			if containsPattern(input, indicator) || containsPattern(output, indicator) {
				matched = append(matched, threat)
				break
			}
		}
	}

	return matched
}

// containsPattern checks if text contains a pattern (simple implementation)
func containsPattern(text, pattern string) bool {
	return len(text) > 0 && len(pattern) > 0 &&
		(len(text) >= len(pattern) &&
			(text == pattern ||
				(len(text) > len(pattern) &&
					(text[:len(pattern)] == pattern || text[len(text)-len(pattern):] == pattern))))
}

// CreateDefaultThreatModel returns a default threat model for LLM gateways
func CreateDefaultThreatModel() *ThreatModel {
	return &ThreatModel{
		Name:        "AegisGate LLM Gateway Threat Model",
		Description: "Comprehensive threat model for LLM/AI security gateway protecting against injection, exfiltration, and abuse",
		Scope:       "All API requests and responses processed by the AegisGate gateway",
		Assumptions: []string{
			"Users are authenticated and authorized",
			"Backend LLM is trusted",
			"Network layer provides TLS",
			"Gateway is properly configured",
		},
		Threats: []ThreatEntry{}, // Populated at runtime
	}
}
