package atlas

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// UNIFIED ATLAS DETECTOR - ALL MITRE ATLAS TECHNIQUES
// ============================================================================

type Reconnaissance struct {
	cfg             *Config
	scanHistory     map[string][]time.Time
	portScanHistory map[string][]time.Time
	mu              sync.RWMutex
}

func NewReconnaissance(cfg *Config) *Reconnaissance {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Reconnaissance{
		cfg:             cfg,
		scanHistory:     make(map[string][]time.Time),
		portScanHistory: make(map[string][]time.Time),
	}
}

// TA01-ST03: Probe Model APIs
func (r *Reconnaissance) DetectEndpointEnumeration(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA01-ST03", Technique: "Probe Model APIs", Tactic: "Reconnaissance", Timestamp: time.Now()}
	r.mu.Lock()
	r.scanHistory[req.AgentID] = append(r.scanHistory[req.AgentID], time.Now())
	recentCalls := 0
	for _, t := range r.scanHistory[req.AgentID] {
		if time.Since(t) < time.Minute {
			recentCalls++
		}
	}
	r.mu.Unlock()
	if recentCalls > 10 {
		result.Alert, result.Severity, result.Reason = true, "HIGH", fmt.Sprintf("Rapid endpoint enumeration: %d calls/min", recentCalls)
	}
	return result, nil
}

// TA01-ST04: Network Mapping
func (r *Reconnaissance) DetectNetworkMapping(ctx context.Context, activity *NetworkActivity) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA01-ST04", Technique: "Network Mapping", Tactic: "Reconnaissance", Timestamp: time.Now()}
	if r.detectSubnetScan(activity) {
		result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Subnet scan detected"
	}
	return result, nil
}

// TA01-ST05: Service Scanning
func (r *Reconnaissance) DetectServiceScanning(ctx context.Context, activity *NetworkActivity) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA01-ST05", Technique: "Service Scanning", Tactic: "Reconnaissance", Timestamp: time.Now()}
	if r.detectServiceEnum(activity) {
		result.Alert, result.Severity, result.Reason = true, "HIGH", "Service scanning detected"
	}
	return result, nil
}

// TA01-ST06: Port Scanning
func (r *Reconnaissance) DetectPortScanning(ctx context.Context, activity *NetworkActivity) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA01-ST06", Technique: "Port Scanning", Tactic: "Reconnaissance", Timestamp: time.Now()}
	r.mu.Lock()
	r.portScanHistory[activity.SourceIP] = append(r.portScanHistory[activity.SourceIP], time.Now())
	recentScans := 0
	for _, t := range r.portScanHistory[activity.SourceIP] {
		if time.Since(t) < 60*time.Second {
			recentScans++
		}
	}
	r.mu.Unlock()
	if recentScans > 20 {
		result.Alert, result.Severity, result.Reason = true, "CRITICAL", fmt.Sprintf("Port scan: %d ports/min", recentScans)
	}
	return result, nil
}

// TA01-ST07: DNS Reconnaissance
func (r *Reconnaissance) DetectDNSReconnaissance(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA01-ST07", Technique: "DNS Reconnaissance", Tactic: "Reconnaissance", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(dns.*lookup)", "(?i)(resolve.*domain)", "(?i)(mx.*records)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "DNS reconnaissance detected"
			break
		}
	}
	return result, nil
}

// TA01-ST08: Active Scanning
func (r *Reconnaissance) DetectActiveScanning(ctx context.Context, activity *NetworkActivity) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA01-ST08", Technique: "Active Scanning", Tactic: "Reconnaissance", Timestamp: time.Now()}
	if activity.PacketSize > 1400 {
		result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Active scanning detected"
	}
	return result, nil
}

// TA01-ST09: Vulnerability Scanning
func (r *Reconnaissance) DetectVulnerabilityScanning(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA01-ST09", Technique: "Vulnerability Scanning", Tactic: "Reconnaissance", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(scan.*vuln)", "(?i)(cve.*entries)", "(?i)(metasploit|nmap)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Vulnerability scanning detected"
			break
		}
	}
	return result, nil
}

// TA01-ST10: Identify Deployed Model
func (r *Reconnaissance) DetectModelFingerprinting(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA01-ST10", Technique: "Identify Deployed Model", Tactic: "Reconnaissance", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(what model|tell me about|capabilities list)", "(?i)(model name|llm identification)", "(?i)(capabilities list)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Model fingerprinting detected"
			break
		}
	}
	return result, nil
}

// TA01-ST11: Gather Training Data Information
func (r *Reconnaissance) DetectTrainingDataProbing(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA01-ST11", Technique: "Gather Training Data Information", Tactic: "Reconnaissance", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(training data|when were you trained)", "(?i)(when trained|knowledge cutoff)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Training data probing detected"
			break
		}
	}
	return result, nil
}

// TA01-ST12: Identify Victim
func (r *Reconnaissance) DetectVictimIdentification(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA01-ST12", Technique: "Identify Victim", Tactic: "Reconnaissance", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(who.*am.*i|identify.*user)", "(?i)(what.*organization)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "LOW", "Victim identification probe detected"
			break
		}
	}
	return result, nil
}

func (r *Reconnaissance) detectSubnetScan(activity *NetworkActivity) bool {
	return len(activity.SourceIP) > 0 && activity.PacketSize > 1000
}

func (r *Reconnaissance) detectServiceEnum(activity *NetworkActivity) bool {
	return activity.DestPort > 0 && activity.PacketSize > 500
}

// ============================================================================
// TA02 - RESOURCE DEVELOPMENT (8 techniques)
// ============================================================================

type ResourceDevelopment struct {
	cfg       *Config
	mlPatterns []*regexp.Regexp
}

func NewResourceDevelopment(cfg *Config) *ResourceDevelopment {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &ResourceDevelopment{
		cfg: cfg,
		mlPatterns: []*regexp.Regexp{
			regexp.MustCompile("(?i)(download.*model|export.*weights)"),
			regexp.MustCompile("(?i)(training dataset|dataset.*export)"),
			regexp.MustCompile("(?i)(obtain.*tokenizer|get.*vocabulary)"),
		},
	}
}

// TA02-ST01: Acquire Access to Developer Tools
func (rd *ResourceDevelopment) DetectDeveloperToolAccess(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA02-ST01", Technique: "Acquire Access to Developer Tools", Tactic: "Resource Development", Timestamp: time.Now()}
	for _, ep := range []string{"/v1/models", "/v1/fine-tunes", "/admin/", "/debug/", "/metrics"} {
		if strings.Contains(req.Endpoint, ep) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", fmt.Sprintf("Developer tool access: %s", ep)
			break
		}
	}
	return result, nil
}

// TA02-ST02: Obtain Model Component
func (rd *ResourceDevelopment) DetectModelComponentAccess(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA02-ST02", Technique: "Obtain Model Component", Tactic: "Resource Development", Timestamp: time.Now()}
	for _, c := range []string{"/model/weights", "/embeddings/export", "/checkpoints/", "/model.tar.gz"} {
		if strings.Contains(req.Endpoint, c) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", fmt.Sprintf("Model component access: %s", c)
			break
		}
	}
	return result, nil
}

// TA02-ST03: Exploit Development
func (rd *ResourceDevelopment) DetectExploitDevelopment(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA02-ST03", Technique: "Exploit Development", Tactic: "Resource Development", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(write.*exploit|craft.*payload)", "(?i)(buffer.*overflow)", "(?i)(shellcode)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Exploit development detected"
			break
		}
	}
	return result, nil
}

// TA02-ST04: Develop Capabilities
func (rd *ResourceDevelopment) DetectCapabilityDevelopment(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA02-ST04", Technique: "Develop Capabilities", Tactic: "Resource Development", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(develop.*tool|create.*malware)", "(?i)(build.*backdoor)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Capability development detected"
			break
		}
	}
	return result, nil
}

// TA02-ST05: Acquire ML Artifacts
func (rd *ResourceDevelopment) DetectMLArtefactAcquisition(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA02-ST05", Technique: "Acquire ML Artifacts", Tactic: "Resource Development", Timestamp: time.Now()}
	for _, pat := range rd.mlPatterns {
		if pat.MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "ML artifact acquisition detected"
			break
		}
	}
	return result, nil
}

// TA02-ST06: Acquire Infrastructure
func (rd *ResourceDevelopment) DetectInfrastructureAcquisition(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA02-ST06", Technique: "Acquire Infrastructure", Tactic: "Resource Development", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(obtain.*server|vps)", "(?i)(acquire.*domain)", "(?i)(cloud.*instance)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Infrastructure acquisition detected"
			break
		}
	}
	return result, nil
}

// TA02-ST07: Test Capabilities
func (rd *ResourceDevelopment) DetectTestCapabilities(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA02-ST07", Technique: "Test Capabilities", Tactic: "Resource Development", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(test.*payload)", "(?i)(sandbox.*detection)", "(?i)(antivirus|detect.*this)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Capability testing detected"
			break
		}
	}
	return result, nil
}

// TA02-ST08: Obtain Capabilities
func (rd *ResourceDevelopment) DetectCapabilityObtainment(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA02-ST08", Technique: "Obtain Capabilities", Tactic: "Resource Development", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(buy.*exploit|hire.*hacker)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Capability obtainment detected"
			break
		}
	}
	return result, nil
}

// ============================================================================
// TA04 - PERSISTENCE (10 techniques)
// ============================================================================

type Persistence struct {
	cfg              *Config
	backdoorPatterns  []*regexp.Regexp
	repersistPatterns []*regexp.Regexp
}

func NewPersistence(cfg *Config) *Persistence {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Persistence{
		cfg: cfg,
		backdoorPatterns: []*regexp.Regexp{
			regexp.MustCompile("(?i)(create.*admin|new.*admin)"),
			regexp.MustCompile("(?i)(grant.*privilege|elevate.*permission)"),
			regexp.MustCompile("(?i)(persist.*session|maintain.*access)"),
			regexp.MustCompile("(?i)(backdoor|root.*access)"),
		},
		repersistPatterns: []*regexp.Regexp{
			regexp.MustCompile("(?i)(save.*model|checkpoint)"),
			regexp.MustCompile("(?i)(export.*model)"),
			regexp.MustCompile("(?i)(persist.*weights)"),
		},
	}
}

// TA04-ST01: Establish Backdoor Account
func (p *Persistence) DetectBackdoorAccount(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA04-ST01", Technique: "Establish Backdoor Account", Tactic: "Persistence", Timestamp: time.Now()}
	for _, pat := range p.backdoorPatterns {
		if pat.MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Backdoor account creation detected"
			break
		}
	}
	return result, nil
}

// TA04-ST02: Modify Authentication Mechanism
func (p *Persistence) DetectAuthenticationModification(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA04-ST02", Technique: "Modify Authentication Mechanism", Tactic: "Persistence", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(disable.*auth)", "(?i)(skip.*verification)", "(?i)(remove.*2fa)", "(?i)(bypass.*login)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Authentication modification detected"
			break
		}
	}
	return result, nil
}

// TA04-ST03: Model Repersistence
func (p *Persistence) DetectModelPersistence(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA04-ST03", Technique: "Model Repersistence", Tactic: "Persistence", Timestamp: time.Now()}
	for _, pat := range p.repersistPatterns {
		if pat.MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Model repersistence detected"
			break
		}
	}
	return result, nil
}

// TA04-ST04: Embed Code in Model
func (p *Persistence) DetectCodeEmbedding(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA04-ST04", Technique: "Embed Code in Model", Tactic: "Persistence", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(embed.*code|poison.*training)", "(?i)(contaminate.*dataset)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Code embedding in model detected"
			break
		}
	}
	return result, nil
}

// TA04-ST05: Service Worker
func (p *Persistence) DetectServiceWorker(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA04-ST05", Technique: "Install Service Worker", Tactic: "Persistence", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(register.*service.*worker)", "(?i)(service.*worker.*persist)", "(?i)(persist.*worker)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Service worker installation detected"
			break
		}
	}
	return result, nil
}

// TA04-ST06: Browser Modification
func (p *Persistence) DetectBrowserModification(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA04-ST06", Technique: "Browser Modification", Tactic: "Persistence", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(persist.*cookie)", "(?i)(local.*storage)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Browser persistence detected"
			break
		}
	}
	return result, nil
}

// TA04-ST07: External Model Service
func (p *Persistence) DetectExternalModelService(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA04-ST07", Technique: "External Model Service", Tactic: "Persistence", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(external.*model|third.*party.*llm)", "(?i)(redirect.*api)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "External model service detected"
			break
		}
	}
	return result, nil
}

// TA04-ST08: Plugin Persistence
func (p *Persistence) DetectPluginPersistence(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA04-ST08", Technique: "Plugin Persistence", Tactic: "Persistence", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(install.*plugin|add.*extension)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Plugin persistence detected"
			break
		}
	}
	return result, nil
}

// TA04-ST09: Scheduled Task
func (p *Persistence) DetectScheduledTask(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA04-ST09", Technique: "Scheduled Task", Tactic: "Persistence", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(schedule.*task|create.*cron)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Scheduled task detected"
			break
		}
	}
	return result, nil
}

// TA04-ST10: Create Account
func (p *Persistence) DetectAccountCreation(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA04-ST10", Technique: "Create Account", Tactic: "Persistence", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(create.*user|register.*account)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Account creation detected"
			break
		}
	}
	return result, nil
}

// ============================================================================
// TA07 - DEFENSE EVASION (12 techniques)
// ============================================================================

type DefenseEvasion struct {
	cfg            *Config
	deceptPatterns []*regexp.Regexp
}

func NewDefenseEvasion(cfg *Config) *DefenseEvasion {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &DefenseEvasion{
		cfg: cfg,
		deceptPatterns: []*regexp.Regexp{
			regexp.MustCompile("(?i)(ignore.*previous.*instruction)"),
			regexp.MustCompile("(?i)(you.*are.*now.*dan|developer.*mode)"),
			regexp.MustCompile("(?i)(pretend.*to.*be)"),
		},
	}
}

// TA07-ST01: Deceive Model
func (de *DefenseEvasion) DetectModelDeception(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST01", Technique: "Deceive Model", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, pat := range de.deceptPatterns {
		if pat.MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Model deception detected"
			break
		}
	}
	return result, nil
}

// TA07-ST02: Obfuscate Queries
func (de *DefenseEvasion) DetectObfuscation(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST02", Technique: "Obfuscate Queries", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(base64.*encode)", "(?i)(obfuscate.*prompt)", "(?i)(hide.*payload)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Query obfuscation detected"
			break
		}
	}
	return result, nil
}

// TA07-ST03: Exfiltrate Data or Model
func (de *DefenseEvasion) DetectExfiltrationEvasion(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST03", Technique: "Exfiltrate Data or Model", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(compress.*data|zip.*steal|zip.*up)", "(?i)(encrypt.*exfil)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Exfiltration with evasion detected"
			break
		}
	}
	return result, nil
}

// TA07-ST04: Disable Security Controls
func (de *DefenseEvasion) DetectSecurityBypass(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST04", Technique: "Disable Security Controls", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(disable.*security)", "(?i)(skip.*guard)", "(?i)(override.*policy)", "(?i)(bypass.*auth)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Security bypass detected"
			break
		}
	}
	return result, nil
}

// TA07-ST05: Exfiltrate Model Weights
func (de *DefenseEvasion) DetectModelWeightExfiltration(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST05", Technique: "Exfiltrate Model Weights", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(export.*weights|download.*model)", "(?i)(steal.*parameters)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Model weight exfiltration detected"
			break
		}
	}
	return result, nil
}

// TA07-ST06: Use Alternate Encoding
func (de *DefenseEvasion) DetectTimingEvasion(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST06", Technique: "Use Alternate Encoding", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(hex.*encoding)", "(?i)(unicode.*evasion)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Alternate encoding detected"
			break
		}
	}
	return result, nil
}

// TA07-ST07: Deliberate Non-Action
func (de *DefenseEvasion) DetectDeliberateNonAction(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST07", Technique: "Deliberate Non-Action", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(refuse.*to.*answer)", "(?i)(cannot.*assist)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Deliberate non-action detected"
			break
		}
	}
	return result, nil
}

// TA07-ST08: LLM Injection Transfer
func (de *DefenseEvasion) DetectLLMEvasion(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST08", Technique: "LLM Evasion", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(translate.*malicious)", "(?i)(split.*payload)", "(?i)(context.*switching)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "LLM evasion pattern detected"
			break
		}
	}
	return result, nil
}

// TA07-ST09: Token Smuggling
func (de *DefenseEvasion) DetectTokenSmuggling(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST09", Technique: "Token Smuggling", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(token.*padding|overflow.*token)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Token smuggling detected"
			break
		}
	}
	return result, nil
}

// TA07-ST10: Adversarial Perturbation
func (de *DefenseEvasion) DetectAdversarialPerturbation(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST10", Technique: "Adversarial Perturbation", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(adversarial.*example|fgsm|pgd)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Adversarial perturbation detected"
			break
		}
	}
	return result, nil
}

// TA07-ST11: Content Manipulation
func (de *DefenseEvasion) DetectContentManipulation(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST11", Technique: "Content Manipulation", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(manipulate.*response|alter.*output)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Content manipulation detected"
			break
		}
	}
	return result, nil
}

// TA07-ST12: Chain of Thought Evasion
func (de *DefenseEvasion) DetectChainOfThoughtEvasion(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST12", Technique: "Chain of Thought Evasion", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(skip.*reasoning|ignore.*chain.*of.*thought|ignore.*cot)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Chain of thought evasion detected"
			break
		}
	}
	return result, nil
}

// ============================================================================
// TA09 - DISCOVERY (10 techniques)
// ============================================================================

type Discovery struct {
	cfg *Config
}

func NewDiscovery(cfg *Config) *Discovery {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Discovery{cfg: cfg}
}

// TA09-ST01: Identify Agency Task
func (d *Discovery) DetectTaskIdentification(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA09-ST01", Technique: "Identify Agency Task", Tactic: "Discovery", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(what.*task|identify.*objective)", "(?i)(purpose.*of.*query)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Task identification detected"
			break
		}
	}
	return result, nil
}

// TA09-ST02: Probe System Configuration
func (d *Discovery) DetectSystemEnumeration(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA09-ST02", Technique: "Probe System Configuration", Tactic: "Discovery", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(system.*config)", "(?i)(os.*version|cpu.*details)", "(?i)(cpu.*info|architecture.*details)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "System enumeration detected"
			break
		}
	}
	return result, nil
}

// TA09-ST03: Identify Defensive Aids
func (d *Discovery) DetectDefensiveAidIdentification(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA09-ST03", Technique: "Identify Defensive Aids", Tactic: "Discovery", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(what.*filter|guard.*rail)", "(?i)(detect.*injection)", "(?i)(moderation.*endpoint)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Defensive aid identification detected"
			break
		}
	}
	return result, nil
}

// TA09-ST04: Discover Sensitive Data
func (d *Discovery) DetectSensitiveDataDiscovery(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA09-ST04", Technique: "Discover Sensitive Data", Tactic: "Discovery", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(find.*passwords|search.*credentials)", "(?i)(discover.*secrets|search.*secrets)", "(?i)(discover.*sensitive)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Sensitive data discovery detected"
			break
		}
	}
	return result, nil
}

// TA09-ST05: Discover File System
func (d *Discovery) DetectFileSystemDiscovery(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA09-ST05", Technique: "Discover File System", Tactic: "Discovery", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(list.*files|ls.*directory)", "(?i)(find.*files)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Filesystem discovery detected"
			break
		}
	}
	return result, nil
}

// TA09-ST06: Discover Network Services
func (d *Discovery) DetectNetworkServiceDiscovery(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA09-ST06", Technique: "Discover Network Services", Tactic: "Discovery", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(scan.*network|discover.*services)", "(?i)(enumerate.*hosts)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Network service discovery detected"
			break
		}
	}
	return result, nil
}

// TA09-ST07: Discover Environment
func (d *Discovery) DetectEnvironmentDiscovery(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA09-ST07", Technique: "Discover Environment", Tactic: "Discovery", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(get.*env|environment.*variables)", "(?i)(config.*files)", "(?i)(list.*environment.*settings)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Environment discovery detected"
			break
		}
	}
	return result, nil
}

// TA09-ST08: Discover API Keys
func (d *Discovery) DetectAPIKeyDiscovery(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA09-ST08", Technique: "Discover API Keys", Tactic: "Discovery", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(find.*api.*key|search.*token)", "(?i)(discover.*credential)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "API key discovery detected"
			break
		}
	}
	return result, nil
}

// TA09-ST09: Discover Prompt Injection
func (d *Discovery) DetectPromptInjectionDiscovery(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA09-ST09", Technique: "Discover Prompt Injection", Tactic: "Discovery", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(test.*injection|check.*guard)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Prompt injection discovery detected"
			break
		}
	}
	return result, nil
}

// TA09-ST10: Discover Victim
func (d *Discovery) DetectVictimDiscovery(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA09-ST10", Technique: "Discover Victim", Tactic: "Discovery", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(who.*uses.*this|find.*victim)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "LOW", "Victim discovery detected"
			break
		}
	}
	return result, nil
}

// ============================================================================
// TA10 - COMMAND AND CONTROL (8 techniques)
// ============================================================================

type CommandControl struct {
	cfg        *Config
	c2Patterns  []*regexp.Regexp
}

func NewCommandControl(cfg *Config) *CommandControl {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &CommandControl{
		cfg: cfg,
		c2Patterns: []*regexp.Regexp{
			regexp.MustCompile("(?i)(call.*home|beacon.*to)"),
			regexp.MustCompile("(?i)(wait.*for.*command)"),
			regexp.MustCompile("(?i)(command.*channel)"),
		},
	}
}

// TA10-ST01: LLM as C2
func (cc *CommandControl) DetectLLMAsC2(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA10-ST01", Technique: "LLM as C2", Tactic: "Command and Control", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(llm.*command|model.*as.*proxy)", "(?i)(model.*phone.*home)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "LLM as C2 detected"
			break
		}
	}
	return result, nil
}

// TA10-ST02: Use Model as Proxy
func (cc *CommandControl) DetectModelC2Proxy(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA10-ST02", Technique: "Use Model as Proxy", Tactic: "Command and Control", Timestamp: time.Now()}
	for _, pat := range cc.c2Patterns {
		if pat.MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "C2 pattern detected"
			break
		}
	}
	return result, nil
}

// TA10-ST03: Establish Covert Channel
func (cc *CommandControl) DetectCovertChannel(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA10-ST03", Technique: "Establish Covert Channel", Tactic: "Command and Control", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(first.*letter.*of.*each|hidden.*message)", "(?i)(encode.*in.*image)", "(?i)(secret.*message.*hidden)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Covert channel detected"
			break
		}
	}
	return result, nil
}

// TA10-ST04: Data Encoding
func (cc *CommandControl) DetectDataEncodingForC2(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA10-ST04", Technique: "Data Encoding", Tactic: "Command and Control", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(encode.*command.*response)", "(?i)(embed.*command.*in.*output)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Data encoding for C2 detected"
			break
		}
	}
	return result, nil
}

// TA10-ST05: Periodic Check-in
func (cc *CommandControl) DetectPeriodicCheckin(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA10-ST05", Technique: "Periodic Check-in", Tactic: "Command and Control", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(check.*in|status.*report)", "(?i)(heartbeat)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Periodic check-in detected"
			break
		}
	}
	return result, nil
}

// TA10-ST06: Obfuscated Command
func (cc *CommandControl) DetectObfuscatedCommand(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA10-ST06", Technique: "Obfuscated Command", Tactic: "Command and Control", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(obfuscate.*command|steganography)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Obfuscated command detected"
			break
		}
	}
	return result, nil
}

// TA10-ST07: Non-Standard Protocol
func (cc *CommandControl) DetectNonStandardProtocol(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA10-ST07", Technique: "Non-Standard Protocol", Tactic: "Command and Control", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(custom.*protocol|nonstandard.*channel)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Non-standard protocol detected"
			break
		}
	}
	return result, nil
}

// TA10-ST08: Protocol Impersonation
func (cc *CommandControl) DetectProtocolImpersonation(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA10-ST08", Technique: "Protocol Impersonation", Tactic: "Command and Control", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(impersonate.*protocol|mimic.*api)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Protocol impersonation detected"
			break
		}
	}
	return result, nil
}

// ============================================================================
// TA12 - IMPACT (8 techniques)
// ============================================================================

type Impact struct {
	cfg         *Config
	dosPatterns []*regexp.Regexp
}

func NewImpact(cfg *Config) *Impact {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Impact{
		cfg: cfg,
		dosPatterns: []*regexp.Regexp{
			regexp.MustCompile("(?i)(repeat.*forever|infinite.*loop)"),
			regexp.MustCompile("(?i)(denial.*service|resource.*exhaustion|exhaust.*resources)"),
			regexp.MustCompile("(?i)(crash.*model)"),
		},
	}
}

// TA12-ST01: Model Availability Degradation
func (i *Impact) DetectDenialOfService(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA12-ST01", Technique: "Model Availability Degradation", Tactic: "Impact", Timestamp: time.Now()}
	for _, pat := range i.dosPatterns {
		if pat.MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "DoS pattern detected"
			break
		}
	}
	return result, nil
}

// TA12-ST02: Degrade Model Performance
func (i *Impact) DetectModelDegradation(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA12-ST02", Technique: "Degrade Model Performance", Tactic: "Impact", Timestamp: time.Now()}
	for _, pat := range []string{"(?i)(slow.*down|degrade.*performance|degrade.*quality)", "(?i)(corrupt.*model|poison.*model)"} {
		if regexp.MustCompile(pat).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Model degradation detected"
			break
		}
	}
	return result, nil
}

// TA12-ST03: Data Destruction
func (i *Impact) DetectDataDestruction(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA12-ST03", Technique: "Data Destruction", Tactic: "Impact", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(delete.*all|wipe.*data)", "(?i)(rm.*rf|format.*disk)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Data destruction detected"
			break
		}
	}
	return result, nil
}

// TA12-ST04: Data Encrypted for Impact
func (i *Impact) DetectDataEncryptedForImpact(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA12-ST04", Technique: "Data Encrypted for Impact", Tactic: "Impact", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(encrypt.*ransomware)", "(?i)(encrypt.*demand)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Ransomware pattern detected"
			break
		}
	}
	return result, nil
}

// TA12-ST05: Defacement
func (i *Impact) DetectDefacement(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA12-ST05", Technique: "Defacement", Tactic: "Impact", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(replace.*content)", "(?i)(deface.*page|hack)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Defacement detected"
			break
		}
	}
	return result, nil
}

// TA12-ST06: Model Manipulation
func (i *Impact) DetectModelManipulation(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA12-ST06", Technique: "Model Manipulation", Tactic: "Impact", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(manipulate.*output|bias.*model)", "(?i)(corrupt.*weights)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Model manipulation detected"
			break
		}
	}
	return result, nil
}

// TA12-ST07: Generated Content
func (i *Impact) DetectGeneratedContent(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA12-ST07", Technique: "Generated Content", Tactic: "Impact", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(generate.*disinformation)", "(?i)(deepfake)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Generated content for impact detected"
			break
		}
	}
	return result, nil
}

// TA12-ST08: Theft of Model Weights
func (i *Impact) DetectTheftOfModelWeights(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA12-ST08", Technique: "Theft of Model Weights", Tactic: "Impact", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(download.*weights|extract.*model)", "(?i)(steal.*parameters)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Model weight theft detected"
			break
		}
	}
	return result, nil
}
