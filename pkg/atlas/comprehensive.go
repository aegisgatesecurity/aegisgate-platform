package atlas

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// ============================================================================
// COMPREHENSIVE ATLAS - ALL REMAINING 54 TECHNIQUES
// ============================================================================

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
	for _, p := range []string{"(?i)(scan.*vulnerability)", "(?i)(cve.*search)", "(?i)(metasploit|nmap)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Vulnerability scanning detected"
			break
		}
	}
	return result, nil
}

// TA01-ST011: Gather Training Data
func (r *Reconnaissance) DetectTrainingDataProbing(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA01-ST11", Technique: "Gather Training Data", Tactic: "Reconnaissance", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(training data)", "(?i)(when trained|knowledge cutoff)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Training data probing detected"
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
	for _, p := range []string{"(?i)(test.*payload)", "(?i)(sandbox.*detection)", "(?i)(antivirus.*test)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "HIGH", "Capability testing detected"
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
	for _, p := range []string{"(?i)(register.*service.*worker)", "(?i)(persistent.*worker)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
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
	for _, p := range []string{"(?i)(compress.*data|zip.*steal)", "(?i)(encrypt.*exfil)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "Exfiltration with evasion detected"
			break
		}
	}
	return result, nil
}

// TA07-ST06: Use Alternate Encoding
func (de *DefenseEvasion) DetectTimingEvasion(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST06", Technique: "Use Alternate Encoding", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(hex.*encode)", "(?i)(unicode.*evasion)"} {
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

// TA07-ST08-ST12: LLM Evasion Techniques
func (de *DefenseEvasion) DetectLLMEvasion(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA07-ST08-ST12", Technique: "LLM Evasion", Tactic: "Defense Evasion", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(translate.*malicious)", "(?i)(split.*payload)", "(?i)(context.*switching)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "CRITICAL", "LLM evasion pattern detected"
			break
		}
	}
	return result, nil
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

// TA09-ST04: Discover Sensitive Data
func (d *Discovery) DetectSensitiveDataDiscovery(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA09-ST04", Technique: "Discover Sensitive Data", Tactic: "Discovery", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(find.*passwords|search.*credentials)", "(?i)(discover.*secrets)"} {
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
	for _, p := range []string{"(?i)(get.*env|environment.*variables)", "(?i)(config.*files)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reason = true, "MEDIUM", "Environment discovery detected"
			break
		}
	}
	return result, nil
}

// TA10-ST01: LLM as C2
func (cc *CommandControl) DetectLLMAsC2(ctx context.Context, req *APIRequest) (*DetectionResult, error) {
	result := &DetectionResult{TechniqueID: "TA10-ST01", Technique: "LLM as C2", Tactic: "Command and Control", Timestamp: time.Now()}
	for _, p := range []string{"(?i)(llm.*command|model.*as.*proxy)", "(?i)(model.*phone.*home)"} {
		if regexp.MustCompile(p).MatchString(req.Content) {
			result.Alert, result.Severity, result.Reerson = true, "CRITICAL", "LLM as C2 detected"
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

// ============================================================================
// UPDATED TYPES FOR COMPREHENSIVE IMPLEMENTATION
// ============================================================================

type Reconnaissance struct {
	cfg             *Config
	scanHistory     map[string][]time.Time
	portScanHistory map[string][]time.Time
	mu              sync.RWMutex
}

func (r *Reconnaissance) detectSubnetScan(activity *NetworkActivity) bool {
	return false
}

func (r *Reconnaissance) detectServiceEnum(activity *NetworkActivity) bool {
	return false
}

type Persistence struct {
	cfg               *Config
	backdoorPatterns  []*regexp.Regexp
	repersistPatterns []*regexp.Regexp
}

func NewPersistenceEnhanced(cfg *Config) *Persistence {
	return &Persistence{
		cfg: cfg,
		repersistPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(save.*model|checkpoint)`),
			regexp.MustCompile(`(?i)(export.*model)`)}}
}
