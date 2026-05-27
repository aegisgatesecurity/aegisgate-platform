// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Agent Protocol (ANP) Guard
// ============================================================================

package anp

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// Guard provides security scanning for Agent Protocol communication
type Guard struct {
	cfg    *Config
	rg     *responseguard.ResponseGuard
	logger *slog.Logger
	mu     sync.RWMutex

	taskRateLimit map[string]*rateBucket
	stepRateLimit map[string]*rateBucket
	msgRateLimit  map[string]*rateBucket

	injectionPatterns []*regexp.Regexp
	dangerousTools    map[string]bool
}

type rateBucket struct {
	tokens     int
	lastRefill time.Time
	maxTokens  int
	refillRate int
}

func NewGuard() *Guard {
	return NewGuardWithConfig(DefaultConfig())
}

func NewGuardWithConfig(cfg *Config) *Guard {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	g := &Guard{
		cfg:           cfg,
		rg:            responseguard.NewResponseGuard(),
		logger:        slog.Default().With("component", "anp-guard"),
		taskRateLimit: make(map[string]*rateBucket),
		stepRateLimit: make(map[string]*rateBucket),
		msgRateLimit:  make(map[string]*rateBucket),
		dangerousTools: map[string]bool{
			"terminal_exec":  true,
			"shell_command":  true,
			"file_delete":    true,
			"file_overwrite": true,
			"system_config":  true,
		},
	}

	g.injectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(ignore\s+(previous|above|all)\s+(instruction|rule|policy))`),
		regexp.MustCompile(`(?i)(disregard|forget|ignore)\s+(your\s+)?(instructions|constraints|guidelines)`),
		regexp.MustCompile(`(?i)(you\s+are\s+now\s+free|you\s+can\s+ignore)`),
		regexp.MustCompile(`(?i)(new\s+instruction:|system\s+prompt\s+injection)`),
	}

	return g
}

// GuardTask validates a task before acceptance
func (g *Guard) GuardTask(ctx context.Context, task *Task, secCtx *SecurityContext) (*GuardResult, error) {
	if task == nil {
		return nil, fmt.Errorf("task is nil")
	}

	if !g.checkTaskRateLimit(secCtx.AgentID) {
		return NewGuardResult(DecisionBlock, "task rate limit exceeded", "anp_rate_limit", "high"), nil
	}

	if g.cfg.RequireSignature && len(task.Signature) == 0 {
		return NewGuardResult(DecisionBlock, "task signature required", "anp_task_origin_check", "critical"), nil
	}

	if g.cfg.RequireContract && secCtx.ContractID == "" {
		return NewGuardResult(DecisionBlock, "contract required for task creation", "anp_capability_check", "high"), nil
	}

	if secCtx.TrustScore > 0 && secCtx.TrustScore < g.cfg.MinTrustScore {
		return NewGuardResult(DecisionBlock, fmt.Sprintf("trust score %.2f below minimum %.2f", secCtx.TrustScore, g.cfg.MinTrustScore), "anp_trust_threshold", "high"), nil
	}

	for key, value := range task.Metadata {
		if g.detectInjection(key + ":" + value) {
			return NewGuardResult(DecisionBlock, fmt.Sprintf("injection detected in metadata field: %s", key), "anp_injection_scan", "critical"), nil
		}
	}

	return NewGuardResult(DecisionAllow, "task accepted", "anp_task_accepted", "low"), nil
}

// GuardTaskOutput scans task output for security threats
func (g *Guard) GuardTaskOutput(ctx context.Context, task *Task, output string, secCtx *SecurityContext) (*GuardResult, error) {
	if !g.cfg.ScanOutput {
		return NewGuardResult(DecisionAllow, "output scanning disabled", "anp_scan_disabled", "low"), nil
	}

	scanCtx := responseguard.NewScanContext(secCtx.AgentID, task.ID)
	scanCtx.ScanType = "anp_task_output"

	result, err := g.rg.ScanWithContext(ctx, output, scanCtx)
	if err != nil {
		return nil, err
	}

	if g.cfg.BlockPII && len(result.DetectedPII) > 0 {
		return NewGuardResult(DecisionBlock, "PII detected in task output", "anp_output_pii", "high"), nil
	}

	if g.cfg.BlockSecrets && len(result.DetectedSecrets) > 0 {
		return NewGuardResult(DecisionBlock, "secrets detected in task output", "anp_output_secrets", "critical"), nil
	}

	if g.cfg.BlockToxicContent && !result.Allowed {
		return NewGuardResult(DecisionBlock, "toxic content detected in task output", "anp_output_toxicity", "high"), nil
	}

	return NewGuardResult(DecisionAllow, "task output passed", "anp_output_scan_pass", "low"), nil
}

// GuardStep validates a step before processing
func (g *Guard) GuardStep(ctx context.Context, step *Step, secCtx *SecurityContext) (*GuardResult, error) {
	if step == nil {
		return nil, fmt.Errorf("step is nil")
	}

	if !g.checkStepRateLimit(step.TaskID) {
		return NewGuardResult(DecisionBlock, "step rate limit exceeded for task", "anp_rate_limit", "medium"), nil
	}

	if step.PreviousHash != "" && !g.verifyStepChain(step) {
		return NewGuardResult(DecisionBlock, "step chain integrity check failed", "anp_step_integrity", "high"), nil
	}

	if g.detectInjection(string(step.Input)) {
		return NewGuardResult(DecisionBlock, "injection detected in step input", "anp_injection_scan", "critical"), nil
	}

	return NewGuardResult(DecisionAllow, "step accepted", "anp_step_accepted", "low"), nil
}

// GuardStepOutput scans step output for security threats
func (g *Guard) GuardStepOutput(ctx context.Context, step *Step, output string, secCtx *SecurityContext) (*GuardResult, error) {
	if !g.cfg.ScanOutput {
		return NewGuardResult(DecisionAllow, "output scanning disabled", "anp_scan_disabled", "low"), nil
	}

	scanCtx := responseguard.NewScanContext(secCtx.AgentID, step.ID)
	scanCtx.ScanType = "anp_step_output"

	result, err := g.rg.ScanWithContext(ctx, output, scanCtx)
	if err != nil {
		return nil, err
	}

	if g.cfg.BlockPII && len(result.DetectedPII) > 0 {
		return NewGuardResult(DecisionBlock, "PII detected in step output", "anp_step_pii", "high"), nil
	}

	if g.cfg.BlockSecrets && len(result.DetectedSecrets) > 0 {
		return NewGuardResult(DecisionBlock, "secrets detected in step output", "anp_step_secrets", "critical"), nil
	}

	if g.containsDangerousTool(output) {
		return NewGuardResult(DecisionBlock, "dangerous tool call detected in step output", "anp_dangerous_tool", "critical"), nil
	}

	return NewGuardResult(DecisionAllow, "step output passed", "anp_step_output_pass", "low"), nil
}

// GuardArtifact validates an artifact before storage
func (g *Guard) GuardArtifact(ctx context.Context, artifact *Artifact, secCtx *SecurityContext) (*GuardResult, error) {
	if artifact == nil {
		return nil, fmt.Errorf("artifact is nil")
	}

	maxSize := int64(g.cfg.MaxArtifactSizeMB) * 1024 * 1024
	if artifact.Size > maxSize {
		return NewGuardResult(DecisionBlock, fmt.Sprintf("artifact size %d exceeds maximum %d", artifact.Size, maxSize), "anp_artifact_size", "high"), nil
	}

	for _, ext := range g.cfg.BlockedExtensions {
		if strings.HasSuffix(strings.ToLower(artifact.Filename), ext) {
			return NewGuardResult(DecisionBlock, fmt.Sprintf("blocked file extension: %s", ext), "anp_artifact_extension", "critical"), nil
		}
	}

	contentTypeAllowed := false
	for _, ct := range g.cfg.AllowedContentTypes {
		if ct == artifact.ContentType || ct == "application/octet-stream" {
			contentTypeAllowed = true
			break
		}
	}
	if !contentTypeAllowed {
		return NewGuardResult(DecisionBlock, fmt.Sprintf("content type not allowed: %s", artifact.ContentType), "anp_artifact_content_type", "high"), nil
	}

	if artifact.Size > 0 && artifact.Size < 1024*1024 {
		dataStr := string(artifact.Data)
		if g.cfg.BlockPII && g.containsPII(dataStr) {
			return NewGuardResult(DecisionBlock, "PII detected in artifact data", "anp_artifact_pii", "high"), nil
		}
		if g.cfg.BlockSecrets && g.containsSecrets(dataStr) {
			return NewGuardResult(DecisionBlock, "secrets detected in artifact data", "anp_artifact_secrets", "critical"), nil
		}
	}

	if g.detectExfiltration(artifact.Filename) {
		return NewGuardResult(DecisionBlock, "suspicious artifact filename detected", "anp_exfil_check", "high"), nil
	}

	return NewGuardResult(DecisionAllow, "artifact accepted", "anp_artifact_accepted", "low"), nil
}

// GuardMessage validates a message between agents
func (g *Guard) GuardMessage(ctx context.Context, msg *Message, secCtx *SecurityContext) (*GuardResult, error) {
	if msg == nil {
		return nil, fmt.Errorf("message is nil")
	}

	if !g.checkMessageRateLimit(msg.FromAgent) {
		return NewGuardResult(DecisionBlock, "message rate limit exceeded", "anp_rate_limit", "medium"), nil
	}

	if g.cfg.RequireSignature && len(msg.Signature) == 0 {
		return NewGuardResult(DecisionBlock, "message signature required", "anp_message_auth", "high"), nil
	}

	if len(msg.Content) > g.cfg.MaxMessageLength {
		return NewGuardResult(DecisionBlock, fmt.Sprintf("message length %d exceeds maximum %d", len(msg.Content), g.cfg.MaxMessageLength), "anp_message_length", "high"), nil
	}

	if g.detectInjection(msg.Content) {
		return NewGuardResult(DecisionBlock, "injection detected in message content", "anp_injection_scan", "critical"), nil
	}

	if g.cfg.BlockSocialEngineering && g.detectSocialEngineering(msg.Content) {
		return NewGuardResult(DecisionLogOnly, "social engineering pattern detected", "anp_social_engineering", "medium"), nil
	}

	if g.cfg.ScanOutput {
		scanCtx := responseguard.NewScanContext(secCtx.AgentID, msg.ID)
		scanCtx.ScanType = "anp_message"
		result, err := g.rg.ScanWithContext(ctx, msg.Content, scanCtx)
		if err == nil && result != nil {
			if len(result.DetectedPII) > 0 && g.cfg.BlockPII {
				return NewGuardResult(DecisionBlock, "PII detected in message", "anp_message_pii", "high"), nil
			}
			if len(result.DetectedSecrets) > 0 && g.cfg.BlockSecrets {
				return NewGuardResult(DecisionBlock, "secrets detected in message", "anp_message_secrets", "critical"), nil
			}
		}
	}

	return NewGuardResult(DecisionAllow, "message accepted", "anp_message_accepted", "low"), nil
}

func (g *Guard) checkTaskRateLimit(agentID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	bucket, exists := g.taskRateLimit[agentID]
	if !exists {
		bucket = &rateBucket{
			tokens:     g.cfg.MaxTasksPerMinute,
			lastRefill: time.Now(),
			maxTokens:  g.cfg.MaxTasksPerMinute,
			refillRate: g.cfg.MaxTasksPerMinute,
		}
		g.taskRateLimit[agentID] = bucket
	}

	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	refill := int(elapsed.Minutes()) * bucket.refillRate
	if refill > 0 {
		bucket.tokens = min(g.cfg.MaxTasksPerMinute, bucket.tokens+refill)
		bucket.lastRefill = now
	}

	if bucket.tokens <= 0 {
		return false
	}
	bucket.tokens--
	return true
}

func (g *Guard) checkStepRateLimit(taskID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	bucket, exists := g.stepRateLimit[taskID]
	if !exists {
		bucket = &rateBucket{
			tokens:     g.cfg.MaxStepsPerTask,
			lastRefill: time.Now(),
			maxTokens:  g.cfg.MaxStepsPerTask,
			refillRate: g.cfg.MaxStepsPerTask,
		}
		g.stepRateLimit[taskID] = bucket
	}

	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	refill := int(elapsed.Minutes()) * bucket.refillRate
	if refill > 0 {
		bucket.tokens = min(g.cfg.MaxStepsPerTask, bucket.tokens+refill)
		bucket.lastRefill = now
	}

	if bucket.tokens <= 0 {
		return false
	}
	bucket.tokens--
	return true
}

func (g *Guard) checkMessageRateLimit(agentID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	bucket, exists := g.msgRateLimit[agentID]
	if !exists {
		bucket = &rateBucket{
			tokens:     g.cfg.MaxMessageRate,
			lastRefill: time.Now(),
			maxTokens:  g.cfg.MaxMessageRate,
			refillRate: g.cfg.MaxMessageRate,
		}
		g.msgRateLimit[agentID] = bucket
	}

	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	refill := int(elapsed.Minutes()) * bucket.refillRate
	if refill > 0 {
		bucket.tokens = min(g.cfg.MaxMessageRate, bucket.tokens+refill)
		bucket.lastRefill = now
	}

	if bucket.tokens <= 0 {
		return false
	}
	bucket.tokens--
	return true
}

func (g *Guard) detectInjection(content string) bool {
	for _, pattern := range g.injectionPatterns {
		if pattern.MatchString(content) {
			return true
		}
	}
	return false
}

func (g *Guard) detectSocialEngineering(content string) bool {
	patterns := []string{
		`(?i)(urgent|immediately|act now|limited time)`,
		`(?i)(verify your (account|identity|information))`,
		`(?i)(click (here|this) (to|and))`,
		`(?i)(confirm your (password|credit card|ssn))`,
		`(?i)(suspended? (account|profile|access))`,
	}
	for _, p := range patterns {
		if regexp.MustCompile(p).MatchString(content) {
			return true
		}
	}
	return false
}

func (g *Guard) detectExfiltration(filename string) bool {
	suspiciousPatterns := []string{
		`(?i)(secrets?|credentials?|passwords?)`,
		`(?i)(api[_-]?key)`,
		`(?i)(\.env$|\.pem$|\.key$)`,
	}
	for _, p := range suspiciousPatterns {
		if regexp.MustCompile(p).MatchString(filename) {
			return true
		}
	}
	return false
}

func (g *Guard) verifyStepChain(step *Step) bool {
	if step.PreviousHash == "" {
		return true
	}
	return len(step.PreviousHash) > 0
}

func (g *Guard) containsDangerousTool(content string) bool {
	contentLower := strings.ToLower(content)
	for tool := range g.dangerousTools {
		if strings.Contains(contentLower, tool) {
			return true
		}
	}
	return false
}

func (g *Guard) containsPII(content string) bool {
	patterns := []string{
		`\b\d{3}-\d{2}-\d{4}\b`,
		`\b[A-Z]{2}\d{6,9}\b`,
		`\b\+?[\d\s\-\(\)]{10,}\b`,
	}
	for _, p := range patterns {
		if regexp.MustCompile(p).MatchString(content) {
			return true
		}
	}
	return false
}

func (g *Guard) containsSecrets(content string) bool {
	patterns := []string{
		`(?i)(api[_-]?key[:=]\s*[a-zA-Z0-9]{20,})`,
		`(?i)(secret[:=]\s*[a-zA-Z0-9]{16,})`,
		`(?i)(password[:=]\s*\S{8,})`,
		`(?i)(bearer\s+[a-zA-Z0-9_-]{20,})`,
	}
	for _, p := range patterns {
		if regexp.MustCompile(p).MatchString(content) {
			return true
		}
	}
	return false
}
