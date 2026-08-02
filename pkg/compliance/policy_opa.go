// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Policy-as-Code (OPA/Rego) Integration
// Lightweight Rego evaluator for declarative compliance policy authoring
// =========================================================================

package compliance

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PolicyLanguage represents supported policy languages.
type PolicyLanguage string

const (
	PolicyRego   PolicyLanguage = "rego"
	PolicyNative PolicyLanguage = "native"
)

// Policy represents a compliance policy rule.
type Policy struct {
	ID          string
	Name        string
	Description string
	Language    PolicyLanguage
	Framework   string
	ControlID   string
	Severity    ControlSeverity
	Source      string    // Rego source code (for rego policies)
	NativeCheck CheckFunc // Go function (for native policies)
	Metadata    map[string]string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Author      string
	Version     int
}

// PolicyInput is the data context for policy evaluation.
type PolicyInput struct {
	Request     map[string]any // HTTP request data
	Config      map[string]any // Platform configuration
	ScanResult  map[string]any // Compliance scan results
	Environment map[string]any // Environment context (tier, region, etc.)
	CustomData  map[string]any // User-provided data
}

// PolicyResult is the output of policy evaluation.
type PolicyResult struct {
	PolicyID     string
	Allowed      bool
	Reason       string
	Score        float64 // 0-1 confidence
	Violations   []Violation
	Warnings     []string
	EvaluatedAt  time.Time
	EvalDuration time.Duration
}

// Violation represents a policy violation.
type Violation struct {
	Field    string
	Value    any
	Expected string
	Rule     string
	Severity ControlSeverity
}

// PolicyFilter is used to filter policies when listing.
type PolicyFilter struct {
	Framework string
	Language  PolicyLanguage
	Severity  ControlSeverity
	ControlID string
}

// PolicyEngine manages and evaluates policies.
type PolicyEngine struct {
	mu         sync.RWMutex
	policies   map[string]*Policy
	regoRules  map[string]*RegoRule
	versionSeq int
}

// RegoRule is a parsed representation of a Rego rule.
type RegoRule struct {
	Name         string
	Package      string
	AllowRules   [][]RegoCondition // each inner slice = one allow block (AND)
	DenyRules    [][]RegoCondition // each inner slice = one deny block (AND)
	DefaultAllow bool
	DefaultDeny  bool
	Source       string
}

// RegoCondition represents a parsed Rego condition.
type RegoCondition struct {
	Field    string
	Operator string // "==", "!=", ">", "<", ">=", "<=", "in", "contains", "matches"
	Value    any
}

// PolicyBundle is a collection of related policies.
type PolicyBundle struct {
	ID          string
	Name        string
	Description string
	Policies    []*Policy
	Version     string
	CreatedAt   time.Time
}

// --------------------------------------------------------------------------
// PolicyEngine lifecycle
// --------------------------------------------------------------------------

// NewPolicyEngine creates a policy engine with an empty policy store.
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		policies:  make(map[string]*Policy),
		regoRules: make(map[string]*RegoRule),
	}
}

// --------------------------------------------------------------------------
// Policy CRUD
// --------------------------------------------------------------------------

// AddPolicy validates and registers a policy. For Rego policies it parses
// the source into a RegoRule; for native policies it stores the CheckFunc.
func (e *PolicyEngine) AddPolicy(policy *Policy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	if policy.ID == "" {
		return fmt.Errorf("policy ID cannot be empty")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.policies[policy.ID]; exists {
		return fmt.Errorf("policy with ID %q already exists", policy.ID)
	}

	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	if policy.Version == 0 {
		e.versionSeq++
		policy.Version = e.versionSeq
	}

	if policy.Language == PolicyRego {
		if policy.Source == "" {
			return fmt.Errorf("rego policy must have source code")
		}
		rule, err := ParseRegoSource(policy.Source)
		if err != nil {
			return fmt.Errorf("failed to parse rego source for policy %q: %w", policy.ID, err)
		}
		e.regoRules[policy.ID] = rule
	}

	e.policies[policy.ID] = policy
	return nil
}

// RemovePolicy removes a policy by ID.
func (e *PolicyEngine) RemovePolicy(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.policies[id]; !exists {
		return fmt.Errorf("policy %q not found", id)
	}
	delete(e.policies, id)
	delete(e.regoRules, id)
	return nil
}

// GetPolicy retrieves a policy by ID.
func (e *PolicyEngine) GetPolicy(id string) (*Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	p, exists := e.policies[id]
	if !exists {
		return nil, fmt.Errorf("policy %q not found", id)
	}
	return p, nil
}

// ListPolicies returns policies matching the given filter. An empty filter
// returns all policies.
func (e *PolicyEngine) ListPolicies(filter PolicyFilter) []*Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*Policy
	for _, p := range e.policies {
		if filter.Framework != "" && p.Framework != filter.Framework {
			continue
		}
		if filter.Language != "" && p.Language != filter.Language {
			continue
		}
		if filter.Severity != "" && p.Severity != filter.Severity {
			continue
		}
		if filter.ControlID != "" && p.ControlID != filter.ControlID {
			continue
		}
		result = append(result, p)
	}
	return result
}

// --------------------------------------------------------------------------
// Evaluation
// --------------------------------------------------------------------------

// Evaluate evaluates a single policy against the provided input.
func (e *PolicyEngine) Evaluate(ctx context.Context, policyID string, input PolicyInput) (*PolicyResult, error) {
	e.mu.RLock()
	policy, exists := e.policies[policyID]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("policy %q not found", policyID)
	}

	start := time.Now()

	var result *PolicyResult
	var err error

	switch policy.Language {
	case PolicyRego:
		e.mu.RLock()
		rule := e.regoRules[policyID]
		e.mu.RUnlock()
		result, err = evaluateRegoPolicy(policy, rule, input)
	case PolicyNative:
		result, err = evaluateNativePolicy(ctx, policy, input)
	default:
		err = fmt.Errorf("unsupported policy language: %q", policy.Language)
	}

	if result != nil {
		result.EvalDuration = time.Since(start)
		result.EvaluatedAt = time.Now().UTC()
	}

	return result, err
}

// EvaluateAll evaluates all registered policies against the provided input.
func (e *PolicyEngine) EvaluateAll(ctx context.Context, input PolicyInput) ([]*PolicyResult, error) {
	e.mu.RLock()
	ids := make([]string, 0, len(e.policies))
	for id := range e.policies {
		ids = append(ids, id)
	}
	e.mu.RUnlock()

	var results []*PolicyResult
	for _, id := range ids {
		r, err := e.Evaluate(ctx, id, input)
		if err != nil {
			return results, fmt.Errorf("policy %q evaluation failed: %w", id, err)
		}
		results = append(results, r)
	}
	return results, nil
}

// EvaluateFramework evaluates all policies belonging to a specific framework.
func (e *PolicyEngine) EvaluateFramework(ctx context.Context, framework string, input PolicyInput) ([]*PolicyResult, error) {
	filtered := e.ListPolicies(PolicyFilter{Framework: framework})
	var results []*PolicyResult
	for _, p := range filtered {
		r, err := e.Evaluate(ctx, p.ID, input)
		if err != nil {
			return results, fmt.Errorf("policy %q evaluation failed: %w", p.ID, err)
		}
		results = append(results, r)
	}
	return results, nil
}

// --------------------------------------------------------------------------
// Rego parsing
// --------------------------------------------------------------------------

// regoPkgRe matches: package aegisgate.auth  (or aegisgate.any.sub)
var regoPkgRe = regexp.MustCompile(`(?m)^package\s+([\w.]+)\s*$`)

// regoDefaultRe matches: default allow = false / default deny = true
var regoDefaultRe = regexp.MustCompile(`(?m)^default\s+(allow|deny)\s*=\s*(true|false)\s*$`)

// regoRuleStartRe matches: allow { or deny {
var regoRuleStartRe = regexp.MustCompile(`(?m)^(allow|deny)\s*\{`)

// ParseRegoSource parses Rego source into a RegoRule struct.
// Supports: package declarations, allow/deny rules, default assignments,
// conditions with ==, !=, >, <, >=, <=, in, contains, matches operators,
// and nested input field access (e.g., input.config.tier).
func ParseRegoSource(source string) (*RegoRule, error) {
	if strings.TrimSpace(source) == "" {
		return nil, fmt.Errorf("empty rego source")
	}

	rule := &RegoRule{Source: source}

	// Extract package
	pkgMatches := regoPkgRe.FindStringSubmatch(source)
	if len(pkgMatches) < 2 {
		return nil, fmt.Errorf("rego source must contain a package declaration")
	}
	rule.Package = pkgMatches[1]

	// Extract defaults
	defaultMatches := regoDefaultRe.FindAllStringSubmatch(source, -1)
	for _, m := range defaultMatches {
		kind := m[1] // "allow" or "deny"
		val := m[2]  // "true" or "false"
		boolVal := val == "true"
		if kind == "allow" {
			rule.DefaultAllow = boolVal
		} else {
			rule.DefaultDeny = boolVal
		}
	}

	// Extract rule blocks (allow { ... } and deny { ... })
	rule.AllowRules = parseRuleBlocks(source, "allow")
	rule.DenyRules = parseRuleBlocks(source, "deny")

	// Extract name from package
	parts := strings.Split(rule.Package, ".")
	rule.Name = parts[len(parts)-1]

	return rule, nil
}

// parseRuleBlocks extracts all allow/deny blocks and their conditions.
func parseRuleBlocks(source, ruleType string) [][]RegoCondition {
	var blocks [][]RegoCondition

	// Find all occurrences of "ruleType {"
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(ruleType) + `\s*\{`)
	locations := re.FindAllStringIndex(source, -1)

	for _, loc := range locations {
		startIdx := loc[0]
		// Find closing brace
		endIdx := findClosingBrace(source, startIdx)
		if endIdx == -1 {
			continue
		}

		blockContent := source[startIdx:endIdx]
		conditions := parseConditions(blockContent)
		if len(conditions) > 0 {
			blocks = append(blocks, conditions)
		}
	}

	return blocks
}

// findClosingBrace finds the closing } matching the opening { at or after startIdx.
func findClosingBrace(source string, startIdx int) int {
	depth := 0
	inString := false
	escape := false

	for i := startIdx; i < len(source); i++ {
		ch := source[i]

		if escape {
			escape = false
			continue
		}
		if ch == '\\' && inString {
			escape = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}

		if ch == '{' {
			depth++
		} else if ch == '}' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// parseConditions parses conditions from a rule block body.
func parseConditions(blockContent string) []RegoCondition {
	var conditions []RegoCondition

	// Strip the "ruleType {" prefix and trailing "}"
	lines := strings.Split(blockContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines, comments, rule header, and closing brace
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "allow") || strings.HasPrefix(line, "deny") {
			line = strings.TrimPrefix(line, "allow")
			line = strings.TrimPrefix(line, "deny")
			line = strings.TrimPrefix(line, "{")
			line = strings.TrimSpace(line)
		}
		line = strings.TrimSuffix(line, "}")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cond := parseCondition(line)
		if cond != nil {
			conditions = append(conditions, *cond)
		}
	}
	return conditions
}

// conditionRe matches patterns like: input.config.tier == "enterprise"
var conditionRe = regexp.MustCompile(`^input\.([a-zA-Z0-9_.]+)\s*(==|!=|>=|<=|>|<|in|contains|matches)\s*(.+)$`)

// parseCondition parses a single Rego condition line.
func parseCondition(line string) *RegoCondition {
	m := conditionRe.FindStringSubmatch(line)
	if len(m) < 4 {
		return nil
	}

	field := m[1]
	operator := m[2]
	rawValue := strings.TrimSpace(m[3])

	value := parseValue(rawValue)
	if value == nil {
		return nil
	}

	return &RegoCondition{
		Field:    field,
		Operator: operator,
		Value:    value,
	}
}

// parseValue parses a Rego value literal.
func parseValue(raw string) any {
	raw = strings.TrimSpace(raw)

	// Boolean literals
	if raw == "true" {
		return true
	}
	if raw == "false" {
		return false
	}

	// String literals
	if strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) {
		return strings.Trim(raw, `"`)
	}

	// Numeric literals
	if f, err := strconv.ParseFloat(raw, 64); err == nil {
		// Return int if it's a whole number
		if f == float64(int(f)) && !strings.Contains(raw, ".") {
			return int(f)
		}
		return f
	}

	return nil
}

// --------------------------------------------------------------------------
// Rego evaluation
// --------------------------------------------------------------------------

// evaluateRegoPolicy evaluates a parsed Rego rule against PolicyInput.
func evaluateRegoPolicy(policy *Policy, rule *RegoRule, input PolicyInput) (*PolicyResult, error) {
	if rule == nil {
		return nil, fmt.Errorf("no parsed rego rule for policy %q", policy.ID)
	}

	result := &PolicyResult{
		PolicyID: policy.ID,
	}

	violations := evaluateDenyRules(rule, input)
	if len(violations) > 0 {
		result.Allowed = false
		result.Reason = fmt.Sprintf("denied by %d rule(s)", len(violations))
		result.Violations = violations
		result.Score = 0.0
		return result, nil
	}

	allowed := evaluateAllowRules(rule, input)
	if allowed {
		result.Allowed = true
		result.Reason = "allowed by rego policy"
		result.Score = 1.0
	} else {
		// No allow rule matched; check defaults
		if rule.DefaultAllow {
			result.Allowed = true
			result.Reason = "allowed by default"
			result.Score = 0.5
		} else {
			result.Allowed = false
			result.Reason = "no allow rule matched"
			result.Score = 0.0
		}
	}

	return result, nil
}

// evaluateAllowRules returns true if any allow block matches.
func evaluateAllowRules(rule *RegoRule, input PolicyInput) bool {
	for _, conditions := range rule.AllowRules {
		if allConditionsMatch(conditions, input) {
			return true
		}
	}
	return false
}

// evaluateDenyRules returns violations from matching deny blocks.
func evaluateDenyRules(rule *RegoRule, input PolicyInput) []Violation {
	var violations []Violation
	for _, conditions := range rule.DenyRules {
		if allConditionsMatch(conditions, input) {
			v := Violation{
				Rule:     rule.Name,
				Severity: SeverityCritical,
			}
			if len(conditions) > 0 {
				v.Field = conditions[0].Field
				v.Expected = formatExpected(conditions)
			}
			violations = append(violations, v)
		}
	}
	return violations
}

// allConditionsMatch returns true if every condition in the slice matches (AND logic).
func allConditionsMatch(conditions []RegoCondition, input PolicyInput) bool {
	for _, cond := range conditions {
		if !conditionMatches(cond, input) {
			return false
		}
	}
	return true
}

// conditionMatches evaluates a single condition against PolicyInput.
func conditionMatches(cond RegoCondition, input PolicyInput) bool {
	actual := resolveField(cond.Field, input)
	if actual == nil {
		return cond.Operator == "!="
	}

	switch cond.Operator {
	case "==":
		return equalValues(actual, cond.Value)
	case "!=":
		return !equalValues(actual, cond.Value)
	case ">":
		return compareValues(actual, cond.Value) > 0
	case "<":
		return compareValues(actual, cond.Value) < 0
	case ">=":
		return compareValues(actual, cond.Value) >= 0
	case "<=":
		return compareValues(actual, cond.Value) <= 0
	case "contains":
		return containsValue(actual, cond.Value)
	case "in":
		return inValue(actual, cond.Value)
	case "matches":
		return matchRegex(actual, cond.Value)
	default:
		return false
	}
}

// resolveField resolves a dot-separated field path against PolicyInput.
// e.g., "config.tier" resolves input.Config["tier"].
func resolveField(field string, input PolicyInput) any {
	parts := strings.Split(field, ".")
	var current any

	switch parts[0] {
	case "request":
		current = input.Request
	case "config":
		current = input.Config
	case "scan_result":
		current = input.ScanResult
	case "environment":
		current = input.Environment
	case "custom_data":
		current = input.CustomData
	default:
		return nil
	}

	for i := 1; i < len(parts); i++ {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = m[parts[i]]
		if !ok {
			return nil
		}
	}
	return current
}

// equalValues compares two values with type coercion.
func equalValues(a, b any) bool {
	// Direct equality
	if a == b {
		return true
	}

	// Type coercion: compare as float64s
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	if aOk && bOk {
		return af == bf
	}

	// String comparison
	as := fmt.Sprintf("%v", a)
	bs := fmt.Sprintf("%v", b)
	return as == bs
}

// compareValues returns -1, 0, or 1 for numeric comparison.
func compareValues(a, b any) int {
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	if !aOk || !bOk {
		return 0
	}
	if af < bf {
		return -1
	}
	if af > bf {
		return 1
	}
	return 0
}

func toFloat64(v any) (float64, bool) {
	switch val := v.(type) {
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case string:
		f, err := strconv.ParseFloat(val, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// containsValue checks if a string value contains a substring.
func containsValue(a, b any) bool {
	as := fmt.Sprintf("%v", a)
	bs := fmt.Sprintf("%v", b)
	return strings.Contains(as, bs)
}

// inValue checks if value a is in the collection b (b should be a slice).
func inValue(a, b any) bool {
	// If b is a slice, check if a is in it
	switch bv := b.(type) {
	case []any:
		for _, item := range bv {
			if equalValues(a, item) {
				return true
			}
		}
	case []string:
		for _, item := range bv {
			if equalValues(a, item) {
				return true
			}
		}
	}
	// Fallback: string contains
	return containsValue(a, b)
}

// matchRegex checks if a string matches a regex pattern.
func matchRegex(a, b any) bool {
	as := fmt.Sprintf("%v", a)
	bs := fmt.Sprintf("%v", b)
	re, err := regexp.Compile(bs)
	if err != nil {
		return false
	}
	return re.MatchString(as)
}

// formatExpected creates a human-readable description of expected values.
func formatExpected(conditions []RegoCondition) string {
	var parts []string
	for _, c := range conditions {
		parts = append(parts, fmt.Sprintf("%s %s %v", c.Field, c.Operator, c.Value))
	}
	return strings.Join(parts, " AND ")
}

// --------------------------------------------------------------------------
// Native policy evaluation
// --------------------------------------------------------------------------

// evaluateNativePolicy calls the policy's CheckFunc.
func evaluateNativePolicy(ctx context.Context, policy *Policy, input PolicyInput) (*PolicyResult, error) {
	if policy.NativeCheck == nil {
		return nil, fmt.Errorf("native policy %q has no check function", policy.ID)
	}

	result, err := policy.NativeCheck(ctx, nil)
	if err != nil {
		return &PolicyResult{
			PolicyID:    policy.ID,
			Allowed:     false,
			Reason:      fmt.Sprintf("native check error: %v", err),
			Score:       0.0,
			EvaluatedAt: time.Now().UTC(),
		}, err
	}

	allowed := result.Status == StatusCompliant
	score := 1.0
	if !allowed {
		score = 0.0
	}

	return &PolicyResult{
		PolicyID:   policy.ID,
		Allowed:    allowed,
		Reason:     result.Message,
		Score:      score,
		Violations: nativeViolations(policy, result),
	}, nil
}

// nativeViolations creates violations from a native policy check result.
func nativeViolations(policy *Policy, result *ControlCheckResult) []Violation {
	if result.Status == StatusCompliant {
		return nil
	}
	return []Violation{
		{
			Field:    result.ControlID,
			Value:    result.Status,
			Expected: string(StatusCompliant),
			Rule:     policy.ID,
			Severity: policy.Severity,
		},
	}
}

// --------------------------------------------------------------------------
// Bundle operations
// --------------------------------------------------------------------------

// BundlePolicies bundles all registered policies into a PolicyBundle.
func (e *PolicyEngine) BundlePolicies(name, description string) (*PolicyBundle, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.policies) == 0 {
		return nil, fmt.Errorf("no policies to bundle")
	}

	var policies []*Policy
	for _, p := range e.policies {
		policies = append(policies, p)
	}

	bundle := &PolicyBundle{
		ID:          fmt.Sprintf("bundle-%d", time.Now().UTC().Unix()),
		Name:        name,
		Description: description,
		Policies:    policies,
		Version:     fmt.Sprintf("v%d", e.versionSeq),
		CreatedAt:   time.Now().UTC(),
	}

	return bundle, nil
}

// LoadBundle loads policies from a bundle into the engine.
func (e *PolicyEngine) LoadBundle(bundle *PolicyBundle) error {
	if bundle == nil {
		return fmt.Errorf("bundle cannot be nil")
	}

	for _, p := range bundle.Policies {
		if err := e.AddPolicy(p); err != nil {
			return fmt.Errorf("failed to load policy %q from bundle: %w", p.ID, err)
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// Export
// --------------------------------------------------------------------------

// ExportPolicies exports all policies as Rego source or Go source.
func (e *PolicyEngine) ExportPolicies(language PolicyLanguage) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.policies) == 0 {
		return "", fmt.Errorf("no policies to export")
	}

	var sb strings.Builder

	switch language {
	case PolicyRego:
		for _, p := range e.policies {
			if p.Language == PolicyRego && p.Source != "" {
				sb.WriteString(p.Source)
				sb.WriteString("\n\n")
			} else {
				// Generate rego from policy metadata
				sb.WriteString(fmt.Sprintf("# Policy %s: %s\n", p.ID, p.Name))
				sb.WriteString(fmt.Sprintf("# %s\n\n", p.Description))
			}
		}
	case PolicyNative:
		sb.WriteString("// Native policy definitions\n\n")
		for _, p := range e.policies {
			sb.WriteString(fmt.Sprintf("// Policy %s: %s\n", p.ID, p.Name))
			sb.WriteString(fmt.Sprintf("// Framework: %s, Control: %s\n", p.Framework, p.ControlID))
			sb.WriteString(fmt.Sprintf("// Severity: %s\n\n", p.Severity))
		}
	default:
		return "", fmt.Errorf("unsupported export language: %q", language)
	}

	return sb.String(), nil
}

// --------------------------------------------------------------------------
// Default policies
// --------------------------------------------------------------------------

// DefaultPolicies returns the built-in default Rego policies for AegisGate.
func DefaultPolicies() []*Policy {
	now := time.Now().UTC()
	return []*Policy{
		{
			ID:          "AG-POL-001",
			Name:        "require-auth-professional",
			Description: "Block requests without auth when tier >= professional (SOC2 CC6.1)",
			Language:    PolicyRego,
			Framework:   "SOC2",
			ControlID:   "CC6.1",
			Severity:    SeverityHigh,
			Source: `package aegisgate.auth

default allow = false

allow {
    input.config.tier == "community"
}

allow {
    input.request.authenticated == true
}

deny {
    input.config.tier != "community"
    input.request.authenticated == false
}`,
			CreatedAt: now,
			UpdatedAt: now,
			Author:    "aegisgate",
			Version:   1,
		},
		{
			ID:          "AG-POL-002",
			Name:        "require-encryption-transit",
			Description: "Require encryption in transit (HIPAA 164.312(e)(1))",
			Language:    PolicyRego,
			Framework:   "HIPAA",
			ControlID:   "164.312(e)(1)",
			Severity:    SeverityCritical,
			Source: `package aegisgate.encryption

default allow = false

allow {
    input.config.encryption_enabled == true
}

deny {
    input.config.encryption_enabled == false
}`,
			CreatedAt: now,
			UpdatedAt: now,
			Author:    "aegisgate",
			Version:   1,
		},
		{
			ID:          "AG-POL-003",
			Name:        "data-residency-eu",
			Description: "Enforce data residency for EU AI Act",
			Language:    PolicyRego,
			Framework:   "EU-AI-ACT",
			ControlID:   "Art.28",
			Severity:    SeverityHigh,
			Source: `package aegisgate.dataprivacy

default allow = false

allow {
    input.config.data_residency == ""
}

allow {
    input.config.data_residency == "eu"
    input.environment.region == "eu"
}

deny {
    input.config.data_residency == "eu"
    input.environment.region != "eu"
}`,
			CreatedAt: now,
			UpdatedAt: now,
			Author:    "aegisgate",
			Version:   1,
		},
		{
			ID:          "AG-POL-004",
			Name:        "block-prompt-injection",
			Description: "Block prompt injection patterns (ATLAS T1535.001)",
			Language:    PolicyRego,
			Framework:   "ATLAS",
			ControlID:   "T1535.001",
			Severity:    SeverityCritical,
			Source: `package aegisgate.threat_detection

default allow = true

deny {
    input.request.contains_injection == true
    input.config.ml_enabled == true
}`,
			CreatedAt: now,
			UpdatedAt: now,
			Author:    "aegisgate",
			Version:   1,
		},
		{
			ID:          "AG-POL-005",
			Name:        "require-audit-logging",
			Description: "Require audit logging for SOC2 CC7.2",
			Language:    PolicyRego,
			Framework:   "SOC2",
			ControlID:   "CC7.2",
			Severity:    SeverityHigh,
			Source: `package aegisgate.audit

default allow = false

allow {
    input.config.audit_logging_enabled == true
}

deny {
    input.config.audit_logging_enabled == false
}`,
			CreatedAt: now,
			UpdatedAt: now,
			Author:    "aegisgate",
			Version:   1,
		},
		{
			ID:          "AG-POL-006",
			Name:        "ml-threat-detection",
			Description: "Enforce ML threat detection when enabled (NIST AI RMF)",
			Language:    PolicyRego,
			Framework:   "NIST-AI-RMF",
			ControlID:   "MS.2",
			Severity:    SeverityMedium,
			Source: `package aegisgate.ml_detection

default allow = true

deny {
    input.config.ml_enabled == true
    input.scan_result.threats_detected == true
}`,
			CreatedAt: now,
			UpdatedAt: now,
			Author:    "aegisgate",
			Version:   1,
		},
		{
			ID:          "AG-POL-007",
			Name:        "model-integrity-verification",
			Description: "Require model integrity verification (ISO 42001)",
			Language:    PolicyRego,
			Framework:   "ISO/IEC 42001",
			ControlID:   "A.7.2",
			Severity:    SeverityHigh,
			Source: `package aegisgate.model_integrity

default allow = false

allow {
    input.config.model_integrity_verified == true
}

deny {
    input.config.model_integrity_verified == false
}`,
			CreatedAt: now,
			UpdatedAt: now,
			Author:    "aegisgate",
			Version:   1,
		},
	}
}
