// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Policy-as-Code (OPA/Rego) Integration Tests
// =========================================================================

package compliance_test

import (
	"context"

	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --------------------------------------------------------------------------
// PolicyEngine lifecycle
// --------------------------------------------------------------------------

func TestNewPolicyEngine(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	assert.NotNil(t, engine)
	policies := engine.ListPolicies(compliance.PolicyFilter{})
	assert.Empty(t, policies)
}

// --------------------------------------------------------------------------
// AddPolicy
// --------------------------------------------------------------------------

func TestAddPolicy_Rego(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID:          "test-rego-001",
		Name:        "test-rego-policy",
		Description: "A test rego policy",
		Language:    compliance.PolicyRego,
		Framework:   "SOC2",
		ControlID:   "CC6.1",
		Severity:    compliance.SeverityHigh,
		Source: `package aegisgate.test

default allow = false

allow {
    input.config.tier == "enterprise"
}`,
	}
	err := engine.AddPolicy(policy)
	require.NoError(t, err)

	retrieved, err := engine.GetPolicy("test-rego-001")
	require.NoError(t, err)
	assert.Equal(t, "test-rego-policy", retrieved.Name)
	assert.Equal(t, compliance.PolicyRego, retrieved.Language)
}

func TestAddPolicy_Native(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID:          "test-native-001",
		Name:        "test-native-policy",
		Description: "A test native policy",
		Language:    compliance.PolicyNative,
		Framework:   "HIPAA",
		ControlID:   "164.312(a)",
		Severity:    compliance.SeverityCritical,
		NativeCheck: func(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
			return &compliance.ControlCheckResult{
				ControlID: "164.312(a)",
				Status:    compliance.StatusCompliant,
				Message:   "check passed",
			}, nil
		},
	}
	err := engine.AddPolicy(policy)
	require.NoError(t, err)

	retrieved, err := engine.GetPolicy("test-native-001")
	require.NoError(t, err)
	assert.Equal(t, "test-native-policy", retrieved.Name)
	assert.Equal(t, compliance.PolicyNative, retrieved.Language)
}

func TestAddPolicy_DuplicateID(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID:        "dup-001",
		Name:      "first",
		Language:  compliance.PolicyRego,
		Framework: "SOC2",
		Severity:  compliance.SeverityHigh,
		Source: `package aegisgate.test

default allow = false

allow {
    input.config.tier == "enterprise"
}`,
	}
	err := engine.AddPolicy(policy)
	require.NoError(t, err)

	policy2 := &compliance.Policy{
		ID:        "dup-001",
		Name:      "second",
		Language:  compliance.PolicyRego,
		Framework: "SOC2",
		Severity:  compliance.SeverityHigh,
		Source: `package aegisgate.test2

default allow = true`,
	}
	err = engine.AddPolicy(policy2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestAddPolicy_NilPolicy(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	err := engine.AddPolicy(nil)
	assert.Error(t, err)
}

func TestAddPolicy_EmptyID(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	err := engine.AddPolicy(&compliance.Policy{Name: "test"})
	assert.Error(t, err)
}

func TestAddPolicy_RegoEmptySource(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	err := engine.AddPolicy(&compliance.Policy{
		ID:       "empty-src",
		Language: compliance.PolicyRego,
		Source:   "",
	})
	assert.Error(t, err)
}

// --------------------------------------------------------------------------
// RemovePolicy
// --------------------------------------------------------------------------

func TestRemovePolicy(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID:        "remove-001",
		Name:      "removable",
		Language:  compliance.PolicyRego,
		Framework: "SOC2",
		Severity:  compliance.SeverityHigh,
		Source: `package aegisgate.remove

default allow = true`,
	}
	err := engine.AddPolicy(policy)
	require.NoError(t, err)

	err = engine.RemovePolicy("remove-001")
	assert.NoError(t, err)

	_, err = engine.GetPolicy("remove-001")
	assert.Error(t, err)
}

func TestRemovePolicy_NotFound(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	err := engine.RemovePolicy("nonexistent")
	assert.Error(t, err)
}

// --------------------------------------------------------------------------
// GetPolicy
// --------------------------------------------------------------------------

func TestGetPolicy(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID:          "get-001",
		Name:        "gettable",
		Description: "can be retrieved",
		Language:    compliance.PolicyRego,
		Framework:   "SOC2",
		ControlID:   "CC6.1",
		Severity:    compliance.SeverityHigh,
		Source: `package aegisgate.gettest

default allow = false

allow {
    input.config.enabled == true
}`,
	}
	err := engine.AddPolicy(policy)
	require.NoError(t, err)

	retrieved, err := engine.GetPolicy("get-001")
	require.NoError(t, err)
	assert.Equal(t, "get-001", retrieved.ID)
	assert.Equal(t, "gettable", retrieved.Name)
	assert.Equal(t, "SOC2", retrieved.Framework)
	assert.Equal(t, "CC6.1", retrieved.ControlID)
}

func TestGetPolicy_NotFound(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	_, err := engine.GetPolicy("nonexistent")
	assert.Error(t, err)
}

// --------------------------------------------------------------------------
// ListPolicies with filters
// --------------------------------------------------------------------------

func TestListPolicies_Filter(t *testing.T) {
	engine := compliance.NewPolicyEngine()

	policies := []*compliance.Policy{
		{
			ID: "soc2-001", Name: "soc2-policy", Language: compliance.PolicyRego,
			Framework: "SOC2", Severity: compliance.SeverityHigh, ControlID: "CC6.1",
			Source: `package aegisgate.soc2

default allow = true`,
		},
		{
			ID: "hipaa-001", Name: "hipaa-policy", Language: compliance.PolicyRego,
			Framework: "HIPAA", Severity: compliance.SeverityCritical, ControlID: "164.312(a)",
			Source: `package aegisgate.hipaa

default allow = true`,
		},
		{
			ID: "soc2-002", Name: "soc2-policy-2", Language: compliance.PolicyRego,
			Framework: "SOC2", Severity: compliance.SeverityMedium, ControlID: "CC7.2",
			Source: `package aegisgate.soc2_2

default allow = true`,
		},
	}

	for _, p := range policies {
		err := engine.AddPolicy(p)
		require.NoError(t, err)
	}

	// Filter by framework
	soc2Policies := engine.ListPolicies(compliance.PolicyFilter{Framework: "SOC2"})
	assert.Len(t, soc2Policies, 2)

	// Filter by severity
	critical := engine.ListPolicies(compliance.PolicyFilter{Severity: compliance.SeverityCritical})
	assert.Len(t, critical, 1)
	assert.Equal(t, "HIPAA", critical[0].Framework)

	// Filter by control ID
	cc61 := engine.ListPolicies(compliance.PolicyFilter{ControlID: "CC6.1"})
	assert.Len(t, cc61, 1)

	// No filter
	all := engine.ListPolicies(compliance.PolicyFilter{})
	assert.Len(t, all, 3)
}

// --------------------------------------------------------------------------
// Evaluate - Rego policy
// --------------------------------------------------------------------------

func TestEvaluate_RegoPolicy_Allow(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "eval-allow-001", Name: "allow-test", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.eval_allow

default allow = false

allow {
    input.config.tier == "enterprise"
}`,
	}
	err := engine.AddPolicy(policy)
	require.NoError(t, err)

	input := compliance.PolicyInput{
		Config: map[string]any{"tier": "enterprise"},
	}
	result, err := engine.Evaluate(context.Background(), "eval-allow-001", input)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "eval-allow-001", result.PolicyID)
	assert.GreaterOrEqual(t, result.Score, 1.0)
}

func TestEvaluate_RegoPolicy_Deny(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "eval-deny-001", Name: "deny-test", Language: compliance.PolicyRego,
		Framework: "HIPAA", Severity: compliance.SeverityCritical,
		Source: `package aegisgate.eval_deny

default allow = false

deny {
    input.config.encryption_enabled == false
}`,
	}
	err := engine.AddPolicy(policy)
	require.NoError(t, err)

	input := compliance.PolicyInput{
		Config: map[string]any{"encryption_enabled": false},
	}
	result, err := engine.Evaluate(context.Background(), "eval-deny-001", input)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.NotEmpty(t, result.Violations)
}

func TestEvaluate_RegoPolicy_DefaultDeny(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "eval-default-001", Name: "default-deny-test", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.eval_default

default allow = false

allow {
    input.config.tier == "enterprise"
}`,
	}
	err := engine.AddPolicy(policy)
	require.NoError(t, err)

	// Input doesn't match the allow condition
	input := compliance.PolicyInput{
		Config: map[string]any{"tier": "community"},
	}
	result, err := engine.Evaluate(context.Background(), "eval-default-001", input)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Less(t, result.Score, 0.5)
}

// --------------------------------------------------------------------------
// Evaluate - Native policy
// --------------------------------------------------------------------------

func TestEvaluate_NativePolicy(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID:          "native-eval-001",
		Name:        "native-eval-test",
		Language:     compliance.PolicyNative,
		Framework:   "HIPAA",
		ControlID:   "164.312(a)",
		Severity:    compliance.SeverityCritical,
		NativeCheck: func(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
			return &compliance.ControlCheckResult{
				ControlID: "164.312(a)",
				Status:    compliance.StatusCompliant,
				Message:   "encryption is enabled",
			}, nil
		},
	}
	err := engine.AddPolicy(policy)
	require.NoError(t, err)

	result, err := engine.Evaluate(context.Background(), "native-eval-001", compliance.PolicyInput{})
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 1.0, result.Score)
}

func TestEvaluate_NativePolicy_NonCompliant(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID:          "native-noncomp-001",
		Name:        "native-noncomp-test",
		Language:     compliance.PolicyNative,
		Framework:   "HIPAA",
		ControlID:   "164.312(a)",
		Severity:    compliance.SeverityCritical,
		NativeCheck: func(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
			return &compliance.ControlCheckResult{
				ControlID: "164.312(a)",
				Status:    compliance.StatusNonCompliant,
				Message:   "encryption is not enabled",
			}, nil
		},
	}
	err := engine.AddPolicy(policy)
	require.NoError(t, err)

	result, err := engine.Evaluate(context.Background(), "native-noncomp-001", compliance.PolicyInput{})
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, 0.0, result.Score)
	assert.NotEmpty(t, result.Violations)
}

// --------------------------------------------------------------------------
// EvaluateAll
// --------------------------------------------------------------------------

func TestEvaluateAll(t *testing.T) {
	engine := compliance.NewPolicyEngine()

	p1 := &compliance.Policy{
		ID: "all-001", Name: "policy-1", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.all1

default allow = true`,
	}
	p2 := &compliance.Policy{
		ID: "all-002", Name: "policy-2", Language: compliance.PolicyRego,
		Framework: "HIPAA", Severity: compliance.SeverityCritical,
		Source: `package aegisgate.all2

default allow = false`,
	}

	require.NoError(t, engine.AddPolicy(p1))
	require.NoError(t, engine.AddPolicy(p2))

	results, err := engine.EvaluateAll(context.Background(), compliance.PolicyInput{})
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

// --------------------------------------------------------------------------
// EvaluateFramework
// --------------------------------------------------------------------------

func TestEvaluateFramework(t *testing.T) {
	engine := compliance.NewPolicyEngine()

	soc2Policy := &compliance.Policy{
		ID: "fw-soc2-001", Name: "soc2-fw", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.fwsoc2

default allow = true`,
	}
	hipaaPolicy := &compliance.Policy{
		ID: "fw-hipaa-001", Name: "hipaa-fw", Language: compliance.PolicyRego,
		Framework: "HIPAA", Severity: compliance.SeverityCritical,
		Source: `package aegisgate.fwhipaa

default allow = true`,
	}

	require.NoError(t, engine.AddPolicy(soc2Policy))
	require.NoError(t, engine.AddPolicy(hipaaPolicy))

	results, err := engine.EvaluateFramework(context.Background(), "SOC2", compliance.PolicyInput{})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "fw-soc2-001", results[0].PolicyID)
}

// --------------------------------------------------------------------------
// ParseRegoSource
// --------------------------------------------------------------------------

func TestParseRegoSource_Simple(t *testing.T) {
	source := `package aegisgate.simple

default allow = false

allow {
    input.config.tier == "enterprise"
}`
	rule, err := compliance.ParseRegoSource(source)
	require.NoError(t, err)
	assert.Equal(t, "aegisgate.simple", rule.Package)
	assert.Equal(t, "simple", rule.Name)
	assert.False(t, rule.DefaultAllow)
	assert.Len(t, rule.AllowRules, 1)
}

func TestParseRegoSource_Complex(t *testing.T) {
	source := `package aegisgate.complex

default allow = false

allow {
    input.config.tier == "enterprise"
    input.request.authenticated == true
}

deny {
    input.config.tier == "professional"
    input.request.authenticated == false
}`
	rule, err := compliance.ParseRegoSource(source)
	require.NoError(t, err)
	assert.Equal(t, "aegisgate.complex", rule.Package)
	assert.Len(t, rule.AllowRules, 1)
	assert.Len(t, rule.AllowRules[0], 2) // two conditions in allow block
	assert.Len(t, rule.DenyRules, 1)
	assert.Len(t, rule.DenyRules[0], 2) // two conditions in deny block
}

func TestParseRegoSource_Invalid(t *testing.T) {
	_, err := compliance.ParseRegoSource("")
	assert.Error(t, err)

	_, err = compliance.ParseRegoSource("not a rego file")
	assert.Error(t, err)
}

func TestParseRegoSource_DefaultTrue(t *testing.T) {
	source := `package aegisgate.defaulttrue

default allow = true

deny {
    input.request.malicious == true
}`
	rule, err := compliance.ParseRegoSource(source)
	require.NoError(t, err)
	assert.True(t, rule.DefaultAllow)
	assert.Len(t, rule.DenyRules, 1)
}

func TestParseRegoSource_MultipleAllowBlocks(t *testing.T) {
	source := `package aegisgate.multiallow

default allow = false

allow {
    input.config.tier == "community"
}

allow {
    input.request.authenticated == true
}`
	rule, err := compliance.ParseRegoSource(source)
	require.NoError(t, err)
	assert.Len(t, rule.AllowRules, 2)
}

func TestParseRegoSource_Operators(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		operator string
	}{
		{
			name: "equals",
			source: `package aegisgate.opeq

default allow = false

allow {
    input.config.value == "test"
}`,
			operator: "==",
		},
		{
			name: "not_equals",
			source: `package aegisgate.opneq

default allow = false

allow {
    input.config.value != "test"
}`,
			operator: "!=",
		},
		{
			name: "greater_than",
			source: `package aegisgate.opgt

default allow = false

allow {
    input.config.score > 50
}`,
			operator: ">",
		},
		{
			name: "less_than",
			source: `package aegisgate.oplt

default allow = false

allow {
    input.config.score < 100
}`,
			operator: "<",
		},
		{
			name: "contains",
			source: `package aegisgate.opcontains

default allow = false

allow {
    input.config.name contains "admin"
}`,
			operator: "contains",
		},
		{
			name: "matches",
			source: `package aegisgate.opmatches

default allow = false

allow {
    input.config.email matches "^[a-z]+@example.com$"
}`,
			operator: "matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := compliance.ParseRegoSource(tt.source)
			require.NoError(t, err)
			assert.Len(t, rule.AllowRules, 1)
			assert.Len(t, rule.AllowRules[0], 1)
			assert.Equal(t, tt.operator, rule.AllowRules[0][0].Operator)
		})
	}
}

// --------------------------------------------------------------------------
// Bundle operations
// --------------------------------------------------------------------------

func TestBundlePolicies(t *testing.T) {
	engine := compliance.NewPolicyEngine()

	p1 := &compliance.Policy{
		ID: "bundle-001", Name: "bundlable-1", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.bundle1

default allow = true`,
	}
	p2 := &compliance.Policy{
		ID: "bundle-002", Name: "bundlable-2", Language: compliance.PolicyRego,
		Framework: "HIPAA", Severity: compliance.SeverityCritical,
		Source: `package aegisgate.bundle2

default allow = true`,
	}
	require.NoError(t, engine.AddPolicy(p1))
	require.NoError(t, engine.AddPolicy(p2))

	bundle, err := engine.BundlePolicies("test-bundle", "A test bundle of policies")
	require.NoError(t, err)
	assert.Equal(t, "test-bundle", bundle.Name)
	assert.Len(t, bundle.Policies, 2)
	assert.NotEmpty(t, bundle.ID)
}

func TestBundlePolicies_Empty(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	_, err := engine.BundlePolicies("empty", "no policies")
	assert.Error(t, err)
}

func TestLoadBundle(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	bundle := &compliance.PolicyBundle{
		ID:          "bundle-load-001",
		Name:        "load-test",
		Description: "test loading",
		Policies: []*compliance.Policy{
			{
				ID: "load-001", Name: "loaded-1", Language: compliance.PolicyRego,
				Framework: "SOC2", Severity: compliance.SeverityHigh,
				Source: `package aegisgate.load1

default allow = true`,
			},
			{
				ID: "load-002", Name: "loaded-2", Language: compliance.PolicyRego,
				Framework: "HIPAA", Severity: compliance.SeverityCritical,
				Source: `package aegisgate.load2

default allow = true`,
			},
		},
	}

	err := engine.LoadBundle(bundle)
	require.NoError(t, err)

	p1, err := engine.GetPolicy("load-001")
	require.NoError(t, err)
	assert.Equal(t, "loaded-1", p1.Name)

	p2, err := engine.GetPolicy("load-002")
	require.NoError(t, err)
	assert.Equal(t, "loaded-2", p2.Name)
}

func TestLoadBundle_Nil(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	err := engine.LoadBundle(nil)
	assert.Error(t, err)
}

func TestLoadBundle_DuplicateID(t *testing.T) {
	engine := compliance.NewPolicyEngine()

	// Add an existing policy first
	existing := &compliance.Policy{
		ID: "dup-load-001", Name: "existing", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.existing

default allow = true`,
	}
	require.NoError(t, engine.AddPolicy(existing))

	bundle := &compliance.PolicyBundle{
		ID:   "dup-bundle",
		Name: "duplicate-test",
		Policies: []*compliance.Policy{
			{
				ID: "dup-load-001", Name: "duplicate", Language: compliance.PolicyRego,
				Framework: "SOC2", Severity: compliance.SeverityHigh,
				Source: `package aegisgate.dup\n\ndefault allow = true`,
			},
		},
	}

	err := engine.LoadBundle(bundle)
	assert.Error(t, err)
}

// --------------------------------------------------------------------------
// ExportPolicies
// --------------------------------------------------------------------------

func TestExportPolicies_Rego(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "export-001", Name: "exportable", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.export

default allow = true`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	exported, err := engine.ExportPolicies(compliance.PolicyRego)
	require.NoError(t, err)
	assert.Contains(t, exported, "package aegisgate.export")
	assert.Contains(t, exported, "default allow = true")
}

func TestExportPolicies_Native(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "export-native-001", Name: "native-export", Language: compliance.PolicyNative,
		Framework: "HIPAA", Severity: compliance.SeverityCritical,
		NativeCheck: func(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
			return &compliance.ControlCheckResult{Status: compliance.StatusCompliant}, nil
		},
	}
	require.NoError(t, engine.AddPolicy(policy))

	exported, err := engine.ExportPolicies(compliance.PolicyNative)
	require.NoError(t, err)
	assert.Contains(t, exported, "export-native-001")
	assert.Contains(t, exported, "HIPAA")
}

func TestExportPolicies_Empty(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	_, err := engine.ExportPolicies(compliance.PolicyRego)
	assert.Error(t, err)
}

// --------------------------------------------------------------------------
// DefaultPolicies
// --------------------------------------------------------------------------

func TestDefaultPolicies(t *testing.T) {
	policies := compliance.DefaultPolicies()
	assert.Len(t, policies, 7)

	// All should have Rego source
	for _, p := range policies {
		assert.NotEmpty(t, p.ID, "policy should have an ID")
		assert.NotEmpty(t, p.Name, "policy should have a name")
		assert.Equal(t, compliance.PolicyRego, p.Language, "policy %s should be Rego", p.ID)
		assert.NotEmpty(t, p.Source, "policy %s should have Rego source", p.ID)
		assert.NotEmpty(t, p.Framework, "policy %s should have a framework", p.ID)
	}

	// Verify specific IDs
	ids := make(map[string]bool)
	for _, p := range policies {
		ids[p.ID] = true
	}
	assert.True(t, ids["AG-POL-001"], "should contain AG-POL-001")
	assert.True(t, ids["AG-POL-002"], "should contain AG-POL-002")
	assert.True(t, ids["AG-POL-003"], "should contain AG-POL-003")
	assert.True(t, ids["AG-POL-004"], "should contain AG-POL-004")
	assert.True(t, ids["AG-POL-005"], "should contain AG-POL-005")
	assert.True(t, ids["AG-POL-006"], "should contain AG-POL-006")
	assert.True(t, ids["AG-POL-007"], "should contain AG-POL-007")
}

// --------------------------------------------------------------------------
// PolicyInput nested access
// --------------------------------------------------------------------------

func TestPolicyInput_NestedAccess(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "nested-001", Name: "nested-test", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.nested

default allow = false

allow {
    input.config.tier == "enterprise"
    input.request.authenticated == true
}`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	// Both conditions match
	input := compliance.PolicyInput{
		Config:   map[string]any{"tier": "enterprise"},
		Request:  map[string]any{"authenticated": true},
	}
	result, err := engine.Evaluate(context.Background(), "nested-001", input)
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	// Only one condition matches
	input2 := compliance.PolicyInput{
		Config:  map[string]any{"tier": "community"},
		Request: map[string]any{"authenticated": true},
	}
	result2, err := engine.Evaluate(context.Background(), "nested-001", input2)
	require.NoError(t, err)
	assert.False(t, result2.Allowed) // community != enterprise
}

func TestPolicyInput_MissingField(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "missing-001", Name: "missing-field-test", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.missing

default allow = false

allow {
    input.config.nonexistent == "value"
}`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	input := compliance.PolicyInput{
		Config: map[string]any{"tier": "enterprise"},
	}
	result, err := engine.Evaluate(context.Background(), "missing-001", input)
	require.NoError(t, err)
	assert.False(t, result.Allowed) // missing field won't match
}

// --------------------------------------------------------------------------
// PolicyResult scoring
// --------------------------------------------------------------------------

func TestPolicyResult_Score(t *testing.T) {
	engine := compliance.NewPolicyEngine()

	// Policy that allows by default (no explicit allow rules match → default applies)
	allowPolicy := &compliance.Policy{
		ID: "score-allow-001", Name: "score-allow", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.scoreallow

default allow = true`,
	}
	require.NoError(t, engine.AddPolicy(allowPolicy))

	result, err := engine.Evaluate(context.Background(), "score-allow-001", compliance.PolicyInput{})
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	// Default allow without matching rule conditions gives confidence score of 0.5
	assert.Equal(t, 0.5, result.Score)

	// Policy that denies with explicit conditions
	denyPolicy := &compliance.Policy{
		ID: "score-deny-001", Name: "score-deny", Language: compliance.PolicyRego,
		Framework: "HIPAA", Severity: compliance.SeverityCritical,
		Source: `package aegisgate.scoredeny

default allow = true

deny {
    input.config.secure == false
}`,
	}
	require.NoError(t, engine.AddPolicy(denyPolicy))

	input := compliance.PolicyInput{
		Config: map[string]any{"secure": false},
	}
	denyResult, err := engine.Evaluate(context.Background(), "score-deny-001", input)
	require.NoError(t, err)
	assert.False(t, denyResult.Allowed)
	assert.LessOrEqual(t, denyResult.Score, 0.0)
}

// --------------------------------------------------------------------------
// Evaluation duration tracking
// --------------------------------------------------------------------------

func TestPolicyResult_EvalDuration(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "duration-001", Name: "duration-test", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.duration

default allow = true`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	result, err := engine.Evaluate(context.Background(), "duration-001", compliance.PolicyInput{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, result.EvalDuration, time.Duration(0))
	assert.False(t, result.EvaluatedAt.IsZero())
}

// --------------------------------------------------------------------------
// Numeric comparisons in Rego evaluation
// --------------------------------------------------------------------------

func TestEvaluate_NumericComparisons(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "numeric-001", Name: "numeric-test", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.numeric

default allow = false

allow {
    input.config.score > 50
}`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	// Score above threshold
	result, err := engine.Evaluate(context.Background(), "numeric-001", compliance.PolicyInput{
		Config: map[string]any{"score": 75},
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	// Score below threshold
	result2, err := engine.Evaluate(context.Background(), "numeric-001", compliance.PolicyInput{
		Config: map[string]any{"score": 25},
	})
	require.NoError(t, err)
	assert.False(t, result2.Allowed)
}

// --------------------------------------------------------------------------
// Contains operator
// --------------------------------------------------------------------------

func TestEvaluate_ContainsOperator(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "contains-001", Name: "contains-test", Language: compliance.PolicyRego,
		Framework: "ATLAS", Severity: compliance.SeverityCritical,
		Source: `package aegisgate.contains

default allow = true

deny {
    input.request.body contains "injection"
}`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	// Contains the substring
	result, err := engine.Evaluate(context.Background(), "contains-001", compliance.PolicyInput{
		Request: map[string]any{"body": "this is an injection attack"},
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	// Does not contain
	result2, err := engine.Evaluate(context.Background(), "contains-001", compliance.PolicyInput{
		Request: map[string]any{"body": "normal request"},
	})
	require.NoError(t, err)
	assert.True(t, result2.Allowed)
}

// --------------------------------------------------------------------------
// Matches operator (regex)
// --------------------------------------------------------------------------

func TestEvaluate_MatchesOperator(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "matches-001", Name: "matches-test", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.matches

default allow = false

allow {
    input.request.email matches "^[a-z]+@example.com$"
}`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	result, err := engine.Evaluate(context.Background(), "matches-001", compliance.PolicyInput{
		Request: map[string]any{"email": "admin@example.com"},
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	result2, err := engine.Evaluate(context.Background(), "matches-001", compliance.PolicyInput{
		Request: map[string]any{"email": "admin@other.com"},
	})
	require.NoError(t, err)
	assert.False(t, result2.Allowed)
}

// --------------------------------------------------------------------------
// End-to-end: Evaluate all default policies
// --------------------------------------------------------------------------

func TestEvaluateDefaultPolicies(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policies := compliance.DefaultPolicies()

	for _, p := range policies {
		err := engine.AddPolicy(p)
		require.NoError(t, err, "failed to add policy %s", p.ID)
	}

	allPolicies := engine.ListPolicies(compliance.PolicyFilter{})
	assert.Len(t, allPolicies, 7)

	// Evaluate AG-POL-001 with authenticated request
	input := compliance.PolicyInput{
		Config:   map[string]any{"tier": "professional"},
		Request:  map[string]any{"authenticated": true},
	}
	result, err := engine.Evaluate(context.Background(), "AG-POL-001", input)
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	// Evaluate AG-POL-001 with unauthenticated request on professional tier
	input2 := compliance.PolicyInput{
		Config:   map[string]any{"tier": "professional"},
		Request:  map[string]any{"authenticated": false},
	}
	result2, err := engine.Evaluate(context.Background(), "AG-POL-001", input2)
	require.NoError(t, err)
	assert.False(t, result2.Allowed)
}

// --------------------------------------------------------------------------
// Rego source with comments
// --------------------------------------------------------------------------

func TestParseRegoSource_WithComments(t *testing.T) {
	source := `# AegisGate Auth Policy
package aegisgate.auth

# Default deny
default allow = false

# Allow if authenticated
allow {
    input.request.authenticated == true
}`
	rule, err := compliance.ParseRegoSource(source)
	require.NoError(t, err)
	assert.Equal(t, "aegisgate.auth", rule.Package)
	assert.Len(t, rule.AllowRules, 1)
}

// --------------------------------------------------------------------------
// Policy not found
// --------------------------------------------------------------------------

func TestEvaluate_PolicyNotFound(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	_, err := engine.Evaluate(context.Background(), "nonexistent", compliance.PolicyInput{})
	assert.Error(t, err)
}

// --------------------------------------------------------------------------
// Type coercion in evaluation
// --------------------------------------------------------------------------

func TestEvaluate_TypeCoercion(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "coerce-001", Name: "coerce-test", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.coerce

default allow = false

allow {
    input.config.count == 10
}`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	// Pass count as float64 (JSON unmarshaling produces float64)
	result, err := engine.Evaluate(context.Background(), "coerce-001", compliance.PolicyInput{
		Config: map[string]any{"count": float64(10)},
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// --------------------------------------------------------------------------
// Bundle round-trip
// --------------------------------------------------------------------------

func TestBundleRoundTrip(t *testing.T) {
	engine1 := compliance.NewPolicyEngine()
	p1 := &compliance.Policy{
		ID: "rt-001", Name: "round-trip-1", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.rt

default allow = true`,
	}
	require.NoError(t, engine1.AddPolicy(p1))

	bundle, err := engine1.BundlePolicies("roundtrip-bundle", "test round trip")
	require.NoError(t, err)

	engine2 := compliance.NewPolicyEngine()
	err = engine2.LoadBundle(bundle)
	require.NoError(t, err)

	retrieved, err := engine2.GetPolicy("rt-001")
	require.NoError(t, err)
	assert.Equal(t, "round-trip-1", retrieved.Name)
}

// --------------------------------------------------------------------------
// Multiple frameworks filter
// --------------------------------------------------------------------------

func TestListPolicies_FrameworkFilter(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	for _, p := range compliance.DefaultPolicies() {
		require.NoError(t, engine.AddPolicy(p))
	}

	soc2Policies := engine.ListPolicies(compliance.PolicyFilter{Framework: "SOC2"})
	assert.GreaterOrEqual(t, len(soc2Policies), 2) // AG-POL-001 and AG-POL-005

	atlasPolicies := engine.ListPolicies(compliance.PolicyFilter{Framework: "ATLAS"})
	assert.GreaterOrEqual(t, len(atlasPolicies), 1) // AG-POL-004
}

// --------------------------------------------------------------------------
// GTE/LTE operators
// --------------------------------------------------------------------------

func TestEvaluate_GTE_LTE_Operators(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "gte-001", Name: "gte-test", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.gte

default allow = false

allow {
    input.config.level >= 5
}`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	// level >= 5 (exact)
	result, err := engine.Evaluate(context.Background(), "gte-001", compliance.PolicyInput{
		Config: map[string]any{"level": 5},
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	// level >= 5 (greater)
	result2, err := engine.Evaluate(context.Background(), "gte-001", compliance.PolicyInput{
		Config: map[string]any{"level": 10},
	})
	require.NoError(t, err)
	assert.True(t, result2.Allowed)

	// level >= 5 (less)
	result3, err := engine.Evaluate(context.Background(), "gte-001", compliance.PolicyInput{
		Config: map[string]any{"level": 3},
	})
	require.NoError(t, err)
	assert.False(t, result3.Allowed)
}

// --------------------------------------------------------------------------
// Not-equal operator
// --------------------------------------------------------------------------

func TestEvaluate_NotEqualOperator(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "neq-001", Name: "neq-test", Language: compliance.PolicyRego,
		Framework: "HIPAA", Severity: compliance.SeverityCritical,
		Source: `package aegisgate.neq

default allow = true

deny {
    input.config.tier != "enterprise"
}`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	// tier is community (not enterprise) → denied
	result, err := engine.Evaluate(context.Background(), "neq-001", compliance.PolicyInput{
		Config: map[string]any{"tier": "community"},
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	// tier is enterprise → not denied (allowed by default)
	result2, err := engine.Evaluate(context.Background(), "neq-001", compliance.PolicyInput{
		Config: map[string]any{"tier": "enterprise"},
	})
	require.NoError(t, err)
	assert.True(t, result2.Allowed)
}

// --------------------------------------------------------------------------
// Policy metadata
// --------------------------------------------------------------------------

func TestPolicy_Metadata(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID:          "meta-001",
		Name:        "metadata-test",
		Description: "policy with metadata",
		Language:    compliance.PolicyRego,
		Framework:   "SOC2",
		ControlID:   "CC6.1",
		Severity:    compliance.SeverityHigh,
		Source: `package aegisgate.meta

default allow = true`,
		Metadata: map[string]string{
			"author":  "security-team",
			"version": "1.0",
		},
	}
	require.NoError(t, engine.AddPolicy(policy))

	retrieved, err := engine.GetPolicy("meta-001")
	require.NoError(t, err)
	assert.Equal(t, "security-team", retrieved.Metadata["author"])
	assert.Equal(t, "1.0", retrieved.Metadata["version"])
	assert.Equal(t, "CC6.1", retrieved.ControlID)
	assert.Equal(t, compliance.SeverityHigh, retrieved.Severity)
}

// --------------------------------------------------------------------------
// EvalDuration populated
// --------------------------------------------------------------------------

func TestPolicyResult_EvalDuration_NotZero(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "dur-001", Name: "duration-check", Language: compliance.PolicyRego,
		Framework: "SOC2", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.dur

default allow = true`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	result, err := engine.Evaluate(context.Background(), "dur-001", compliance.PolicyInput{})
	require.NoError(t, err)
	assert.NotZero(t, result.EvalDuration)
	assert.False(t, result.EvaluatedAt.IsZero())
}

// --------------------------------------------------------------------------
// Environment field access
// --------------------------------------------------------------------------

func TestEvaluate_EnvironmentField(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "env-001", Name: "env-test", Language: compliance.PolicyRego,
		Framework: "EU-AI-ACT", Severity: compliance.SeverityHigh,
		Source: `package aegisgate.env

default allow = false

allow {
    input.environment.region == "eu"
}`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	result, err := engine.Evaluate(context.Background(), "env-001", compliance.PolicyInput{
		Environment: map[string]any{"region": "eu"},
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// --------------------------------------------------------------------------
// ScanResult field access
// --------------------------------------------------------------------------

func TestEvaluate_ScanResultField(t *testing.T) {
	engine := compliance.NewPolicyEngine()
	policy := &compliance.Policy{
		ID: "scan-001", Name: "scan-test", Language: compliance.PolicyRego,
		Framework: "NIST-AI-RMF", Severity: compliance.SeverityMedium,
		Source: `package aegisgate.scan

default allow = true

deny {
    input.scan_result.threats_detected == true
}`,
	}
	require.NoError(t, engine.AddPolicy(policy))

	result, err := engine.Evaluate(context.Background(), "scan-001", compliance.PolicyInput{
		ScanResult: map[string]any{"threats_detected": true},
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}