// Package mcp - Mock implementations for testing
package mcp

import (
	"context"
	"sync"
)

// MockToolAuthorizer implements ToolAuthorizer interface for testing
type MockToolAuthorizer struct {
	mu                sync.Mutex
	AuthorizedTools   map[string]bool
	AuthorizationRate map[string]int
	MockDecision      *AuthorizationDecision
	MockError         error
	AuthorizeCalls    []AuthorizationCall
}

func NewMockToolAuthorizer() *MockToolAuthorizer {
	return &MockToolAuthorizer{
		AuthorizedTools:   make(map[string]bool),
		AuthorizationRate: make(map[string]int),
		AuthorizeCalls:    make([]AuthorizationCall, 0),
	}
}

func (m *MockToolAuthorizer) Authorize(ctx context.Context, call *AuthorizationCall) (*AuthorizationDecision, error) {
	m.mu.Lock()
	m.AuthorizeCalls = append(m.AuthorizeCalls, *call)
	m.mu.Unlock()

	if m.MockError != nil {
		return nil, m.MockError
	}

	if m.MockDecision != nil {
		return m.MockDecision, nil
	}

	decision := &AuthorizationDecision{
		Allowed:     true,
		Reason:      "allowed by default",
		RiskScore:   0,
		MatchedRule: "default_policy",
	}

	m.mu.Lock()
	if allowed, ok := m.AuthorizedTools[call.Name]; ok {
		decision.Allowed = allowed
		if !allowed {
			decision.Reason = "tool denied by policy"
		}
	}

	if rate, ok := m.AuthorizationRate[call.Name]; ok {
		decision.RiskScore = rate
	}
	m.mu.Unlock()

	return decision, nil
}

// GetAuthorizeCalls returns a copy of the authorize calls slice (thread-safe)
func (m *MockToolAuthorizer) GetAuthorizeCalls() []AuthorizationCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	calls := make([]AuthorizationCall, len(m.AuthorizeCalls))
	copy(calls, m.AuthorizeCalls)
	return calls
}

// MockPolicyEngine implements PolicyEngine interface for testing
type MockPolicyEngine struct {
	mu            sync.Mutex
	PolicyResults map[string]*PolicyEvalResult
	MockResult    *PolicyEvalResult
	MockError     error
	EvaluateCalls []PolicyEvalContext
}

func NewMockPolicyEngine() *MockPolicyEngine {
	return &MockPolicyEngine{
		PolicyResults: make(map[string]*PolicyEvalResult),
		EvaluateCalls: make([]PolicyEvalContext, 0),
	}
}

func (m *MockPolicyEngine) Evaluate(ctx context.Context, eval *PolicyEvalContext) (*PolicyEvalResult, error) {
	m.mu.Lock()
	m.EvaluateCalls = append(m.EvaluateCalls, *eval)
	m.mu.Unlock()

	if m.MockError != nil {
		return nil, m.MockError
	}

	if m.MockResult != nil {
		return m.MockResult, nil
	}

	result := &PolicyEvalResult{
		Allowed:      true,
		Reason:       "policy evaluation passed",
		MatchedRules: []string{},
		ModifiedRisk: eval.Parameters["risk_score"].(int),
	}

	m.mu.Lock()
	key := eval.ToolName + ":" + eval.SessionID + ":" + eval.AgentID
	if res, ok := m.PolicyResults[key]; ok {
		result = res
	}
	m.mu.Unlock()

	return result, nil
}

// GetEvaluateCalls returns a copy of the evaluate calls slice (thread-safe)
func (m *MockPolicyEngine) GetEvaluateCalls() []PolicyEvalContext {
	m.mu.Lock()
	defer m.mu.Unlock()
	calls := make([]PolicyEvalContext, len(m.EvaluateCalls))
	copy(calls, m.EvaluateCalls)
	return calls
}

// MockAuditLogger implements AuditLogger interface for testing
type MockAuditLogger struct {
	mu           sync.Mutex
	AuditEntries []*AuditEntry
	LoggedErrors []error
	LogError     error
}

func NewMockAuditLogger() *MockAuditLogger {
	return &MockAuditLogger{
		AuditEntries: make([]*AuditEntry, 0),
	}
}

func (m *MockAuditLogger) Log(ctx context.Context, entry *AuditEntry) error {
	if m.LogError != nil {
		return m.LogError
	}
	m.mu.Lock()
	m.AuditEntries = append(m.AuditEntries, entry)
	m.mu.Unlock()
	return nil
}

// GetAuditEntries returns a copy of the audit entries slice (thread-safe)
func (m *MockAuditLogger) GetAuditEntries() []*AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := make([]*AuditEntry, len(m.AuditEntries))
	copy(entries, m.AuditEntries)
	return entries
}

// MockSessionManager implements SessionManager interface for testing
type MockSessionManager struct {
	mu           sync.Mutex
	Sessions     map[string]*Session
	LastError    error
	CreatedCalls []struct{ AgentID string }
	DeletedCalls []string
}

func NewMockSessionManager() *MockSessionManager {
	return &MockSessionManager{
		Sessions: make(map[string]*Session),
	}
}

func (m *MockSessionManager) CreateSession(ctx context.Context, agentID string) (*Session, error) {
	m.mu.Lock()
	m.CreatedCalls = append(m.CreatedCalls, struct{ AgentID string }{AgentID: agentID})
	m.mu.Unlock()

	if m.LastError != nil {
		return nil, m.LastError
	}

	session := &Session{
		ID:      "session-" + agentID,
		AgentID: agentID,
	}
	m.mu.Lock()
	m.Sessions[session.ID] = session
	m.mu.Unlock()
	return session, nil
}

func (m *MockSessionManager) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	m.mu.Lock()
	session, ok := m.Sessions[sessionID]
	m.mu.Unlock()

	if ok {
		return session, nil
	}
	return nil, m.LastError
}

func (m *MockSessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	m.DeletedCalls = append(m.DeletedCalls, sessionID)
	delete(m.Sessions, sessionID)
	m.mu.Unlock()
	return nil
}

// GetCreatedCalls returns a copy of the created calls slice (thread-safe)
func (m *MockSessionManager) GetCreatedCalls() []struct{ AgentID string } {
	m.mu.Lock()
	defer m.mu.Unlock()
	calls := make([]struct{ AgentID string }, len(m.CreatedCalls))
	copy(calls, m.CreatedCalls)
	return calls
}

// GetDeletedCalls returns a copy of the deleted calls slice (thread-safe)
func (m *MockSessionManager) GetDeletedCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	calls := make([]string, len(m.DeletedCalls))
	copy(calls, m.DeletedCalls)
	return calls
}

// TestConnection is a test implementation of Connection
type TestConnection struct {
	ID      string
	AgentID string
}

func (c *TestConnection) GetAgentID() string {
	return c.AgentID
}

func (c *TestConnection) GetSessionID() string {
	return c.ID
}
