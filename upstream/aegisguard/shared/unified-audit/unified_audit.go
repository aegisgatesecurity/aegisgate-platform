package unifiedaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AuditLog represents a structured audit log entry for compliance and observability.
type AuditLog struct {
	Timestamp  time.Time              `json:"timestamp"`
	Component  string                 `json:"component"`
	Operation  string                 `json:"operation"`
	EntityType string                 `json:"entity_type"`
	EntityID   string                 `json:"entity_id,omitempty"`
	Status     string                 `json:"status"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Compliance []ComplianceViolation  `json:"compliance_violations,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ComplianceViolation represents a detected compliance violation.
type ComplianceViolation struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
}

// AuditLogger is the interface for unified audit logging.
type AuditLogger interface {
	Log(ctx context.Context, log AuditLog) error
	Close() error
}

// FileAuditLogger writes audit logs to a file.
type FileAuditLogger struct {
	file    *os.File
	encoder *json.Encoder
	mu      sync.Mutex
	log     *logrus.Logger
}

// NewFileAuditLogger creates a new FileAuditLogger.
func NewFileAuditLogger(filePath string) (*FileAuditLogger, error) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	logger := logrus.New()
	logger.SetOutput(file)
	logger.SetFormatter(&logrus.JSONFormatter{})

	return &FileAuditLogger{
		file:    file,
		encoder: json.NewEncoder(file),
		log:     logger,
	}, nil
}

// Log writes an audit log entry.
func (f *FileAuditLogger) Log(ctx context.Context, log AuditLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Ensure timestamp is set
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now().UTC()
	}

	// Log using logrus for structured logging
	entry := f.log.WithFields(logrus.Fields{
		"timestamp":   log.Timestamp,
		"component":   log.Component,
		"operation":   log.Operation,
		"entity_type": log.EntityType,
		"entity_id":   log.EntityID,
		"status":      log.Status,
		"details":     log.Details,
		"compliance":  log.Compliance,
		"metadata":    log.Metadata,
	})

	entry.Info("Audit Log")

	// Also write as JSON for structured storage
	if err := f.encoder.Encode(log); err != nil {
		return err
	}

	return nil
}

// Close closes the underlying file.
func (f *FileAuditLogger) Close() error {
	return f.file.Close()
}

// MemoryAuditLogger stores audit logs in memory for testing.
type MemoryAuditLogger struct {
	logs []AuditLog
	mu   sync.Mutex
}

// NewMemoryAuditLogger creates a new MemoryAuditLogger.
func NewMemoryAuditLogger() *MemoryAuditLogger {
	return &MemoryAuditLogger{
		logs: make([]AuditLog, 0),
	}
}

// Log stores an audit log entry in memory.
func (m *MemoryAuditLogger) Log(ctx context.Context, log AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now().UTC()
	}

	m.logs = append(m.logs, log)
	return nil
}

// Close is a no-op for the memory logger.
func (m *MemoryAuditLogger) Close() error {
	return nil
}

// GetLogs returns all logged audit entries.
func (m *MemoryAuditLogger) GetLogs() []AuditLog {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return a copy to avoid race conditions
	logs := make([]AuditLog, len(m.logs))
	copy(logs, m.logs)
	return logs
}

// ComplianceFramework defines the interface for compliance frameworks.
type ComplianceFramework interface {
	Check(ctx context.Context, input CheckInput) (*CheckResult, error)
	GetName() string
	GetVersion() string
}

// CheckInput represents the input for compliance checks.
type CheckInput struct {
	Content    string                 `json:"content"`
	EntityType string                 `json:"entity_type"`
	EntityID   string                 `json:"entity_id,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// CheckResult represents the result of a compliance check.
type CheckResult struct {
	Framework  string                 `json:"framework"`
	Version    string                 `json:"version"`
	Violations []ComplianceViolation  `json:"violations,omitempty"`
	Compliant  bool                   `json:"compliant"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// ComplianceRegistry manages compliance frameworks.
type ComplianceRegistry struct {
	frameworks map[string]ComplianceFramework
	mu         sync.RWMutex
}

// NewComplianceRegistry creates a new ComplianceRegistry.
func NewComplianceRegistry() *ComplianceRegistry {
	return &ComplianceRegistry{
		frameworks: make(map[string]ComplianceFramework),
	}
}

// Register adds a compliance framework to the registry.
func (r *ComplianceRegistry) Register(framework ComplianceFramework) error {
	if framework == nil {
		return errors.New("framework cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	name := framework.GetName()
	if _, exists := r.frameworks[name]; exists {
		return errors.New("framework already registered")
	}

	r.frameworks[name] = framework
	return nil
}

// Get returns a registered compliance framework.
func (r *ComplianceRegistry) Get(name string) (ComplianceFramework, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	framework, exists := r.frameworks[name]
	return framework, exists
}

// Check runs compliance checks against all registered frameworks.
func (r *ComplianceRegistry) Check(ctx context.Context, input CheckInput) ([]CheckResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []CheckResult
	for _, framework := range r.frameworks {
		result, err := framework.Check(ctx, input)
		if err != nil {
			return nil, err
		}
		results = append(results, *result)
	}

	return results, nil
}

// ClientConfig holds configuration for the unified audit client.
type ClientConfig struct {
	AegisGateURL  string
	APIKey        string
	Secret        string
	Timeout       time.Duration
	AsyncEnabled  bool
	BufferSize    int
	FlushInterval time.Duration
}

// Client is the unified audit client for sending events to AegisGate.
type Client struct {
	config   *ClientConfig
	client   *http.Client
	buffer   chan *AuditLog
	stopChan chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	closed   bool
}

// NewClient creates a new unified audit client.
func NewClient(config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}
	if config.AegisGateURL == "" {
		return nil, errors.New("AegisGateURL cannot be empty")
	}
	if config.APIKey == "" {
		return nil, errors.New("APIKey cannot be empty")
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}

	client := &Client{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		stopChan: make(chan struct{}),
	}

	if config.AsyncEnabled {
		if config.BufferSize <= 0 {
			config.BufferSize = 100
		}
		if config.FlushInterval <= 0 {
			config.FlushInterval = 5 * time.Second
		}
		client.buffer = make(chan *AuditLog, config.BufferSize)
		client.wg.Add(1)
		go client.flushWorker()
	}

	return client, nil
}

// Close shuts down the client and flushes any buffered events.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	if c.config.AsyncEnabled {
		close(c.stopChan)
		c.wg.Wait()
		close(c.buffer)
		c.flush()
	}

	return nil
}

// SendToolCall sends a tool call event to the unified audit system.
func (c *Client) SendToolCall(ctx context.Context, sessionID, agentID, toolName string, params map[string]interface{}, allowed bool) error {
	logEntry := &AuditLog{
		Timestamp:  time.Now().UTC(),
		Component:  "aegisguard",
		Operation:  "tool_call",
		EntityType: "tool",
		EntityID:   toolName,
		Status:     "completed",
		Details: map[string]interface{}{
			"session_id": sessionID,
			"agent_id":   agentID,
			"tool_name":  toolName,
			"parameters": params,
			"allowed":    allowed,
		},
		Metadata: map[string]interface{}{
			"source": "aegisguard",
		},
	}

	if !allowed {
		logEntry.Status = "denied"
		logEntry.Details["reason"] = "Tool denied by policy"
	}

	return c.send(ctx, logEntry)
}

// SendToolDenied sends a tool denied event to the unified audit system.
func (c *Client) SendToolDenied(ctx context.Context, sessionID, agentID, toolName string, params map[string]interface{}, reason string) error {
	logEntry := &AuditLog{
		Timestamp:  time.Now().UTC(),
		Component:  "aegisguard",
		Operation:  "tool_call",
		EntityType: "tool",
		EntityID:   toolName,
		Status:     "denied",
		Details: map[string]interface{}{
			"session_id": sessionID,
			"agent_id":   agentID,
			"tool_name":  toolName,
			"parameters": params,
			"reason":     reason,
		},
		Metadata: map[string]interface{}{
			"source": "aegisguard",
		},
	}

	return c.send(ctx, logEntry)
}

// send sends an audit log entry to the unified audit system.
func (c *Client) send(ctx context.Context, logEntry *AuditLog) error {
	if c.config.AsyncEnabled {
		select {
		case c.buffer <- logEntry:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Buffer is full, flush and try again
			c.flush()
			select {
			case c.buffer <- logEntry:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	} else {
		return c.sendSync(ctx, logEntry)
	}
}

// sendSync sends an audit log entry synchronously.
func (c *Client) sendSync(ctx context.Context, logEntry *AuditLog) error {
	// Marshal the log entry
	data, err := json.Marshal(logEntry)
	if err != nil {
		return err
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "POST", c.config.AegisGateURL, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.config.APIKey)
	req.Header.Set("X-Audit-Secret", c.config.Secret)

	// Send the request
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("audit service returned error: %s, body: %s", resp.Status, string(body))
	}

	return nil
}

// flushWorker periodically flushes buffered events.
func (c *Client) flushWorker() {
	ticker := time.NewTicker(c.config.FlushInterval)
	defer ticker.Stop()
	defer c.wg.Done()

	for {
		select {
		case <-ticker.C:
			c.flush()
		case <-c.stopChan:
			c.flush()
			return
		}
	}
}

// flush sends all buffered events to the audit service.
func (c *Client) flush() {
	if len(c.buffer) == 0 {
		return
	}

	var batch []*AuditLog
	for {
		select {
		case logEntry := <-c.buffer:
			batch = append(batch, logEntry)
		default:
			// No more entries in the buffer
			if len(batch) > 0 {
				c.sendBatch(context.Background(), batch)
				batch = nil
			}
			return
		}
	}
}

// sendBatch sends a batch of audit log entries.
func (c *Client) sendBatch(ctx context.Context, batch []*AuditLog) {
	// Marshal the batch
	data, err := json.Marshal(batch)
	if err != nil {
		log.Printf("Failed to marshal audit batch: %v", err)
		return
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "POST", c.config.AegisGateURL+"/batch", bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to create audit request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.config.APIKey)
	req.Header.Set("X-Audit-Secret", c.config.Secret)

	// Send the request
	resp, err := c.client.Do(req)
	if err != nil {
		log.Printf("Failed to send audit batch: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Audit service returned error: %s, body: %s", resp.Status, string(body))
	}
}
