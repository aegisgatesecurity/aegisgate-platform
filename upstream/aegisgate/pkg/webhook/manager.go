// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package webhook provides the webhook manager implementation.
package webhook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/siem"
)

// ============================================================================
// Manager - Webhook Manager
// ============================================================================

// Manager manages webhook registrations and deliveries.
type Manager struct {
	config   ManagerConfig
	webhooks map[string]*WebhookConfig
	senders  map[string]Sender
	statuses map[string]*DeliveryStatus
	stats    *ManagerStats
	sender   Sender
	filter   *EventMatcher
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.RWMutex

	// Channels
	deliveryChan chan *deliveryRequest
	errorChan    chan error

	// Worker pool
	workerPool chan struct{}
}

// ManagerConfig contains manager configuration.
type ManagerConfig struct {
	// HTTP client configuration
	HTTPClient *HTTPClientConfig
	// Worker pool configuration
	WorkerPool WorkerPoolConfig
	// Batch delivery configuration
	Batch BatchDeliveryConfig
	// Default retry configuration
	DefaultRetry RetryConfig
	// Enable metrics collection
	EnableMetrics bool
	// Maximum delivery history per webhook
	MaxHistorySize int
}

// DefaultManagerConfig returns default manager configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		HTTPClient:     DefaultHTTPClientConfig(),
		WorkerPool:     DefaultWorkerPoolConfig(),
		Batch:          DefaultBatchDeliveryConfig(),
		DefaultRetry:   DefaultRetryConfig(),
		EnableMetrics:  true,
		MaxHistorySize: 100,
	}
}

// deliveryRequest represents a webhook delivery request.
type deliveryRequest struct {
	webhookID string
	payload   *WebhookPayload
}

// NewManager creates a new webhook manager.
func NewManager(config ManagerConfig) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:       config,
		webhooks:     make(map[string]*WebhookConfig),
		senders:      make(map[string]Sender),
		statuses:     make(map[string]*DeliveryStatus),
		stats:        &ManagerStats{WebhookStats: make(map[string]*WebhookStats)},
		filter:       NewEventMatcher(),
		ctx:          ctx,
		cancel:       cancel,
		deliveryChan: make(chan *deliveryRequest, config.WorkerPool.QueueSize),
		errorChan:    make(chan error, 100),
		workerPool:   make(chan struct{}, config.WorkerPool.Workers),
	}

	// Create default sender
	httpClient, err := NewHTTPClient(config.HTTPClient)
	if err != nil {
		cancel()
		return nil, NewError("", "init", "failed to create HTTP client", false, err)
	}
	m.sender = NewHTTPSender(httpClient, config.DefaultRetry)

	return m, nil
}

// Start starts the webhook manager.
func (m *Manager) Start() {
	// Start worker pool
	for i := 0; i < m.config.WorkerPool.Workers; i++ {
		m.wg.Add(1)
		go m.worker(i)
	}

	// Start error collector
	m.wg.Add(1)
	go m.collectErrors()

	// Start batch processor if enabled
	if m.config.Batch.Enabled {
		m.wg.Add(1)
		go m.batchProcessor()
	}
}

// Stop stops the webhook manager.
func (m *Manager) Stop() {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), m.config.WorkerPool.ShutdownTimeout)
	defer shutdownCancel()

	m.cancel()

	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		close(m.deliveryChan)
		close(m.errorChan)
	case <-shutdownCtx.Done():
		// Force shutdown
	}
}

// ============================================================================
// Webhook Registration
// ============================================================================

// Register registers a new webhook.
func (m *Manager) Register(config WebhookConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Set default auth type to "none" if not specified
	if config.Auth.Type == "" {
		config.Auth.Type = AuthNone
	}

	// Validate configuration
	if err := m.validateConfig(&config); err != nil {
		return err
	}

	// Generate ID if not provided
	if config.ID == "" {
		config.ID = generateID()
	}

	// Set timestamps
	if config.CreatedAt.IsZero() {
		config.CreatedAt = time.Now()
	}
	config.UpdatedAt = time.Now()

	// Set defaults
	if config.Method == "" {
		config.Method = http.MethodPost
	}
	if config.ContentType == "" {
		config.ContentType = "application/json"
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxConcurrency == 0 {
		config.MaxConcurrency = 5
	}
	if len(config.Headers) == 0 {
		config.Headers = make(map[string]string)
	}

	// Create sender for this webhook
	sender, err := m.createSender(&config)
	if err != nil {
		return err
	}

	// Store webhook
	m.webhooks[config.ID] = &config
	m.senders[config.ID] = sender
	m.stats.WebhookStats[config.ID] = &WebhookStats{}

	// Update stats
	m.stats.TotalWebhooks++
	if config.Enabled {
		m.stats.EnabledWebhooks++
	}

	return nil
}

// Unregister removes a webhook.
func (m *Manager) Unregister(webhookID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.webhooks[webhookID]; !exists {
		return NewError(webhookID, "unregister", "webhook not found", false, nil)
	}

	// Check if webhook is enabled before decrementing
	if m.webhooks[webhookID].Enabled {
		m.stats.EnabledWebhooks--
	}
	m.stats.TotalWebhooks--

	delete(m.webhooks, webhookID)
	delete(m.senders, webhookID)
	delete(m.stats.WebhookStats, webhookID)
	delete(m.statuses, webhookID)

	return nil
}

// Update updates an existing webhook.
func (m *Manager) Update(config WebhookConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.webhooks[config.ID]; !exists {
		return NewError(config.ID, "update", "webhook not found", false, nil)
	}

	// Set default auth type to "none" if not specified
	if config.Auth.Type == "" {
		config.Auth.Type = AuthNone
	}

	// Validate configuration
	if err := m.validateConfig(&config); err != nil {
		return err
	}

	// Update timestamp
	config.UpdatedAt = time.Now()

	// Recreate sender if needed
	sender, err := m.createSender(&config)
	if err != nil {
		return err
	}

	// Update stored webhook
	oldEnabled := m.webhooks[config.ID].Enabled
	m.webhooks[config.ID] = &config
	m.senders[config.ID] = sender

	// Update enabled count
	if oldEnabled != config.Enabled {
		if config.Enabled {
			m.stats.EnabledWebhooks++
		} else {
			m.stats.EnabledWebhooks--
		}
	}

	return nil
}

// GetWebhook retrieves a webhook by ID.
func (m *Manager) GetWebhook(webhookID string) (*WebhookConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	webhook, exists := m.webhooks[webhookID]
	if !exists {
		return nil, NewError(webhookID, "get", "webhook not found", false, nil)
	}
	return webhook, nil
}

// ListWebhooks returns all registered webhooks.
func (m *Manager) ListWebhooks() []*WebhookConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	webhooks := make([]*WebhookConfig, 0, len(m.webhooks))
	for _, w := range m.webhooks {
		webhooks = append(webhooks, w)
	}
	return webhooks
}

// Enable enables a webhook.
func (m *Manager) Enable(webhookID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	webhook, exists := m.webhooks[webhookID]
	if !exists {
		return NewError(webhookID, "enable", "webhook not found", false, nil)
	}

	if !webhook.Enabled {
		webhook.Enabled = true
		webhook.UpdatedAt = time.Now()
		m.stats.EnabledWebhooks++
	}

	return nil
}

// Disable disables a webhook.
func (m *Manager) Disable(webhookID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	webhook, exists := m.webhooks[webhookID]
	if !exists {
		return NewError(webhookID, "disable", "webhook not found", false, nil)
	}

	if webhook.Enabled {
		webhook.Enabled = false
		webhook.UpdatedAt = time.Now()
		m.stats.EnabledWebhooks--
	}

	return nil
}

// ============================================================================
// Webhook Delivery
// ============================================================================

// Send sends an event to matching webhooks.
func (m *Manager) Send(ctx context.Context, event *siem.Event) error {
	if event == nil {
		return NewError("", "send", "event is nil", false, nil)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var deliveries []*deliveryRequest

	for _, webhook := range m.webhooks {
		if !webhook.Enabled {
			continue
		}

		// Check if event matches triggers
		if !m.matchTriggers(event, webhook.Triggers) {
			m.stats.mu.Lock()
			m.stats.EventsFiltered++
			m.stats.mu.Unlock()
			continue
		}

		// Create payload
		payload := m.createPayload(webhook, event)
		deliveries = append(deliveries, &deliveryRequest{
			webhookID: webhook.ID,
			payload:   payload,
		})
	}

	// Queue deliveries
	for _, d := range deliveries {
		select {
		case m.deliveryChan <- d:
			m.updateStats(d.webhookID, false, false, nil, nil)
			m.stats.mu.Lock()
			m.stats.TotalDeliveries++
			m.stats.mu.Unlock()
		default:
			// Queue full, record error
			m.errorChan <- NewError(d.webhookID, "send", "delivery queue full", false, nil)
		}
	}

	return nil
}

// SendBatch sends multiple events to matching webhooks.
func (m *Manager) SendBatch(ctx context.Context, events []*siem.Event) error {
	for _, event := range events {
		if err := m.Send(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

// SendSync sends an event synchronously to matching webhooks.
func (m *Manager) SendSync(ctx context.Context, event *siem.Event) error {
	if event == nil {
		return NewError("", "send_sync", "event is nil", false, nil)
	}

	// Collect webhooks to send to while holding read lock
	type delivery struct {
		webhook *WebhookConfig
		sender  Sender
	}
	var deliveries []delivery

	m.mu.RLock()
	for _, webhook := range m.webhooks {
		if !webhook.Enabled {
			continue
		}

		// Check if event matches triggers
		if !m.matchTriggers(event, webhook.Triggers) {
			continue
		}

		sender := m.senders[webhook.ID]
		if sender == nil {
			sender = m.sender
		}
		deliveries = append(deliveries, delivery{webhook: webhook, sender: sender})
	}
	m.mu.RUnlock()

	// Send without holding any locks
	var lastErr error
	for _, d := range deliveries {
		payload := m.createPayload(d.webhook, event)

		resp, err := d.sender.Send(ctx, d.webhook, payload)
		if err != nil {
			lastErr = err
			m.recordDelivery(d.webhook.ID, payload.ID, false, err, resp)
		} else {
			m.recordDelivery(d.webhook.ID, payload.ID, true, nil, resp)
		}
	}

	return lastErr
}

// SendToWebhook sends an event to a specific webhook.
func (m *Manager) SendToWebhook(ctx context.Context, webhookID string, event *siem.Event) error {
	m.mu.RLock()
	webhook, exists := m.webhooks[webhookID]
	sender := m.senders[webhookID]
	m.mu.RUnlock()

	if !exists {
		return NewError(webhookID, "send", "webhook not found", false, nil)
	}

	if !webhook.Enabled {
		return NewError(webhookID, "send", "webhook is disabled", false, nil)
	}

	payload := m.createPayload(webhook, event)
	if sender == nil {
		sender = m.sender
	}

	resp, err := sender.Send(ctx, webhook, payload)
	if err != nil {
		m.recordDelivery(webhookID, payload.ID, false, err, resp)
		return err
	}

	m.recordDelivery(webhookID, payload.ID, true, nil, resp)
	return nil
}

// ============================================================================
// Status and Statistics
// ============================================================================

// GetStatus returns the delivery status for a webhook.
func (m *Manager) GetStatus(webhookID string) (*DeliveryStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status, exists := m.statuses[webhookID]
	if !exists {
		return nil, NewError(webhookID, "status", "no status available", false, nil)
	}
	return status, nil
}

// GetStats returns webhook statistics.
func (m *Manager) GetStats(webhookID string) (*WebhookStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats, exists := m.stats.WebhookStats[webhookID]
	if !exists {
		return nil, NewError(webhookID, "stats", "webhook not found", false, nil)
	}
	return stats, nil
}

// GetManagerStats returns overall manager statistics.
func (m *Manager) GetManagerStats() *ManagerStats {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()

	return &ManagerStats{
		TotalWebhooks:   m.stats.TotalWebhooks,
		EnabledWebhooks: m.stats.EnabledWebhooks,
		TotalDeliveries: m.stats.TotalDeliveries,
		SuccessCount:    m.stats.SuccessCount,
		FailureCount:    m.stats.FailureCount,
		EventsFiltered:  m.stats.EventsFiltered,
		WebhookStats:    m.stats.WebhookStats,
	}
}

// ============================================================================
// Validation
// ============================================================================

// Validate validates a webhook configuration.
func (m *Manager) Validate(config *WebhookConfig) error {
	// Set default auth type to "none" if not specified
	if config.Auth.Type == "" {
		config.Auth.Type = AuthNone
	}
	return m.validateConfig(config)
}

// ValidateConfig validates a webhook configuration.
func ValidateConfig(config *WebhookConfig) error {
	m, err := NewManager(DefaultManagerConfig())
	if err != nil {
		return err
	}
	// Set default auth type to "none" if not specified
	if config.Auth.Type == "" {
		config.Auth.Type = AuthNone
	}
	return m.validateConfig(config)
}

func (m *Manager) validateConfig(config *WebhookConfig) error {
	if config == nil {
		return NewError("", "validate", "config is nil", false, nil)
	}

	if config.URL == "" {
		return NewError(config.ID, "validate", "URL is required", false, nil)
	}

	// Validate URL
	if len(config.URL) < 4 || config.URL[:4] != "http" {
		return NewError(config.ID, "validate", "URL must start with http:// or https://", false, nil)
	}

	// Validate method
	validMethods := map[string]bool{
		http.MethodPost:  true,
		http.MethodPut:   true,
		http.MethodPatch: true,
	}
	if config.Method != "" && !validMethods[config.Method] {
		return NewError(config.ID, "validate", "invalid HTTP method", false, nil)
	}

	// Validate authentication
	if err := m.validateAuth(config); err != nil {
		return err
	}

	// Validate retry config
	if config.Retry.Enabled && config.Retry.MaxAttempts < 1 {
		return NewError(config.ID, "validate", "max attempts must be at least 1", false, nil)
	}

	return nil
}

func (m *Manager) validateAuth(config *WebhookConfig) error {
	switch config.Auth.Type {
	case AuthNone:
		// No validation needed
	case AuthBasic:
		if config.Auth.Username == "" {
			return NewError(config.ID, "validate", "username required for basic auth", false, nil)
		}
	case AuthBearer:
		if config.Auth.Token == "" {
			return NewError(config.ID, "validate", "token required for bearer auth", false, nil)
		}
	case AuthAPIKey:
		if config.Auth.APIKey == "" {
			return NewError(config.ID, "validate", "API key required for API key auth", false, nil)
		}
	case AuthHMAC:
		if config.Auth.HMAC == nil || config.Auth.HMAC.Secret == "" {
			return NewError(config.ID, "validate", "HMAC config required for HMAC auth", false, nil)
		}
	case AuthOAuth2:
		if config.Auth.OAuth2 == nil || config.Auth.OAuth2.TokenURL == "" {
			return NewError(config.ID, "validate", "OAuth2 config required for OAuth2 auth", false, nil)
		}
	default:
		return NewError(config.ID, "validate", "unknown authentication type", false, nil)
	}
	return nil
}

// ============================================================================
// Testing
// ============================================================================

// Test tests a webhook configuration by sending a test request.
func (m *Manager) Test(ctx context.Context, config *WebhookConfig) error {
	// Set default auth type to "none" if not specified
	if config.Auth.Type == "" {
		config.Auth.Type = AuthNone
	}

	if err := m.validateConfig(config); err != nil {
		return err
	}

	// Create a test payload
	payload := &WebhookPayload{
		ID:        generateID(),
		Timestamp: time.Now(),
		WebhookID: config.ID,
		EventType: "test",
		Severity:  siem.SeverityInfo,
		Source:    "aegisgate-webhook-test",
		Message:   "Webhook test request",
		Data: map[string]interface{}{
			"test": true,
			"time": time.Now().Format(time.RFC3339),
		},
	}

	// Create sender
	sender, err := m.createSender(config)
	if err != nil {
		return err
	}

	// Send test request
	resp, err := sender.Send(ctx, config, payload)
	if err != nil {
		return NewError(config.ID, "test", "test request failed: "+err.Error(), false, err)
	}

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(config.ID, "test", fmt.Sprintf("test request returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

// ============================================================================
// Helper Methods
// ============================================================================

// createSender creates a sender for a webhook.
func (m *Manager) createSender(config *WebhookConfig) (Sender, error) {
	httpConfig := &HTTPClientConfig{
		Timeout:               config.Timeout,
		MaxIdleConns:          m.config.HTTPClient.MaxIdleConns,
		MaxIdleConnsPerHost:   m.config.HTTPClient.MaxIdleConnsPerHost,
		IdleConnTimeout:       m.config.HTTPClient.IdleConnTimeout,
		ResponseHeaderTimeout: m.config.HTTPClient.ResponseHeaderTimeout,
		ExpectContinueTimeout: m.config.HTTPClient.ExpectContinueTimeout,
		TLS:                   &config.TLS,
	}

	if httpConfig.Timeout == 0 {
		httpConfig.Timeout = 30 * time.Second
	}

	httpClient, err := NewHTTPClient(httpConfig)
	if err != nil {
		return nil, err
	}

	retry := config.Retry
	if !retry.Enabled {
		retry = m.config.DefaultRetry
	}

	return NewHTTPSender(httpClient, retry), nil
}

// createPayload creates a webhook payload from an event.
func (m *Manager) createPayload(config *WebhookConfig, event *siem.Event) *WebhookPayload {
	payload := &WebhookPayload{
		ID:        generateID(),
		Timestamp: time.Now(),
		WebhookID: config.ID,
		EventType: event.Type,
		Severity:  event.Severity,
		Category:  event.Category,
		Source:    event.Source,
		Message:   event.Message,
		Data:      make(map[string]interface{}),
		Metadata:  make(map[string]string),
	}

	if config.IncludeEventDetails {
		payload.Event = event
	}

	return payload
}

// matchTriggers checks if an event matches trigger conditions.
func (m *Manager) matchTriggers(event *siem.Event, triggers []TriggerCondition) bool {
	if len(triggers) == 0 {
		return true
	}

	for _, trigger := range triggers {
		if m.matchTrigger(event, trigger) {
			return true
		}
	}
	return false
}

// matchTrigger checks if an event matches a single trigger condition.
func (m *Manager) matchTrigger(event *siem.Event, trigger TriggerCondition) bool {
	// Check minimum severity
	if trigger.MinSeverity != "" {
		if !m.meetsMinSeverity(event.Severity, trigger.MinSeverity) {
			return false
		}
	}

	// Check excluded severities
	for _, sev := range trigger.ExcludeSeverities {
		if event.Severity == sev {
			return false
		}
	}

	// Check categories
	if len(trigger.Categories) > 0 {
		found := false
		for _, cat := range trigger.Categories {
			if event.Category == cat {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check excluded categories
	for _, cat := range trigger.ExcludeCategories {
		if event.Category == cat {
			return false
		}
	}

	// Check sources
	if len(trigger.Sources) > 0 {
		found := false
		for _, src := range trigger.Sources {
			if event.Source == src {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check excluded sources
	for _, src := range trigger.ExcludeSources {
		if event.Source == src {
			return false
		}
	}

	// Check event types
	if len(trigger.EventTypes) > 0 {
		found := false
		for _, t := range trigger.EventTypes {
			if event.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check excluded event types
	for _, t := range trigger.ExcludeEventTypes {
		if event.Type == t {
			return false
		}
	}

	return true
}

// meetsMinSeverity checks if an event meets the minimum severity.
func (m *Manager) meetsMinSeverity(eventSev, minSev siem.Severity) bool {
	severityOrder := map[siem.Severity]int{
		siem.SeverityCritical: 5,
		siem.SeverityHigh:     4,
		siem.SeverityMedium:   3,
		siem.SeverityLow:      2,
		siem.SeverityInfo:     1,
	}

	eventLevel := severityOrder[eventSev]
	minLevel := severityOrder[minSev]

	return eventLevel >= minLevel
}

// recordDelivery records the result of a delivery attempt.
func (m *Manager) recordDelivery(webhookID, payloadID string, success bool, err error, resp *DeliveryResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get or create status
	status, exists := m.statuses[webhookID]
	if !exists {
		status = &DeliveryStatus{
			WebhookID: webhookID,
			Status:    StatusPending,
			CreatedAt: time.Now(),
		}
		m.statuses[webhookID] = status
	}

	// Update delivery attempt
	attempt := DeliveryAttempt{
		Timestamp: time.Now(),
		Success:   success,
	}
	if err != nil {
		attempt.Error = err.Error()
	}
	if resp != nil {
		attempt.StatusCode = resp.StatusCode
		attempt.ResponseBody = resp.Body
		attempt.ResponseHeaders = resp.Headers
	}

	status.Attempts = append(status.Attempts, attempt)
	status.TotalAttempts = len(status.Attempts)
	status.LastAttempt = attempt.Timestamp

	// Update status
	if success {
		status.Status = StatusDelivered
		status.LastSuccess = attempt.Timestamp
		status.FinalResponse = resp
	} else {
		status.Status = StatusFailed
		status.FinalResponse = resp
	}

	// Trim history if needed
	if len(status.Attempts) > m.config.MaxHistorySize {
		status.Attempts = status.Attempts[len(status.Attempts)-m.config.MaxHistorySize:]
	}

	// Update stats
	m.updateStats(webhookID, success, false, resp, err)
}

// updateStats updates webhook statistics.
func (m *Manager) updateStats(webhookID string, success, dropped bool, resp *DeliveryResponse, err error) {
	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()

	stats, exists := m.stats.WebhookStats[webhookID]
	if !exists {
		stats = &WebhookStats{}
		m.stats.WebhookStats[webhookID] = stats
	}

	if dropped {
		stats.EventsDropped++
		m.stats.EventsFiltered++
		return
	}

	if success {
		stats.SuccessCount++
		stats.LastSuccess = time.Now()
		stats.ConsecutiveFailures = 0
		stats.EventsSent++
		m.stats.SuccessCount++
	} else {
		stats.FailureCount++
		stats.LastFailure = time.Now()
		stats.ConsecutiveFailures++
		if err != nil {
			stats.LastError = err.Error()
		}
		m.stats.FailureCount++
	}
}

// ============================================================================
// Background Workers
// ============================================================================

// worker processes delivery requests.
func (m *Manager) worker(id int) {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case req, ok := <-m.deliveryChan:
			if !ok {
				return
			}
			m.processDelivery(req)
		}
	}
}

// processDelivery processes a single delivery request.
func (m *Manager) processDelivery(req *deliveryRequest) {
	m.mu.RLock()
	webhook := m.webhooks[req.webhookID]
	sender := m.senders[req.webhookID]
	m.mu.RUnlock()

	if webhook == nil || !webhook.Enabled {
		m.errorChan <- NewError(req.webhookID, "deliver", "webhook not available", false, nil)
		return
	}

	if sender == nil {
		sender = m.sender
	}

	resp, err := sender.Send(m.ctx, webhook, req.payload)
	if err != nil {
		m.errorChan <- err
		m.recordDelivery(req.webhookID, req.payload.ID, false, err, resp)
	} else {
		m.recordDelivery(req.webhookID, req.payload.ID, true, nil, resp)
	}
}

// collectErrors collects and processes errors.
func (m *Manager) collectErrors() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case err, ok := <-m.errorChan:
			if !ok {
				return
			}
			// Log error (in a real implementation, this would go to a logger)
			_ = err
		}
	}
}

// batchProcessor handles batch delivery.
func (m *Manager) batchProcessor() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.Batch.MaxWait)
	defer ticker.Stop()

	batches := make(map[string][]*WebhookPayload)

	for {
		select {
		case <-m.ctx.Done():
			// Flush remaining batches
			for webhookID, batch := range batches {
				if len(batch) > 0 {
					m.sendBatch(webhookID, batch)
				}
			}
			return
		case <-ticker.C:
			// Flush all batches
			for webhookID, batch := range batches {
				if len(batch) > 0 {
					m.sendBatch(webhookID, batch)
					batches[webhookID] = nil
				}
			}
		}
	}
}

// sendBatch sends a batch of payloads to a webhook.
func (m *Manager) sendBatch(webhookID string, payloads []*WebhookPayload) {
	if len(payloads) == 0 {
		return
	}

	m.mu.RLock()
	webhook := m.webhooks[webhookID]
	sender := m.senders[webhookID]
	m.mu.RUnlock()

	if webhook == nil || sender == nil {
		return
	}

	batch := &BatchPayload{
		ID:        generateID(),
		Timestamp: time.Now(),
		WebhookID: webhookID,
		Events:    payloads,
	}

	// Calculate size
	data, _ := json.Marshal(batch)
	batch.Size = len(data)

	// Send batch - ignore error for batch operations
	_, _ = sender.Send(m.ctx, webhook, batch)
}

// ============================================================================
// Global Manager
// ============================================================================

var (
	globalManager     *Manager
	globalManagerOnce sync.Once
	globalManagerMu   sync.RWMutex
)

// InitGlobalManager initializes the global webhook manager.
func InitGlobalManager(config ManagerConfig) error {
	var err error
	globalManagerOnce.Do(func() {
		globalManager, err = NewManager(config)
		if err == nil {
			globalManager.Start()
		}
	})
	return err
}

// GlobalManager returns the global webhook manager.
func GlobalManager() *Manager {
	globalManagerMu.RLock()
	defer globalManagerMu.RUnlock()
	return globalManager
}

// SetGlobalManager sets the global webhook manager.
func SetGlobalManager(m *Manager) {
	globalManagerMu.Lock()
	defer globalManagerMu.Unlock()
	globalManager = m
}

// ============================================================================
// Helper Functions
// ============================================================================

// generateID generates a unique identifier.
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Errors returns the error channel.
func (m *Manager) Errors() <-chan error {
	return m.errorChan
}
