// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package siem provides the central manager for SIEM integrations.
package siem

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// ============================================================================
// Manager - Central SIEM Integration Manager
// ============================================================================

// Manager is the central manager for all SIEM integrations.
// It provides a unified interface for sending events to multiple
// SIEM platforms simultaneously.
type Manager struct {
	config    Config
	clients   map[Platform]Client
	formatter Formatter
	filter    *EventFilter
	buffer    *EventBuffer
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex

	// Channels
	eventChan chan *Event
	errChan   chan error
	stats     *ManagerStats
}

// Client is the interface for SIEM platform clients.
type Client interface {
	Send(ctx context.Context, event *Event) error
	SendBatch(ctx context.Context, events []*Event) error
	Start()
	Stop()
	Events() chan<- *Event
	Errors() <-chan error
}

// ManagerStats tracks statistics for the manager.
type ManagerStats struct {
	mu             sync.RWMutex
	EventsReceived int64
	EventsSent     int64
	EventsDropped  int64
	EventsFiltered int64
	Errors         int64
	LastSendTime   time.Time
	PlatformStats  map[Platform]*PlatformStats
}

// PlatformStats tracks per-platform statistics.
type PlatformStats struct {
	EventsSent    int64
	EventsDropped int64
	Errors        int64
	LastSendTime  time.Time
	LastError     string
}

// NewManager creates a new SIEM integration manager.
func NewManager(config Config) (*Manager, error) {
	// Apply defaults
	if config.Global.AppName == "" {
		config.Global.AppName = "aegisgate"
	}
	if config.Global.DefaultSeverity == "" {
		config.Global.DefaultSeverity = SeverityInfo
	}
	if config.Buffer.MaxSize == 0 {
		config.Buffer.MaxSize = 10000
	}
	if config.Buffer.FlushInterval == 0 {
		config.Buffer.FlushInterval = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:    config,
		clients:   make(map[Platform]Client),
		formatter: NewJSONFormatter(PlatformCustom),
		filter:    NewEventFilter(config.Filter),
		buffer:    NewEventBuffer(PlatformCustom, config.Buffer.MaxSize),
		ctx:       ctx,
		cancel:    cancel,
		eventChan: make(chan *Event, 10000),
		errChan:   make(chan error, 1000),
		stats: &ManagerStats{
			PlatformStats: make(map[Platform]*PlatformStats),
		},
	}

	// Initialize clients for each platform
	for _, platformCfg := range config.Platforms {
		if !platformCfg.Enabled {
			continue
		}

		client, err := m.createClient(platformCfg)
		if err != nil {
			return nil, err
		}

		m.clients[platformCfg.Platform] = client
		m.stats.PlatformStats[platformCfg.Platform] = &PlatformStats{}
	}

	return m, nil
}

// createClient creates a client for the specified platform.
func (m *Manager) createClient(config PlatformConfig) (Client, error) {
	switch config.Platform {
	case PlatformSplunk:
		return NewSplunkClient(config)
	case PlatformElasticsearch:
		return NewElasticsearchClient(config)
	case PlatformQRadar:
		return NewQRadarClient(config)
	case PlatformSentinel:
		return NewSentinelClient(config)
	case PlatformSumoLogic:
		return NewSumoLogicClient(config)
	case PlatformLogRhythm:
		return NewLogRhythmClient(config)
	case PlatformArcSight:
		return NewArcSightClient(config)
	case PlatformSyslog:
		return NewSyslogClient(config)
	default:
		return nil, NewError(config.Platform, "init", "unsupported platform", false, nil)
	}
}

// Start starts the manager and all platform clients.
func (m *Manager) Start() {
	// Start all platform clients
	for _, client := range m.clients {
		client.Start()
	}

	// Start event processor
	m.wg.Add(1)
	go m.processEvents()

	// Start error collector
	m.wg.Add(1)
	go m.collectErrors()
}

// Stop stops the manager and all platform clients.
func (m *Manager) Stop() {
	m.cancel()

	// Stop all platform clients
	for _, client := range m.clients {
		client.Stop()
	}

	m.wg.Wait()
	close(m.eventChan)
	close(m.errChan)
}

// Send sends an event to all configured SIEM platforms.
func (m *Manager) Send(event *Event) error {
	// Validate event
	if err := m.validateEvent(event); err != nil {
		return err
	}

	// Apply defaults
	m.applyDefaults(event)

	// Check filter
	if !m.filter.Allow(event) {
		m.stats.mu.Lock()
		m.stats.EventsFiltered++
		m.stats.mu.Unlock()
		return nil
	}

	// Send to event channel (non-blocking)
	select {
	case m.eventChan <- event:
		m.stats.mu.Lock()
		m.stats.EventsReceived++
		m.stats.mu.Unlock()
		return nil
	default:
		m.stats.mu.Lock()
		m.stats.EventsDropped++
		m.stats.mu.Unlock()
		return NewError(PlatformCustom, "send", "event channel full", false, nil)
	}
}

// SendBatch sends multiple events to all configured SIEM platforms.
func (m *Manager) SendBatch(events []*Event) error {
	for _, event := range events {
		if err := m.Send(event); err != nil {
			return err
		}
	}
	return nil
}

// SendSync sends an event synchronously to all platforms.
func (m *Manager) SendSync(ctx context.Context, event *Event) error {
	// Validate and prepare event
	if err := m.validateEvent(event); err != nil {
		return err
	}
	m.applyDefaults(event)

	if !m.filter.Allow(event) {
		return nil
	}

	// Send to each platform
	var lastErr error
	for platform, client := range m.clients {
		if err := client.Send(ctx, event); err != nil {
			lastErr = err
			m.updatePlatformStats(platform, false, err)
		} else {
			m.updatePlatformStats(platform, true, nil)
		}
	}

	return lastErr
}

// Events returns the event channel for direct event injection.
func (m *Manager) Events() chan<- *Event {
	return m.eventChan
}

// Errors returns the error channel.
func (m *Manager) Errors() <-chan error {
	return m.errChan
}

// Stats returns current manager statistics.
func (m *Manager) Stats() *ManagerStats {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()

	// Create a copy without the mutex
	stats := &ManagerStats{
		EventsReceived: m.stats.EventsReceived,
		EventsSent:     m.stats.EventsSent,
		EventsDropped:  m.stats.EventsDropped,
		EventsFiltered: m.stats.EventsFiltered,
		Errors:         m.stats.Errors,
		LastSendTime:   m.stats.LastSendTime,
		PlatformStats:  make(map[Platform]*PlatformStats),
	}

	for k, v := range m.stats.PlatformStats {
		stats.PlatformStats[k] = &PlatformStats{
			EventsSent:    v.EventsSent,
			EventsDropped: v.EventsDropped,
			Errors:        v.Errors,
			LastSendTime:  v.LastSendTime,
			LastError:     v.LastError,
		}
	}

	return stats
}

// validateEvent validates an event before sending.
func (m *Manager) validateEvent(event *Event) error {
	if event == nil {
		return NewError(PlatformCustom, "validate", "event is nil", false, nil)
	}
	if event.ID == "" {
		event.ID = generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	return nil
}

// applyDefaults applies default values to an event.
func (m *Manager) applyDefaults(event *Event) {
	if event.Source == "" {
		event.Source = m.config.Global.AppName
	}
	if event.Severity == "" {
		event.Severity = m.config.Global.DefaultSeverity
	}
	if m.config.Global.AddHostname && event.Attributes != nil {
		if _, ok := event.Attributes["hostname"]; !ok {
			event.Attributes["hostname"] = getHostname()
		}
	}
}

// updatePlatformStats updates statistics for a platform.
func (m *Manager) updatePlatformStats(platform Platform, success bool, err error) {
	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()

	stats, ok := m.stats.PlatformStats[platform]
	if !ok {
		stats = &PlatformStats{}
		m.stats.PlatformStats[platform] = stats
	}

	if success {
		stats.EventsSent++
		stats.LastSendTime = time.Now()
	} else {
		stats.Errors++
		if err != nil {
			stats.LastError = err.Error()
		}
	}
}

// processEvents handles background event distribution.
func (m *Manager) processEvents() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case event := <-m.eventChan:
			m.distributeEvent(event)
		}
	}
}

// distributeEvent sends an event to all platform clients.
func (m *Manager) distributeEvent(event *Event) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for platform, client := range m.clients {
		select {
		case client.Events() <- event:
			// Event sent to client channel
		default:
			// Client channel full, record drop
			m.stats.mu.Lock()
			if stats, ok := m.stats.PlatformStats[platform]; ok {
				stats.EventsDropped++
			}
			m.stats.mu.Unlock()
		}
	}
}

// collectErrors collects errors from all platform clients.
func (m *Manager) collectErrors() {
	defer m.wg.Done()

	// Create error channels for each client
	errChans := make([]<-chan error, 0, len(m.clients))
	for _, client := range m.clients {
		errChans = append(errChans, client.Errors())
	}

	// Use select with a reflect-based approach for multiple channels
	// For simplicity, we'll poll each channel
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			for _, errChan := range errChans {
				select {
				case err := <-errChan:
					select {
					case m.errChan <- err:
						m.stats.mu.Lock()
						m.stats.Errors++
						m.stats.mu.Unlock()
					default:
						// Error channel full
					}
				default:
					// No error on this channel
				}
			}
		}
	}
}

// ============================================================================
// Event Filter
// ============================================================================

// EventFilter filters events based on configuration rules.
type EventFilter struct {
	config FilterConfig
}

// NewEventFilter creates a new event filter.
func NewEventFilter(config FilterConfig) *EventFilter {
	return &EventFilter{config: config}
}

// Allow determines if an event should be forwarded.
func (f *EventFilter) Allow(event *Event) bool {
	// Check minimum severity
	if !f.meetsMinSeverity(event.Severity) {
		return false
	}

	// Check include categories
	if len(f.config.IncludeCategories) > 0 {
		found := false
		for _, cat := range f.config.IncludeCategories {
			if event.Category == cat {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check exclude categories
	for _, cat := range f.config.ExcludeCategories {
		if event.Category == cat {
			return false
		}
	}

	// Check include types
	if len(f.config.IncludeTypes) > 0 {
		found := false
		for _, t := range f.config.IncludeTypes {
			if event.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check exclude types
	for _, t := range f.config.ExcludeTypes {
		if event.Type == t {
			return false
		}
	}

	return true
}

// meetsMinSeverity checks if an event meets the minimum severity threshold.
func (f *EventFilter) meetsMinSeverity(sev Severity) bool {
	severityOrder := map[Severity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
	}

	eventLevel := severityOrder[sev]
	minLevel := severityOrder[f.config.MinSeverity]

	return eventLevel >= minLevel
}

// ============================================================================
// Event Builders
// ============================================================================

// EventBuilder provides a fluent interface for building events.
type EventBuilder struct {
	event *Event
}

// NewEventBuilder creates a new event builder.
func NewEventBuilder() *EventBuilder {
	return &EventBuilder{
		event: &Event{
			ID:         generateEventID(),
			Timestamp:  time.Now(),
			Attributes: make(map[string]string),
			Entities:   make([]Entity, 0),
			Raw:        make(map[string]interface{}),
		},
	}
}

// WithID sets the event ID.
func (b *EventBuilder) WithID(id string) *EventBuilder {
	b.event.ID = id
	return b
}

// WithTimestamp sets the event timestamp.
func (b *EventBuilder) WithTimestamp(ts time.Time) *EventBuilder {
	b.event.Timestamp = ts
	return b
}

// WithSource sets the event source.
func (b *EventBuilder) WithSource(source string) *EventBuilder {
	b.event.Source = source
	return b
}

// WithCategory sets the event category.
func (b *EventBuilder) WithCategory(cat EventCategory) *EventBuilder {
	b.event.Category = cat
	return b
}

// WithType sets the event type.
func (b *EventBuilder) WithType(eventType string) *EventBuilder {
	b.event.Type = eventType
	return b
}

// WithSeverity sets the event severity.
func (b *EventBuilder) WithSeverity(sev Severity) *EventBuilder {
	b.event.Severity = sev
	return b
}

// WithMessage sets the event message.
func (b *EventBuilder) WithMessage(msg string) *EventBuilder {
	b.event.Message = msg
	return b
}

// WithAttribute adds an attribute to the event.
func (b *EventBuilder) WithAttribute(key, value string) *EventBuilder {
	b.event.Attributes[key] = value
	return b
}

// WithEntity adds an entity to the event.
func (b *EventBuilder) WithEntity(entityType, id, name, value string) *EventBuilder {
	b.event.Entities = append(b.event.Entities, Entity{
		Type:  entityType,
		ID:    id,
		Name:  name,
		Value: value,
	})
	return b
}

// WithMITRE adds MITRE ATT&CK mapping to the event.
func (b *EventBuilder) WithMITRE(tactic, technique string) *EventBuilder {
	b.event.MITRE = &MITREMapping{
		Tactic:    tactic,
		Technique: technique,
	}
	return b
}

// WithCompliance adds compliance framework mapping to the event.
func (b *EventBuilder) WithCompliance(framework, control string) *EventBuilder {
	b.event.Compliance = append(b.event.Compliance, ComplianceMapping{
		Framework: framework,
		Control:   control,
	})
	return b
}

// WithRaw sets raw event data.
func (b *EventBuilder) WithRaw(key string, value interface{}) *EventBuilder {
	b.event.Raw[key] = value
	return b
}

// Build returns the constructed event.
func (b *EventBuilder) Build() *Event {
	return b.event
}

// ============================================================================
// Helper Functions
// ============================================================================

// generateEventID generates a unique event ID.
func generateEventID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ============================================================================
// Configuration Loading
// ============================================================================

// LoadConfig loads SIEM configuration from a file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, NewError(PlatformCustom, "config", "failed to read config file", false, err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, NewError(PlatformCustom, "config", "failed to parse config file", false, err)
	}

	return &config, nil
}

// SaveConfig saves SIEM configuration to a file.
func SaveConfig(config *Config, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return NewError(PlatformCustom, "config", "failed to marshal config", false, err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return NewError(PlatformCustom, "config", "failed to write config file", false, err)
	}

	return nil
}

// ============================================================================
// Global Manager Instance
// ============================================================================

var (
	globalManager     *Manager
	globalManagerOnce sync.Once
	globalManagerMu   sync.RWMutex
)

// InitGlobalManager initializes the global SIEM manager.
func InitGlobalManager(config Config) error {
	var err error
	globalManagerOnce.Do(func() {
		globalManager, err = NewManager(config)
		if err == nil {
			globalManager.Start()
		}
	})
	return err
}

// GlobalManager returns the global SIEM manager.
func GlobalManager() *Manager {
	globalManagerMu.RLock()
	defer globalManagerMu.RUnlock()
	return globalManager
}

// SetGlobalManager sets the global SIEM manager.
func SetGlobalManager(m *Manager) {
	globalManagerMu.Lock()
	defer globalManagerMu.Unlock()
	globalManager = m
}

// SendEvent sends an event using the global manager.
func SendEvent(event *Event) error {
	if globalManager == nil {
		return NewError(PlatformCustom, "send", "global manager not initialized", false, nil)
	}
	return globalManager.Send(event)
}

// SendEventSync sends an event synchronously using the global manager.
func SendEventSync(ctx context.Context, event *Event) error {
	if globalManager == nil {
		return NewError(PlatformCustom, "send", "global manager not initialized", false, nil)
	}
	return globalManager.SendSync(ctx, event)
}
