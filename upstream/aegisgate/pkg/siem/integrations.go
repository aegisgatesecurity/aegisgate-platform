// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package siem provides Splunk SIEM integration.
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Splunk Integration
// ============================================================================

// SplunkClient implements SIEM integration with Splunk.
type SplunkClient struct {
	config     PlatformConfig
	httpClient *HTTPClient
	formatter  Formatter
	eventChan  chan *Event
	errChan    chan error
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	buffer     *EventBuffer
}

// SplunkEvent represents a Splunk HEC event.
type SplunkEvent struct {
	Time       int64                  `json:"time"`
	Host       string                 `json:"host"`
	Source     string                 `json:"source"`
	SourceType string                 `json:"sourcetype"`
	Index      string                 `json:"index"`
	Data       interface{}            `json:"event"`
	Fields     map[string]interface{} `json:"fields,omitempty"`
}

// SplunkConfig contains Splunk-specific settings.
type SplunkConfig struct {
	// HEC endpoint URL
	HECURL string `json:"hec_url"`
	// HEC token
	HECToken string `json:"hec_token"`
	// Index name
	Index string `json:"index"`
	// Source type
	SourceType string `json:"source_type"`
	// Source name
	Source string `json:"source"`
	// Use batch API
	UseBatchAPI bool `json:"use_batch_api"`
}

// NewSplunkClient creates a new Splunk SIEM client.
func NewSplunkClient(config PlatformConfig) (*SplunkClient, error) {
	if config.Endpoint == "" {
		return nil, NewError(PlatformSplunk, "init", "endpoint URL is required", false, nil)
	}

	httpClient, err := NewHTTPClient(PlatformSplunk, config.TLS)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &SplunkClient{
		config:     config,
		httpClient: httpClient,
		formatter:  NewJSONFormatter(PlatformSplunk),
		eventChan:  make(chan *Event, 1000),
		errChan:    make(chan error, 100),
		ctx:        ctx,
		cancel:     cancel,
		buffer:     NewEventBuffer(PlatformSplunk, config.Batch.MaxSize),
	}

	return client, nil
}

// Send sends an event to Splunk.
func (c *SplunkClient) Send(ctx context.Context, event *Event) error {
	// Convert to Splunk format
	splunkEvent := c.convertEvent(event)

	data, err := json.Marshal(splunkEvent)
	if err != nil {
		return NewError(PlatformSplunk, "send", "failed to marshal event", false, err)
	}

	// Build request URL
	endpoint := strings.TrimSuffix(c.config.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/services/collector") {
		endpoint = endpoint + "/services/collector"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return NewError(PlatformSplunk, "send", "failed to create request", false, err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Splunk %s", c.config.Auth.APIKey))

	// Send request
	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformSplunk, "send", fmt.Sprintf("splunk returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

// SendBatch sends multiple events to Splunk.
func (c *SplunkClient) SendBatch(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	// Build batch payload
	var buf bytes.Buffer
	for _, event := range events {
		splunkEvent := c.convertEvent(event)
		data, err := json.Marshal(splunkEvent)
		if err != nil {
			continue // Skip malformed events
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	// Build request URL
	endpoint := strings.TrimSuffix(c.config.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/services/collector") {
		endpoint = endpoint + "/services/collector"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return NewError(PlatformSplunk, "send_batch", "failed to create request", false, err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Splunk %s", c.config.Auth.APIKey))

	// Send request
	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformSplunk, "send_batch", fmt.Sprintf("splunk returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

// convertEvent converts a generic Event to Splunk format.
func (c *SplunkClient) convertEvent(event *Event) SplunkEvent {
	// Get config settings
	splunkConfig := c.getSplunkConfig()

	return SplunkEvent{
		Time:       event.Timestamp.Unix(),
		Host:       getHostname(),
		Source:     splunkConfig.Source,
		SourceType: splunkConfig.SourceType,
		Index:      splunkConfig.Index,
		Data:       event,
		Fields: map[string]interface{}{
			"severity":   string(event.Severity),
			"category":   string(event.Category),
			"event_type": event.Type,
			"event_id":   event.ID,
		},
	}
}

// getSplunkConfig extracts Splunk-specific configuration.
func (c *SplunkClient) getSplunkConfig() SplunkConfig {
	config := SplunkConfig{
		Index:      "main",
		SourceType: "aegisgate:security",
		Source:     "aegisgate",
	}

	if c.config.Settings != nil {
		if idx, ok := c.config.Settings["index"].(string); ok {
			config.Index = idx
		}
		if st, ok := c.config.Settings["source_type"].(string); ok {
			config.SourceType = st
		}
		if s, ok := c.config.Settings["source"].(string); ok {
			config.Source = s
		}
	}

	return config
}

// Start starts the background event processor.
func (c *SplunkClient) Start() {
	c.wg.Add(1)
	go c.processEvents()
}

// Stop stops the client.
func (c *SplunkClient) Stop() {
	c.cancel()
	c.wg.Wait()
	close(c.eventChan)
	close(c.errChan)
}

// Events returns the event channel.
func (c *SplunkClient) Events() chan<- *Event {
	return c.eventChan
}

// Errors returns the error channel.
func (c *SplunkClient) Errors() <-chan error {
	return c.errChan
}

// processEvents handles background event processing.
func (c *SplunkClient) processEvents() {
	defer c.wg.Done()

	batchTimer := time.NewTimer(c.config.Batch.MaxWait)
	defer batchTimer.Stop()

	for {
		select {
		case <-c.ctx.Done():
			// Flush remaining events
			c.flush()
			return

		case event := <-c.eventChan:
			if err := c.buffer.Add(event); err != nil {
				c.errChan <- err
				continue
			}

			// Check if we should flush
			if c.buffer.IsFull() {
				c.flush()
				batchTimer.Reset(c.config.Batch.MaxWait)
			}

		case <-batchTimer.C:
			c.flush()
			batchTimer.Reset(c.config.Batch.MaxWait)
		}
	}
}

// flush sends buffered events.
func (c *SplunkClient) flush() {
	events := c.buffer.Flush()
	if len(events) == 0 {
		return
	}

	if err := c.SendBatch(c.ctx, events); err != nil {
		c.errChan <- err
	}
}

// ============================================================================
// Elasticsearch Integration
// ============================================================================

// ElasticsearchClient implements SIEM integration with Elasticsearch.
type ElasticsearchClient struct {
	config     PlatformConfig
	httpClient *HTTPClient
	formatter  Formatter
	eventChan  chan *Event
	errChan    chan error
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	buffer     *EventBuffer
}

// ElasticsearchConfig contains Elasticsearch-specific settings.
type ElasticsearchConfig struct {
	// Index name (supports date patterns)
	Index string `json:"index"`
	// Pipeline name
	Pipeline string `json:"pipeline,omitempty"`
	// Use data stream
	DataStream bool `json:"data_stream"`
	// Data stream type
	DataStreamType string `json:"data_stream_type"`
}

// NewElasticsearchClient creates a new Elasticsearch SIEM client.
func NewElasticsearchClient(config PlatformConfig) (*ElasticsearchClient, error) {
	if config.Endpoint == "" {
		return nil, NewError(PlatformElasticsearch, "init", "endpoint URL is required", false, nil)
	}

	httpClient, err := NewHTTPClient(PlatformElasticsearch, config.TLS)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &ElasticsearchClient{
		config:     config,
		httpClient: httpClient,
		formatter:  NewJSONFormatter(PlatformElasticsearch),
		eventChan:  make(chan *Event, 1000),
		errChan:    make(chan error, 100),
		ctx:        ctx,
		cancel:     cancel,
		buffer:     NewEventBuffer(PlatformElasticsearch, config.Batch.MaxSize),
	}

	return client, nil
}

// Send sends an event to Elasticsearch.
func (c *ElasticsearchClient) Send(ctx context.Context, event *Event) error {
	esConfig := c.getESConfig()

	// Build index URL (support date patterns)
	indexName := c.resolveIndexName(esConfig.Index, event.Timestamp)
	endpoint := fmt.Sprintf("%s/%s/_doc", strings.TrimSuffix(c.config.Endpoint, "/"), indexName)

	data, err := json.Marshal(event)
	if err != nil {
		return NewError(PlatformElasticsearch, "send", "failed to marshal event", false, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return NewError(PlatformElasticsearch, "send", "failed to create request", false, err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	c.setAuthHeaders(req)

	// Send request
	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformElasticsearch, "send", fmt.Sprintf("elasticsearch returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

// SendBatch sends multiple events using bulk API.
func (c *ElasticsearchClient) SendBatch(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	esConfig := c.getESConfig()

	// Build bulk request
	var buf bytes.Buffer
	for _, event := range events {
		indexName := c.resolveIndexName(esConfig.Index, event.Timestamp)

		// Write action line
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": indexName,
			},
		}
		actionData, _ := json.Marshal(action)
		buf.Write(actionData)
		buf.WriteByte('\n')

		// Write document
		docData, err := json.Marshal(event)
		if err != nil {
			continue
		}
		buf.Write(docData)
		buf.WriteByte('\n')
	}

	// Build bulk URL
	endpoint := fmt.Sprintf("%s/_bulk", strings.TrimSuffix(c.config.Endpoint, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return NewError(PlatformElasticsearch, "send_batch", "failed to create request", false, err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-ndjson")
	c.setAuthHeaders(req)

	// Send request
	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformElasticsearch, "send_batch", fmt.Sprintf("elasticsearch returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

// getESConfig extracts Elasticsearch-specific configuration.
func (c *ElasticsearchClient) getESConfig() ElasticsearchConfig {
	config := ElasticsearchConfig{
		Index:          "aegisgate-security",
		DataStream:     false,
		DataStreamType: "logs",
	}

	if c.config.Settings != nil {
		if idx, ok := c.config.Settings["index"].(string); ok {
			config.Index = idx
		}
		if ds, ok := c.config.Settings["data_stream"].(bool); ok {
			config.DataStream = ds
		}
		if dst, ok := c.config.Settings["data_stream_type"].(string); ok {
			config.DataStreamType = dst
		}
	}

	return config
}

// resolveIndexName resolves index name with date patterns.
func (c *ElasticsearchClient) resolveIndexName(pattern string, ts time.Time) string {
	// Support common date patterns: {yyyy.MM.dd}
	result := pattern
	result = strings.ReplaceAll(result, "{yyyy}", ts.Format("2006"))
	result = strings.ReplaceAll(result, "{MM}", ts.Format("01"))
	result = strings.ReplaceAll(result, "{dd}", ts.Format("02"))
	result = strings.ReplaceAll(result, "{yyyy.MM.dd}", ts.Format("2006.01.02"))
	result = strings.ReplaceAll(result, "{yyyy-MM-dd}", ts.Format("2006-01-02"))
	return result
}

// setAuthHeaders sets authentication headers based on config.
func (c *ElasticsearchClient) setAuthHeaders(req *http.Request) {
	switch c.config.Auth.Type {
	case "api_key":
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", c.config.Auth.APIKey))
	case "basic":
		req.SetBasicAuth(c.config.Auth.Username, c.config.Auth.Password)
	case "bearer":
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.config.Auth.APIKey))
	}
}

// Start starts the background event processor.
func (c *ElasticsearchClient) Start() {
	c.wg.Add(1)
	go c.processEvents()
}

// Stop stops the client.
func (c *ElasticsearchClient) Stop() {
	c.cancel()
	c.wg.Wait()
	close(c.eventChan)
	close(c.errChan)
}

// Events returns the event channel.
func (c *ElasticsearchClient) Events() chan<- *Event {
	return c.eventChan
}

// Errors returns the error channel.
func (c *ElasticsearchClient) Errors() <-chan error {
	return c.errChan
}

// processEvents handles background event processing.
func (c *ElasticsearchClient) processEvents() {
	defer c.wg.Done()

	batchTimer := time.NewTimer(c.config.Batch.MaxWait)
	defer batchTimer.Stop()

	for {
		select {
		case <-c.ctx.Done():
			c.flush()
			return

		case event := <-c.eventChan:
			if err := c.buffer.Add(event); err != nil {
				c.errChan <- err
				continue
			}

			if c.buffer.IsFull() {
				c.flush()
				batchTimer.Reset(c.config.Batch.MaxWait)
			}

		case <-batchTimer.C:
			c.flush()
			batchTimer.Reset(c.config.Batch.MaxWait)
		}
	}
}

// flush sends buffered events.
func (c *ElasticsearchClient) flush() {
	events := c.buffer.Flush()
	if len(events) == 0 {
		return
	}

	if err := c.SendBatch(c.ctx, events); err != nil {
		c.errChan <- err
	}
}

// getHostname returns the system hostname.
func getHostname() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		return "unknown"
	}
	return hostname
}
