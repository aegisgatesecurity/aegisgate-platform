// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package siem provides additional SIEM platform integrations.
package siem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// QRadar Integration (IBM Security)
// ============================================================================

type QRadarClient struct {
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

type QRadarConfig struct {
	LogSourceID        string
	LogSourceName      string
	UseLEEF            bool
	LEEFVersion        string
	EventCollectorHost string
	EventCollectorPort int
}

func NewQRadarClient(config PlatformConfig) (*QRadarClient, error) {
	if config.Endpoint == "" {
		return nil, NewError(PlatformQRadar, "init", "endpoint URL is required", false, nil)
	}

	httpClient, err := NewHTTPClient(PlatformQRadar, config.TLS)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	formatter := Formatter(NewLEEFFormatter(PlatformQRadar, LEEFOptions{}))
	if config.Format == FormatJSON {
		formatter = NewJSONFormatter(PlatformQRadar)
	}

	client := &QRadarClient{
		config:     config,
		httpClient: httpClient,
		formatter:  formatter,
		eventChan:  make(chan *Event, 1000),
		errChan:    make(chan error, 100),
		ctx:        ctx,
		cancel:     cancel,
		buffer:     NewEventBuffer(PlatformQRadar, config.Batch.MaxSize),
	}

	return client, nil
}

func (c *QRadarClient) Send(ctx context.Context, event *Event) error {
	data, err := c.formatter.Format(event)
	if err != nil {
		return NewError(PlatformQRadar, "send", "failed to format event", false, err)
	}

	endpoint := strings.TrimSuffix(c.config.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/api/siem/events") {
		endpoint = endpoint + "/api/siem/events"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return NewError(PlatformQRadar, "send", "failed to create request", false, err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.config.Auth.Type == "basic" {
		req.SetBasicAuth(c.config.Auth.Username, c.config.Auth.Password)
	} else if c.config.Auth.APIKey != "" {
		req.Header.Set("SEC", c.config.Auth.APIKey)
	}

	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformQRadar, "send", fmt.Sprintf("qradar returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

func (c *QRadarClient) SendBatch(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, event := range events {
		data, err := c.formatter.Format(event)
		if err != nil {
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	endpoint := strings.TrimSuffix(c.config.Endpoint, "/") + "/api/siem/events"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return NewError(PlatformQRadar, "send_batch", "failed to create request", false, err)
	}

	req.Header.Set("Content-Type", "application/x-leef")
	if c.config.Auth.Type == "basic" {
		req.SetBasicAuth(c.config.Auth.Username, c.config.Auth.Password)
	} else if c.config.Auth.APIKey != "" {
		req.Header.Set("SEC", c.config.Auth.APIKey)
	}

	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformQRadar, "send_batch", fmt.Sprintf("qradar returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

func (c *QRadarClient) Start() {
	c.wg.Add(1)
	go c.processEvents()
}

func (c *QRadarClient) Stop() {
	c.cancel()
	c.wg.Wait()
	close(c.eventChan)
	close(c.errChan)
}

func (c *QRadarClient) Events() chan<- *Event {
	return c.eventChan
}

func (c *QRadarClient) Errors() <-chan error {
	return c.errChan
}

func (c *QRadarClient) processEvents() {
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

func (c *QRadarClient) flush() {
	events := c.buffer.Flush()
	if len(events) == 0 {
		return
	}
	if err := c.SendBatch(c.ctx, events); err != nil {
		c.errChan <- err
	}
}

// ============================================================================
// Microsoft Sentinel Integration
// ============================================================================

type SentinelClient struct {
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

type SentinelConfig struct {
	WorkspaceID string
	SharedKey   string
	LogType     string
	ARMEndpoint string
}

func NewSentinelClient(config PlatformConfig) (*SentinelClient, error) {
	if config.Endpoint == "" {
		if wid, ok := config.Settings["workspace_id"].(string); ok {
			config.Endpoint = "https://" + wid + ".ods.opinsights.azure.com"
		} else {
			return nil, NewError(PlatformSentinel, "init", "workspace_id or endpoint is required", false, nil)
		}
	}

	httpClient, err := NewHTTPClient(PlatformSentinel, config.TLS)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &SentinelClient{
		config:     config,
		httpClient: httpClient,
		formatter:  NewJSONFormatter(PlatformSentinel),
		eventChan:  make(chan *Event, 1000),
		errChan:    make(chan error, 100),
		ctx:        ctx,
		cancel:     cancel,
		buffer:     NewEventBuffer(PlatformSentinel, config.Batch.MaxSize),
	}

	return client, nil
}

func (c *SentinelClient) Send(ctx context.Context, event *Event) error {
	sentinelConfig := c.getSentinelConfig()

	data, err := c.formatter.Format(event)
	if err != nil {
		return NewError(PlatformSentinel, "send", "failed to format event", false, err)
	}

	endpoint := fmt.Sprintf("%s/api/logs?api-version=2016-04-01", strings.TrimSuffix(c.config.Endpoint, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return NewError(PlatformSentinel, "send", "failed to create request", false, err)
	}

	c.setAuthHeaders(req, len(data), sentinelConfig)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Log-Type", sentinelConfig.LogType)
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))

	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformSentinel, "send", fmt.Sprintf("sentinel returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

func (c *SentinelClient) SendBatch(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	sentinelConfig := c.getSentinelConfig()

	data, err := c.formatter.FormatBatch(events)
	if err != nil {
		return NewError(PlatformSentinel, "send_batch", "failed to format events", false, err)
	}

	endpoint := fmt.Sprintf("%s/api/logs?api-version=2016-04-01", strings.TrimSuffix(c.config.Endpoint, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return NewError(PlatformSentinel, "send_batch", "failed to create request", false, err)
	}

	c.setAuthHeaders(req, len(data), sentinelConfig)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Log-Type", sentinelConfig.LogType)
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))

	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformSentinel, "send_batch", fmt.Sprintf("sentinel returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

func (c *SentinelClient) getSentinelConfig() SentinelConfig {
	config := SentinelConfig{
		LogType:     "AegisGateSecurity",
		ARMEndpoint: "https://management.azure.com",
	}

	if c.config.Settings != nil {
		if wid, ok := c.config.Settings["workspace_id"].(string); ok {
			config.WorkspaceID = wid
		}
		if sk, ok := c.config.Settings["shared_key"].(string); ok {
			config.SharedKey = sk
		}
		if lt, ok := c.config.Settings["log_type"].(string); ok {
			config.LogType = lt
		}
		if ae, ok := c.config.Settings["arm_endpoint"].(string); ok {
			config.ARMEndpoint = ae
		}
	}

	return config
}

func (c *SentinelClient) setAuthHeaders(req *http.Request, contentLength int, config SentinelConfig) {
	date := time.Now().UTC().Format(http.TimeFormat)
	stringToSign := fmt.Sprintf("POST\n%d\napplication/json\nx-ms-date:%s\n/api/logs", contentLength, date)

	decodedKey, err := base64.StdEncoding.DecodeString(config.SharedKey)
	if err != nil {
		req.Header.Set("Authorization", "SharedKey "+config.WorkspaceID+":invalid")
		return
	}

	signature := hmacSHA256(decodedKey, []byte(stringToSign))
	authHeader := fmt.Sprintf("SharedKey %s:%s", config.WorkspaceID, base64.StdEncoding.EncodeToString(signature))

	req.Header.Set("Authorization", authHeader)
}

func (c *SentinelClient) Start() {
	c.wg.Add(1)
	go c.processEvents()
}

func (c *SentinelClient) Stop() {
	c.cancel()
	c.wg.Wait()
	close(c.eventChan)
	close(c.errChan)
}

func (c *SentinelClient) Events() chan<- *Event {
	return c.eventChan
}

func (c *SentinelClient) Errors() <-chan error {
	return c.errChan
}

func (c *SentinelClient) processEvents() {
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

func (c *SentinelClient) flush() {
	events := c.buffer.Flush()
	if len(events) == 0 {
		return
	}
	if err := c.SendBatch(c.ctx, events); err != nil {
		c.errChan <- err
	}
}

// ============================================================================
// SumoLogic Integration
// ============================================================================

type SumoLogicClient struct {
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

type SumoLogicConfig struct {
	HTTPSourceURL  string
	SourceCategory string
	SourceName     string
	SourceHost     string
	UseGzip        bool
}

func NewSumoLogicClient(config PlatformConfig) (*SumoLogicClient, error) {
	if config.Endpoint == "" {
		return nil, NewError(PlatformSumoLogic, "init", "HTTP source URL is required", false, nil)
	}

	httpClient, err := NewHTTPClient(PlatformSumoLogic, config.TLS)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &SumoLogicClient{
		config:     config,
		httpClient: httpClient,
		formatter:  NewJSONFormatter(PlatformSumoLogic),
		eventChan:  make(chan *Event, 1000),
		errChan:    make(chan error, 100),
		ctx:        ctx,
		cancel:     cancel,
		buffer:     NewEventBuffer(PlatformSumoLogic, config.Batch.MaxSize),
	}

	return client, nil
}

func (c *SumoLogicClient) Send(ctx context.Context, event *Event) error {
	data, err := c.formatter.Format(event)
	if err != nil {
		return NewError(PlatformSumoLogic, "send", "failed to format event", false, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return NewError(PlatformSumoLogic, "send", "failed to create request", false, err)
	}

	req.Header.Set("Content-Type", "application/json")
	c.setSumoHeaders(req)

	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformSumoLogic, "send", fmt.Sprintf("sumologic returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

func (c *SumoLogicClient) SendBatch(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	data, err := c.formatter.FormatBatch(events)
	if err != nil {
		return NewError(PlatformSumoLogic, "send_batch", "failed to format events", false, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return NewError(PlatformSumoLogic, "send_batch", "failed to create request", false, err)
	}

	req.Header.Set("Content-Type", "application/json")
	c.setSumoHeaders(req)

	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformSumoLogic, "send_batch", fmt.Sprintf("sumologic returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

func (c *SumoLogicClient) getSumoConfig() SumoLogicConfig {
	config := SumoLogicConfig{
		SourceCategory: "aegisgate/security",
		SourceName:     "aegisgate",
		SourceHost:     getHostname(),
		UseGzip:        false,
	}

	if c.config.Settings != nil {
		if sc, ok := c.config.Settings["source_category"].(string); ok {
			config.SourceCategory = sc
		}
		if sn, ok := c.config.Settings["source_name"].(string); ok {
			config.SourceName = sn
		}
		if sh, ok := c.config.Settings["source_host"].(string); ok {
			config.SourceHost = sh
		}
		if ug, ok := c.config.Settings["use_gzip"].(bool); ok {
			config.UseGzip = ug
		}
	}

	return config
}

func (c *SumoLogicClient) setSumoHeaders(req *http.Request) {
	sumoConfig := c.getSumoConfig()

	req.Header.Set("X-Sumo-Category", sumoConfig.SourceCategory)
	req.Header.Set("X-Sumo-Name", sumoConfig.SourceName)
	req.Header.Set("X-Sumo-Host", sumoConfig.SourceHost)

	if c.config.Auth.APIKey != "" {
		req.Header.Set("X-Sumo-Fields", "token="+c.config.Auth.APIKey)
	}
}

func (c *SumoLogicClient) Start() {
	c.wg.Add(1)
	go c.processEvents()
}

func (c *SumoLogicClient) Stop() {
	c.cancel()
	c.wg.Wait()
	close(c.eventChan)
	close(c.errChan)
}

func (c *SumoLogicClient) Events() chan<- *Event {
	return c.eventChan
}

func (c *SumoLogicClient) Errors() <-chan error {
	return c.errChan
}

func (c *SumoLogicClient) processEvents() {
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

func (c *SumoLogicClient) flush() {
	events := c.buffer.Flush()
	if len(events) == 0 {
		return
	}
	if err := c.SendBatch(c.ctx, events); err != nil {
		c.errChan <- err
	}
}

// ============================================================================
// LogRhythm Integration
// ============================================================================

type LogRhythmClient struct {
	config     PlatformConfig
	httpClient *HTTPClient
	formatter  Formatter
	eventChan  chan *Event
	errChan    chan error
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	buffer     *EventBuffer
	syslogConn net.Conn
}

type LogRhythmConfig struct {
	SyslogHost          string
	SyslogPort          int
	UseTLS              bool
	APIEndpoint         string
	LogSourceIdentifier string
}

func NewLogRhythmClient(config PlatformConfig) (*LogRhythmClient, error) {
	httpClient, err := NewHTTPClient(PlatformLogRhythm, config.TLS)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &LogRhythmClient{
		config:     config,
		httpClient: httpClient,
		formatter:  NewSyslogFormatter(PlatformLogRhythm, SyslogOptions{}),
		eventChan:  make(chan *Event, 1000),
		errChan:    make(chan error, 100),
		ctx:        ctx,
		cancel:     cancel,
		buffer:     NewEventBuffer(PlatformLogRhythm, config.Batch.MaxSize),
	}

	lrConfig := client.getLogRhythmConfig()
	if lrConfig.SyslogHost != "" {
		if err := client.connectSyslog(lrConfig); err != nil {
			return nil, err
		}
	}

	return client, nil
}

func (c *LogRhythmClient) connectSyslog(config LogRhythmConfig) error {
	addr := net.JoinHostPort(config.SyslogHost, fmt.Sprintf("%d", config.SyslogPort))

	var conn net.Conn
	var err error

	if config.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.config.TLS.InsecureSkipVerify,
			ServerName:         config.SyslogHost,
		}
		conn, err = tls.Dial("tcp", addr, tlsConfig)
	} else {
		conn, err = net.Dial("tcp", addr)
	}

	if err != nil {
		return NewError(PlatformLogRhythm, "connect", "failed to connect to syslog", true, err)
	}

	c.syslogConn = conn
	return nil
}

func (c *LogRhythmClient) Send(ctx context.Context, event *Event) error {
	lrConfig := c.getLogRhythmConfig()

	if c.syslogConn != nil {
		return c.sendSyslog(event, lrConfig)
	}

	return c.sendHTTP(ctx, event)
}

func (c *LogRhythmClient) sendSyslog(event *Event, config LogRhythmConfig) error {
	data, err := c.formatter.Format(event)
	if err != nil {
		return NewError(PlatformLogRhythm, "send", "failed to format event", false, err)
	}

	_, err = c.syslogConn.Write(data)
	if err != nil {
		if reconErr := c.connectSyslog(config); reconErr != nil {
			return NewError(PlatformLogRhythm, "send", "failed to reconnect to syslog", true, reconErr)
		}
		return NewError(PlatformLogRhythm, "send", "failed to send via syslog", true, err)
	}

	return nil
}

func (c *LogRhythmClient) sendHTTP(ctx context.Context, event *Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return NewError(PlatformLogRhythm, "send", "failed to marshal event", false, err)
	}

	endpoint := strings.TrimSuffix(c.config.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/api/v1/logs") {
		endpoint = endpoint + "/api/v1/logs"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return NewError(PlatformLogRhythm, "send", "failed to create request", false, err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.config.Auth.APIKey != "" {
		req.Header.Set("X-API-Key", c.config.Auth.APIKey)
	}

	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformLogRhythm, "send", fmt.Sprintf("logrhythm returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

func (c *LogRhythmClient) SendBatch(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	if c.syslogConn != nil {
		lrConfig := c.getLogRhythmConfig()
		for _, event := range events {
			if err := c.sendSyslog(event, lrConfig); err != nil {
				return err
			}
		}
		return nil
	}

	var buf bytes.Buffer
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	endpoint := strings.TrimSuffix(c.config.Endpoint, "/") + "/api/v1/logs/batch"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return NewError(PlatformLogRhythm, "send_batch", "failed to create request", false, err)
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	if c.config.Auth.APIKey != "" {
		req.Header.Set("X-API-Key", c.config.Auth.APIKey)
	}

	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformLogRhythm, "send_batch", fmt.Sprintf("logrhythm returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

func (c *LogRhythmClient) getLogRhythmConfig() LogRhythmConfig {
	config := LogRhythmConfig{
		SyslogPort:          514,
		UseTLS:              true,
		LogSourceIdentifier: "aegisgate",
	}

	if c.config.Settings != nil {
		if sh, ok := c.config.Settings["syslog_host"].(string); ok {
			config.SyslogHost = sh
		}
		if sp, ok := c.config.Settings["syslog_port"].(float64); ok {
			config.SyslogPort = int(sp)
		}
		if ut, ok := c.config.Settings["use_tls"].(bool); ok {
			config.UseTLS = ut
		}
		if ae, ok := c.config.Settings["api_endpoint"].(string); ok {
			config.APIEndpoint = ae
		}
		if lsi, ok := c.config.Settings["log_source_identifier"].(string); ok {
			config.LogSourceIdentifier = lsi
		}
	}

	return config
}

func (c *LogRhythmClient) Start() {
	c.wg.Add(1)
	go c.processEvents()
}

func (c *LogRhythmClient) Stop() {
	c.cancel()
	if c.syslogConn != nil {
		_ = c.syslogConn.Close()
	}
	c.wg.Wait()
	close(c.eventChan)
	close(c.errChan)
}

func (c *LogRhythmClient) Events() chan<- *Event {
	return c.eventChan
}

func (c *LogRhythmClient) Errors() <-chan error {
	return c.errChan
}

func (c *LogRhythmClient) processEvents() {
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

func (c *LogRhythmClient) flush() {
	events := c.buffer.Flush()
	if len(events) == 0 {
		return
	}
	if err := c.SendBatch(c.ctx, events); err != nil {
		c.errChan <- err
	}
}

// ============================================================================
// ArcSight Integration
// ============================================================================

type ArcSightClient struct {
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

type ArcSightConfig struct {
	CEFDestination     string
	DeviceVendor       string
	DeviceProduct      string
	DeviceVersion      string
	SmartConnectorHost string
	SmartConnectorPort int
}

func NewArcSightClient(config PlatformConfig) (*ArcSightClient, error) {
	httpClient, err := NewHTTPClient(PlatformArcSight, config.TLS)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &ArcSightClient{
		config:     config,
		httpClient: httpClient,
		formatter:  NewCEFFormatter(PlatformArcSight, CEFOptions{}),
		eventChan:  make(chan *Event, 1000),
		errChan:    make(chan error, 100),
		ctx:        ctx,
		cancel:     cancel,
		buffer:     NewEventBuffer(PlatformArcSight, config.Batch.MaxSize),
	}

	return client, nil
}

func (c *ArcSightClient) Send(ctx context.Context, event *Event) error {
	data, err := c.formatter.Format(event)
	if err != nil {
		return NewError(PlatformArcSight, "send", "failed to format event", false, err)
	}

	endpoint := strings.TrimSuffix(c.config.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/api/events") {
		endpoint = endpoint + "/api/events"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return NewError(PlatformArcSight, "send", "failed to create request", false, err)
	}

	req.Header.Set("Content-Type", "application/cef")
	c.setAuthHeaders(req)

	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformArcSight, "send", fmt.Sprintf("arcsight returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

func (c *ArcSightClient) SendBatch(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, event := range events {
		data, err := c.formatter.Format(event)
		if err != nil {
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	endpoint := strings.TrimSuffix(c.config.Endpoint, "/") + "/api/events"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return NewError(PlatformArcSight, "send_batch", "failed to create request", false, err)
	}

	req.Header.Set("Content-Type", "application/x-cef")
	c.setAuthHeaders(req)

	resp, err := c.httpClient.DoRequest(ctx, req, c.config.Retry)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewError(PlatformArcSight, "send_batch", fmt.Sprintf("arcsight returned status %d", resp.StatusCode), false, nil)
	}

	return nil
}

func (c *ArcSightClient) setAuthHeaders(req *http.Request) {
	switch c.config.Auth.Type {
	case "basic":
		req.SetBasicAuth(c.config.Auth.Username, c.config.Auth.Password)
	case "api_key":
		req.Header.Set("X-Auth-Token", c.config.Auth.APIKey)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+c.config.Auth.APIKey)
	}
}

func (c *ArcSightClient) Start() {
	c.wg.Add(1)
	go c.processEvents()
}

func (c *ArcSightClient) Stop() {
	c.cancel()
	c.wg.Wait()
	close(c.eventChan)
	close(c.errChan)
}

func (c *ArcSightClient) Events() chan<- *Event {
	return c.eventChan
}

func (c *ArcSightClient) Errors() <-chan error {
	return c.errChan
}

func (c *ArcSightClient) processEvents() {
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

func (c *ArcSightClient) flush() {
	events := c.buffer.Flush()
	if len(events) == 0 {
		return
	}
	if err := c.SendBatch(c.ctx, events); err != nil {
		c.errChan <- err
	}
}

// ============================================================================
// Generic Syslog Integration
// ============================================================================

type SyslogClient struct {
	config    PlatformConfig
	formatter Formatter
	eventChan chan *Event
	errChan   chan error
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	buffer    *EventBuffer
	conn      net.Conn
	protocol  string
}

type SyslogConfig struct {
	Host            string
	Port            int
	Protocol        string
	RFC5424         bool
	Facility        int
	AppName         string
	MessageIDPrefix string
}

func NewSyslogClient(config PlatformConfig) (*SyslogClient, error) {
	ctx, cancel := context.WithCancel(context.Background())

	client := &SyslogClient{
		config:    config,
		formatter: NewSyslogFormatter(PlatformSyslog, SyslogOptions{}),
		eventChan: make(chan *Event, 1000),
		errChan:   make(chan error, 100),
		ctx:       ctx,
		cancel:    cancel,
		buffer:    NewEventBuffer(PlatformSyslog, config.Batch.MaxSize),
		protocol:  "tcp",
	}

	syslogConfig := client.getSyslogConfig()
	client.protocol = syslogConfig.Protocol

	if err := client.connect(syslogConfig); err != nil {
		return nil, err
	}

	return client, nil
}

func (c *SyslogClient) connect(config SyslogConfig) error {
	addr := net.JoinHostPort(config.Host, fmt.Sprintf("%d", config.Port))

	var conn net.Conn
	var err error

	switch config.Protocol {
	case "tls":
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.config.TLS.InsecureSkipVerify,
			ServerName:         config.Host,
		}
		conn, err = tls.Dial("tcp", addr, tlsConfig)
	case "tcp":
		conn, err = net.Dial("tcp", addr)
	case "udp":
		conn, err = net.Dial("udp", addr)
	default:
		conn, err = net.Dial("tcp", addr)
	}

	if err != nil {
		return NewError(PlatformSyslog, "connect", "failed to connect to syslog server", true, err)
	}

	c.conn = conn
	return nil
}

func (c *SyslogClient) Send(ctx context.Context, event *Event) error {
	data, err := c.formatter.Format(event)
	if err != nil {
		return NewError(PlatformSyslog, "send", "failed to format event", false, err)
	}

	_, err = c.conn.Write(data)
	if err != nil {
		syslogConfig := c.getSyslogConfig()
		if reconErr := c.connect(syslogConfig); reconErr != nil {
			return NewError(PlatformSyslog, "send", "failed to send and reconnect", true, err)
		}
		_, err = c.conn.Write(data)
		if err != nil {
			return NewError(PlatformSyslog, "send", "failed to send after reconnect", true, err)
		}
	}

	return nil
}

func (c *SyslogClient) SendBatch(ctx context.Context, events []*Event) error {
	for _, event := range events {
		if err := c.Send(ctx, event); err != nil {
			return err
		}
		if c.protocol == "udp" {
			time.Sleep(1 * time.Millisecond)
		}
	}
	return nil
}

func (c *SyslogClient) getSyslogConfig() SyslogConfig {
	config := SyslogConfig{
		Port:     514,
		Protocol: "tcp",
		RFC5424:  true,
		Facility: 1,
		AppName:  "aegisgate",
	}

	if c.config.Settings != nil {
		if h, ok := c.config.Settings["host"].(string); ok {
			config.Host = h
		}
		if p, ok := c.config.Settings["port"].(float64); ok {
			config.Port = int(p)
		}
		if pr, ok := c.config.Settings["protocol"].(string); ok {
			config.Protocol = pr
		}
		if r, ok := c.config.Settings["rfc_5424"].(bool); ok {
			config.RFC5424 = r
		}
		if f, ok := c.config.Settings["facility"].(float64); ok {
			config.Facility = int(f)
		}
		if an, ok := c.config.Settings["app_name"].(string); ok {
			config.AppName = an
		}
		if mip, ok := c.config.Settings["message_id_prefix"].(string); ok {
			config.MessageIDPrefix = mip
		}
	}

	if config.Host == "" && c.config.Endpoint != "" {
		if strings.Contains(c.config.Endpoint, ":") {
			parts := strings.Split(c.config.Endpoint, ":")
			config.Host = parts[0]
			if len(parts) > 1 {
				if _, err := fmt.Sscanf(parts[1], "%d", &config.Port); err != nil {
					// Use default port if parsing fails
					config.Port = 514
				}
			}
		} else {
			config.Host = c.config.Endpoint
		}
	}

	return config
}

func (c *SyslogClient) Start() {
	c.wg.Add(1)
	go c.processEvents()
}

func (c *SyslogClient) Stop() {
	c.cancel()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.wg.Wait()
	close(c.eventChan)
	close(c.errChan)
}

func (c *SyslogClient) Events() chan<- *Event {
	return c.eventChan
}

func (c *SyslogClient) Errors() <-chan error {
	return c.errChan
}

func (c *SyslogClient) processEvents() {
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

func (c *SyslogClient) flush() {
	events := c.buffer.Flush()
	if len(events) == 0 {
		return
	}
	if err := c.SendBatch(c.ctx, events); err != nil {
		c.errChan <- err
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
