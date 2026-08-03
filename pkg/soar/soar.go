package soar

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Platform identifies the target SOAR/automation platform.
type Platform string

const (
	PlatformPagerDuty  Platform = "pagerduty"
	PlatformJira       Platform = "jira"
	PlatformServiceNow Platform = "servicenow"
	PlatformCustom     Platform = "custom"
)

// Severity represents the urgency of an incident.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// IncidentStatus represents the lifecycle state of an incident.
type IncidentStatus string

const (
	StatusTriggered    IncidentStatus = "triggered"
	StatusAcknowledged IncidentStatus = "acknowledged"
	StatusResolved     IncidentStatus = "resolved"
)

// AuthConfig holds authentication credentials for a platform endpoint.
type AuthConfig struct {
	Type         string `json:"type"`          // api_key, basic, oauth2, hmac
	APIKey       string `json:"api_key"`       // used for api_key and as PagerDuty routing_key
	Username     string `json:"username"`      // basic auth
	Password     string `json:"password"`      // basic auth
	TokenURL     string `json:"token_url"`     // oauth2
	ClientID     string `json:"client_id"`     // oauth2
	ClientSecret string `json:"client_secret"` // oauth2
	HMACSecret   string `json:"hmac_secret"`   // HMAC-SHA256 signing
}

// GlobalConfig holds settings that apply across all platforms.
type GlobalConfig struct {
	AppName       string        `json:"app_name"`
	Environment   string        `json:"environment"`
	MaxRetries    int           `json:"max_retries"`
	RetryInterval time.Duration `json:"retry_interval"`
}

// PlatformConfig holds per-platform connection settings.
type PlatformConfig struct {
	Platform Platform               `json:"platform"`
	Enabled  bool                   `json:"enabled"`
	Endpoint string                 `json:"endpoint"`
	Auth     AuthConfig             `json:"auth"`
	Settings map[string]interface{} `json:"settings"`
}

// Config is the top-level SOAR configuration.
type Config struct {
	Platforms []PlatformConfig `json:"platforms"`
	Global    GlobalConfig     `json:"global"`
}

// Incident is the core outbound alert sent to SOAR platforms.
type Incident struct {
	ID              string            `json:"id"`
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	Severity        Severity          `json:"severity"`
	Status          IncidentStatus    `json:"status"`
	Source          string            `json:"source"` // always "aegisgate"
	Timestamp       time.Time         `json:"timestamp"`
	Framework       string            `json:"framework"`  // e.g. "hipaa", "cjis"
	ControlID       string            `json:"control_id"` // e.g. "CJIS-AC-001"
	ControlName     string            `json:"control_name"`
	Details         string            `json:"details"`
	Remediation     string            `json:"remediation"`
	AffectedSystems []string          `json:"affected_systems"`
	Labels          map[string]string `json:"labels"`
	DedupKey        string            `json:"dedup_key"` // PagerDuty deduplication
}

// DeliveryResult captures the outcome of a single platform delivery attempt.
type DeliveryResult struct {
	Platform   Platform  `json:"platform"`
	IncidentID string    `json:"incident_id"`
	HTTPStatus int       `json:"http_status"`
	Error      error     `json:"error,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	RetryCount int       `json:"retry_count"`
}

// HealthStatus reports the operational state of the SOAR manager.
type HealthStatus struct {
	Healthy   bool             `json:"healthy"`
	Started   bool             `json:"started"`
	StartTime time.Time        `json:"start_time"`
	Uptime    time.Duration    `json:"uptime"`
	Platforms []PlatformHealth `json:"platforms"`
}

// PlatformHealth reports the health of a single platform integration.
type PlatformHealth struct {
	Platform  Platform `json:"platform"`
	Enabled   bool     `json:"enabled"`
	Endpoint  string   `json:"endpoint"`
	Healthy   bool     `json:"healthy"`
	LastError string   `json:"last_error,omitempty"`
}

// PlatformStats tracks delivery statistics for a single platform.
type PlatformStats struct {
	Sent      int       `json:"sent"`
	Failed    int       `json:"failed"`
	LastSent  time.Time `json:"last_sent"`
	LastError string    `json:"last_error"`
}

// ManagerStats tracks aggregate delivery statistics.
type ManagerStats struct {
	TotalSent     int                         `json:"total_sent"`
	TotalFailed   int                         `json:"total_failed"`
	PlatformStats map[Platform]*PlatformStats `json:"platform_stats"`
	mu            sync.RWMutex
}

// Manager orchestrates outbound incident delivery to SOAR platforms.
type Manager struct {
	config     Config
	httpClient *http.Client
	logger     *slog.Logger
	mu         sync.RWMutex
	stats      ManagerStats
	started    bool
	startTime  time.Time
}

// NewManager creates a new SOAR Manager with the given configuration.
func NewManager(cfg Config, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	maxRetries := cfg.Global.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}
	retryInterval := cfg.Global.RetryInterval
	if retryInterval <= 0 {
		retryInterval = 5 * time.Second
	}
	cfg.Global.MaxRetries = maxRetries
	cfg.Global.RetryInterval = retryInterval

	platformStats := make(map[Platform]*PlatformStats)
	for _, pc := range cfg.Platforms {
		platformStats[pc.Platform] = &PlatformStats{}
	}

	return &Manager{
		config:     cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
		stats: ManagerStats{
			PlatformStats: platformStats,
		},
	}
}

// Start initializes the SOAR manager for delivery.
func (m *Manager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started = true
	m.startTime = time.Now()
	m.logger.Info("SOAR manager started",
		slog.Int("platforms", len(m.config.Platforms)),
	)
}

// Stop shuts down the SOAR manager.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started = false
	m.logger.Info("SOAR manager stopped")
}

// SendIncident delivers an incident to ALL enabled platforms.
func (m *Manager) SendIncident(ctx context.Context, incident *Incident) []DeliveryResult {
	var results []DeliveryResult
	for _, pc := range m.config.Platforms {
		if !pc.Enabled {
			continue
		}
		result, err := m.SendIncidentToPlatform(ctx, pc.Platform, incident)
		if err != nil {
			// result already has error info from the platform sender
			if result == nil {
				result = &DeliveryResult{
					Platform:   pc.Platform,
					IncidentID: incident.ID,
					Error:      err,
					Timestamp:  time.Now(),
				}
			}
		}
		results = append(results, *result)
	}
	return results
}

// SendIncidentToPlatform delivers an incident to a specific platform.
func (m *Manager) SendIncidentToPlatform(ctx context.Context, platform Platform, incident *Incident) (*DeliveryResult, error) {
	m.mu.RLock()
	started := m.started
	m.mu.RUnlock()

	if !started {
		return nil, fmt.Errorf("SOAR manager not started")
	}

	// Find platform config
	var platformCfg *PlatformConfig
	for i := range m.config.Platforms {
		if m.config.Platforms[i].Platform == platform {
			platformCfg = &m.config.Platforms[i]
			break
		}
	}
	if platformCfg == nil {
		return nil, fmt.Errorf("platform %s not configured", platform)
	}
	if !platformCfg.Enabled {
		return nil, fmt.Errorf("platform %s is not enabled", platform)
	}

	m.logger.Info("sending incident to platform",
		slog.String("platform", string(platform)),
		slog.String("incident_id", incident.ID),
		slog.String("severity", string(incident.Severity)),
	)

	var result *DeliveryResult
	var err error

	switch platform {
	case PlatformPagerDuty:
		result, err = m.sendPagerDuty(ctx, incident, platformCfg)
	case PlatformJira:
		result, err = m.sendJira(ctx, incident, platformCfg)
	case PlatformServiceNow:
		result, err = m.sendServiceNow(ctx, incident, platformCfg)
	case PlatformCustom:
		result, err = m.sendCustom(ctx, incident, platformCfg)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", platform)
	}

	if err != nil {
		m.recordFailure(platform, err.Error())
		if result == nil {
			result = &DeliveryResult{
				Platform:   platform,
				IncidentID: incident.ID,
				Error:      err,
				Timestamp:  time.Now(),
			}
		}
		return result, err
	}

	m.recordSuccess(platform)
	return result, nil
}

// Stats returns a copy of the current delivery statistics.
func (m *Manager) Stats() ManagerStats {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()
	return ManagerStats{
		TotalSent:     m.stats.TotalSent,
		TotalFailed:   m.stats.TotalFailed,
		PlatformStats: m.stats.PlatformStats,
	}
}

// HealthCheck returns the operational health of the SOAR manager.
func (m *Manager) HealthCheck() HealthStatus {
	m.mu.RLock()
	started := m.started
	startTime := m.startTime
	m.mu.RUnlock()

	m.stats.mu.RLock()
	platformHealths := make([]PlatformHealth, 0, len(m.config.Platforms))
	for _, pc := range m.config.Platforms {
		ph := PlatformHealth{
			Platform: pc.Platform,
			Enabled:  pc.Enabled,
			Endpoint: pc.Endpoint,
			Healthy:  true,
		}
		if ps, ok := m.stats.PlatformStats[pc.Platform]; ok {
			ph.LastError = ps.LastError
			if ps.Failed > ps.Sent && ps.Sent == 0 {
				ph.Healthy = false
			}
		}
		platformHealths = append(platformHealths, ph)
	}
	m.stats.mu.RUnlock()

	overallHealthy := started
	for _, ph := range platformHealths {
		if ph.Enabled && !ph.Healthy {
			overallHealthy = false
		}
	}

	uptime := time.Duration(0)
	if started {
		uptime = time.Since(startTime)
	}

	return HealthStatus{
		Healthy:   overallHealthy,
		Started:   started,
		StartTime: startTime,
		Uptime:    uptime,
		Platforms: platformHealths,
	}
}

// --- Internal methods ---

func (m *Manager) recordSuccess(platform Platform) {
	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()
	m.stats.TotalSent++
	if ps, ok := m.stats.PlatformStats[platform]; ok {
		ps.Sent++
		ps.LastSent = time.Now()
		ps.LastError = ""
	}
}

func (m *Manager) recordFailure(platform Platform, errMsg string) {
	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()
	m.stats.TotalFailed++
	if ps, ok := m.stats.PlatformStats[platform]; ok {
		ps.Failed++
		ps.LastError = errMsg
	}
}

// mapSeverityPagerDuty converts internal severity to PagerDuty severity.
func mapSeverityPagerDuty(s Severity) string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow, SeverityInfo:
		return "info"
	default:
		return "info"
	}
}

// mapSeverityJira converts internal severity to Jira priority name.
func mapSeverityJira(s Severity) string {
	switch s {
	case SeverityCritical:
		return "Highest"
	case SeverityHigh:
		return "High"
	case SeverityMedium:
		return "Medium"
	case SeverityLow:
		return "Low"
	case SeverityInfo:
		return "Lowest"
	default:
		return "Medium"
	}
}

// mapSeverityServiceNow converts internal severity to ServiceNow severity (1-4).
func mapSeverityServiceNow(s Severity) int {
	switch s {
	case SeverityCritical:
		return 1
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 3
	case SeverityLow, SeverityInfo:
		return 4
	default:
		return 3
	}
}

func (m *Manager) sendPagerDuty(ctx context.Context, incident *Incident, cfg *PlatformConfig) (*DeliveryResult, error) {
	routingKey := cfg.Auth.APIKey
	if routingKey == "" {
		return nil, fmt.Errorf("pagerduty: missing routing key (api_key)")
	}

	eventAction := "trigger"
	switch incident.Status {
	case StatusAcknowledged:
		eventAction = "acknowledge"
	case StatusResolved:
		eventAction = "resolve"
	}

	payload := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": eventAction,
		"dedup_key":    incident.DedupKey,
		"payload": map[string]interface{}{
			"summary":   incident.Title,
			"severity":  mapSeverityPagerDuty(incident.Severity),
			"source":    "aegisgate",
			"component": incident.ControlID,
			"group":     incident.Framework,
			"class":     "compliance_violation",
			"custom_details": map[string]interface{}{
				"control_id":       incident.ControlID,
				"control_name":     incident.ControlName,
				"framework":        incident.Framework,
				"details":          incident.Details,
				"remediation":      incident.Remediation,
				"affected_systems": incident.AffectedSystems,
				"labels":           incident.Labels,
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("pagerduty: marshal payload: %w", err)
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://events.pagerduty.com/v2/enqueue"
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	resp, reqErr := m.doRequest(ctx, http.MethodPost, endpoint, body, headers)
	if reqErr != nil {
		return &DeliveryResult{
			Platform:   PlatformPagerDuty,
			IncidentID: incident.ID,
			Error:      reqErr,
			Timestamp:  time.Now(),
		}, reqErr
	}
	defer resp.Body.Close()

	result := &DeliveryResult{
		Platform:   PlatformPagerDuty,
		IncidentID: incident.ID,
		HTTPStatus: resp.StatusCode,
		Timestamp:  time.Now(),
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Errorf("pagerduty: HTTP %d: %s", resp.StatusCode, string(respBody))
		return result, result.Error
	}

	m.logger.Info("pagerduty incident delivered",
		slog.String("incident_id", incident.ID),
		slog.Int("status", resp.StatusCode),
	)
	return result, nil
}

func (m *Manager) sendJira(ctx context.Context, incident *Incident, cfg *PlatformConfig) (*DeliveryResult, error) {
	projectKey := "AEG"
	if pk, ok := cfg.Settings["project_key"]; ok {
		if s, ok := pk.(string); ok && s != "" {
			projectKey = s
		}
	}

	description := incident.Description
	if incident.Details != "" {
		description += "\n\nDetails: " + incident.Details
	}
	if incident.Remediation != "" {
		description += "\n\nRemediation: " + incident.Remediation
	}
	description += fmt.Sprintf("\n\nFramework: %s | Control: %s (%s)", incident.Framework, incident.ControlID, incident.ControlName)

	labels := []string{"aegisgate", incident.Framework, incident.ControlID}

	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project":     map[string]string{"key": projectKey},
			"issuetype":   map[string]string{"name": "Bug"},
			"summary":     "[AegisGate] " + incident.Title,
			"description": description,
			"priority":    map[string]string{"name": mapSeverityJira(incident.Severity)},
			"labels":      labels,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("jira: marshal payload: %w", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	// Auth: basic or api_key (bearer token)
	switch cfg.Auth.Type {
	case "basic":
		headers["Authorization"] = "Basic " + basicAuth(cfg.Auth.Username, cfg.Auth.Password)
	case "api_key":
		headers["Authorization"] = "Bearer " + cfg.Auth.APIKey
	}

	resp, reqErr := m.doRequest(ctx, http.MethodPost, cfg.Endpoint, body, headers)
	if reqErr != nil {
		return &DeliveryResult{
			Platform:   PlatformJira,
			IncidentID: incident.ID,
			Error:      reqErr,
			Timestamp:  time.Now(),
		}, reqErr
	}
	defer resp.Body.Close()

	result := &DeliveryResult{
		Platform:   PlatformJira,
		IncidentID: incident.ID,
		HTTPStatus: resp.StatusCode,
		Timestamp:  time.Now(),
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Errorf("jira: HTTP %d: %s", resp.StatusCode, string(respBody))
		return result, result.Error
	}

	m.logger.Info("jira incident delivered",
		slog.String("incident_id", incident.ID),
		slog.Int("status", resp.StatusCode),
	)
	return result, nil
}

func (m *Manager) sendServiceNow(ctx context.Context, incident *Incident, cfg *PlatformConfig) (*DeliveryResult, error) {
	description := incident.Description
	if incident.Details != "" {
		description += "\n\nDetails: " + incident.Details
	}
	if incident.Remediation != "" {
		description += "\n\nRemediation: " + incident.Remediation
	}

	payload := map[string]interface{}{
		"short_description": "[AegisGate] " + incident.Title,
		"description":       description,
		"severity":          mapSeverityServiceNow(incident.Severity),
		"category":          "security",
		"subcategory":       "compliance",
		"u_framework":       incident.Framework,
		"u_control_id":      incident.ControlID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("servicenow: marshal payload: %w", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	switch cfg.Auth.Type {
	case "basic":
		headers["Authorization"] = "Basic " + basicAuth(cfg.Auth.Username, cfg.Auth.Password)
	case "api_key":
		headers["Authorization"] = "Bearer " + cfg.Auth.APIKey
	}

	resp, reqErr := m.doRequest(ctx, http.MethodPost, cfg.Endpoint, body, headers)
	if reqErr != nil {
		return &DeliveryResult{
			Platform:   PlatformServiceNow,
			IncidentID: incident.ID,
			Error:      reqErr,
			Timestamp:  time.Now(),
		}, reqErr
	}
	defer resp.Body.Close()

	result := &DeliveryResult{
		Platform:   PlatformServiceNow,
		IncidentID: incident.ID,
		HTTPStatus: resp.StatusCode,
		Timestamp:  time.Now(),
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Errorf("servicenow: HTTP %d: %s", resp.StatusCode, string(respBody))
		return result, result.Error
	}

	m.logger.Info("servicenow incident delivered",
		slog.String("incident_id", incident.ID),
		slog.Int("status", resp.StatusCode),
	)
	return result, nil
}

func (m *Manager) sendCustom(ctx context.Context, incident *Incident, cfg *PlatformConfig) (*DeliveryResult, error) {
	payload := map[string]interface{}{
		"id":               incident.ID,
		"title":            incident.Title,
		"description":      incident.Description,
		"severity":         string(incident.Severity),
		"status":           string(incident.Status),
		"source":           "aegisgate",
		"timestamp":        incident.Timestamp.Format(time.RFC3339),
		"framework":        incident.Framework,
		"control_id":       incident.ControlID,
		"control_name":     incident.ControlName,
		"details":          incident.Details,
		"remediation":      incident.Remediation,
		"affected_systems": incident.AffectedSystems,
		"labels":           incident.Labels,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("custom: marshal payload: %w", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	switch cfg.Auth.Type {
	case "api_key":
		headers["X-API-Key"] = cfg.Auth.APIKey
	case "basic":
		headers["Authorization"] = "Basic " + basicAuth(cfg.Auth.Username, cfg.Auth.Password)
	case "hmac":
		sig := signHMAC(body, cfg.Auth.HMACSecret)
		headers["X-Signature"] = sig
		headers["X-Signature-Algorithm"] = "hmac-sha256"
	}

	resp, reqErr := m.doRequest(ctx, http.MethodPost, cfg.Endpoint, body, headers)
	if reqErr != nil {
		return &DeliveryResult{
			Platform:   PlatformCustom,
			IncidentID: incident.ID,
			Error:      reqErr,
			Timestamp:  time.Now(),
		}, reqErr
	}
	defer resp.Body.Close()

	result := &DeliveryResult{
		Platform:   PlatformCustom,
		IncidentID: incident.ID,
		HTTPStatus: resp.StatusCode,
		Timestamp:  time.Now(),
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Errorf("custom: HTTP %d: %s", resp.StatusCode, string(respBody))
		return result, result.Error
	}

	m.logger.Info("custom webhook incident delivered",
		slog.String("incident_id", incident.ID),
		slog.Int("status", resp.StatusCode),
	)
	return result, nil
}

// signHMAC produces an HMAC-SHA256 hex-encoded signature.
func signHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// basicAuth produces a Base64-encoded basic auth header value.
func basicAuth(username, password string) string {
	creds := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(creds))
}

// doRequest executes an HTTP request with retry logic.
func (m *Manager) doRequest(ctx context.Context, method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	maxRetries := m.config.Global.MaxRetries
	retryInterval := m.config.Global.RetryInterval

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			m.logger.Info("retrying request",
				slog.String("url", url),
				slog.Int("attempt", attempt),
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryInterval):
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := m.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Retry on server errors (5xx)
		if resp.StatusCode >= 500 {
			respBody, _ := io.ReadAll(resp.Body) // #nosec G104 -- response body read after error check; error intentionally discarded
			resp.Body.Close()                    // #nosec G104 -- response body close; error is non-fatal in error handler path
			lastErr = fmt.Errorf("server error: HTTP %d", resp.StatusCode)
			_ = respBody
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", maxRetries, lastErr)
}
