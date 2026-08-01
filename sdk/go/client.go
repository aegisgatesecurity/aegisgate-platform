// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform Go SDK — v3.6.0
// =========================================================================
//
// Package aegisgate provides a Go client SDK for the AegisGate v3.6.0
// platform API. It offers typed access to all platform services including
// authentication, compliance, trust scoring, scanning, guardrails, analytics,
// IOC, SIEM, ML metrics, audit, policy, cluster, bridge, attestation, AI-BOM,
// A2A intent, digest, incident management, evaluator, persistence,
// certificates, licensing, SLA, TSA, and health/version endpoints.
//
// Basic usage:
//
//	cfg := aegisgate.DefaultConfig()
//	cfg.BaseURL = "https://aegisgate.example.com"
//	cfg.APIKey = "your-api-key"
//	client, err := aegisgate.NewClient(cfg)
//	if err != nil { log.Fatal(err) }
//	defer client.Close()
//
//	ctx := context.Background()
//	health, err := client.Health.Get(ctx)
// =========================================================================

package aegisgate

import (
	"context"
	"fmt"
	"net/http"
	"os"
)

// Version is the semantic version of this SDK.
const Version = "3.6.0"

// Client is the top-level AegisGate API client. It holds the HTTP client,
// configuration, and references to every service namespace.
type Client struct {
	cfg    *Config
	http   *http.Client
	baseURL string

	// Services provide typed access to each AegisGate API surface.
	Auth         *AuthService
	Compliance   *ComplianceService
	Trust        *TrustService
	Scan         *ScanService
	Guardrails   *GuardrailsService
	Analytics    *AnalyticsService
	IOC          *IOCService
	SIEM         *SIEMService
	ML           *MLService
	Audit        *AuditService
	Policy       *PolicyService
	Cluster      *ClusterService
	Bridge       *BridgeService
	Attestation  *AttestationService
	AIBOM        *AIBOMService
	A2A          *A2AService
	Digest       *DigestService
	Incident     *IncidentService
	Evaluator    *EvaluatorService
	Persistence  *PersistenceService
	Certs        *CertsService
	License      *LicenseService
	SLA          *SLAService
	TSA          *TSAService
	Health       *HealthService
	Version      *VersionService
}

// NewClient creates a new AegisGate client from the provided configuration.
// It validates required fields and initialises all service namespaces.
func NewClient(cfg *Config) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("aegisgate: config must not be nil")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("aegisgate: BaseURL is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if cfg.TLSConfig != nil {
			transport.TLSClientConfig = cfg.TLSConfig
		}
		httpClient = &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		}
	}

	c := &Client{
		cfg:     cfg,
		http:    httpClient,
		baseURL: cfg.BaseURL,
	}

	// Initialise service namespaces.
	c.Auth = &AuthService{client: c}
	c.Compliance = &ComplianceService{client: c}
	c.Trust = &TrustService{client: c}
	c.Scan = &ScanService{client: c}
	c.Guardrails = &GuardrailsService{client: c}
	c.Analytics = &AnalyticsService{client: c}
	c.IOC = &IOCService{client: c}
	c.SIEM = &SIEMService{client: c}
	c.ML = &MLService{client: c}
	c.Audit = &AuditService{client: c}
	c.Policy = &PolicyService{client: c}
	c.Cluster = &ClusterService{client: c}
	c.Bridge = &BridgeService{client: c}
	c.Attestation = &AttestationService{client: c}
	c.AIBOM = &AIBOMService{client: c}
	c.A2A = &A2AService{client: c}
	c.Digest = &DigestService{client: c}
	c.Incident = &IncidentService{client: c}
	c.Evaluator = &EvaluatorService{client: c}
	c.Persistence = &PersistenceService{client: c}
	c.Certs = &CertsService{client: c}
	c.License = &LicenseService{client: c}
	c.SLA = &SLAService{client: c}
	c.TSA = &TSAService{client: c}
	c.Health = &HealthService{client: c}
	c.Version = &VersionService{client: c}

	return c, nil
}

// NewClientFromEnv creates a client using environment variables:
//   - AEGISGATE_BASE_URL  (required)
//   - AEGISGATE_API_KEY   (optional; used when no Token is set)
func NewClientFromEnv() (*Client, error) {
	cfg := DefaultConfig()
	cfg.BaseURL = os.Getenv("AEGISGATE_BASE_URL")
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("aegisgate: AEGISGATE_BASE_URL environment variable is required")
	}
	if apiKey := os.Getenv("AEGISGATE_API_KEY"); apiKey != "" {
		cfg.APIKey = apiKey
	}
	return NewClient(cfg)
}

// Close idle connections on the underlying transport.
func (c *Client) Close() {
	if tr, ok := c.http.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

// do is the internal request helper. It builds an HTTP request, attaches auth
// headers, and decodes the JSON response into v.
func (c *Client) do(ctx context.Context, method, path string, body, v interface{}) error {
	hc := &HTTPClient{client: c}
	return hc.Do(ctx, method, c.baseURL+path, body, v)
}

// setAuthHeaders applies API key or token authentication to the request.
func (c *Client) setAuthHeaders(req *http.Request) {
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	} else if c.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", c.cfg.APIKey)
	}
	req.Header.Set("User-Agent", "aegisgate-go-sdk/"+Version)
	req.Header.Set("Accept", "application/json")
}