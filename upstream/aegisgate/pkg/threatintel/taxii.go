// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package threatintel provides TAXII 2.1 protocol client implementation.
package threatintel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// TAXII Client Configuration
// ============================================================================

// TAXIIConfig contains TAXII client configuration.
type TAXIIConfig struct {
	// Server URL (e.g., https://taxii.example.com/api2)
	ServerURL string `json:"server_url"`
	// Discovery URL
	DiscoveryURL string `json:"discovery_url,omitempty"`
	// Authentication type: basic, token, oauth2
	AuthType string `json:"auth_type"`
	// Username for basic auth
	Username string `json:"username,omitempty"`
	// Password for basic auth
	Password string `json:"password,omitempty"`
	// API token for token auth
	APIToken string `json:"api_token,omitempty"`
	// Token header name
	TokenHeader string `json:"token_header,omitempty"`
	// OAuth2 configuration
	OAuth2 OAuth2Config `json:"oauth2,omitempty"`
	// TLS configuration
	TLS TLSConfig `json:"tls"`
	// Retry configuration
	Retry RetryConfig `json:"retry"`
	// Timeout for requests
	Timeout time.Duration `json:"timeout"`
	// User agent
	UserAgent string `json:"user_agent,omitempty"`
	// Default collection
	DefaultCollection string `json:"default_collection,omitempty"`
}

// OAuth2Config contains OAuth2 authentication settings.
type OAuth2Config struct {
	// Token URL
	TokenURL string `json:"token_url"`
	// Client ID
	ClientID string `json:"client_id"`
	// Client secret
	ClientSecret string `json:"client_secret"`
	// Scopes
	Scopes []string `json:"scopes,omitempty"`
	// Existing token
	Token string `json:"token,omitempty"`
	// Token expiry
	TokenExpiry time.Time `json:"token_expiry,omitempty"`
}

// TLSConfig contains TLS settings.
type TLSConfig struct {
	// Enable TLS
	Enabled bool `json:"enabled"`
	// Skip certificate verification (insecure)
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
	// CA certificate file
	CAFile string `json:"ca_file,omitempty"`
	// Client certificate file
	CertFile string `json:"cert_file,omitempty"`
	// Client key file
	KeyFile string `json:"key_file,omitempty"`
	// Server name for SNI
	ServerName string `json:"server_name,omitempty"`
	// Minimum TLS version
	MinVersion string `json:"min_version,omitempty"`
}

// RetryConfig contains retry settings.
type RetryConfig struct {
	// Enable retries
	Enabled bool `json:"enabled"`
	// Maximum retry attempts
	MaxAttempts int `json:"max_attempts"`
	// Initial backoff duration
	InitialBackoff time.Duration `json:"initial_backoff"`
	// Maximum backoff duration
	MaxBackoff time.Duration `json:"max_backoff"`
	// Backoff multiplier
	BackoffMultiplier float64 `json:"backoff_multiplier"`
	// Retry on these HTTP status codes
	RetryOnStatusCodes []int `json:"retry_on_status_codes,omitempty"`
}

// DefaultTAXIIConfig returns default TAXII configuration.
func DefaultTAXIIConfig() TAXIIConfig {
	return TAXIIConfig{
		AuthType:    "basic",
		TokenHeader: "Authorization",
		TLS: TLSConfig{
			Enabled: true,
		},
		Retry: RetryConfig{
			Enabled:            true,
			MaxAttempts:        3,
			InitialBackoff:     1 * time.Second,
			MaxBackoff:         30 * time.Second,
			BackoffMultiplier:  2.0,
			RetryOnStatusCodes: []int{429, 500, 502, 503, 504},
		},
		Timeout:   30 * time.Second,
		UserAgent: "AegisGate-TAXII/2.1",
	}
}

// ============================================================================
// TAXII Client
// ============================================================================

// TAXIIClient is a client for TAXII 2.1 servers.
type TAXIIClient struct {
	config     TAXIIConfig
	httpClient *http.Client
	token      string
	tokenMu    sync.RWMutex
	baseURL    *url.URL
	apiRoot    string
	session    *TAXIISession
	sessionMu  sync.RWMutex
}

// NewTAXIIClient creates a new TAXII client.
func NewTAXIIClient(config TAXIIConfig) (*TAXIIClient, error) {
	if config.ServerURL == "" {
		return nil, NewError("taxii_client", "server URL is required", false, nil)
	}

	// Parse base URL
	baseURL, err := url.Parse(config.ServerURL)
	if err != nil {
		return nil, NewError("taxii_client", "invalid server URL", false, err)
	}

	// Apply defaults
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.TokenHeader == "" {
		config.TokenHeader = "Authorization"
	}
	if config.UserAgent == "" {
		config.UserAgent = "AegisGate-TAXII/2.1"
	}

	// Create HTTP client
	httpClient, err := createTAXIIHTTPClient(config)
	if err != nil {
		return nil, err
	}

	client := &TAXIIClient{
		config:     config,
		httpClient: httpClient,
		baseURL:    baseURL,
	}

	// Set initial token for API token auth
	if config.AuthType == "token" && config.APIToken != "" {
		client.token = config.APIToken
	}

	return client, nil
}

// createTAXIIHTTPClient creates an HTTP client with TLS configuration.
func createTAXIIHTTPClient(config TAXIIConfig) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	if config.TLS.Enabled {
		tlsConf := &tls.Config{
			InsecureSkipVerify: config.TLS.InsecureSkipVerify,
			ServerName:         config.TLS.ServerName,
		}

		// Load CA certificate
		if config.TLS.CAFile != "" {
			caCert, err := os.ReadFile(config.TLS.CAFile)
			if err != nil {
				return nil, NewError("taxii_client", "failed to load CA certificate", false, err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, NewError("taxii_client", "failed to parse CA certificate", false, nil)
			}
			tlsConf.RootCAs = caCertPool
		}

		// Load client certificate
		if config.TLS.CertFile != "" && config.TLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(config.TLS.CertFile, config.TLS.KeyFile)
			if err != nil {
				return nil, NewError("taxii_client", "failed to load client certificate", false, err)
			}
			tlsConf.Certificates = []tls.Certificate{cert}
		}

		// Set minimum TLS version
		if config.TLS.MinVersion != "" {
			switch config.TLS.MinVersion {
			case "1.2":
				tlsConf.MinVersion = tls.VersionTLS12
			case "1.3":
				tlsConf.MinVersion = tls.VersionTLS13
			}
		}

		transport.TLSClientConfig = tlsConf
	}

	return &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}, nil
}

// Authenticate authenticates with the TAXII server.
func (c *TAXIIClient) Authenticate(ctx context.Context) error {
	switch c.config.AuthType {
	case "basic":
		// Basic auth - credentials are set per-request
		return nil
	case "token":
		// Token auth - already set
		return nil
	case "oauth2":
		return c.authenticateOAuth2(ctx)
	default:
		return NewError("taxii_auth", "unknown auth type: "+c.config.AuthType, false, nil)
	}
}

// authenticateOAuth2 authenticates using OAuth2.
func (c *TAXIIClient) authenticateOAuth2(ctx context.Context) error {
	if c.config.OAuth2.Token != "" && time.Now().Before(c.config.OAuth2.TokenExpiry) {
		c.tokenMu.Lock()
		c.token = c.config.OAuth2.Token
		c.tokenMu.Unlock()
		return nil
	}

	// Request new token
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.config.OAuth2.ClientID)
	data.Set("client_secret", c.config.OAuth2.ClientSecret)
	if len(c.config.OAuth2.Scopes) > 0 {
		data.Set("scope", strings.Join(c.config.OAuth2.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.OAuth2.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return NewError("oauth2_auth", "failed to create token request", false, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return NewError("oauth2_auth", "token request failed", true, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return NewError("oauth2_auth", fmt.Sprintf("token request failed: %d: %s", resp.StatusCode, string(body)), false, nil)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return NewError("oauth2_auth", "failed to decode token response", false, err)
	}

	c.tokenMu.Lock()
	c.token = tokenResp.AccessToken
	c.tokenMu.Unlock()

	c.config.OAuth2.Token = tokenResp.AccessToken
	c.config.OAuth2.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return nil
}

// GetToken returns the current authentication token.
func (c *TAXIIClient) GetToken() string {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.token
}

// SetToken sets the authentication token.
func (c *TAXIIClient) SetToken(token string) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.token = token
}

// ============================================================================
// Discovery Endpoint
// ============================================================================

// Discovery retrieves the TAXII server discovery information.
func (c *TAXIIClient) Discovery(ctx context.Context) (*TAXIIDiscovery, error) {
	discoveryURL := c.config.DiscoveryURL
	if discoveryURL == "" {
		discoveryURL = c.config.ServerURL + "/taxii2/"
	}

	req, err := c.newRequest(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	var discovery TAXIIDiscovery
	if err := c.doRequest(req, &discovery); err != nil {
		return nil, err
	}

	return &discovery, nil
}

// GetAPIRoots retrieves available API roots from discovery.
func (c *TAXIIClient) GetAPIRoots(ctx context.Context) ([]string, error) {
	discovery, err := c.Discovery(ctx)
	if err != nil {
		return nil, err
	}
	return discovery.APIRoots, nil
}

// ============================================================================
// API Root Operations
// ============================================================================

// GetAPIRoot retrieves information about an API root.
func (c *TAXIIClient) GetAPIRoot(ctx context.Context, apiRootURL string) (*TAXIIAPIRoot, error) {
	req, err := c.newRequest(ctx, http.MethodGet, apiRootURL, nil)
	if err != nil {
		return nil, err
	}

	var apiRoot TAXIIAPIRoot
	if err := c.doRequest(req, &apiRoot); err != nil {
		return nil, err
	}

	return &apiRoot, nil
}

// SetAPIRoot sets the current API root for the client.
func (c *TAXIIClient) SetAPIRoot(apiRoot string) {
	c.apiRoot = apiRoot
}

// ============================================================================
// Collection Operations
// ============================================================================

// GetCollections retrieves all collections from an API root.
func (c *TAXIIClient) GetCollections(ctx context.Context, apiRootURL string) (*TAXIICollections, error) {
	url := apiRootURL + "/collections"
	req, err := c.newRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	var collections TAXIICollections
	if err := c.doRequest(req, &collections); err != nil {
		return nil, err
	}

	return &collections, nil
}

// GetCollection retrieves a specific collection by ID.
func (c *TAXIIClient) GetCollection(ctx context.Context, apiRootURL, collectionID string) (*TAXIICollection, error) {
	url := apiRootURL + "/collections/" + collectionID
	req, err := c.newRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	var collection TAXIICollection
	if err := c.doRequest(req, &collection); err != nil {
		return nil, err
	}

	return &collection, nil
}

// ============================================================================
// Object Operations
// ============================================================================

// GetObjects retrieves objects from a collection.
func (c *TAXIIClient) GetObjects(ctx context.Context, apiRootURL, collectionID string, opts *TAXIIGetObjectsRequest) (*Bundle, *TAXIIContentRange, error) {
	url := apiRootURL + "/collections/" + collectionID + "/objects"

	req, err := c.newRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	// Add query parameters
	if opts != nil {
		q := req.URL.Query()
		if !opts.AddedAfter.IsZero() {
			q.Set("added_after", opts.AddedAfter.Format(time.RFC3339))
		}
		if len(opts.IDs) > 0 {
			q.Set("match[id]", strings.Join(opts.IDs, ","))
		}
		if len(opts.Types) > 0 {
			q.Set("match[type]", strings.Join(opts.Types, ","))
		}
		if len(opts.Versions) > 0 {
			q.Set("match[version]", strings.Join(opts.Versions, ","))
		}
		req.URL.RawQuery = q.Encode()
	}

	var bundle Bundle
	contentRange, err := c.doRequestWithContentRange(req, &bundle)
	if err != nil {
		return nil, nil, err
	}

	return &bundle, contentRange, nil
}

// GetObject retrieves a specific object from a collection.
func (c *TAXIIClient) GetObject(ctx context.Context, apiRootURL, collectionID, objectID string) (json.RawMessage, error) {
	url := apiRootURL + "/collections/" + collectionID + "/objects/" + objectID

	req, err := c.newRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	var result json.RawMessage
	if err := c.doRequest(req, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// AddObjects adds objects to a collection.
func (c *TAXIIClient) AddObjects(ctx context.Context, apiRootURL, collectionID string, bundle *Bundle) (*TAXIIEnvelopes, error) {
	url := apiRootURL + "/collections/" + collectionID + "/objects"

	req, err := c.newRequest(ctx, http.MethodPost, url, bundle)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/stix+json;version=2.1")

	var envelopes TAXIIEnvelopes
	if err := c.doRequest(req, &envelopes); err != nil {
		return nil, err
	}

	return &envelopes, nil
}

// DeleteObject deletes an object from a collection.
func (c *TAXIIClient) DeleteObject(ctx context.Context, apiRootURL, collectionID, objectID string) error {
	url := apiRootURL + "/collections/" + collectionID + "/objects/" + objectID

	req, err := c.newRequest(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	return c.doRequest(req, nil)
}

// ============================================================================
// Manifest Operations
// ============================================================================

// GetManifest retrieves the manifest for a collection.
func (c *TAXIIClient) GetManifest(ctx context.Context, apiRootURL, collectionID string, addedAfter time.Time) (*TAXIIManifest, error) {
	url := apiRootURL + "/collections/" + collectionID + "/manifest"

	req, err := c.newRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameters
	if !addedAfter.IsZero() {
		q := req.URL.Query()
		q.Set("added_after", addedAfter.Format(time.RFC3339))
		req.URL.RawQuery = q.Encode()
	}

	var manifest TAXIIManifest
	if err := c.doRequest(req, &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

// ============================================================================
// Paginated Operations
// ============================================================================

// GetObjectsPaginator provides paginated access to objects.
type GetObjectsPaginator struct {
	client       *TAXIIClient
	apiRootURL   string
	collectionID string
	opts         *TAXIIGetObjectsRequest
	pageSize     int
	next         string
	hasMore      bool
}

// NewGetObjectsPaginator creates a new paginator for objects.
func (c *TAXIIClient) NewGetObjectsPaginator(apiRootURL, collectionID string, opts *TAXIIGetObjectsRequest, pageSize int) *GetObjectsPaginator {
	return &GetObjectsPaginator{
		client:       c,
		apiRootURL:   apiRootURL,
		collectionID: collectionID,
		opts:         opts,
		pageSize:     pageSize,
		hasMore:      true,
	}
}

// Next retrieves the next page of objects.
func (p *GetObjectsPaginator) Next(ctx context.Context) (*Bundle, error) {
	if !p.hasMore {
		return nil, nil
	}

	url := p.apiRootURL + "/collections/" + p.collectionID + "/objects"

	req, err := p.client.newRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameters
	q := req.URL.Query()
	if p.opts != nil {
		if !p.opts.AddedAfter.IsZero() {
			q.Set("added_after", p.opts.AddedAfter.Format(time.RFC3339))
		}
		if len(p.opts.IDs) > 0 {
			q.Set("match[id]", strings.Join(p.opts.IDs, ","))
		}
		if len(p.opts.Types) > 0 {
			q.Set("match[type]", strings.Join(p.opts.Types, ","))
		}
	}
	if p.pageSize > 0 {
		q.Set("limit", strconv.Itoa(p.pageSize))
	}
	if p.next != "" {
		q.Set("next", p.next)
	}
	req.URL.RawQuery = q.Encode()

	var bundle Bundle
	headers, err := p.client.doRequestWithHeaders(req, &bundle)
	if err != nil {
		return nil, err
	}

	// Check for next page token
	if nextHeader := headers.Get("X-Taxii-Next"); nextHeader != "" {
		p.next = nextHeader
	} else {
		p.hasMore = false
	}

	return &bundle, nil
}

// HasMore returns true if there are more pages.
func (p *GetObjectsPaginator) HasMore() bool {
	return p.hasMore
}

// ============================================================================
// Poll Operations
// ============================================================================

// PollOptions contains options for polling a collection.
type PollOptions struct {
	// Collection ID to poll
	CollectionID string
	// AddedAfter filters objects added after this time
	AddedAfter time.Time
	// Types filters by object types
	Types []string
	// PollInterval is the interval between polls
	PollInterval time.Duration
	// MaxPolls is the maximum number of polls (0 = infinite)
	MaxPolls int
	// Handler is called for each received object
	Handler func(obj json.RawMessage) error
}

// Poll polls a collection for new objects.
func (c *TAXIIClient) Poll(ctx context.Context, apiRootURL string, opts PollOptions) error {
	interval := opts.PollInterval
	if interval == 0 {
		interval = 5 * time.Minute
	}

	pollCount := 0
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	getOpts := &TAXIIGetObjectsRequest{
		AddedAfter: opts.AddedAfter,
		Types:      opts.Types,
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			bundle, _, err := c.GetObjects(ctx, apiRootURL, opts.CollectionID, getOpts)
			if err != nil {
				return err
			}

			for _, obj := range bundle.Objects {
				if opts.Handler != nil {
					if err := opts.Handler(obj); err != nil {
						return err
					}
				}
			}

			// Update added_after for next poll
			getOpts.AddedAfter = time.Now().UTC()

			pollCount++
			if opts.MaxPolls > 0 && pollCount >= opts.MaxPolls {
				return nil
			}
		}
	}
}

// ============================================================================
// Push Operations
// ============================================================================

// PushOptions contains options for pushing objects.
type PushOptions struct {
	// Collection ID to push to
	CollectionID string
	// Bundle of objects to push
	Bundle *Bundle
	// BatchSize for batching pushes
	BatchSize int
}

// Push pushes objects to a TAXII collection.
func (c *TAXIIClient) Push(ctx context.Context, apiRootURL string, opts PushOptions) (*TAXIIEnvelopes, error) {
	if opts.BatchSize <= 0 || opts.BatchSize >= len(opts.Bundle.Objects) {
		return c.AddObjects(ctx, apiRootURL, opts.CollectionID, opts.Bundle)
	}

	// Push in batches
	var results []json.RawMessage
	for i := 0; i < len(opts.Bundle.Objects); i += opts.BatchSize {
		end := i + opts.BatchSize
		if end > len(opts.Bundle.Objects) {
			end = len(opts.Bundle.Objects)
		}

		batchBundle := &Bundle{
			Type:    STIXTypeBundle,
			ID:      opts.Bundle.ID + "-" + strconv.Itoa(i/opts.BatchSize),
			Objects: opts.Bundle.Objects[i:end],
		}

		envelopes, err := c.AddObjects(ctx, apiRootURL, opts.CollectionID, batchBundle)
		if err != nil {
			return nil, err
		}

		results = append(results, envelopes.Objects...)
	}

	return &TAXIIEnvelopes{Objects: results}, nil
}

// PushIndicator pushes a single indicator to a collection.
func (c *TAXIIClient) PushIndicator(ctx context.Context, apiRootURL, collectionID string, indicator *Indicator) (*TAXIIEnvelopes, error) {
	bundleID, err := GenerateSTIXID(STIXTypeBundle)
	if err != nil {
		return nil, err
	}

	bundle := NewBundle(bundleID)
	if err := bundle.AddObject(indicator); err != nil {
		return nil, err
	}

	return c.AddObjects(ctx, apiRootURL, collectionID, bundle)
}

// PushIndicators pushes multiple indicators to a collection.
func (c *TAXIIClient) PushIndicators(ctx context.Context, apiRootURL, collectionID string, indicators []*Indicator, batchSize int) (*TAXIIEnvelopes, error) {
	bundleID, err := GenerateSTIXID(STIXTypeBundle)
	if err != nil {
		return nil, err
	}

	bundle := NewBundle(bundleID)
	for _, indicator := range indicators {
		if err := bundle.AddObject(indicator); err != nil {
			return nil, err
		}
	}

	return c.Push(ctx, apiRootURL, PushOptions{
		CollectionID: collectionID,
		Bundle:       bundle,
		BatchSize:    batchSize,
	})
}

// ============================================================================
// Session Management
// ============================================================================

// CreateSession creates a new TAXII session.
func (c *TAXIIClient) CreateSession(ctx context.Context) (*TAXIISession, error) {
	// Authenticate first
	if err := c.Authenticate(ctx); err != nil {
		return nil, err
	}

	session := &TAXIISession{
		SessionID: generateSessionID(),
		ServerURL: c.config.ServerURL,
		Token:     c.GetToken(),
	}

	c.sessionMu.Lock()
	c.session = session
	c.sessionMu.Unlock()

	return session, nil
}

// GetSession returns the current session.
func (c *TAXIIClient) GetSession() *TAXIISession {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.session
}

// CloseSession closes the current session.
func (c *TAXIIClient) CloseSession() {
	c.sessionMu.Lock()
	c.session = nil
	c.sessionMu.Unlock()
}

// generateSessionID generates a random session ID.
func generateSessionID() string {
	uuid, _ := generateRandomUUID()
	return "session--" + uuid
}

// ============================================================================
// HTTP Request Helpers
// ============================================================================

// newRequest creates a new HTTP request with proper headers.
func (c *TAXIIClient) newRequest(ctx context.Context, method, urlStr string, body interface{}) (*http.Request, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, NewError("taxii_request", "failed to marshal request body", false, err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, bodyReader)
	if err != nil {
		return nil, NewError("taxii_request", "failed to create request", false, err)
	}

	// Set headers
	req.Header.Set("Accept", "application/stix+json;version=2.1")
	req.Header.Set("User-Agent", c.config.UserAgent)

	// Set authentication
	switch c.config.AuthType {
	case "basic":
		if c.config.Username != "" && c.config.Password != "" {
			req.SetBasicAuth(c.config.Username, c.config.Password)
		}
	case "token", "oauth2":
		token := c.GetToken()
		if token != "" {
			if c.config.TokenHeader == "Authorization" {
				req.Header.Set("Authorization", "Bearer "+token)
			} else {
				req.Header.Set(c.config.TokenHeader, token)
			}
		}
	}

	return req, nil
}

// doRequest executes an HTTP request with retry logic.
func (c *TAXIIClient) doRequest(req *http.Request, result interface{}) error {
	_, err := c.doRequestWithHeaders(req, result)
	return err
}

// doRequestWithHeaders executes an HTTP request and returns headers.
func (c *TAXIIClient) doRequestWithHeaders(req *http.Request, result interface{}) (http.Header, error) {
	var lastErr error
	maxAttempts := 1
	if c.config.Retry.Enabled {
		maxAttempts = c.config.Retry.MaxAttempts
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			backoff := c.calculateBackoff(attempt)
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(backoff):
			}
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = NewError("taxii_request", "request failed", true, err)
			continue
		}

		// Check for retryable status codes
		if c.shouldRetry(resp.StatusCode) && attempt < maxAttempts-1 {
			resp.Body.Close()
			lastErr = NewError("taxii_request", fmt.Sprintf("status code %d", resp.StatusCode), true, nil)
			continue
		}

		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			taxiiErr := &TAXIIError{
				Title:       "TAXII Error",
				Description: string(body),
				ErrorCode:   resp.StatusCode,
				HTTPHeaders: resp.Header,
			}

			// Try to parse TAXII error response
			var errResp struct {
				Title       string `json:"title"`
				Description string `json:"description"`
				ErrorCode   int    `json:"error_code"`
			}
			if json.Unmarshal(body, &errResp) == nil {
				if errResp.Title != "" {
					taxiiErr.Title = errResp.Title
				}
				if errResp.Description != "" {
					taxiiErr.Description = errResp.Description
				}
				if errResp.ErrorCode != 0 {
					taxiiErr.ErrorCode = errResp.ErrorCode
				}
			}

			return nil, taxiiErr
		}

		if result != nil {
			if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
				return nil, NewError("taxii_request", "failed to decode response", false, err)
			}
		}

		return resp.Header, nil
	}

	return nil, lastErr
}

// doRequestWithContentRange executes a request and returns content range.
func (c *TAXIIClient) doRequestWithContentRange(req *http.Request, result interface{}) (*TAXIIContentRange, error) {
	headers, err := c.doRequestWithHeaders(req, result)
	if err != nil {
		return nil, err
	}

	crHeader := headers.Get("Content-Range")
	if crHeader == "" {
		return nil, nil
	}

	return ParseTAXIIContentRange(crHeader)
}

// calculateBackoff calculates the backoff duration for a retry attempt.
func (c *TAXIIClient) calculateBackoff(attempt int) time.Duration {
	backoff := c.config.Retry.InitialBackoff
	for i := 1; i < attempt; i++ {
		backoff = time.Duration(float64(backoff) * c.config.Retry.BackoffMultiplier)
		if backoff > c.config.Retry.MaxBackoff {
			return c.config.Retry.MaxBackoff
		}
	}
	return backoff
}

// shouldRetry determines if a status code should trigger a retry.
func (c *TAXIIClient) shouldRetry(statusCode int) bool {
	for _, code := range c.config.Retry.RetryOnStatusCodes {
		if statusCode == code {
			return true
		}
	}
	return false
}

// ============================================================================
// Client Stats
// ============================================================================

// TAXIIClientStats contains client statistics.
type TAXIIClientStats struct {
	RequestsTotal   int64
	RequestsSuccess int64
	RequestsFailed  int64
	RequestsRetried int64
	BytesSent       int64
	BytesReceived   int64
	LastRequestTime time.Time
	LastError       string
}

// GetStats returns client statistics.
func (c *TAXIIClient) GetStats() *TAXIIClientStats {
	return &TAXIIClientStats{}
}

// ============================================================================
// Connection Pool
// ============================================================================

// TAXIIConnectionPool manages a pool of TAXII clients.
type TAXIIConnectionPool struct {
	mu      sync.RWMutex
	clients chan *TAXIIClient
	config  TAXIIConfig
	maxSize int
}

// NewTAXIIConnectionPool creates a new connection pool.
func NewTAXIIConnectionPool(config TAXIIConfig, maxSize int) (*TAXIIConnectionPool, error) {
	pool := &TAXIIConnectionPool{
		clients: make(chan *TAXIIClient, maxSize),
		config:  config,
		maxSize: maxSize,
	}

	// Pre-create some clients
	initial := min(5, maxSize)
	for i := 0; i < initial; i++ {
		client, err := NewTAXIIClient(config)
		if err != nil {
			return nil, err
		}
		pool.clients <- client
	}

	return pool, nil
}

// Get retrieves a client from the pool.
func (p *TAXIIConnectionPool) Get() (*TAXIIClient, error) {
	select {
	case client := <-p.clients:
		return client, nil
	default:
		// Create new client if pool is empty
		return NewTAXIIClient(p.config)
	}
}

// Put returns a client to the pool.
func (p *TAXIIConnectionPool) Put(client *TAXIIClient) {
	select {
	case p.clients <- client:
		// Returned to pool
	default:
		// Pool is full, client will be garbage collected
	}
}

// Close closes all clients in the pool.
func (p *TAXIIConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	close(p.clients)
	for client := range p.clients {
		_ = client // Client doesn't have a Close method, just discard
	}
}

// ============================================================================
// Rate Limiter
// ============================================================================

// TAXIIRateLimiter implements rate limiting for TAXII requests.
type TAXIIRateLimiter struct {
	mu           sync.Mutex
	rate         int           // requests per second
	tokens       int           // current tokens
	maxTokens    int           // max tokens (burst)
	refillTicker *time.Ticker  // token refill ticker
	stopCh       chan struct{} // stop channel
}

// NewTAXIIRateLimiter creates a new rate limiter.
func NewTAXIIRateLimiter(rate int) *TAXIIRateLimiter {
	rl := &TAXIIRateLimiter{
		rate:      rate,
		tokens:    rate,
		maxTokens: rate,
		stopCh:    make(chan struct{}),
	}

	// Refill tokens every second
	rl.refillTicker = time.NewTicker(time.Second)
	go rl.refill()

	return rl
}

// refill refills tokens periodically.
func (rl *TAXIIRateLimiter) refill() {
	for {
		select {
		case <-rl.refillTicker.C:
			rl.mu.Lock()
			if rl.tokens < rl.maxTokens {
				rl.tokens++
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// Wait waits for a token to be available.
func (rl *TAXIIRateLimiter) Wait(ctx context.Context) error {
	for {
		rl.mu.Lock()
		if rl.tokens > 0 {
			rl.tokens--
			rl.mu.Unlock()
			return nil
		}
		rl.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			continue
		}
	}
}

// Stop stops the rate limiter.
func (rl *TAXIIRateLimiter) Stop() {
	rl.refillTicker.Stop()
	close(rl.stopCh)
}

// ============================================================================
// Helper Functions
// ============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
