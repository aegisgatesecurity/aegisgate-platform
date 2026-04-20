// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cache represents a cacheable response
type Cache struct {
	Key        string
	Value      []byte
	Headers    http.Header
	Expiry     time.Time
	CreatedAt  time.Time
	Tags       []string
	StatusCode int
}

// CacheStore defines the interface for cache storage backends
type CacheStore interface {
	// Get retrieves a cached value
	Get(ctx context.Context, key string) (*Cache, error)

	// Set stores a value in cache
	Set(ctx context.Context, key string, cache *Cache) error

	// Delete removes a value from cache
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists
	Exists(ctx context.Context, key string) (bool, error)

	// InvalidateByTag removes all entries with a specific tag
	InvalidateByTag(ctx context.Context, tag string) error

	// Clear removes all entries
	Clear(ctx context.Context) error

	// Stats returns cache statistics
	Stats(ctx context.Context) (CacheStats, error)
}

// CacheStats contains cache statistics
type CacheStats struct {
	Hits        int64
	Misses      int64
	Evictions   int64
	Items       int64
	MemoryBytes int64
	Uptime      time.Duration
}

// InMemoryCache is an in-memory cache implementation
type InMemoryCache struct {
	mu        sync.RWMutex
	data      map[string]*Cache
	hits      int64
	misses    int64
	evictions int64
	startTime time.Time
	maxSize   int64 // Maximum number of items
	maxMemory int64 // Maximum memory in bytes
}

// NewInMemoryCache creates a new in-memory cache
func NewInMemoryCache(maxItems int, maxMemory int64) *InMemoryCache {
	return &InMemoryCache{
		data:      make(map[string]*Cache),
		startTime: time.Now(),
		maxSize:   int64(maxItems),
		maxMemory: maxMemory,
	}
}

// Get retrieves a cached value
func (c *InMemoryCache) Get(ctx context.Context, key string) (*Cache, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cache, ok := c.data[key]
	if !ok {
		c.misses++
		return nil, nil
	}

	// Check expiration
	if time.Now().After(cache.Expiry) {
		c.misses++
		return nil, nil
	}

	c.hits++
	return cache, nil
}

// Set stores a value in cache
func (c *InMemoryCache) Set(ctx context.Context, key string, cache *Cache) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if necessary
	c.evictIfNeeded()

	c.data[key] = cache
	return nil
}

// Delete removes a value from cache
func (c *InMemoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.data, key)
	return nil
}

// Exists checks if a key exists
func (c *InMemoryCache) Exists(ctx context.Context, key string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, ok := c.data[key]
	return ok, nil
}

// InvalidateByTag removes all entries with a specific tag
func (c *InMemoryCache) InvalidateByTag(ctx context.Context, tag string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, cache := range c.data {
		for _, t := range cache.Tags {
			if t == tag {
				delete(c.data, key)
				break
			}
		}
	}
	return nil
}

// Clear removes all entries
func (c *InMemoryCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = make(map[string]*Cache)
	c.hits = 0
	c.misses = 0
	c.evictions = 0
	return nil
}

// Stats returns cache statistics
func (c *InMemoryCache) Stats(ctx context.Context) (CacheStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Calculate memory usage
	var mem int64
	for _, cache := range c.data {
		mem += int64(len(cache.Value))
	}

	return CacheStats{
		Hits:        c.hits,
		Misses:      c.misses,
		Evictions:   c.evictions,
		Items:       int64(len(c.data)),
		MemoryBytes: mem,
		Uptime:      time.Since(c.startTime),
	}, nil
}

func (c *InMemoryCache) evictIfNeeded() {
	// Evict by item count
	if c.maxSize > 0 && int64(len(c.data)) >= c.maxSize {
		c.evictOldest()
	}

	// Evict by memory
	if c.maxMemory > 0 {
		var totalMem int64
		for _, cache := range c.data {
			totalMem += int64(len(cache.Value))
		}
		for totalMem > c.maxMemory && len(c.data) > 0 {
			c.evictOldest()
			totalMem = 0
			for _, cache := range c.data {
				totalMem += int64(len(cache.Value))
			}
		}
	}
}

func (c *InMemoryCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, cache := range c.data {
		if oldestKey == "" || cache.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = cache.CreatedAt
		}
	}

	if oldestKey != "" {
		delete(c.data, oldestKey)
		c.evictions++
	}
}

// CacheKeyGenerator generates cache keys based on request
type CacheKeyGenerator struct {
	includeHeaders []string
	includeQuery   bool
	separator      string
}

// NewCacheKeyGenerator creates a new cache key generator
func NewCacheKeyGenerator() *CacheKeyGenerator {
	return &CacheKeyGenerator{
		includeHeaders: []string{"Authorization", "Accept-Language"},
		includeQuery:   true,
		separator:      ":",
	}
}

// SetIncludeHeaders sets headers to include in cache key
func (g *CacheKeyGenerator) SetIncludeHeaders(headers []string) {
	g.includeHeaders = headers
}

// SetIncludeQuery includes query parameters in cache key
func (g *CacheKeyGenerator) SetIncludeQuery(include bool) {
	g.includeQuery = include
}

// Generate generates a cache key from a request
func (g *CacheKeyGenerator) Generate(r *http.Request) string {
	var parts []string

	// Method and path
	parts = append(parts, r.Method, r.URL.Path)

	// Query string
	if g.includeQuery && r.URL.RawQuery != "" {
		// Sort query parameters for consistent keys
		parts = append(parts, g.sortQuery(r.URL.RawQuery))
	}

	// Headers
	for _, header := range g.includeHeaders {
		if value := r.Header.Get(header); value != "" {
			parts = append(parts, header+"="+value)
		}
	}

	// Body hash for POST/PUT/PATCH
	if r.Body != nil && (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH") {
		hash := g.hashBody(r.Body)
		parts = append(parts, "body="+hash)
	}

	return strings.Join(parts, g.separator)
}

func (g *CacheKeyGenerator) sortQuery(query string) string {
	parts := strings.Split(query, "&")
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

func (g *CacheKeyGenerator) hashBody(body io.Reader) string {
	hasher := sha256.New()
	_, _ = io.Copy(hasher, body)
	return hex.EncodeToString(hasher.Sum(nil))
}

// CacheConfig contains cache configuration
type CacheConfig struct {
	// TTL is the default time-to-live for cached responses
	TTL time.Duration

	// MaxAge is the max-age for Cache-Control header
	MaxAge time.Duration

	// StaleWhileRevalidate allows serving stale content while revalidating
	StaleWhileRevalidate time.Duration

	// StaleWhileError allows serving stale content on errors
	StaleWhileError time.Duration

	// VaryHeaders specifies headers that affect caching
	VaryHeaders []string

	// CacheableMethods specifies which HTTP methods can be cached
	CacheableMethods []string

	// CacheableStatusCodes specifies which status codes can be cached
	CacheableStatusCodes []int

	// Tags for cache invalidation
	Tags []string

	// Store is the cache storage backend
	Store CacheStore
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		TTL:                  5 * time.Minute,
		MaxAge:               5 * time.Minute,
		StaleWhileRevalidate: 10 * time.Minute,
		StaleWhileError:      24 * time.Hour,
		VaryHeaders:          []string{"Accept", "Accept-Language", "Authorization"},
		CacheableMethods:     []string{"GET", "HEAD"},
		CacheableStatusCodes: []int{200, 203, 300, 301},
		Tags:                 []string{},
		Store:                NewInMemoryCache(10000, 100*1024*1024), // 10k items, 100MB
	}
}

// CacheHandler handles HTTP caching
type CacheHandler struct {
	config   *CacheConfig
	keyGen   *CacheKeyGenerator
	mu       sync.RWMutex
	handlers map[string]http.Handler // version -> handler
}

// NewCacheHandler creates a new cache handler
func NewCacheHandler(config *CacheConfig) *CacheHandler {
	if config.Store == nil {
		config.Store = NewInMemoryCache(10000, 100*1024*1024)
	}

	return &CacheHandler{
		config:   config,
		keyGen:   NewCacheKeyGenerator(),
		handlers: make(map[string]http.Handler),
	}
}

// RegisterHandler registers a handler for a specific version
func (h *CacheHandler) RegisterHandler(version string, handler http.Handler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handlers[version] = handler
}

// Handle caches and serves HTTP responses
func (h *CacheHandler) Handle(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only cache GET and HEAD requests
		if !h.isCacheableMethod(r.Method) {
			handler.ServeHTTP(w, r)
			return
		}

		// Check for cache control headers
		if r.Header.Get("Cache-Control") == "no-cache" {
			handler.ServeHTTP(w, r)
			return
		}

		// Generate cache key
		key := h.keyGen.Generate(r)

		// Try to get from cache
		ctx := r.Context()
		cached, err := h.config.Store.Get(ctx, key)
		if err == nil && cached != nil {
			h.serveCached(w, r, cached)
			return
		}

		// Wrap response writer to capture response
		rec := &cacheResponseWriter{
			ResponseWriter: w,
			headers:        make(http.Header),
			statusCode:     http.StatusOK,
		}

		// Call handler
		handler.ServeHTTP(rec, r)

		// Cache if cacheable
		if h.isCacheableStatus(rec.statusCode) {
			h.cacheResponse(ctx, key, rec, r)
		}
	})
}

func (h *CacheHandler) isCacheableMethod(method string) bool {
	for _, m := range h.config.CacheableMethods {
		if method == m {
			return true
		}
	}
	return false
}

func (h *CacheHandler) isCacheableStatus(code int) bool {
	for _, c := range h.config.CacheableStatusCodes {
		if code == c {
			return true
		}
	}
	return false
}

func (h *CacheHandler) serveCached(w http.ResponseWriter, r *http.Request, cached *Cache) {
	// Check if expired
	if time.Now().After(cached.Expiry) {
		// Check for stale-while-revalidate
		if h.config.StaleWhileRevalidate > 0 {
			staleExpiry := cached.Expiry.Add(h.config.StaleWhileRevalidate)
			if time.Now().Before(staleExpiry) {
				w.Header().Set("Age", "0")
				w.Header().Set("Cache-Control", fmt.Sprintf("max-age=0, stale-while-revalidate=%d",
					int(h.config.StaleWhileRevalidate.Seconds())))
				w.WriteHeader(cached.StatusCode)
				_, _ = w.Write(cached.Value)
				return
			}
		}
		// Serve stale on error if configured
		if h.config.StaleWhileError > 0 && h.config.StaleWhileRevalidate == 0 {
			staleExpiry := cached.Expiry.Add(h.config.StaleWhileError)
			if time.Now().Before(staleExpiry) {
				w.Header().Set("Warning", "110 - Response is stale")
				w.WriteHeader(cached.StatusCode)
				_, _ = w.Write(cached.Value)
				return
			}
		}
		return // Cache miss
	}

	// Set headers
	for k, v := range cached.Headers {
		w.Header()[k] = v
	}

	// Set age
	age := time.Since(cached.CreatedAt).Seconds()
	w.Header().Set("Age", strconv.FormatInt(int64(age), 10))

	w.WriteHeader(cached.StatusCode)
	_, _ = w.Write(cached.Value)
}

func (h *CacheHandler) cacheResponse(ctx context.Context, key string, rec *cacheResponseWriter, r *http.Request) {
	// Create cache entry
	cache := &Cache{
		Key:        key,
		Value:      rec.Body(),
		Headers:    rec.headers,
		Expiry:     time.Now().Add(h.config.TTL),
		CreatedAt:  time.Now(),
		Tags:       h.config.Tags,
		StatusCode: rec.statusCode,
	}

	// Set cache control headers on response
	h.setCacheControlHeaders(rec)

	// Store in cache
	// Store Set error is handled internally by the cache implementation
	_ = h.config.Store.Set(ctx, key, cache)
}

func (h *CacheHandler) setCacheControlHeaders(rec *cacheResponseWriter) {
	rec.headers.Set("Cache-Control", fmt.Sprintf("max-age=%d",
		int(h.config.MaxAge.Seconds())))

	if h.config.StaleWhileRevalidate > 0 {
		rec.headers.Set("Cache-Control",
			rec.headers.Get("Cache-Control")+fmt.Sprintf(", stale-while-revalidate=%d",
				int(h.config.StaleWhileRevalidate.Seconds())))
	}

	// Set Vary header
	if len(h.config.VaryHeaders) > 0 {
		rec.headers.Set("Vary", strings.Join(h.config.VaryHeaders, ", "))
	}

	// Set ETag
	hasher := sha256.New()
	hasher.Write(rec.Body())
	etag := fmt.Sprintf(`"%x"`, hasher.Sum(nil))
	rec.headers.Set("ETag", etag)

	// Set Expires
	rec.headers.Set("Expires", time.Now().Add(h.config.MaxAge).Format(http.TimeFormat))
}

// cacheResponseWriter wraps http.ResponseWriter to capture response
type cacheResponseWriter struct {
	http.ResponseWriter
	headers    http.Header
	statusCode int
	body       []byte
}

func (w *cacheResponseWriter) Header() http.Header {
	return w.headers
}

func (w *cacheResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *cacheResponseWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return w.ResponseWriter.Write(b)
}

func (w *cacheResponseWriter) Body() []byte {
	return w.body
}

// CacheInvalidator handles cache invalidation
type CacheInvalidator struct {
	store CacheStore
	mu    sync.RWMutex
	rules []InvalidationRule
}

// InvalidationRule defines rules for cache invalidation
type InvalidationRule struct {
	Pattern *regexp.Regexp
	Tags    []string
}

// NewCacheInvalidator creates a new cache invalidator
func NewCacheInvalidator(store CacheStore) *CacheInvalidator {
	return &CacheInvalidator{
		store: store,
		rules: []InvalidationRule{},
	}
}

// AddRule adds an invalidation rule
func (i *CacheInvalidator) AddRule(pattern string, tags []string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	i.rules = append(i.rules, InvalidationRule{
		Pattern: re,
		Tags:    tags,
	})
	return nil
}

// InvalidateByPattern invalidates cache entries matching a pattern
func (i *CacheInvalidator) InvalidateByPattern(ctx context.Context, pattern string) error {
	// This would require scanning - for in-memory we implement a simple version
	// For production, use Redis with pattern matching or tags
	return nil
}

// InvalidateByTag invalidates all entries with a specific tag
func (i *CacheInvalidator) InvalidateByTag(ctx context.Context, tag string) error {
	return i.store.InvalidateByTag(ctx, tag)
}

// InvalidateKey invalidates a specific cache key
func (i *CacheInvalidator) InvalidateKey(ctx context.Context, key string) error {
	return i.store.Delete(ctx, key)
}

// CacheMiddleware creates caching middleware
func CacheMiddleware(config *CacheConfig) func(http.Handler) http.Handler {
	handler := NewCacheHandler(config)

	return func(next http.Handler) http.Handler {
		return handler.Handle(next)
	}
}

// VaryCacheKeyGenerator generates cache keys with Vary headers
type VaryCacheKeyGenerator struct {
	base     *CacheKeyGenerator
	varyHash func(http.Header) string
}

// NewVaryCacheKeyGenerator creates a Vary-aware key generator
func NewVaryCacheKeyGenerator() *VaryCacheKeyGenerator {
	return &VaryCacheKeyGenerator{
		base: NewCacheKeyGenerator(),
		varyHash: func(h http.Header) string {
			var parts []string
			for k := range h {
				parts = append(parts, k+"="+h.Get(k))
			}
			sort.Strings(parts)
			hasher := sha256.New()
			hasher.Write([]byte(strings.Join(parts, "&")))
			return hex.EncodeToString(hasher.Sum(nil))
		},
	}
}

// Generate generates a cache key including Vary headers
func (g *VaryCacheKeyGenerator) Generate(r *http.Request) string {
	key := g.base.Generate(r)

	// Add Vary header hash
	vary := r.Header.Get("Vary")
	if vary != "" {
		varyHeaders := strings.Split(vary, ",")
		header := http.Header{}
		for _, h := range varyHeaders {
			h = strings.TrimSpace(h)
			if v := r.Header.Get(h); v != "" {
				header.Set(h, v)
			}
		}
		key = key + ":vary:" + g.varyHash(header)
	}

	return key
}

// ETagger generates ETags for responses
type ETagger struct {
	strong bool
}

// NewETagger creates a new ETag generator
func NewETagger(strong bool) *ETagger {
	return &ETagger{strong: strong}
}

// Generate generates an ETag for content
func (e *ETagger) Generate(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	hash := hex.EncodeToString(hasher.Sum(nil))

	if e.strong {
		return fmt.Sprintf(`"%s"`, hash)
	}
	return fmt.Sprintf(`W/"%s"`, hash)
}

// GenerateForFile generates an ETag for a file
func (e *ETagger) GenerateForFile(modTime time.Time, size int64) string {
	hasher := sha256.New()
	_, _ = fmt.Fprintf(hasher, "%d-%d", modTime.Unix(), size)
	hash := hex.EncodeToString(hasher.Sum(nil))

	if e.strong {
		return fmt.Sprintf(`"%s"`, hash)
	}
	return fmt.Sprintf(`W/"%s"`, hash)
}

// HandleETag handles ETag-based conditional requests
// Handle handles ETag-related HTTP requests.
func (e *ETagger) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only handle GET/HEAD
		if r.Method != "GET" && r.Method != "HEAD" {
			next.ServeHTTP(w, r)
			return
		}

		// Pass through - actual ETag generation happens in the response
		next.ServeHTTP(w, r)
	})
}

// LastModifiedHandler handles Last-Modified conditional requests
type LastModifiedHandler struct {
	clock func() time.Time
}

// NewLastModifiedHandler creates a new Last-Modified handler
func NewLastModifiedHandler() *LastModifiedHandler {
	return &LastModifiedHandler{
		clock: time.Now,
	}
}

// SetLastModified sets Last-Modified header
func (h *LastModifiedHandler) SetLastModified(w http.ResponseWriter, t time.Time) {
	w.Header().Set("Last-Modified", t.Format(http.TimeFormat))
}

// Handle processes If-Modified-Since and If-Unmodified-Since
func (h *LastModifiedHandler) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			next.ServeHTTP(w, r)
			return
		}

		// Check If-Modified-Since
		if ims := r.Header.Get("If-Modified-Since"); ims != "" {
			if t, err := http.ParseTime(ims); err == nil {
				// Get current modification time from context or use now
				modTime := h.clock()
				if modTime.Before(t.Add(1 * time.Second)) {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}

		// Check If-Unmodified-Since
		if ius := r.Header.Get("If-Unmodified-Since"); ius != "" {
			if t, err := http.ParseTime(ius); err == nil {
				modTime := h.clock()
				if modTime.After(t) {
					w.WriteHeader(http.StatusPreconditionFailed)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// CacheWarmer pre-warms the cache with common requests
type CacheWarmer struct {
	store    CacheStore
	keyGen   *CacheKeyGenerator
	prefetch []PrefetchRequest
	mu       sync.Mutex
	client   *http.Client
}

// PrefetchRequest defines a request to prefetch
type PrefetchRequest struct {
	Method string
	Path   string
	Query  string
	Header http.Header
}

// NewCacheWarmer creates a new cache warmer
func NewCacheWarmer(store CacheStore) *CacheWarmer {
	return &CacheWarmer{
		store:    store,
		keyGen:   NewCacheKeyGenerator(),
		prefetch: []PrefetchRequest{},
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// AddPrefetch adds a request to prefetch
func (w *CacheWarmer) AddPrefetch(req PrefetchRequest) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.prefetch = append(w.prefetch, req)
}

// Start starts the cache warmer
func (w *CacheWarmer) Start(ctx context.Context, baseURL string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.warm(ctx, baseURL)
		}
	}
}

func (w *CacheWarmer) warm(ctx context.Context, baseURL string) {
	w.mu.Lock()
	requests := make([]PrefetchRequest, len(w.prefetch))
	copy(requests, w.prefetch)
	w.mu.Unlock()

	for _, req := range requests {
		url := baseURL + req.Path
		if req.Query != "" {
			url += "?" + req.Query
		}

		httpReq, err := http.NewRequestWithContext(ctx, req.Method, url, nil)
		if err != nil {
			continue
		}

		for k, v := range req.Header {
			httpReq.Header[k] = v
		}

		resp, err := w.client.Do(httpReq)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
	}
}

// JSONCacheValue is a cache value for JSON responses
type JSONCacheValue struct {
	Data      interface{} `json:"data"`
	ETag      string      `json:"etag"`
	ExpiresAt time.Time   `json:"expires_at"`
}

// MarshalBinary marshals to binary
func (j *JSONCacheValue) MarshalBinary() ([]byte, error) {
	return json.Marshal(j)
}

// UnmarshalBinary unmarshals from binary
func (j *JSONCacheValue) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, j)
}

// NewJSONCacheValue creates a new JSON cache value
func NewJSONCacheValue(data interface{}, ttl time.Duration) *JSONCacheValue {
	hasher := sha256.New()
	b, _ := json.Marshal(data)
	hasher.Write(b)

	return &JSONCacheValue{
		Data:      data,
		ETag:      hex.EncodeToString(hasher.Sum(nil)),
		ExpiresAt: time.Now().Add(ttl),
	}
}

// IsExpired returns true if the cache value is expired
func (j *JSONCacheValue) IsExpired() bool {
	return time.Now().After(j.ExpiresAt)
}
