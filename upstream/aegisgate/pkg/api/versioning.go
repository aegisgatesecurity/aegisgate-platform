// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package api

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// contextKey is a type for context values
type contextKey string

const (
	apiVersionKey  contextKey = "api_version"
	versionInfoKey contextKey = "version_info"
)

// Version represents an API version
type Version struct {
	Major       int
	Minor       int
	Label       string     // e.g., "beta", "alpha", "rc1"
	Deprecated  bool       // Version is deprecated
	Sunset      *time.Time // When version will be removed
	Unsupported bool       // Version is no longer supported
}

// String returns version string (e.g., "v1", "v2beta", "v1.2")
func (v *Version) String() string {
	str := fmt.Sprintf("v%d", v.Major)
	if v.Minor > 0 {
		str = fmt.Sprintf("v%d.%d", v.Major, v.Minor)
	}
	if v.Label != "" {
		str = fmt.Sprintf("v%d.%d-%s", v.Major, v.Minor, v.Label)
	}
	return str
}

// Compare compares two versions
// Returns: -1 if v < other, 0 if v == other, 1 if v > other
func (v *Version) Compare(other *Version) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}

	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}

	// Label precedence: alpha < beta < rc < (none/release) < (deprecated)
	precedence := map[string]int{
		"alpha": 0,
		"beta":  1,
		"rc":    2,
		"":      3,
	}

	vPrec := precedence[v.Label]
	otherPrec := precedence[other.Label]

	if vPrec != otherPrec {
		if vPrec < otherPrec {
			return -1
		}
		return 1
	}

	return 0
}

// IsSupported returns true if version is supported
func (v *Version) IsSupported() bool {
	return !v.Unsupported
}

// IsDeprecated returns true if version is deprecated but still supported
func (v *Version) IsDeprecated() bool {
	return v.Deprecated && !v.Unsupported
}

// ParseVersion parses a version string
func ParseVersion(s string) (*Version, error) {
	// Remove leading 'v' if present
	s = strings.TrimPrefix(s, "v")

	// Match version patterns: "1", "1.2", "1-beta", "2.0-rc1", "1.0-alpha"
	pattern := regexp.MustCompile(`^(\d+)(?:\.(\d+))?(?:-(\w+))?$`)
	matches := pattern.FindStringSubmatch(s)

	if matches == nil {
		return nil, fmt.Errorf("invalid version format: %s", s)
	}

	major, _ := strconv.Atoi(matches[1])
	minor := 0
	if matches[2] != "" {
		minor, _ = strconv.Atoi(matches[2])
	}

	return &Version{
		Major: major,
		Minor: minor,
		Label: matches[3],
	}, nil
}

// VersionManager manages API versions
type VersionManager struct {
	mu         sync.RWMutex
	versions   map[string]*Version
	deprecated map[string]string // deprecated -> replacement
	supported  []string          // sorted list of supported versions
	defaultVer string
}

// NewVersionManager creates a new version manager
func NewVersionManager() *VersionManager {
	return &VersionManager{
		versions:   make(map[string]*Version),
		deprecated: make(map[string]string),
		supported:  []string{},
	}
}

// RegisterVersion registers an API version
func (m *VersionManager) RegisterVersion(v *Version) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := v.String()
	m.versions[key] = v

	// Update supported list
	found := false
	for _, s := range m.supported {
		if s == key {
			found = true
			break
		}
	}
	if !found {
		m.supported = append(m.supported, key)
		m.sortVersions()
	}
}

// RegisterDeprecated marks a version as deprecated
func (m *VersionManager) RegisterDeprecated(deprecated, replacement string, sunset time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := "v" + deprecated
	if v, ok := m.versions[key]; ok {
		v.Deprecated = true
		v.Sunset = &sunset
	} else if strings.Contains(deprecated, ".") {
		// Try major-only version (e.g., "1.0" -> "1")
		majorVer := "v" + strings.Split(deprecated, ".")[0]
		if v, ok := m.versions[majorVer]; ok {
			v.Deprecated = true
			v.Sunset = &sunset
		}
	}
	m.deprecated[key] = replacement
}

// RegisterUnsupported marks a version as unsupported
func (m *VersionManager) RegisterUnsupported(version string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := "v" + version
	if v, ok := m.versions[key]; ok {
		v.Unsupported = true
	} else if strings.Contains(version, ".") {
		// Try major-only version (e.g., "1.0" -> "1")
		majorVer := "v" + strings.Split(version, ".")[0]
		if v, ok := m.versions[majorVer]; ok {
			v.Unsupported = true
		}
	}
}

// SetDefaultVersion sets the default version
func (m *VersionManager) SetDefaultVersion(version string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultVer = version
}

// GetVersion returns version info
func (m *VersionManager) GetVersion(version string) (*Version, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := "v" + version
	v, ok := m.versions[key]
	return v, ok
}

// GetSupportedVersions returns all supported versions
func (m *VersionManager) GetSupportedVersions() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, len(m.supported))
	copy(result, m.supported)
	return result
}

// GetDeprecationWarning returns deprecation info if version is deprecated
func (m *VersionManager) GetDeprecationWarning(version string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := "v" + version
	if replacement, ok := m.deprecated[key]; ok {
		return fmt.Sprintf("API version %s is deprecated. Please use %s.", version, replacement), true
	}
	return "", false
}

// GetDefaultVersion returns the default version
func (m *VersionManager) GetDefaultVersion() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultVer
}

func (m *VersionManager) sortVersions() {
	// Sort by version number (descending), with stable order
	m.supported = VersionList(m.supported).Sort()
}

// VersionList is a list of version strings
type VersionList []string

// Sort returns the sorted list of version strings.
// Sort returns the sorted list of version strings.
func (v VersionList) Sort() []string {
	versions := make([]*Version, len(v))
	for i, s := range v {
		ver, _ := ParseVersion(s)
		versions[i] = ver
	}

	// Sort descending
	for i := 0; i < len(versions)-1; i++ {
		for j := i + 1; j < len(versions); j++ {
			if versions[i].Compare(versions[j]) < 0 {
				versions[i], versions[j] = versions[j], versions[i]
			}
		}
	}

	result := make([]string, len(versions))
	for i, ver := range versions {
		result[i] = ver.String()
	}
	return result
}

// VersionNegotiator handles API version negotiation
type VersionNegotiator struct {
	manager     *VersionManager
	headerName  string // Default: "Accept-Version"
	queryParam  string // Default: "version"
	pathPattern string // URL pattern for version in path
}

// NewVersionNegotiator creates a new version negotiator
func NewVersionNegotiator(manager *VersionManager) *VersionNegotiator {
	return &VersionNegotiator{
		manager:     manager,
		headerName:  "Accept-Version",
		queryParam:  "version",
		pathPattern: "/v{version}/",
	}
}

// NegotiationResult contains the result of version negotiation
type NegotiationResult struct {
	Version         string
	VersionInfo     *Version
	ContentType     string // e.g., "application/vnd.aegisgate.v1+json"
	DeprecationInfo string
}

// Negotiate determines the best version from a request
func (n *VersionNegotiator) Negotiate(r *http.Request) *NegotiationResult {
	result := &NegotiationResult{}

	// Priority 1: Query parameter
	if qv := r.URL.Query().Get(n.queryParam); qv != "" {
		result.Version = "v" + qv
		// Try full version first, then try without minor version
		if v, ok := n.manager.GetVersion(qv); ok && v.IsSupported() {
			result.VersionInfo = v
			if msg, hasWarning := n.manager.GetDeprecationWarning(qv); hasWarning {
				result.DeprecationInfo = msg
			}
			return result
		}
		// Try without minor version (e.g., "1.0" -> "1")
		if strings.Contains(qv, ".") {
			shortVer := strings.Split(qv, ".")[0]
			if v, ok := n.manager.GetVersion(shortVer); ok && v.IsSupported() {
				result.Version = "v" + shortVer
				result.VersionInfo = v
				if msg, hasWarning := n.manager.GetDeprecationWarning(shortVer); hasWarning {
					result.DeprecationInfo = msg
				}
				return result
			}
		}
	}

	// Priority 2: Accept header (Accept-Version)
	if av := r.Header.Get(n.headerName); av != "" {
		result.Version = "v" + av
		if v, ok := n.manager.GetVersion(av); ok && v.IsSupported() {
			result.VersionInfo = v
			if msg, hasWarning := n.manager.GetDeprecationWarning(av); hasWarning {
				result.DeprecationInfo = msg
			}
			return result
		}
		// Try without minor version
		if strings.Contains(av, ".") {
			shortVer := strings.Split(av, ".")[0]
			if v, ok := n.manager.GetVersion(shortVer); ok && v.IsSupported() {
				result.Version = "v" + shortVer
				result.VersionInfo = v
				if msg, hasWarning := n.manager.GetDeprecationWarning(shortVer); hasWarning {
					result.DeprecationInfo = msg
				}
				return result
			}
		}
	}

	// Priority 3: Accept header with content negotiation
	// e.g., Accept: application/vnd.aegisgate.v1+json
	if accept := r.Header.Get("Accept"); accept != "" {
		if ct := n.parseContentType(accept); ct != "" {
			result.Version = ct
			// ct already has "v" prefix from parseContentType
			ver := strings.TrimPrefix(ct, "v")
			if v, ok := n.manager.GetVersion(ver); ok && v.IsSupported() {
				result.VersionInfo = v
				result.ContentType = accept
				if msg, hasWarning := n.manager.GetDeprecationWarning(ver); hasWarning {
					result.DeprecationInfo = msg
				}
				return result
			}
			// Try without minor version
			if strings.Contains(ver, ".") {
				shortVer := strings.Split(ver, ".")[0]
				if v, ok := n.manager.GetVersion(shortVer); ok && v.IsSupported() {
					result.Version = "v" + shortVer
					result.VersionInfo = v
					result.ContentType = accept
					if msg, hasWarning := n.manager.GetDeprecationWarning(shortVer); hasWarning {
						result.DeprecationInfo = msg
					}
					return result
				}
			}
		}
	}

	// Priority 4: URL path
	// e.g., /api/v1/users
	if pv := n.parseVersionFromPath(r.URL.Path); pv != "" {
		result.Version = "v" + pv
		if v, ok := n.manager.GetVersion(pv); ok && v.IsSupported() {
			result.VersionInfo = v
			if msg, hasWarning := n.manager.GetDeprecationWarning(pv); hasWarning {
				result.DeprecationInfo = msg
			}
			return result
		}
		// Try without minor version
		if strings.Contains(pv, ".") {
			shortVer := strings.Split(pv, ".")[0]
			if v, ok := n.manager.GetVersion(shortVer); ok && v.IsSupported() {
				result.Version = "v" + shortVer
				result.VersionInfo = v
				if msg, hasWarning := n.manager.GetDeprecationWarning(shortVer); hasWarning {
					result.DeprecationInfo = msg
				}
				return result
			}
		}
	}

	// Default: Use default version
	result.Version = n.manager.GetDefaultVersion()
	if result.Version == "" {
		result.Version = "v1"
	}
	result.VersionInfo, _ = n.manager.GetVersion(result.Version)

	return result
}

func (n *VersionNegotiator) parseContentType(accept string) string {
	// Parse: application/vnd.aegisgate.v1+json
	pattern := regexp.MustCompile(`application/vnd\.aegisgate\.v(\d+(?:\.\d+)?(?:-[\w]+)?)`)
	matches := pattern.FindStringSubmatch(accept)
	if matches != nil {
		return "v" + matches[1] // Return with "v" prefix
	}
	return ""
}

func (n *VersionNegotiator) parseVersionFromPath(path string) string {
	// Match: /api/v1/, /api/v2.0/, /api/v1.2-beta/
	pattern := regexp.MustCompile(`/api/v(\d+(?:\.\d+)?(?:-[\w]+)?)/`)
	matches := pattern.FindStringSubmatch(path)
	if matches != nil {
		return matches[1]
	}
	return ""
}

// VersionMiddleware creates middleware for version handling
func VersionMiddleware(manager *VersionManager) func(http.Handler) http.Handler {
	negotiator := NewVersionNegotiator(manager)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result := negotiator.Negotiate(r)

			// Add deprecation header if deprecated
			if result.DeprecationInfo != "" && result.VersionInfo != nil && result.VersionInfo.IsDeprecated() {
				w.Header().Set("Deprecation", "true")
				w.Header().Set("Sunset", result.VersionInfo.Sunset.Format(http.TimeFormat))
				w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"successor-version\"",
					strings.Replace(r.URL.Path, result.Version, "v2", 1)))
			}

			// Add version to request context
			ctx := context.WithValue(r.Context(), apiVersionKey, result.Version)
			ctx = context.WithValue(ctx, versionInfoKey, result.VersionInfo)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// VersionHandler routes requests to version-specific handlers
type VersionHandler struct {
	mu       sync.RWMutex
	handlers map[string]http.Handler // version -> handler
	manager  *VersionManager
	notFound http.Handler
}

// NewVersionHandler creates a new version handler router
func NewVersionHandler(manager *VersionManager) *VersionHandler {
	return &VersionHandler{
		handlers: make(map[string]http.Handler),
		manager:  manager,
	}
}

// RegisterHandler registers a handler for a specific version
func (vh *VersionHandler) RegisterHandler(version string, handler http.Handler) {
	vh.mu.Lock()
	defer vh.mu.Unlock()
	// version should already include "v" prefix (e.g., "v1", "v2")
	vh.handlers[version] = handler
}

// SetNotFound sets the handler for unmatched versions
func (vh *VersionHandler) SetNotFound(handler http.Handler) {
	vh.mu.Lock()
	defer vh.mu.Unlock()
	vh.notFound = handler
}

// ServeHTTP routes to the appropriate version handler
func (vh *VersionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	result := NewVersionNegotiator(vh.manager).Negotiate(r)

	vh.mu.RLock()
	handler, ok := vh.handlers[result.Version]
	// If not found, try major-only version (e.g., "v1.0" -> "v1")
	if !ok && strings.Contains(result.Version, ".") {
		majorVer := "v" + strings.Split(strings.TrimPrefix(result.Version, "v"), ".")[0]
		handler, ok = vh.handlers[majorVer]
	}
	vh.mu.RUnlock()

	if !ok {
		if vh.notFound != nil {
			vh.notFound.ServeHTTP(w, r)
			return
		}
		http.Error(w, "API version not supported", http.StatusNotAcceptable)
		return
	}

	handler.ServeHTTP(w, r)
}

// VersionedRouter is a router that supports versioned routes
type VersionedRouter struct {
	mu         sync.RWMutex
	routes     map[string]map[string]http.Handler // version -> method -> handler
	manager    *VersionManager
	middleware []func(http.Handler) http.Handler
}

// NewVersionedRouter creates a new versioned router
func NewVersionedRouter(manager *VersionManager) *VersionedRouter {
	return &VersionedRouter{
		routes:     make(map[string]map[string]http.Handler),
		manager:    manager,
		middleware: []func(http.Handler) http.Handler{},
	}
}

// AddRoute adds a route for a specific version
func (vr *VersionedRouter) AddRoute(version, method, path string, handler http.Handler) {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	// version should already include "v" prefix (e.g., "v1", "v2")
	key := version
	if vr.routes[key] == nil {
		vr.routes[key] = make(map[string]http.Handler)
	}
	vr.routes[key][method+" "+path] = handler
}

// Use adds middleware to all routes
func (vr *VersionedRouter) Use(middleware func(http.Handler) http.Handler) {
	vr.mu.Lock()
	defer vr.mu.Unlock()
	vr.middleware = append(vr.middleware, middleware)
}

// Handler returns a handler for the router
func (vr *VersionedRouter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := NewVersionNegotiator(vr.manager).Negotiate(r)

		vr.mu.RLock()
		versionRoutes := vr.routes[result.Version]
		// If not found, try major-only version (e.g., "v1.0" -> "v1")
		if versionRoutes == nil && strings.Contains(result.Version, ".") {
			majorVer := "v" + strings.Split(strings.TrimPrefix(result.Version, "v"), ".")[0]
			versionRoutes = vr.routes[majorVer]
		}
		vr.mu.RUnlock()

		if versionRoutes == nil {
			http.Error(w, "API version not supported", http.StatusNotAcceptable)
			return
		}

		key := r.Method + " " + r.URL.Path
		handler, ok := versionRoutes[key]

		if !ok {
			// Try matching without query params
			for routeKey, h := range versionRoutes {
				if strings.HasPrefix(key, routeKey) {
					handler = h
					ok = true
					break
				}
			}
		}

		if !ok {
			http.Error(w, "Route not found", http.StatusNotFound)
			return
		}

		// Apply middleware
		for _, m := range vr.middleware {
			handler = m(handler)
		}

		handler.ServeHTTP(w, r)
	})
}

// DefaultVersionManager creates a default version manager with standard versions
func DefaultVersionManager() *VersionManager {
	manager := NewVersionManager()

	// Register supported versions
	manager.RegisterVersion(&Version{Major: 1, Minor: 0})
	manager.RegisterVersion(&Version{Major: 1, Minor: 1})
	manager.RegisterVersion(&Version{Major: 2, Minor: 0})
	manager.RegisterVersion(&Version{Major: 2, Minor: 1, Label: "beta"})
	manager.RegisterVersion(&Version{Major: 3, Minor: 0, Label: "alpha"})

	// Mark v1.0 as deprecated
	sunset := time.Now().Add(6 * 30 * 24 * time.Hour) // 6 months
	manager.RegisterDeprecated("1.0", "v2", sunset)

	// Mark v1.1 as deprecated
	manager.RegisterDeprecated("1.1", "v2", sunset)

	// Mark v1.x as unsupported
	manager.RegisterUnsupported("1")

	// Set default
	manager.SetDefaultVersion("v2")

	return manager
}
