package sso

import (
	"net/http"
	"strings"
)

// Middleware provides SSO authentication middleware
type Middleware struct {
	manager    *Manager
	cookieName string
	cookieOpts CookieOptions
}

// CookieOptions holds cookie configuration
type CookieOptions struct {
	Secure   bool
	HTTPOnly bool
	SameSite string
	Path     string
	Domain   string
	MaxAge   int
}

// DefaultCookieOptions returns default cookie options
func DefaultCookieOptions() CookieOptions {
	return CookieOptions{
		Secure:   true,
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
	}
}

// NewMiddleware creates a new SSO middleware
func NewMiddleware(manager *Manager, opts *CookieOptions) *Middleware {
	options := DefaultCookieOptions()
	if opts != nil {
		options = *opts
	}

	return &Middleware{
		manager:    manager,
		cookieName: "sso_session",
		cookieOpts: options,
	}
}

// RequireSession middleware requires a valid SSO session
func (m *Middleware) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := m.getSessionFromRequest(r)
		if err != nil {
			m.handleUnauthorized(w, r, err)
			return
		}

		// Validate session
		validatedSession, err := m.manager.ValidateSession(session.ID)
		if err != nil {
			m.clearSessionCookie(w)
			m.handleUnauthorized(w, r, err)
			return
		}

		// Add session and user to context
		ctx := ContextWithSession(r.Context(), validatedSession)
		if validatedSession.User != nil {
			ctx = ContextWithUser(ctx, validatedSession.User)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalSession middleware adds session info if available but doesn't require it
func (m *Middleware) OptionalSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := m.getSessionFromRequest(r)
		if err == nil {
			// Try to validate session
			validatedSession, validateErr := m.manager.ValidateSession(session.ID)
			if validateErr == nil {
				ctx := ContextWithSession(r.Context(), validatedSession)
				if validatedSession.User != nil {
					ctx = ContextWithUser(ctx, validatedSession.User)
				}
				r = r.WithContext(ctx)
			}
		}

		next.ServeHTTP(w, r)
	})
}

// RequireRole middleware requires a specific role
func (m *Middleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				m.handleUnauthorized(w, r, NewSSOError(ErrInvalidToken, "no user in context"))
				return
			}

			if !user.RoleAtLeast(role) {
				m.handleForbidden(w, r, NewSSOError(ErrUserNotAllowed, "insufficient role"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole middleware requires any of the specified roles
func (m *Middleware) RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				m.handleUnauthorized(w, r, NewSSOError(ErrInvalidToken, "no user in context"))
				return
			}

			hasRole := false
			for _, role := range roles {
				if user.RoleAtLeast(role) {
					hasRole = true
					break
				}
			}

			if !hasRole {
				m.handleForbidden(w, r, NewSSOError(ErrUserNotAllowed, "insufficient role"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireDomain middleware requires the user to be from a specific domain
func (m *Middleware) RequireDomain(domains ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				m.handleUnauthorized(w, r, NewSSOError(ErrInvalidToken, "no user in context"))
				return
			}

			email := user.Email
			if email == "" {
				m.handleForbidden(w, r, NewSSOError(ErrDomainNotAllowed, "no email in user"))
				return
			}

			allowed := false
			for _, domain := range domains {
				if domainMatches(email, domain) {
					allowed = true
					break
				}
			}

			if !allowed {
				m.handleForbidden(w, r, NewSSOError(ErrDomainNotAllowed, "domain not allowed"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireGroup middleware requires the user to be in a specific group
func (m *Middleware) RequireGroup(groups ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				m.handleUnauthorized(w, r, NewSSOError(ErrInvalidToken, "no user in context"))
				return
			}

			inGroup := false
			for _, group := range user.Groups {
				for _, required := range groups {
					if group == required {
						inGroup = true
						break
					}
				}
				if inGroup {
					break
				}
			}

			if !inGroup {
				m.handleForbidden(w, r, NewSSOError(ErrUserNotAllowed, "not in required group"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// LoginHandler returns a handler that initiates SSO login
func (m *Middleware) LoginHandler(providerName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginURL, _, err := m.manager.InitiateLogin(providerName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
	})
}

// CallbackHandler returns a handler for SSO callbacks
func (m *Middleware) CallbackHandler(providerName string, onSuccess, onFailure string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := make(map[string]string)
		for key, values := range r.URL.Query() {
			if len(values) > 0 {
				params[key] = values[0]
			}
		}

		response, err := m.manager.HandleCallback(providerName, params)
		if err != nil {
			if onFailure != "" {
				http.Redirect(w, r, onFailure+"?error="+err.Error(), http.StatusTemporaryRedirect)
			} else {
				http.Error(w, err.Error(), http.StatusUnauthorized)
			}
			return
		}

		// Set session cookie
		if response.Session != nil {
			m.setSessionCookie(w, response.Session.ID)
		}

		if onSuccess != "" {
			http.Redirect(w, r, onSuccess, http.StatusTemporaryRedirect)
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Authentication successful"))
		}
	})
}

// LogoutHandler returns a handler for SSO logout
func (m *Middleware) LogoutHandler(redirectURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := SessionFromContext(r.Context())
		if session == nil {
			// Try to get session from cookie
			cookie, err := r.Cookie(m.cookieName)
			if err == nil && cookie.Value != "" {
				session, _ = m.manager.GetSession(cookie.Value)
			}
		}

		// Clear session cookie
		m.clearSessionCookie(w)

		var logoutURL string
		if session != nil {
			logoutURL, _ = m.manager.Logout(session.ID)
		}

		// If provider has a logout URL, redirect there
		if logoutURL != "" {
			http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
			return
		}

		// Otherwise redirect to the specified URL
		if redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Logged out successfully"))
		}
	})
}

// MetadataHandler returns SAML metadata for a provider
func (m *Middleware) MetadataHandler(providerName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata, err := m.manager.GetProviderMetadata(providerName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(metadata)
	})
}

// getSessionFromRequest extracts the session from a request
func (m *Middleware) getSessionFromRequest(r *http.Request) (*SSOSession, error) {
	// Try cookie first
	cookie, err := r.Cookie(m.cookieName)
	if err == nil && cookie.Value != "" {
		session, err := m.manager.GetSession(cookie.Value)
		if err == nil {
			return session, nil
		}
	}

	// Try Authorization header
	auth := r.Header.Get("Authorization")
	if auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			session, err := m.manager.GetSession(token)
			if err == nil {
				return session, nil
			}
		}
	}

	return nil, NewSSOError(ErrSessionExpired, "no session found")
}

// setSessionCookie sets the session cookie
func (m *Middleware) setSessionCookie(w http.ResponseWriter, sessionID string) {
	cookie := &http.Cookie{
		Name:     m.cookieName,
		Value:    sessionID,
		Path:     m.cookieOpts.Path,
		Domain:   m.cookieOpts.Domain,
		MaxAge:   m.cookieOpts.MaxAge,
		Secure:   m.cookieOpts.Secure,
		HttpOnly: m.cookieOpts.HTTPOnly,
	}

	// Enforce Secure and HttpOnly in production to prevent session hijacking
	if !cookie.Secure {
		cookie.Secure = true
	}
	if !cookie.HttpOnly {
		cookie.HttpOnly = true
	}

	switch m.cookieOpts.SameSite {
	case "Strict":
		cookie.SameSite = http.SameSiteStrictMode
	case "Lax":
		cookie.SameSite = http.SameSiteLaxMode
	case "None":
		cookie.SameSite = http.SameSiteNoneMode
	default:
		cookie.SameSite = http.SameSiteStrictMode
	}

	http.SetCookie(w, cookie)
}

// clearSessionCookie clears the session cookie
func (m *Middleware) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{ // #nosec G124 -- Secure and HttpOnly enforced below
		Name:     m.cookieName,
		Value:    "",
		Path:     m.cookieOpts.Path,
		Domain:   m.cookieOpts.Domain,
		MaxAge:   -1,
		Secure:   m.cookieOpts.Secure,
		HttpOnly: m.cookieOpts.HTTPOnly,
	}

	// Enforce Secure and HttpOnly in production to prevent session hijacking
	if !cookie.Secure {
		cookie.Secure = true
	}
	if !cookie.HttpOnly {
		cookie.HttpOnly = true
	}

	http.SetCookie(w, cookie)
}

// handleUnauthorized handles unauthorized requests
func (m *Middleware) handleUnauthorized(w http.ResponseWriter, r *http.Request, err error) {
	// Check if it's an API request
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if _, writeErr := w.Write([]byte(`{"error":"unauthorized","message":"` + err.Error() + `"}`)); writeErr != nil {
			_ = writeErr
		}
		return
	}

	// Redirect to login page for web requests
	http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
}

// handleForbidden handles forbidden requests
func (m *Middleware) handleForbidden(w http.ResponseWriter, r *http.Request, err error) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if _, writeErr := w.Write([]byte(`{"error":"forbidden","message":"` + err.Error() + `"}`)); writeErr != nil {
			_ = writeErr
		}
		return
	}

	http.Error(w, "Forbidden", http.StatusForbidden)
}
