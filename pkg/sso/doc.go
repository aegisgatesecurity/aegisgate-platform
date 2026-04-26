// SPDX-License-Identifier: Apache-2.0

// Package sso provides Single Sign-On (SSO) support for the AegisGate Security Platform,
// including OIDC (OpenID Connect) and SAML 2.0 authentication providers.
//
// # Overview
//
// This package implements enterprise-grade SSO capabilities that integrate with
// the platform's tier-based licensing system. SSO is available on Developer tier
// and above.
//
// # Supported Protocols
//
//   - OIDC (OpenID Connect): Modern OAuth 2.0 based authentication
//   - SAML 2.0: Enterprise SSO with XML-based assertions
//
// # Usage
//
// Register a provider and use the SSO endpoints:
//
//	mgr := sso.NewManager(&sso.ManagerConfig{
//	    SessionStore: stores.NewMemorySessionStore(),
//	    RequestStore: stores.NewMemoryRequestStore(),
//	})
//
//	// Register OIDC provider
//	oidc, _ := sso.NewOIDCProvider(sso.OIDCConfig{
//	    ClientID:     "client-id",
//	    ClientSecret: "client-secret",
//	    IssuerURL:    "https://idp.example.com",
//	    RedirectURL:  "https://aegisgate.example.com/auth/callback",
//	})
//	mgr.RegisterProvider("oidc", oidc)
//
// # Lab Environment
//
// For testing, use the Docker-based lab environment:
//
//	cd testlab && docker-compose up -d
//
// Run integration tests with:
//
//	LAB_ENABLED=1 go test -tags=lab ./pkg/sso/...
//
// # Architecture
//
//   - Provider implementations: oidc.go, saml.go
//   - Session/request management: manager.go, stores/
//   - HTTP middleware: middleware.go
//   - Mock servers for testing: *mock_server.go
//   - Integration tests: sso_lab_test.go, sso_integration_test.go
package sso
