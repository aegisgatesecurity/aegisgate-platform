// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateSessionID() string {
	return "sess_" + generateRandomString(32)
}

func generateUserID(providerID string, provider Provider) string {
	hash := sha256.Sum256([]byte(providerID + string(provider)))
	return "user_" + hex.EncodeToString(hash[:16])
}

func generatePKCEVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func generatePKCEChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (m *Manager) setSessionCookie(w http.ResponseWriter, session *Session) {
	cookie := &http.Cookie{
		Name:     m.config.CookieName,
		Value:    session.ID,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: m.config.CookieHTTPOnly,
		Secure:   m.config.CookieSecure,
		SameSite: m.config.CookieSameSite,
	}
	http.SetCookie(w, cookie)
}

func (m *Manager) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     m.config.CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: m.config.CookieHTTPOnly,
		Secure:   m.config.CookieSecure,
		SameSite: m.config.CookieSameSite,
	}
	http.SetCookie(w, cookie)
}

func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[1]
	}
	return ""
}

func validateEmail(email string) bool {
	pattern := regexp.MustCompile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+[.][a-zA-Z]{2,}$")
	return pattern.MatchString(email)
}

func hashPassword(password, salt string) string {
	hash := sha256.Sum256([]byte(password + salt))
	return hex.EncodeToString(hash[:])
}

func constantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
