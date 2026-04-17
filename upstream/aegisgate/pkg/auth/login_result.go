package auth

import "time"

// LoginResult represents the result of a login attempt
type LoginResult struct {
	Success   bool      `json:"success"`
	Token     string    `json:"token"`
	Error     string    `json:"error"`
	ExpiresAt time.Time `json:"expires_at"`
}
