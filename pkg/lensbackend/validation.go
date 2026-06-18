// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - Event Validation
// =========================================================================
//
// validation.go defines the Event struct that the Lens extension
// sends to the backend, the Category / Severity / UserAction
// enums, and the Validate method that enforces the §1.1 schema
// from plans/AEGISGATE-LENS-PRIVACY-POLICY-DRAFT.md.
//
// The schema is locked. Any change to the field set, the field
// names, the field types, or the enum values is a breaking change
// to the Lens protocol and requires a major version bump of the
// backend (and a coordinated update of the Lens extension).
//
// The 9 fields the backend accepts (and only these 9):
//
//   1.  domain_hash      string  16 hex chars (SHA-256 prefix)
//   2.  category         string  one of the Category constants
//   3.  severity         string  one of the Severity constants
//   4.  user_action      string  one of the UserAction constants
//   5.  timestamp        int64   unix seconds, must be within ±24h
//   6.  model_version    string  Lens version + classifier version
//                                (e.g., "0.1.0+regex-v1")
//   7.  lens_version     string  Lens version (e.g., "0.1.0")
//   8.  confidence       float   0.0..1.0
//   9.  id               string  optional client-side UUID for
//                                client-side dedup; not stored
//
// Any other field in the JSON body is rejected. This is enforced
// by RejectUnknownFields in handlers.go when the request is
// decoded.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package lensbackend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Category is the sensitive-data category that the Lens detected.
// See plans/AEGISGATE-LENS-ARCHITECTURE-v1.md §3.2 (the 7 categories
// of regex patterns). The constants below are the wire format: any
// new category requires a backend code change AND an extension code
// change AND a privacy policy disclosure.
type Category string

const (
	// CategoryPIIEmail: email address detected in prompt.
	CategoryPIIEmail Category = "pii_email"
	// CategoryPIIPhone: phone number detected in prompt.
	CategoryPIIPhone Category = "pii_phone"
	// CategoryPIISSN: US Social Security Number detected in prompt.
	CategoryPIISSN Category = "pii_ssn"
	// CategoryPIICreditCard: credit card number (Luhn-valid) detected in prompt.
	CategoryPIICreditCard Category = "pii_credit_card"
	// CategorySecretAPIKey: API key or token (AWS, GitHub, Stripe, etc.) detected.
	CategorySecretAPIKey Category = "secret_api_key"
	// CategorySourceCode: code that looks like a private key, signing key, or
	// similar high-value source artifact.
	CategorySourceCode Category = "source_code"
)

// AllCategories is the closed set of valid categories. Used for
// validation in Validate().
var AllCategories = []Category{
	CategoryPIIEmail,
	CategoryPIIPhone,
	CategoryPIISSN,
	CategoryPIICreditCard,
	CategorySecretAPIKey,
	CategorySourceCode,
}

// Severity is the severity of the detection. Reuses the same
// vocabulary as pkg/ioc.Severity and pkg/logging.Severity so that
// downstream IOCs are compatible.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// UserAction is what the user did in response to the Lens's warning.
type UserAction string

const (
	// UserActionSendAnyway: user dismissed the warning and sent the
	// prompt anyway. This is the most operationally interesting
	// event — it means the user knowingly shared sensitive data.
	UserActionSendAnyway UserAction = "send_anyway"
	// UserActionEdit: user edited the prompt to remove the sensitive
	// data before sending.
	UserActionEdit UserAction = "edit"
	// UserActionCancel: user cancelled the prompt entirely.
	UserActionCancel UserAction = "cancel"
	// UserActionDismiss: user dismissed the warning but did not
	// send the prompt during the session we observed (the prompt
	// might have been sent later without the Lens running, or
	// the session ended).
	UserActionDismiss UserAction = "dismiss"
)

// AllUserActions is the closed set of valid user actions.
var AllUserActions = []UserAction{
	UserActionSendAnyway,
	UserActionEdit,
	UserActionCancel,
	UserActionDismiss,
}

// Event is the §1.1 schema. The struct tags are the wire format.
// The Validate method enforces all field-level constraints. The
// backend's JSON decoder uses RejectUnknownFields so any extra
// fields in the request body are rejected.
type Event struct {
	// DomainHash is the 16-hex-character SHA-256 prefix of the
	// AI provider's hostname. Computed locally by the extension.
	// The backend re-computes the SHA-256 of the TLS SNI in the
	// inbound request and rejects any event whose DomainHash
	// does not match. See domain_hash.go.
	DomainHash string `json:"domain_hash"`

	// Category is the sensitive-data category that was detected.
	Category string `json:"category"`

	// Severity is the severity of the detection.
	Severity string `json:"severity"`

	// UserAction is what the user did in response to the warning.
	UserAction string `json:"user_action"`

	// Timestamp is the unix-second timestamp of the detection,
	// stamped by the extension at detection time (not by the
	// backend at receive time). Must be within ±24 hours of
	// the backend's wall clock; otherwise rejected.
	Timestamp int64 `json:"timestamp"`

	// ModelVersion identifies the classifier that made the
	// detection. Format: "<lens_version>+<classifier>-<rev>".
	// Example: "0.1.0+regex-v1".
	ModelVersion string `json:"model_version"`

	// LensVersion is the version of the Lens extension that
	// produced the event. Format: semver.
	LensVersion string `json:"lens_version"`

	// Confidence is the classifier's confidence in the detection,
	// 0.0..1.0. Currently always 1.0 for the regex detector
	// (regex matches are deterministic); the field exists for
	// forward compatibility with v0.2's ML classifier.
	Confidence float64 `json:"confidence"`

	// ID is an optional client-side UUID for client-side dedup.
	// The backend does NOT store this — it exists so the
	// extension can suppress duplicate events from the same
	// detection (e.g., the same prompt being edited and re-sent).
	// The backend accepts and ignores it.
	ID string `json:"id,omitempty"`
}

// ErrInvalidEvent is returned by Validate for any field-level
// validation failure. The error message is safe to log and to
// return to the client (it contains no PII, just a description
// of which field failed).
var ErrInvalidEvent = errors.New("invalid event")

// Validate enforces the §1.1 schema. It is called by the handler
// immediately after JSON decoding.
//
// The validation is intentionally strict: any field that does not
// match its constraint causes the entire event to be rejected with
// HTTP 400. This is a privacy feature, not just a correctness
// feature: if the extension ever sends a field we don't expect
// (e.g., a future bug sends a URL or a content hash), we reject
// it rather than silently accepting and potentially storing it.
//
// The list of checks:
//
//  1. domain_hash is exactly 16 lowercase hex characters
//  2. category is in AllCategories
//  3. severity is in {info, low, medium, high, critical}
//  4. user_action is in AllUserActions
//  5. timestamp is within ±24 hours of backend wall clock
//  6. model_version is non-empty and contains a "+"
//  7. lens_version is non-empty
//  8. confidence is in [0.0, 1.0]
func (e *Event) Validate() error {
	if len(e.DomainHash) != 16 {
		return fmt.Errorf("%w: domain_hash must be 16 hex chars, got %d", ErrInvalidEvent, len(e.DomainHash))
	}
	for _, c := range e.DomainHash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("%w: domain_hash must be lowercase hex", ErrInvalidEvent)
		}
	}

	if !isValidCategory(e.Category) {
		return fmt.Errorf("%w: category %q not in %v", ErrInvalidEvent, e.Category, AllCategories)
	}
	if !isValidSeverity(e.Severity) {
		return fmt.Errorf("%w: severity %q not in {info, low, medium, high, critical}", ErrInvalidEvent, e.Severity)
	}
	if !isValidUserAction(e.UserAction) {
		return fmt.Errorf("%w: user_action %q not in %v", ErrInvalidEvent, e.UserAction, AllUserActions)
	}

	now := time.Now().Unix()
	if e.Timestamp <= 0 {
		return fmt.Errorf("%w: timestamp must be positive", ErrInvalidEvent)
	}
	delta := e.Timestamp - now
	if delta < -24*3600 || delta > 24*3600 {
		return fmt.Errorf("%w: timestamp must be within ±24h of server clock", ErrInvalidEvent)
	}

	if e.ModelVersion == "" {
		return fmt.Errorf("%w: model_version must be non-empty", ErrInvalidEvent)
	}
	if !containsPlus(e.ModelVersion) {
		return fmt.Errorf("%w: model_version must contain '+' (e.g., '0.1.0+regex-v1')", ErrInvalidEvent)
	}
	if e.LensVersion == "" {
		return fmt.Errorf("%w: lens_version must be non-empty", ErrInvalidEvent)
	}
	if e.Confidence < 0.0 || e.Confidence > 1.0 {
		return fmt.Errorf("%w: confidence must be in [0.0, 1.0], got %f", ErrInvalidEvent, e.Confidence)
	}
	return nil
}

// isValidCategory returns true if c is one of the AllCategories.
func isValidCategory(c string) bool {
	for _, v := range AllCategories {
		if string(v) == c {
			return true
		}
	}
	return false
}

// isValidSeverity returns true if s is one of the Severity constants.
func isValidSeverity(s string) bool {
	switch Severity(s) {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// isValidUserAction returns true if u is one of the AllUserActions.
func isValidUserAction(u string) bool {
	for _, v := range AllUserActions {
		if string(v) == u {
			return true
		}
	}
	return false
}

// containsPlus returns true if s contains a '+' character.
// Hand-rolled to avoid importing strings just for one character.
func containsPlus(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '+' {
			return true
		}
	}
	return false
}

// decodeEvent decodes a JSON body into an Event, rejecting any
// unknown fields. This is the first line of defense against the
// extension ever sending a field we don't know about.
func decodeEvent(body []byte) (Event, error) {
	var e Event
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, fmt.Errorf("decode: %w", err)
	}
	return e, nil
}
