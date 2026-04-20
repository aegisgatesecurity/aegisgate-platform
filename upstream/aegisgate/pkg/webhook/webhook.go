// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package webhook

import "time"

// Webhook represents a webhook configuration
type Webhook struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	URL         string             `json:"url"`
	Method      string             `json:"method"`
	Enabled     bool               `json:"enabled"`
	Auth        Authentication     `json:"auth"`
	TLS         TLSConfig          `json:"tls"`
	Triggers    []TriggerCondition `json:"triggers"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

// GetID returns the webhook ID
func (w *Webhook) GetID() string {
	return w.ID
}

// GetName returns the webhook name
func (w *Webhook) GetName() string {
	return w.Name
}

// GetURL returns the webhook URL
func (w *Webhook) GetURL() string {
	return w.URL
}

// IsEnabled returns whether the webhook is enabled
func (w *Webhook) IsEnabled() bool {
	return w.Enabled
}
