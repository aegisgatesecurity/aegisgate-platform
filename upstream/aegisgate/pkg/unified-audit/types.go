package unifiedaudit

import "time"

// AuditEvent represents a unified audit event.
type AuditEvent struct {
	EventID       string         `json:"event_id"`
	Timestamp     time.Time      `json:"timestamp"`
	Source        string         `json:"source"` // "aegisguard" or "aegisgate"
	Action        string         `json:"action"`
	UserID        string         `json:"user_id,omitempty"`
	GDPRMetadata  *GDPRMetadata  `json:"gdpr_metadata,omitempty"`
	HIPAAMetadata *HIPAAMetadata `json:"hipaa_metadata,omitempty"`
}

// GDPRMetadata contains GDPR-specific audit metadata.
type GDPRMetadata struct {
	DataSubjectRight string `json:"data_subject_right,omitempty"`
	LawfulBasis      string `json:"lawful_basis,omitempty"`
	ConsentID        string `json:"consent_id,omitempty"`
}

// HIPAAMetadata contains HIPAA-specific audit metadata.
type HIPAAMetadata struct {
	PHIType       string `json:"phi_type,omitempty"`
	AccessPurpose string `json:"access_purpose,omitempty"`
	PatientID     string `json:"patient_id,omitempty"`
}
