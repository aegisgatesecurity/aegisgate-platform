// Package sandbox provides feed-level sandboxing capabilities
package sandbox

import (
	"time"
)

// SandboxID represents a unique sandbox identifier
type SandboxID string

// SandboxStatus represents the current status of a sandbox
type SandboxStatus string

const (
	SandboxStatusCreated   SandboxStatus = "created"
	SandboxStatusRunning   SandboxStatus = "running"
	SandboxStatusPaused    SandboxStatus = "paused"
	SandboxStatusStopped   SandboxStatus = "stopped"
	SandboxStatusErrored   SandboxStatus = "errored"
	SandboxStatusDestroyed SandboxStatus = "destroyed"
)

// ResourceQuota defines resource limits for a sandbox
type ResourceQuota struct {
	CPU      int64   `json:"cpu" yaml:"cpu"`                     // MilliCPU units
	Memory   int64   `json:"memory" yaml:"memory"`               // Bytes
	Disk     int64   `json:"disk" yaml:"disk"`                   // Bytes
	Network  int64   `json:"network" yaml:"network"`             // Bytes per second
	Files    int64   `json:"files" yaml:"files"`                 // Maximum files
	Process  int64   `json:"process" yaml:"process"`             // Maximum processes
	Duration *string `json:"duration" yaml:"duration,omitempty"` // Max duration
}

// SandboxPolicy defines configuration for a sandbox
type SandboxPolicy struct {
	ID             SandboxID       `json:"id" yaml:"id"`
	FeedID         string          `json:"feed_id" yaml:"feed_id"`
	Status         SandboxStatus   `json:"status" yaml:"status"`
	ResourceQuota  ResourceQuota   `json:"resource_quota" yaml:"resource_quota"`
	IsolationLevel IsolationLevel  `json:"isolation_level" yaml:"isolation_level"`
	SecurityPolicy *SecurityPolicy `json:"security_policy,omitempty" yaml:"security_policy,omitempty"`
	AuditLogging   bool            `json:"audit_logging" yaml:"audit_logging"`
	CreatedAt      time.Time       `json:"created_at" yaml:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at" yaml:"updated_at"`
}

// IsolationLevel defines the level of isolation for a sandbox
type IsolationLevel string

const (
	IsolationNone    IsolationLevel = "none"
	IsolationPartial IsolationLevel = "partial"
	IsolationFull    IsolationLevel = "full"
)

// SecurityPolicy defines security boundaries for a sandbox
type SecurityPolicy struct {
	NetworkIsolation bool     `json:"network_isolation" yaml:"network_isolation"`
	FileAccess       []string `json:"file_access" yaml:"file_access"`
	NetworkAccess    []string `json:"network_access" yaml:"network_access"`
	ProcessAccess    []string `json:"process_access" yaml:"process_access"`
	ResourceLimits   bool     `json:"resource_limits" yaml:"resource_limits"`
}

// SandboxInfo contains runtime information about a sandbox
type SandboxInfo struct {
	ID        SandboxID     `json:"id" yaml:"id"`
	Status    SandboxStatus `json:"status" yaml:"status"`
	PID       int           `json:"pid" yaml:"pid,omitempty"`
	StartedAt time.Time     `json:"started_at" yaml:"started_at,omitempty"`
	Resources ResourceUsage `json:"resources" yaml:"resources"`
	Uptime    time.Duration `json:"uptime" yaml:"uptime,omitempty"`
}

// ResourceUsage tracks current resource usage
type ResourceUsage struct {
	CPU     int64 `json:"cpu" yaml:"cpu"`
	Memory  int64 `json:"memory" yaml:"memory"`
	Disk    int64 `json:"disk" yaml:"disk"`
	Network int64 `json:"network" yaml:"network"`
	Files   int64 `json:"files" yaml:"files"`
	Process int64 `json:"process" yaml:"process"`
}
