// Package sandbox provides feed-level sandboxing capabilities
package sandbox

// ContainerSystem represents the container backend
type ContainerSystem interface {
	// Create creates a new container
	Create(config *ContainerConfig) (Container, error)

	// Start starts a container
	Start(containerID string) error

	// Stop stops a container
	Stop(containerID string) error

	// Destroy destroys a container
	Destroy(containerID string) error

	// Pause pauses a container
	Pause(containerID string) error

	// Resume resumes a container
	Resume(containerID string) error

	// Exec executes a command in a container
	Exec(containerID string, cmd []string) ([]byte, error)

	// Stats returns container statistics
	Stats(containerID string) (*ContainerStats, error)

	// List lists all containers
	List() ([]ContainerInfo, error)
}

// Container represents an active container
type Container interface {
	ID() string
	Start() error
	Stop() error
	Destroy() error
	Exec(cmd []string) ([]byte, error)
	Stats() (*ContainerStats, error)
}

// ContainerConfig configuration for a container
type ContainerConfig struct {
	SandboxID    SandboxID         `json:"sandbox_id" yaml:"sandbox_id"`
	FeedID       string            `json:"feed_id" yaml:"feed_id"`
	Image        string            `json:"image" yaml:"image"`
	Command      []string          `json:"command" yaml:"command"`
	Environment  map[string]string `json:"environment" yaml:"environment"`
	Volumes      []string          `json:"volumes" yaml:"volumes"`
	NetworkMode  string            `json:"network_mode" yaml:"network_mode"`
	Resources    ResourceQuota     `json:"resources" yaml:"resources"`
	SecurityOpts []string          `json:"security_opts" yaml:"security_opts"`
}

// ContainerStats container resource statistics
type ContainerStats struct {
	CPU     float64 `json:"cpu" yaml:"cpu"`
	Memory  int64   `json:"memory" yaml:"memory"`
	Network int64   `json:"network" yaml:"network"`
	Disk    int64   `json:"disk" yaml:"disk"`
}

// ContainerInfo container information
type ContainerInfo struct {
	ID        string `json:"id" yaml:"id"`
	SandboxID string `json:"sandbox_id" yaml:"sandbox_id"`
	Status    string `json:"status" yaml:"status"`
}
