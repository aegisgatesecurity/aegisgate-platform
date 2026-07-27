package tls

// TLSConfig represents TLS configuration for gRPC service
type TLSConfig struct {
	Enabled      bool   `json:"enabled"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	AutoGenerate bool   `json:"auto_generate"`
	MinVersion   string `json:"min_version"`
}

// GetConfig returns the TLS configuration
func (m *Manager) GetConfig() *TLSConfig {
	return &TLSConfig{
		Enabled:      m.certFile != "",
		CertFile:     m.certFile,
		KeyFile:      m.keyFile,
		AutoGenerate: m.autoGenerate,
		MinVersion:   "1.2",
	}
}
