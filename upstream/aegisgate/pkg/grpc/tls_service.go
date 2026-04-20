// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package grpc

import (
	"context"
	"log/slog"

	"github.com/aegisgatesecurity/aegisgate/pkg/tls"
)

// TLSSvc implements the TLS service
type TLSSvc struct {
	UnimplementedTLSSvcServer
	manager *tls.Manager
	logger  *slog.Logger
}

// NewTLSSvc creates a new TLS service
func NewTLSSvc(manager *tls.Manager, logger *slog.Logger) *TLSSvc {
	return &TLSSvc{
		manager: manager,
		logger:  logger,
	}
}

// GetConfig returns TLS configuration
func (s *TLSSvc) GetConfig(ctx context.Context, req *GetTLSConfigRequest) (*GetTLSConfigResponse, error) {
	cfg := s.manager.GetConfig()

	return &GetTLSConfigResponse{
		Enabled:      cfg.Enabled,
		CertFile:     cfg.CertFile,
		KeyFile:      cfg.KeyFile,
		AutoGenerate: cfg.AutoGenerate,
		MinVersion:   cfg.MinVersion,
	}, nil
}

// GetCertificates returns all certificates
func (s *TLSSvc) GetCertificates(ctx context.Context, req *GetCertificatesRequest) (*GetCertificatesResponse, error) {
	// Would get certificates from manager
	return &GetCertificatesResponse{Certificates: []*CertificateInfo{}}, nil
}

// GenerateCertificate generates a new certificate
func (s *TLSSvc) GenerateCertificate(ctx context.Context, req *GenerateCertificateRequest) (*GenerateCertificateResponse, error) {
	// Would generate certificate
	return &GenerateCertificateResponse{}, nil
}

// GetMTLSConfig returns mTLS configuration
func (s *TLSSvc) GetMTLSConfig(ctx context.Context, req *GetMTLSConfigRequest) (*GetMTLSConfigResponse, error) {
	return &GetMTLSConfigResponse{}, nil
}
