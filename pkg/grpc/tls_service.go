// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC TLS Service Implementation
// =========================================================================

package grpc

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TLSSvc implements TLSSvcServer using a TLSBackend.
type TLSSvc struct {
	UnimplementedTLSSvcServer
	backend TLSBackend
	logger  *slog.Logger
}

// NewTLSSvc creates a new TLSSvc with the given backend.
func NewTLSSvc(backend TLSBackend, logger *slog.Logger) *TLSSvc {
	return &TLSSvc{backend: backend, logger: logger}
}

// GetConfig returns TLS configuration.
func (s *TLSSvc) GetConfig(ctx context.Context, req *GetTLSConfigRequest) (*GetTLSConfigResponse, error) {
	cfg, err := s.backend.GetConfig(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get TLS config: %v", err)
	}

	return &GetTLSConfigResponse{
		Enabled:      cfg.Enabled,
		CertFile:     cfg.CertFile,
		KeyFile:      cfg.KeyFile,
		AutoGenerate: cfg.AutoGenerate,
		MinVersion:   cfg.MinVersion,
	}, nil
}

// GetCertificates returns all certificates.
func (s *TLSSvc) GetCertificates(ctx context.Context, req *GetCertificatesRequest) (*GetCertificatesResponse, error) {
	certs, err := s.backend.GetCertificates(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get certificates: %v", err)
	}

	result := make([]*CertificateInfo, 0, len(certs))
	for _, c := range certs {
		result = append(result, &CertificateInfo{
			Subject:     c.Subject,
			Issuer:      c.Issuer,
			NotBefore:   c.NotBefore,
			NotAfter:    c.NotAfter,
			Fingerprint: c.Fingerprint,
		})
	}

	return &GetCertificatesResponse{Certificates: result}, nil
}

// GenerateCertificate generates a new certificate.
func (s *TLSSvc) GenerateCertificate(ctx context.Context, req *GenerateCertificateRequest) (*GenerateCertificateResponse, error) {
	if req.CommonName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "common_name is required")
	}

	validity := req.ValidityDays
	if validity <= 0 {
		validity = 365 // default 1 year
	}

	cert, err := s.backend.GenerateCertificate(ctx, req.CommonName, req.Organization, validity)
	if err != nil {
		return &GenerateCertificateResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &GenerateCertificateResponse{
		Success: true,
		Certificate: &CertificateInfo{
			Subject:     cert.Subject,
			Issuer:      cert.Issuer,
			NotBefore:   cert.NotBefore,
			NotAfter:    cert.NotAfter,
			Fingerprint: cert.Fingerprint,
		},
	}, nil
}

// GetMTLSConfig returns mTLS configuration.
func (s *TLSSvc) GetMTLSConfig(ctx context.Context, req *GetMTLSConfigRequest) (*GetMTLSConfigResponse, error) {
	cfg, err := s.backend.GetMTLSConfig(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get mTLS config: %v", err)
	}

	return &GetMTLSConfigResponse{
		Enabled:        cfg.Enabled,
		CaCertFile:     cfg.CACertFile,
		ClientCertFile: cfg.ClientCertFile,
		ClientKeyFile:  cfg.ClientKeyFile,
	}, nil
}