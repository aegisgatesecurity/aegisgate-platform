// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC Webhook Service Implementation
// =========================================================================

package grpc

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WebhookService implements WebhookServiceServer using a WebhookBackend.
type WebhookService struct {
	UnimplementedWebhookServiceServer
	backend WebhookBackend
	logger  *slog.Logger
}

// NewWebhookService creates a new WebhookService with the given backend.
func NewWebhookService(backend WebhookBackend, logger *slog.Logger) *WebhookService {
	return &WebhookService{backend: backend, logger: logger}
}

// ListWebhooks lists all webhooks.
func (s *WebhookService) ListWebhooks(ctx context.Context, req *ListWebhooksRequest) (*ListWebhooksResponse, error) {
	webhooks, err := s.backend.ListWebhooks(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list webhooks: %v", err)
	}

	result := make([]*WebhookInfo, 0, len(webhooks))
	for _, w := range webhooks {
		result = append(result, webhookDetailToProto(w))
	}

	return &ListWebhooksResponse{Webhooks: result}, nil
}

// GetWebhook gets a webhook by ID.
func (s *WebhookService) GetWebhook(ctx context.Context, req *GetWebhookRequest) (*GetWebhookResponse, error) {
	if req.WebhookId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "webhook_id is required")
	}

	webhook, err := s.backend.GetWebhook(ctx, req.WebhookId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "webhook not found: %s", req.WebhookId)
	}

	return &GetWebhookResponse{Webhook: webhookDetailToProto(webhook)}, nil
}

// CreateWebhook creates a new webhook.
func (s *WebhookService) CreateWebhook(ctx context.Context, req *CreateWebhookRequest) (*CreateWebhookResponse, error) {
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "name is required")
	}
	if req.Url == "" {
		return nil, status.Errorf(codes.InvalidArgument, "url is required")
	}

	webhook, err := s.backend.CreateWebhook(ctx, req.Name, req.Url, req.Events, req.Enabled)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create webhook: %v", err)
	}

	return &CreateWebhookResponse{Webhook: webhookDetailToProto(webhook)}, nil
}

// UpdateWebhook updates a webhook.
func (s *WebhookService) UpdateWebhook(ctx context.Context, req *UpdateWebhookRequest) (*UpdateWebhookResponse, error) {
	if req.WebhookId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "webhook_id is required")
	}

	webhook, err := s.backend.UpdateWebhook(ctx, req.WebhookId, req.Name, req.Url, req.Events, req.Enabled)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update webhook: %v", err)
	}

	return &UpdateWebhookResponse{Webhook: webhookDetailToProto(webhook)}, nil
}

// DeleteWebhook deletes a webhook.
func (s *WebhookService) DeleteWebhook(ctx context.Context, req *DeleteWebhookRequest) (*DeleteWebhookResponse, error) {
	if req.WebhookId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "webhook_id is required")
	}

	if err := s.backend.DeleteWebhook(ctx, req.WebhookId); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete webhook: %v", err)
	}

	return &DeleteWebhookResponse{Success: true}, nil
}

// EnableWebhook enables a webhook.
func (s *WebhookService) EnableWebhook(ctx context.Context, req *EnableWebhookRequest) (*EnableWebhookResponse, error) {
	if req.WebhookId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "webhook_id is required")
	}

	webhook, err := s.backend.EnableWebhook(ctx, req.WebhookId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to enable webhook: %v", err)
	}

	return &EnableWebhookResponse{Webhook: webhookDetailToProto(webhook)}, nil
}

// DisableWebhook disables a webhook.
func (s *WebhookService) DisableWebhook(ctx context.Context, req *DisableWebhookRequest) (*DisableWebhookResponse, error) {
	if req.WebhookId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "webhook_id is required")
	}

	webhook, err := s.backend.DisableWebhook(ctx, req.WebhookId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to disable webhook: %v", err)
	}

	return &DisableWebhookResponse{Webhook: webhookDetailToProto(webhook)}, nil
}

// TestWebhook tests a webhook delivery.
func (s *WebhookService) TestWebhook(ctx context.Context, req *TestWebhookRequest) (*TestWebhookResponse, error) {
	if req.WebhookId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "webhook_id is required")
	}

	success, message, err := s.backend.TestWebhook(ctx, req.WebhookId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "webhook test failed: %v", err)
	}

	return &TestWebhookResponse{
		Success: success,
		Message: message,
	}, nil
}

// GetStats returns webhook statistics.
func (s *WebhookService) GetStats(ctx context.Context, req *GetWebhookStatsRequest) (*GetWebhookStatsResponse, error) {
	stats, err := s.backend.GetStats(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get webhook stats: %v", err)
	}

	return &GetWebhookStatsResponse{
		TotalWebhooks:     stats.TotalWebhooks,
		ActiveWebhooks:    stats.ActiveWebhooks,
		DeliveriesTotal:   stats.DeliveriesTotal,
		DeliveriesSuccess: stats.DeliveriesSuccess,
		DeliveriesFailed:  stats.DeliveriesFailed,
	}, nil
}

// webhookDetailToProto converts a WebhookDetail to a gRPC WebhookInfo message.
func webhookDetailToProto(w *WebhookDetail) *WebhookInfo {
	if w == nil {
		return nil
	}
	return &WebhookInfo{
		Id:      w.ID,
		Name:    w.Name,
		Url:     w.URL,
		Events:  w.Events,
		Enabled: w.Enabled,
	}
}