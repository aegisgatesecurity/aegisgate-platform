// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC Service Layer
// =========================================================================
//
// Package grpc provides the gRPC API for AegisGate Platform.
// It exposes platform capabilities (auth, compliance, proxy, SIEM, TLS,
// webhooks, core) over gRPC for programmatic access by operators,
// integrations, and internal microservices.
//
// Services:
//   - AuthService       — user authentication, session management
//   - ProxyService      — proxy statistics, health, configuration
//   - ComplianceService — framework listing, status, checks, reports
//   - SIEMService       — SIEM configuration, events, stats
//   - WebhookService    — webhook CRUD, testing, stats
//   - CoreService       — modules, health, metrics, version
//   - TLSSvc           — TLS/mTLS configuration, certificates
//
// The package uses hand-crafted type definitions and service descriptors
// (no protobuf code generation required). Service descriptors include
// proper method handlers for full gRPC dispatch.
//
// Wire into your application:
//
//	server := grpc.NewGRPCServer(authMgr, compMgr, proxyObj, siemMgr,
//	    webhookStore, metricsMgr, tlsMgr, logger)
//	go server.Serve(":50051")
//	// ... later ...
//	server.GracefulStop()
//
// =========================================================================
package grpc