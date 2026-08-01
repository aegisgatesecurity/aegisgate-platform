// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - SIEM Integration
// =========================================================================
//
// Package siem provides Security Information and Event Management integration
// for forwarding AegisGate security events to external SIEM systems via Syslog
// (RFC 5424) and CEF (Common Event Format) protocols.
//
// Supported outputs:
//   - Syslog (RFC 5424) over TCP/TLS
//   - CEF (Common Event Format) over UDP
//   - JSON webhook for custom SIEM integrations
//
// =========================================================================

package siem
