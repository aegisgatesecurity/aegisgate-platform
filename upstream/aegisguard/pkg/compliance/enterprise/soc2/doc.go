// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// SOC 2 Type II Compliance Module
//
// This module provides SOC 2 Type II Trust Service Criteria compliance
// for AI agent operations within AegisGuard.
//
// Trust Service Principles Covered:
//   - Security (TSP-SEC)
//   - Availability (TSP-AVAIL)
//   - Processing Integrity (TSP-PROC)
//   - Confidentiality (TSP-CONF)
//   - Privacy (TSP-PRIV)
//
// SOC 2 Criteria Mapped:
//   - CC6.1: Logical and physical access controls
//   - CC6.2: Authorization before processing
//   - CC6.3: Role-based access controls
//   - CC6.4: System accounts and credentials
//   - CC6.5: Security event monitoring
//   - CC6.6: Incident management
//   - CC6.7: End-user computing controls
//   - A1.1-A1.3: Availability commitments
//   - PI1.1-PI1.4: Processing integrity
//   - C1.1-C1.2: Confidentiality commitments
//   - P1.1-P8.1: Privacy criteria
//
// Usage:
//
//	f := soc2.NewSOC2Framework()
//
//	// Check an agent action
//	result, err := f.Check(ctx, common.CheckInput{
//	    Content: "agent_action_data",
//	    Metadata: map[string]string{"agent_id": "agent-123"},
//	})
//
// For more information on SOC 2, see:
// https://www.aicpa.org/soc2
//
// =========================================================================

package soc2
