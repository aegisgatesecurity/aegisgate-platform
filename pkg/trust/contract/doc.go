// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Capability Contract System
// =========================================================================
//
// The Capability Contract System defines what actions an AI agent is
// permitted to perform within an organization. Each contract specifies:
//   - Specific capabilities (file:read, net:http, agent:call, etc.)
//   - Risk levels for each capability
//   - Resource scopes (which resources a capability applies to)
//   - Conditions (time-based, approval-based, context-based)
//   - Rate limits
//
// Example contract:
//
//	contract := contract.NewContract(
//	    "CustomerSupport Agent",
//	    "Standard customer support agent capabilities",
//	    "agent-123",
//	    "org-456",
//	    []contract.ContractRule{
//	        {
//	            Capability:  contract.CapNetHTTP,
//	            Scope:       contract.ScopeGlobal,
//	            RiskLevel:   contract.RiskLow,
//	        },
//	        {
//	            Capability:  contract.CapFileRead,
//	            Scope:       contract.ScopeResource,
//	            Resources: []contract.Resource{
//	                {Type: "file", Pattern: "/data/customers/*"},
//	            },
//	            RiskLevel: contract.RiskMedium,
//	        },
//	    },
//	)
//
// Enforcement:
//
//	enforcer := contract.NewEnforcer(registry, rateLimiter)
//	result, err := enforcer.Enforce(ctx, &contract.EnforcementContext{
//	    AgentID:    "agent-123",
//	    Capability: contract.CapFileRead,
//	})
//
// =========================================================================

package contract
