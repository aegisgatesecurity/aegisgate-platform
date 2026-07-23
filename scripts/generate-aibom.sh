#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# =========================================================================
# AegisGate Platform — AIBOM Generator Script
# =========================================================================
#
# Generates a CycloneDX 1.6 AI Bill of Materials for the AegisGate Platform
# release. The AIBOM describes the AI components, models, and safety
# characteristics of the platform deployment.
#
# Usage: ./scripts/generate-aibom.sh <version> <output-dir>
#   version:    e.g., "3.4.0"
#   output-dir: directory to write aibom.json (default: .)
#
# The output is a CycloneDX 1.6 JSON document with the aibom extension
# that describes the AI components and safety properties of the deployment.
# This file is intended to be published alongside the SPDX SBOM in the
# GitHub Release assets.
#
# v3.4.0+
# =========================================================================

set -euo pipefail

VERSION="${1:?Usage: $0 <version> [output-dir]}"
OUTPUT_DIR="${2:-.}"
AIBOM_FILE="${OUTPUT_DIR}/aibom.json"

# Generate a UUIDv4 for the serial number
SERIAL=$(uuidgen 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

mkdir -p "${OUTPUT_DIR}"

cat > "${AIBOM_FILE}" << EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "serialNumber": "urn:uuid:${SERIAL}",
  "metadata": {
    "timestamp": "${TIMESTAMP}",
    "tools": [
      {
        "vendor": "AegisGate",
        "name": "aegisgate-platform",
        "version": "${VERSION}"
      }
    ],
    "component": {
      "type": "application",
      "bom-ref": "aegisgate-platform-${VERSION}",
      "name": "aegisgate-platform",
      "version": "${VERSION}",
      "description": "AegisGate Platform — Enterprise AI Security Gateway",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0"
          }
        }
      ],
      "properties": [
        { "name": "aibom:deployment:type", "value": "self-hosted" },
        { "name": "aibom:deployment:topology", "value": "single-instance" },
        { "name": "aibom:deployment:region", "value": "customer-managed" }
      ]
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "aegisgate-response-guard",
      "name": "ResponseGuard",
      "version": "${VERSION}",
      "description": "7-stage AI response scanning pipeline: PII, Secrets, XSS, Compliance, Tokens, Toxicity, Hallucination",
      "properties": [
        { "name": "aibom:ai:task", "value": "response-safety" },
        { "name": "aibom:ai:technique", "value": "rule-based-detection" },
        { "name": "aibom:ai:model:type", "value": "none" },
        { "name": "aibom:ai:safety:mechanism", "value": "multi-stage-pipeline" },
        { "name": "aibom:ai:safety:threshold", "value": "153-pattern-detection" }
      ]
    },
    {
      "type": "library",
      "bom-ref": "aegisgate-ioc-engine",
      "name": "IOCEngine",
      "version": "${VERSION}",
      "description": "Indicator of Compromise detection and reputation scoring engine",
      "properties": [
        { "name": "aibom:ai:task", "value": "threat-detection" },
        { "name": "aibom:ai:technique", "value": "fingerprint-matching" },
        { "name": "aibom:ai:model:type", "value": "none" },
        { "name": "aibom:ai:safety:mechanism", "value": "ecdsa-attestation" }
      ]
    },
    {
      "type": "library",
      "bom-ref": "aegisgate-correlation-engine",
      "name": "CorrelationEngine",
      "version": "${VERSION}",
      "description": "Cross-protocol threat correlation engine with pattern matching",
      "properties": [
        { "name": "aibom:ai:task", "value": "threat-correlation" },
        { "name": "aibom:ai:technique", "value": "pattern-matching" },
        { "name": "aibom:ai:model:type", "value": "none" },
        { "name": "aibom:ai:safety:mechanism", "value": "5-threat-pattern-detection" }
      ]
    },
    {
      "type": "library",
      "bom-ref": "aegisgate-trust-score",
      "name": "TrustScoring",
      "version": "${VERSION}",
      "description": "Multi-source trust scoring with ECDSA attestation",
      "properties": [
        { "name": "aibom:ai:task", "value": "trust-scoring" },
        { "name": "aibom:ai:technique", "value": "weighted-average" },
        { "name": "aibom:ai:model:type", "value": "none" },
        { "name": "aibom:ai:safety:mechanism", "value": "ecdsa-signed-attestation" }
      ]
    },
    {
      "type": "library",
      "bom-ref": "aegisgate-rbac",
      "name": "RBACEngine",
      "version": "${VERSION}",
      "description": "Role-based access control with tenant isolation and session management",
      "properties": [
        { "name": "aibom:ai:task", "value": "access-control" },
        { "name": "aibom:ai:technique", "value": "role-based-access-control" },
        { "name": "aibom:ai:model:type", "value": "none" },
        { "name": "aibom:ai:safety:mechanism", "value": "tenant-isolation" }
      ]
    },
    {
      "type": "library",
      "bom-ref": "aegisgate-mcp-server",
      "name": "MCPServer",
      "version": "${VERSION}",
      "description": "Model Context Protocol server with tool authorization and guardrails",
      "properties": [
        { "name": "aibom:ai:task", "value": "tool-authorization" },
        { "name": "aibom:ai:technique", "value": "policy-based-filtering" },
        { "name": "aibom:ai:model:type", "value": "none" },
        { "name": "aibom:ai:safety:mechanism", "value": "tier-gated-tool-access" }
      ]
    }
  ],
  "properties": [
    { "name": "aibom:platform:name", "value": "AegisGate Platform" },
    { "name": "aibom:platform:version", "value": "${VERSION}" },
    { "name": "aibom:platform:license", "value": "Apache-2.0" },
    { "name": "aibom:platform:url", "value": "https://github.com/aegisgatesecurity/aegisgate-platform" },
    { "name": "aibom:platform:tier", "value": "community" },
    { "name": "aibom:ai:safety:hasHumanOversight", "value": "true" },
    { "name": "aibom:ai:safety:hasKillSwitch", "value": "true" },
    { "name": "aibom:ai:safety:hasOutputFiltering", "value": "true" },
    { "name": "aibom:ai:safety:hasInputFiltering", "value": "true" },
    { "name": "aibom:ai:safety:hasAuditLogging", "value": "true" },
    { "name": "aibom:ai:safety:hasComplianceReporting", "value": "true" },
    { "name": "aibom:ai:safety:maxTokensPerResponse", "value": "4096" },
    { "name": "aibom:ai:safety:detectionPatterns", "value": "153" },
    { "name": "aibom:ai:transparency:codeAvailable", "value": "true" },
    { "name": "aibom:ai:transparency:trainingDataDocumented", "value": "false" },
    { "name": "aibom:ai:transparency:usesExternalModels", "value": "false" },
    { "name": "aibom:compliance:fedramp", "value": "aligned" },
    { "name": "aibom:compliance:sox", "value": "supported" },
    { "name": "aibom:compliance:gdpr", "value": "supported" },
    { "name": "aibom:compliance:hipaa", "value": "supported" }
  ]
}
EOF

echo "✅ AIBOM generated: ${AIBOM_FILE} ($(wc -c < "${AIBOM_FILE}") bytes)"