# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.

"""
Service modules for the AegisGate Python SDK v3.6.0.
"""

from aegisgate.services.auth import AuthService, AsyncAuthService
from aegisgate.services.proxy import ProxyService, AsyncProxyService
from aegisgate.services.compliance import ComplianceService, AsyncComplianceService
from aegisgate.services.trust import TrustService, AsyncTrustService
from aegisgate.services.scan import ScanService, AsyncScanService
from aegisgate.services.guardrails import GuardrailsService, AsyncGuardrailsService
from aegisgate.services.analytics import AnalyticsService, AsyncAnalyticsService
from aegisgate.services.ioc import IOCService, AsyncIOCService
from aegisgate.services.siem import SIEMService, AsyncSIEMService
from aegisgate.services.ml import MLService, AsyncMLService
from aegisgate.services.audit import AuditService, AsyncAuditService
from aegisgate.services.policy import PolicyService, AsyncPolicyService
from aegisgate.services.cluster import ClusterService, AsyncClusterService
from aegisgate.services.bridge import BridgeService, AsyncBridgeService
from aegisgate.services.attestation import AttestationService, AsyncAttestationService
from aegisgate.services.aibom import AIBOMService, AsyncAIBOMService
from aegisgate.services.a2a import A2AService, AsyncA2AService
from aegisgate.services.digest import DigestService, AsyncDigestService
from aegisgate.services.incident import IncidentService, AsyncIncidentService
from aegisgate.services.evaluator import EvaluatorService, AsyncEvaluatorService
from aegisgate.services.persistence import PersistenceService, AsyncPersistenceService
from aegisgate.services.certs import CertsService, AsyncCertsService
from aegisgate.services.license import LicenseService, AsyncLicenseService
from aegisgate.services.sla import SLAService, AsyncSLAService
from aegisgate.services.tsa import TSAService, AsyncTSAService
from aegisgate.services.webhook import WebhookService, AsyncWebhookService
from aegisgate.services.core import CoreService, AsyncCoreService
from aegisgate.services.vendor_risk import VendorRiskService, AsyncVendorRiskService
from aegisgate.services.policy_engine import PolicyEngineService, AsyncPolicyEngineService
from aegisgate.services.evidence import EvidenceService, AsyncEvidenceService
from aegisgate.services.ab_test import ABTestService, AsyncABTestService
from aegisgate.services.evasion import EvasionService, AsyncEvasionService

__all__ = [
    # Sync services
    "AuthService",
    "ProxyService",
    "ComplianceService",
    "TrustService",
    "ScanService",
    "GuardrailsService",
    "AnalyticsService",
    "IOCService",
    "SIEMService",
    "MLService",
    "AuditService",
    "PolicyService",
    "ClusterService",
    "BridgeService",
    "AttestationService",
    "AIBOMService",
    "A2AService",
    "DigestService",
    "IncidentService",
    "EvaluatorService",
    "PersistenceService",
    "CertsService",
    "LicenseService",
    "SLAService",
    "TSAService",
    "WebhookService",
    "CoreService",
    # Async services
    "AsyncAuthService",
    "AsyncProxyService",
    "AsyncComplianceService",
    "AsyncTrustService",
    "AsyncScanService",
    "AsyncGuardrailsService",
    "AsyncAnalyticsService",
    "AsyncIOCService",
    "AsyncSIEMService",
    "AsyncMLService",
    "AsyncAuditService",
    "AsyncPolicyService",
    "AsyncClusterService",
    "AsyncBridgeService",
    "AsyncAttestationService",
    "AsyncAIBOMService",
    "AsyncA2AService",
    "AsyncDigestService",
    "AsyncIncidentService",
    "AsyncEvaluatorService",
    "AsyncPersistenceService",
    "AsyncCertsService",
    "AsyncLicenseService",
    "AsyncSLAService",
    "AsyncTSAService",
    "AsyncWebhookService",
    "AsyncCoreService",
    # New services
    "VendorRiskService",
    "AsyncVendorRiskService",
    "PolicyEngineService",
    "AsyncPolicyEngineService",
    "EvidenceService",
    "AsyncEvidenceService",
    "ABTestService",
    "AsyncABTestService",
    "EvasionService",
    "AsyncEvasionService",
]