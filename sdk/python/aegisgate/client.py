# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.

"""
Main client for the AegisGate Python SDK v3.6.0.
"""

import os
from typing import Optional

from aegisgate.connection import ConnectionConfig, SyncConnection, AsyncConnection
from aegisgate.services import (
    AuthService, AsyncAuthService,
    ProxyService, AsyncProxyService,
    ComplianceService, AsyncComplianceService,
    TrustService, AsyncTrustService,
    ScanService, AsyncScanService,
    GuardrailsService, AsyncGuardrailsService,
    AnalyticsService, AsyncAnalyticsService,
    IOCService, AsyncIOCService,
    SIEMService, AsyncSIEMService,
    MLService, AsyncMLService,
    AuditService, AsyncAuditService,
    PolicyService, AsyncPolicyService,
    ClusterService, AsyncClusterService,
    BridgeService, AsyncBridgeService,
    AttestationService, AsyncAttestationService,
    AIBOMService, AsyncAIBOMService,
    A2AService, AsyncA2AService,
    DigestService, AsyncDigestService,
    IncidentService, AsyncIncidentService,
    EvaluatorService, AsyncEvaluatorService,
    PersistenceService, AsyncPersistenceService,
    CertsService, AsyncCertsService,
    LicenseService, AsyncLicenseService,
    SLAService, AsyncSLAService,
    TSAService, AsyncTSAService,
    WebhookService, AsyncWebhookService,
    CoreService, AsyncCoreService,
)
from aegisgate.services.vendor_risk import VendorRiskService
from aegisgate.services.policy_engine import PolicyEngineService
from aegisgate.services.evidence import EvidenceService
from aegisgate.services.ab_test import ABTestService
from aegisgate.services.evasion import EvasionService


class Client:
    """
    Synchronous AegisGate client for v3.6.0.

    Usage:
        client = Client(base_url="http://localhost:8080", api_key="your-key")
        health = client.core.health()
        print(health)
        client.close()

    Or as context manager:
        with Client(base_url="http://localhost:8080") as client:
            health = client.core.health()
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        verify_ssl: bool = True,
        **kwargs
    ):
        if base_url is None:
            base_url = os.environ.get("AEGISGATE_BASE_URL", "http://localhost:8080")
        if api_key is None:
            api_key = os.environ.get("AEGISGATE_API_KEY")

        self._config = ConnectionConfig(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            max_retries=max_retries,
            verify_ssl=verify_ssl,
            custom_headers=kwargs.get("headers"),
            proxy=kwargs.get("proxy"),
        )

        self._connection = SyncConnection(self._config)
        self._token: Optional[str] = None

        # Initialize services
        self._auth = AuthService(self._connection)
        self._proxy = ProxyService(self._connection)
        self._compliance = ComplianceService(self._connection)
        self._trust = TrustService(self._connection)
        self._scan = ScanService(self._connection)
        self._guardrails = GuardrailsService(self._connection)
        self._analytics = AnalyticsService(self._connection)
        self._ioc = IOCService(self._connection)
        self._siem = SIEMService(self._connection)
        self._ml = MLService(self._connection)
        self._audit = AuditService(self._connection)
        self._policy = PolicyService(self._connection)
        self._cluster = ClusterService(self._connection)
        self._bridge = BridgeService(self._connection)
        self._attestation = AttestationService(self._connection)
        self._aibom = AIBOMService(self._connection)
        self._a2a = A2AService(self._connection)
        self._digest = DigestService(self._connection)
        self._incident = IncidentService(self._connection)
        self._evaluator = EvaluatorService(self._connection)
        self._persistence = PersistenceService(self._connection)
        self._certs = CertsService(self._connection)
        self._license = LicenseService(self._connection)
        self._sla = SLAService(self._connection)
        self._tsa = TSAService(self._connection)
        self._webhook = WebhookService(self._connection)
        self._core = CoreService(self._connection)
        self._vendor_risk = VendorRiskService(self._connection)
        self._policy_engine = PolicyEngineService(self._connection)
        self._evidence = EvidenceService(self._connection)
        self._ab_test = ABTestService(self._connection)
        self._evasion = EvasionService(self._connection)

    @property
    def auth(self) -> AuthService:
        """Access authentication service."""
        return self._auth

    @property
    def proxy(self) -> ProxyService:
        """Access proxy service."""
        return self._proxy

    @property
    def compliance(self) -> ComplianceService:
        """Access compliance service."""
        return self._compliance

    @property
    def trust(self) -> TrustService:
        """Access trust service."""
        return self._trust

    @property
    def scan(self) -> ScanService:
        """Access scan service."""
        return self._scan

    @property
    def guardrails(self) -> GuardrailsService:
        """Access guardrails service."""
        return self._guardrails

    @property
    def analytics(self) -> AnalyticsService:
        """Access analytics service."""
        return self._analytics

    @property
    def ioc(self) -> IOCService:
        """Access IOC service."""
        return self._ioc

    @property
    def siem(self) -> SIEMService:
        """Access SIEM service."""
        return self._siem

    @property
    def ml(self) -> MLService:
        """Access ML metrics service."""
        return self._ml

    @property
    def audit(self) -> AuditService:
        """Access audit service."""
        return self._audit

    @property
    def policy(self) -> PolicyService:
        """Access policy service."""
        return self._policy

    @property
    def cluster(self) -> ClusterService:
        """Access cluster service."""
        return self._cluster

    @property
    def bridge(self) -> BridgeService:
        """Access bridge service."""
        return self._bridge

    @property
    def attestation(self) -> AttestationService:
        """Access attestation service."""
        return self._attestation

    @property
    def aibom(self) -> AIBOMService:
        """Access AIBOM service."""
        return self._aibom

    @property
    def a2a(self) -> A2AService:
        """Access A2A service."""
        return self._a2a

    @property
    def digest(self) -> DigestService:
        """Access digest service."""
        return self._digest

    @property
    def incident(self) -> IncidentService:
        """Access incident service."""
        return self._incident

    @property
    def evaluator(self) -> EvaluatorService:
        """Access evaluator service."""
        return self._evaluator

    @property
    def persistence(self) -> PersistenceService:
        """Access persistence service."""
        return self._persistence

    @property
    def certs(self) -> CertsService:
        """Access certs service."""
        return self._certs

    @property
    def license(self) -> LicenseService:
        """Access license service."""
        return self._license

    @property
    def sla(self) -> SLAService:
        """Access SLA service."""
        return self._sla

    @property
    def tsa(self) -> TSAService:
        """Access TSA service."""
        return self._tsa

    @property
    def webhook(self) -> WebhookService:
        """Access webhook service."""
        return self._webhook

    @property
    def core(self) -> CoreService:
        """Access core service."""
        return self._core

    @property
    def vendor_risk(self) -> VendorRiskService:
        """Access vendor risk assessment service."""
        return self._vendor_risk

    @property
    def policy_engine(self) -> PolicyEngineService:
        """Access policy engine (OPA/Rego) service."""
        return self._policy_engine

    @property
    def evidence(self) -> EvidenceService:
        """Access evidence collection service."""
        return self._evidence

    @property
    def ab_test(self) -> ABTestService:
        """Access ML A/B testing service."""
        return self._ab_test

    @property
    def evasion(self) -> EvasionService:
        """Access evasion resistance detection service."""
        return self._evasion

    def set_token(self, token: str) -> None:
        """Set authentication token."""
        self._token = token
        self._connection.config.api_key = None
        self._connection.config.custom_headers["Authorization"] = f"Bearer {token}"

    def set_api_key(self, api_key: str) -> None:
        """Set API key for authentication."""
        self._config.api_key = api_key
        self._token = None
        if "Authorization" in self._connection.config.custom_headers:
            del self._connection.config.custom_headers["Authorization"]

    def close(self) -> None:
        """Close the client and release resources."""
        self._connection.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class AsyncClient:
    """
    Asynchronous AegisGate client for v3.6.0.

    Usage:
        async with AsyncClient(base_url="http://localhost:8080") as client:
            health = await client.core.health()
            print(health)
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        verify_ssl: bool = True,
        **kwargs
    ):
        if base_url is None:
            base_url = os.environ.get("AEGISGATE_BASE_URL", "http://localhost:8080")
        if api_key is None:
            api_key = os.environ.get("AEGISGATE_API_KEY")

        self._config = ConnectionConfig(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            max_retries=max_retries,
            verify_ssl=verify_ssl,
            custom_headers=kwargs.get("headers"),
            proxy=kwargs.get("proxy"),
        )

        self._connection = AsyncConnection(self._config)
        self._token: Optional[str] = None

        self._auth = AsyncAuthService(self._connection)
        self._proxy = AsyncProxyService(self._connection)
        self._compliance = AsyncComplianceService(self._connection)
        self._trust = AsyncTrustService(self._connection)
        self._scan = AsyncScanService(self._connection)
        self._guardrails = AsyncGuardrailsService(self._connection)
        self._analytics = AsyncAnalyticsService(self._connection)
        self._ioc = AsyncIOCService(self._connection)
        self._siem = AsyncSIEMService(self._connection)
        self._ml = AsyncMLService(self._connection)
        self._audit = AsyncAuditService(self._connection)
        self._policy = AsyncPolicyService(self._connection)
        self._cluster = AsyncClusterService(self._connection)
        self._bridge = AsyncBridgeService(self._connection)
        self._attestation = AsyncAttestationService(self._connection)
        self._aibom = AsyncAIBOMService(self._connection)
        self._a2a = AsyncA2AService(self._connection)
        self._digest = AsyncDigestService(self._connection)
        self._incident = AsyncIncidentService(self._connection)
        self._evaluator = AsyncEvaluatorService(self._connection)
        self._persistence = AsyncPersistenceService(self._connection)
        self._certs = AsyncCertsService(self._connection)
        self._license = AsyncLicenseService(self._connection)
        self._sla = AsyncSLAService(self._connection)
        self._tsa = AsyncTSAService(self._connection)
        self._webhook = AsyncWebhookService(self._connection)
        self._core = AsyncCoreService(self._connection)
        self._vendor_risk = VendorRiskService(self._connection)
        self._policy_engine = PolicyEngineService(self._connection)
        self._evidence = EvidenceService(self._connection)
        self._ab_test = ABTestService(self._connection)
        self._evasion = EvasionService(self._connection)

    @property
    def auth(self) -> AsyncAuthService: return self._auth
    @property
    def proxy(self) -> AsyncProxyService: return self._proxy
    @property
    def compliance(self) -> AsyncComplianceService: return self._compliance
    @property
    def trust(self) -> AsyncTrustService: return self._trust
    @property
    def scan(self) -> AsyncScanService: return self._scan
    @property
    def guardrails(self) -> AsyncGuardrailsService: return self._guardrails
    @property
    def analytics(self) -> AsyncAnalyticsService: return self._analytics
    @property
    def ioc(self) -> AsyncIOCService: return self._ioc
    @property
    def siem(self) -> AsyncSIEMService: return self._siem
    @property
    def ml(self) -> AsyncMLService: return self._ml
    @property
    def audit(self) -> AsyncAuditService: return self._audit
    @property
    def policy(self) -> AsyncPolicyService: return self._policy
    @property
    def cluster(self) -> AsyncClusterService: return self._cluster
    @property
    def bridge(self) -> AsyncBridgeService: return self._bridge
    @property
    def attestation(self) -> AsyncAttestationService: return self._attestation
    @property
    def aibom(self) -> AsyncAIBOMService: return self._aibom
    @property
    def a2a(self) -> AsyncA2AService: return self._a2a
    @property
    def digest(self) -> AsyncDigestService: return self._digest
    @property
    def incident(self) -> AsyncIncidentService: return self._incident
    @property
    def evaluator(self) -> AsyncEvaluatorService: return self._evaluator
    @property
    def persistence(self) -> AsyncPersistenceService: return self._persistence
    @property
    def certs(self) -> AsyncCertsService: return self._certs
    @property
    def license(self) -> AsyncLicenseService: return self._license
    @property
    def sla(self) -> AsyncSLAService: return self._sla
    @property
    def tsa(self) -> AsyncTSAService: return self._tsa
    @property
    def webhook(self) -> AsyncWebhookService: return self._webhook
    @property
    def core(self) -> AsyncCoreService: return self._core

    @property
    def vendor_risk(self) -> VendorRiskService: return self._vendor_risk

    @property
    def policy_engine(self) -> PolicyEngineService: return self._policy_engine

    @property
    def evidence(self) -> EvidenceService: return self._evidence

    @property
    def ab_test(self) -> ABTestService: return self._ab_test

    @property
    def evasion(self) -> EvasionService: return self._evasion

    def set_token(self, token: str) -> None:
        self._token = token
        self._connection.config.api_key = None
        self._connection.config.custom_headers["Authorization"] = f"Bearer {token}"

    def set_api_key(self, api_key: str) -> None:
        self._config.api_key = api_key
        self._token = None
        if "Authorization" in self._connection.config.custom_headers:
            del self._connection.config.custom_headers["Authorization"]

    async def close(self) -> None:
        await self._connection.close()

    async def __aenter__(self) -> "AsyncClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
