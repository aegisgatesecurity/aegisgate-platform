# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Compliance service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import ScanReport, ComplianceReport, ComplianceIntegrity, EvidenceResult


class ComplianceService:
    """Synchronous compliance service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def scan(self) -> ScanReport:
        response = self._conn.get("/api/v1/compliance/scan")
        return ScanReport.from_dict(response)

    def report(self, framework: Optional[str] = None) -> ComplianceReport:
        params = {"framework": framework} if framework else None
        response = self._conn.get("/api/v1/compliance/report", params=params)
        return ComplianceReport.from_dict(response)

    def integrity(self) -> ComplianceIntegrity:
        response = self._conn.get("/api/v1/compliance/integrity")
        return ComplianceIntegrity.from_dict(response)

    def evidence(self) -> EvidenceResult:
        response = self._conn.get("/api/v1/compliance/evidence")
        return EvidenceResult.from_dict(response)


class AsyncComplianceService:
    """Asynchronous compliance service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def scan(self) -> ScanReport:
        response = await self._conn.get("/api/v1/compliance/scan")
        return ScanReport.from_dict(response)

    async def report(self, framework: Optional[str] = None) -> ComplianceReport:
        params = {"framework": framework} if framework else None
        response = await self._conn.get("/api/v1/compliance/report", params=params)
        return ComplianceReport.from_dict(response)

    async def integrity(self) -> ComplianceIntegrity:
        response = await self._conn.get("/api/v1/compliance/integrity")
        return ComplianceIntegrity.from_dict(response)

    async def evidence(self) -> EvidenceResult:
        response = await self._conn.get("/api/v1/compliance/evidence")
        return EvidenceResult.from_dict(response)
