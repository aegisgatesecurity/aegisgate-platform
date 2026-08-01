# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Trust service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import TrustDashboard, TrustScore, TrustAnomaly, TrustCompliance


class TrustService:
    """Synchronous trust service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def dashboard(self) -> TrustDashboard:
        response = self._conn.get("/api/v1/trust/dashboard")
        return TrustDashboard.from_dict(response)

    def scores(self) -> TrustScore:
        response = self._conn.get("/api/v1/trust/scores")
        return TrustScore.from_dict(response)

    def anomalies(self) -> TrustAnomaly:
        response = self._conn.get("/api/v1/trust/anomalies")
        return TrustAnomaly.from_dict(response)

    def compliance(self) -> TrustCompliance:
        response = self._conn.get("/api/v1/trust/compliance")
        return TrustCompliance.from_dict(response)


class AsyncTrustService:
    """Asynchronous trust service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def dashboard(self) -> TrustDashboard:
        response = await self._conn.get("/api/v1/trust/dashboard")
        return TrustDashboard.from_dict(response)

    async def scores(self) -> TrustScore:
        response = await self._conn.get("/api/v1/trust/scores")
        return TrustScore.from_dict(response)

    async def anomalies(self) -> TrustAnomaly:
        response = await self._conn.get("/api/v1/trust/anomalies")
        return TrustAnomaly.from_dict(response)

    async def compliance(self) -> TrustCompliance:
        response = await self._conn.get("/api/v1/trust/compliance")
        return TrustCompliance.from_dict(response)
