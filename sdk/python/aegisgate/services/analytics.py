# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Analytics service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import AnalyticsUsage, AnalyticsCost, AnalyticsAnomalies, AnalyticsDashboard


class AnalyticsService:
    """Synchronous analytics service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def usage(self, period: Optional[str] = None) -> AnalyticsUsage:
        params = {"period": period} if period else None
        response = self._conn.get("/api/v1/analytics/usage", params=params)
        return AnalyticsUsage.from_dict(response)

    def cost(self, period: Optional[str] = None) -> AnalyticsCost:
        params = {"period": period} if period else None
        response = self._conn.get("/api/v1/analytics/cost", params=params)
        return AnalyticsCost.from_dict(response)

    def anomalies(self) -> AnalyticsAnomalies:
        response = self._conn.get("/api/v1/analytics/anomalies")
        return AnalyticsAnomalies.from_dict(response)

    def dashboard(self) -> AnalyticsDashboard:
        response = self._conn.get("/api/v1/analytics/dashboard")
        return AnalyticsDashboard.from_dict(response)


class AsyncAnalyticsService:
    """Asynchronous analytics service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def usage(self, period: Optional[str] = None) -> AnalyticsUsage:
        params = {"period": period} if period else None
        response = await self._conn.get("/api/v1/analytics/usage", params=params)
        return AnalyticsUsage.from_dict(response)

    async def cost(self, period: Optional[str] = None) -> AnalyticsCost:
        params = {"period": period} if period else None
        response = await self._conn.get("/api/v1/analytics/cost", params=params)
        return AnalyticsCost.from_dict(response)

    async def anomalies(self) -> AnalyticsAnomalies:
        response = await self._conn.get("/api/v1/analytics/anomalies")
        return AnalyticsAnomalies.from_dict(response)

    async def dashboard(self) -> AnalyticsDashboard:
        response = await self._conn.get("/api/v1/analytics/dashboard")
        return AnalyticsDashboard.from_dict(response)
