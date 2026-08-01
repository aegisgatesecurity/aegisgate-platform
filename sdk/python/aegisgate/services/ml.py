# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""ML metrics service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import MLShadowMetrics


class MLService:
    """Synchronous ML metrics service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def metrics(self) -> MLShadowMetrics:
        response = self._conn.get("/api/v1/ml/metrics")
        return MLShadowMetrics.from_dict(response)


class AsyncMLService:
    """Asynchronous ML metrics service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def metrics(self) -> MLShadowMetrics:
        response = await self._conn.get("/api/v1/ml/metrics")
        return MLShadowMetrics.from_dict(response)
