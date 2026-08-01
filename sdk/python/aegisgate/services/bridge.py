# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Bridge service for the AegisGate Python SDK."""

from typing import Any, Dict
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import BridgeResult


class BridgeService:
    """Synchronous bridge service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def status(self) -> BridgeResult:
        response = self._conn.get("/api/v1/bridge")
        return BridgeResult.from_dict(response)


class AsyncBridgeService:
    """Asynchronous bridge service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def status(self) -> AsyncBridgeResult:
        response = await self._conn.get("/api/v1/bridge")
        return BridgeResult.from_dict(response)
