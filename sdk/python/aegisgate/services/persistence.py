# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Persistence service for the AegisGate Python SDK."""

from typing import Any, Dict
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import PersistenceResult


class PersistenceService:
    """Synchronous persistence service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def get(self) -> PersistenceResult:
        response = self._conn.get("/api/v1/persistence")
        return PersistenceResult.from_dict(response)


class AsyncPersistenceService:
    """Asynchronous persistence service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def get(self) -> PersistenceResult:
        response = await self._conn.get("/api/v1/persistence")
        return PersistenceResult.from_dict(response)
