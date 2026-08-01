# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Core service for the AegisGate Python SDK."""

from typing import Any, Dict
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import Health, Version, Module


class CoreService:
    """Synchronous core service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def health(self) -> Health:
        response = self._conn.get("/health")
        return Health.from_dict(response)

    def version(self) -> Version:
        response = self._conn.get("/version")
        return Version.from_dict(response)

    def modules(self) -> list:
        response = self._conn.get("/api/v1/modules")
        modules = response.get("modules", response if isinstance(response, list) else [])
        return [Module.from_dict(m) for m in modules]

    def ready(self) -> Dict[str, Any]:
        response = self._conn.get("/ready")
        return response


class AsyncCoreService:
    """Asynchronous core service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def health(self) -> Health:
        response = await self._conn.get("/health")
        return Health.from_dict(response)

    async def version(self) -> Version:
        response = await self._conn.get("/version")
        return Version.from_dict(response)

    async def modules(self) -> list:
        response = await self._conn.get("/api/v1/modules")
        modules = response.get("modules", response if isinstance(response, list) else [])
        return [Module.from_dict(m) for m in modules]

    async def ready(self) -> Dict[str, Any]:
        response = await self._conn.get("/ready")
        return response
