# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""IOC (Indicator of Compromise) service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import IOCManifest, IOCStatus


class IOCService:
    """Synchronous IOC service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def manifest(self) -> IOCManifest:
        response = self._conn.get("/api/v1/ioc/manifest")
        return IOCManifest.from_dict(response)

    def health(self) -> Dict[str, Any]:
        response = self._conn.get("/api/v1/ioc/health")
        return response

    def admin_status(self) -> IOCStatus:
        response = self._conn.get("/api/v1/ioc/admin/status")
        return IOCStatus.from_dict(response)


class AsyncIOCService:
    """Asynchronous IOC service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def manifest(self) -> IOCManifest:
        response = await self._conn.get("/api/v1/ioc/manifest")
        return IOCManifest.from_dict(response)

    async def health(self) -> Dict[str, Any]:
        response = await self._conn.get("/api/v1/ioc/health")
        return response

    async def admin_status(self) -> IOCStatus:
        response = await self._conn.get("/api/v1/ioc/admin/status")
        return IOCStatus.from_dict(response)
