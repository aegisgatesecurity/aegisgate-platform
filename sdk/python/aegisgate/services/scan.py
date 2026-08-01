# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Scan service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import ScanReport


class ScanService:
    """Synchronous scan service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def scan(self, content: str, framework: Optional[str] = None) -> ScanReport:
        data: Dict[str, Any] = {"content": content}
        if framework:
            data["framework"] = framework
        response = self._conn.post("/api/v1/scan", json_data=data)
        return ScanReport.from_dict(response)


class AsyncScanService:
    """Asynchronous scan service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def scan(self, content: str, framework: Optional[str] = None) -> ScanReport:
        data: Dict[str, Any] = {"content": content}
        if framework:
            data["framework"] = framework
        response = await self._conn.post("/api/v1/scan", json_data=data)
        return ScanReport.from_dict(response)
