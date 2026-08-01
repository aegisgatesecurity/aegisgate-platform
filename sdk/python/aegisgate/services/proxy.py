# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Proxy service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import Violation


class ProxyService:
    """Synchronous proxy service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def get_stats(self) -> Dict[str, Any]:
        return self._conn.get("/api/v1/stats")

    def get_violations(self, severity: Optional[str] = None, limit: Optional[int] = None) -> list:
        params: Dict[str, Any] = {}
        if severity:
            params["severity"] = severity
        if limit:
            params["limit"] = limit
        response = self._conn.get("/api/v1/guardrails", params=params)
        violations = response.get("violations", response if isinstance(response, list) else [])
        return [Violation.from_dict(v) for v in violations]

    def scan(self, content: str, framework: Optional[str] = None) -> Dict[str, Any]:
        data: Dict[str, Any] = {"content": content}
        if framework:
            data["framework"] = framework
        return self._conn.post("/api/v1/scan", json_data=data)


class AsyncProxyService:
    """Asynchronous proxy service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def get_stats(self) -> Dict[str, Any]:
        return await self._conn.get("/api/v1/stats")

    async def get_violations(self, severity: Optional[str] = None, limit: Optional[int] = None) -> list:
        params: Dict[str, Any] = {}
        if severity:
            params["severity"] = severity
        if limit:
            params["limit"] = limit
        response = await self._conn.get("/api/v1/guardrails", params=params)
        violations = response.get("violations", response if isinstance(response, list) else [])
        return [Violation.from_dict(v) for v in violations]

    async def scan(self, content: str, framework: Optional[str] = None) -> Dict[str, Any]:
        data: Dict[str, Any] = {"content": content}
        if framework:
            data["framework"] = framework
        return await self._conn.post("/api/v1/scan", json_data=data)
