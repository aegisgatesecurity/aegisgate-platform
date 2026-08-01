# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Audit service for the AegisGate Python SDK."""

from typing import Any, Dict, List, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import AuditEntry


class AuditService:
    """Synchronous audit service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def query(self, limit: Optional[int] = None, offset: Optional[int] = None,
              event_type: Optional[str] = None, agent_id: Optional[str] = None) -> List[AuditEntry]:
        params: Dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if event_type:
            params["event_type"] = event_type
        if agent_id:
            params["agent_id"] = agent_id
        response = self._conn.get("/api/v1/audit", params=params)
        entries = response.get("entries", response if isinstance(response, list) else [])
        return [AuditEntry.from_dict(e) for e in entries]


class AsyncAuditService:
    """Asynchronous audit service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def query(self, limit: Optional[int] = None, offset: Optional[int] = None,
                    event_type: Optional[str] = None, agent_id: Optional[str] = None) -> List[AuditEntry]:
        params: Dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if event_type:
            params["event_type"] = event_type
        if agent_id:
            params["agent_id"] = agent_id
        response = await self._conn.get("/api/v1/audit", params=params)
        entries = response.get("entries", response if isinstance(response, list) else [])
        return [AuditEntry.from_dict(e) for e in entries]
