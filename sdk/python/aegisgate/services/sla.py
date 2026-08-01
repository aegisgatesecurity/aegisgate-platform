# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Sla service for the AegisGate Python SDK."""

from typing import Any, Dict
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import SLAInfo


class SlaService:
    """Synchronous sla service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def get(self) -> SLAInfo:
        response = self._conn.get("/api/v1/sla")
        return SLAInfo.from_dict(response)


class AsyncSlaService:
    """Asynchronous sla service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def get(self) -> SLAInfo:
        response = await self._conn.get("/api/v1/sla")
        return SLAInfo.from_dict(response)
