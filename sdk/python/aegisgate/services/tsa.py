# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Tsa service for the AegisGate Python SDK."""

from typing import Any, Dict
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import TSAStatus


class TsaService:
    """Synchronous tsa service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def get(self) -> TSAStatus:
        response = self._conn.get("/api/v1/tsa/status")
        return TSAStatus.from_dict(response)


class AsyncTsaService:
    """Asynchronous tsa service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def get(self) -> TSAStatus:
        response = await self._conn.get("/api/v1/tsa/status")
        return TSAStatus.from_dict(response)
