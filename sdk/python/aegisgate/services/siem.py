# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""SIEM service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import SIEMStatus


class SIEMService:
    """Synchronous SIEM service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def status(self) -> SIEMStatus:
        response = self._conn.get("/api/v1/siem/status")
        return SIEMStatus.from_dict(response)


class AsyncSIEMService:
    """Asynchronous SIEM service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def status(self) -> SIEMStatus:
        response = await self._conn.get("/api/v1/siem/status")
        return SIEMStatus.from_dict(response)
