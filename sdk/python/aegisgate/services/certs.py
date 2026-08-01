# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Certs service for the AegisGate Python SDK."""

from typing import Any, Dict
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import CertInfo


class CertsService:
    """Synchronous certs service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def get(self) -> CertInfo:
        response = self._conn.get("/api/v1/certs")
        return CertInfo.from_dict(response)


class AsyncCertsService:
    """Asynchronous certs service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def get(self) -> CertInfo:
        response = await self._conn.get("/api/v1/certs")
        return CertInfo.from_dict(response)
