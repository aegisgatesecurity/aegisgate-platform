# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Evasion Resistance service for the AegisGate Python SDK."""

from typing import Any, Dict, List, Optional
from aegisgate.connection import SyncConnection, AsyncConnection


class EvasionService:
    """Synchronous evasion resistance detection service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def detect(self, text: str) -> Dict[str, Any]:
        return self._conn.post("/api/v1/ml/evasion/detect", {"text": text})


class AsyncEvasionService:
    """Asynchronous evasion resistance detection service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def detect(self, text: str) -> Dict[str, Any]:
        return await self._conn.post("/api/v1/ml/evasion/detect", {"text": text})