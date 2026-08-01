# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Digest service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import DigestResult


class DigestService:
    """Synchronous digest service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def generate(self, content: str, algorithm: Optional[str] = None) -> DigestResult:
        data: Dict[str, Any] = {"content": content}
        if algorithm:
            data["algorithm"] = algorithm
        response = self._conn.post("/api/v1/digest/generate", json_data=data)
        return DigestResult.from_dict(response)

    def verify(self, content: str, digest: str, algorithm: Optional[str] = None) -> DigestResult:
        data: Dict[str, Any] = {"content": content, "digest": digest}
        if algorithm:
            data["algorithm"] = algorithm
        response = self._conn.post("/api/v1/digest/verify", json_data=data)
        return DigestResult.from_dict(response)


class AsyncDigestService:
    """Asynchronous digest service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def generate(self, content: str, algorithm: Optional[str] = None) -> DigestResult:
        data: Dict[str, Any] = {"content": content}
        if algorithm:
            data["algorithm"] = algorithm
        response = await self._conn.post("/api/v1/digest/generate", json_data=data)
        return DigestResult.from_dict(response)

    async def verify(self, content: str, digest: str, algorithm: Optional[str] = None) -> DigestResult:
        data: Dict[str, Any] = {"content": content, "digest": digest}
        if algorithm:
            data["algorithm"] = algorithm
        response = await self._conn.post("/api/v1/digest/verify", json_data=data)
        return DigestResult.from_dict(response)
