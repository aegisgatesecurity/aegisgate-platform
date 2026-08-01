# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""AIBOM (AI Bill of Materials) service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import AIBOMResult


class AIBOMService:
    """Synchronous AIBOM service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def generate(self, model_name: Optional[str] = None, model_version: Optional[str] = None,
                 framework: Optional[str] = None, **kwargs: Any) -> AIBOMResult:
        data: Dict[str, Any] = {}
        if model_name:
            data["model_name"] = model_name
        if model_version:
            data["model_version"] = model_version
        if framework:
            data["framework"] = framework
        data.update(kwargs)
        response = self._conn.post("/api/v1/aibom/generate", json_data=data)
        return AIBOMResult.from_dict(response)

    def verify(self, bom_data: str, signature: Optional[str] = None) -> AIBOMResult:
        data: Dict[str, Any] = {"bom_data": bom_data}
        if signature:
            data["signature"] = signature
        response = self._conn.post("/api/v1/aibom/verify", json_data=data)
        return AIBOMResult.from_dict(response)


class AsyncAIBOMService:
    """Asynchronous AIBOM service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def generate(self, model_name: Optional[str] = None, model_version: Optional[str] = None,
                       framework: Optional[str] = None, **kwargs: Any) -> AIBOMResult:
        data: Dict[str, Any] = {}
        if model_name:
            data["model_name"] = model_name
        if model_version:
            data["model_version"] = model_version
        if framework:
            data["framework"] = framework
        data.update(kwargs)
        response = await self._conn.post("/api/v1/aibom/generate", json_data=data)
        return AIBOMResult.from_dict(response)

    async def verify(self, bom_data: str, signature: Optional[str] = None) -> AIBOMResult:
        data: Dict[str, Any] = {"bom_data": bom_data}
        if signature:
            data["signature"] = signature
        response = await self._conn.post("/api/v1/aibom/verify", json_data=data)
        return AIBOMResult.from_dict(response)
