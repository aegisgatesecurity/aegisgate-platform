# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Guardrails service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import GuardrailsResult


class GuardrailsService:
    """Synchronous guardrails service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def check(self, content: str, policy: Optional[str] = None) -> GuardrailsResult:
        data: Dict[str, Any] = {"content": content}
        if policy:
            data["policy"] = policy
        response = self._conn.get("/api/v1/guardrails", params={"content": content})
        return GuardrailsResult.from_dict(response)


class AsyncGuardrailsService:
    """Asynchronous guardrails service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def check(self, content: str, policy: Optional[str] = None) -> GuardrailsResult:
        data: Dict[str, Any] = {"content": content}
        if policy:
            data["policy"] = policy
        response = await self._conn.get("/api/v1/guardrails", params={"content": content})
        return GuardrailsResult.from_dict(response)
