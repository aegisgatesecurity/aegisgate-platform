# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""A2A (Agent-to-Agent) service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import A2AIntentResult


class A2AService:
    """Synchronous A2A service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def sign_intent(self, intent: str, agent_id: Optional[str] = None, **kwargs: Any) -> A2AIntentResult:
        data: Dict[str, Any] = {"intent": intent}
        if agent_id:
            data["agent_id"] = agent_id
        data.update(kwargs)
        response = self._conn.post("/api/v1/a2a/intent/sign", json_data=data)
        return A2AIntentResult.from_dict(response)

    def verify_intent(self, intent: str, signature: str, agent_id: Optional[str] = None) -> A2AIntentResult:
        data: Dict[str, Any] = {"intent": intent, "signature": signature}
        if agent_id:
            data["agent_id"] = agent_id
        response = self._conn.post("/api/v1/a2a/intent/verify", json_data=data)
        return A2AIntentResult.from_dict(response)


class AsyncA2AService:
    """Asynchronous A2A service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def sign_intent(self, intent: str, agent_id: Optional[str] = None, **kwargs: Any) -> A2AIntentResult:
        data: Dict[str, Any] = {"intent": intent}
        if agent_id:
            data["agent_id"] = agent_id
        data.update(kwargs)
        response = await self._conn.post("/api/v1/a2a/intent/sign", json_data=data)
        return A2AIntentResult.from_dict(response)

    async def verify_intent(self, intent: str, signature: str, agent_id: Optional[str] = None) -> A2AIntentResult:
        data: Dict[str, Any] = {"intent": intent, "signature": signature}
        if agent_id:
            data["agent_id"] = agent_id
        response = await self._conn.post("/api/v1/a2a/intent/verify", json_data=data)
        return A2AIntentResult.from_dict(response)
