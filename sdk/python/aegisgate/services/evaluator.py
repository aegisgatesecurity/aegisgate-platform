# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Evaluator service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import EvaluatorResult


class EvaluatorService:
    """Synchronous evaluator service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def run(self, content: str, policy: Optional[str] = None, **kwargs: Any) -> EvaluatorResult:
        data: Dict[str, Any] = {"content": content}
        if policy:
            data["policy"] = policy
        data.update(kwargs)
        response = self._conn.post("/api/v1/evaluator/run", json_data=data)
        return EvaluatorResult.from_dict(response)

    def verify(self, result_id: str, **kwargs: Any) -> EvaluatorResult:
        data: Dict[str, Any] = {"result_id": result_id}
        data.update(kwargs)
        response = self._conn.post("/api/v1/evaluator/verify", json_data=data)
        return EvaluatorResult.from_dict(response)


class AsyncEvaluatorService:
    """Asynchronous evaluator service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def run(self, content: str, policy: Optional[str] = None, **kwargs: Any) -> EvaluatorResult:
        data: Dict[str, Any] = {"content": content}
        if policy:
            data["policy"] = policy
        data.update(kwargs)
        response = await self._conn.post("/api/v1/evaluator/run", json_data=data)
        return EvaluatorResult.from_dict(response)

    async def verify(self, result_id: str, **kwargs: Any) -> EvaluatorResult:
        data: Dict[str, Any] = {"result_id": result_id}
        data.update(kwargs)
        response = await self._conn.post("/api/v1/evaluator/verify", json_data=data)
        return EvaluatorResult.from_dict(response)
