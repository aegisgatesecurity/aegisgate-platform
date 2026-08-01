# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Policy service for the AegisGate Python SDK."""

from typing import Any, Dict, List, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import Policy


class PolicyService:
    """Synchronous policy service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def list(self) -> List[Policy]:
        response = self._conn.get("/api/v1/policies")
        policies = response.get("policies", response if isinstance(response, list) else [])
        return [Policy.from_dict(p) for p in policies]

    def get(self, policy_id: str) -> Policy:
        response = self._conn.get(f"/api/v1/policies/{policy_id}")
        return Policy.from_dict(response)


class AsyncPolicyService:
    """Asynchronous policy service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def list(self) -> List[Policy]:
        response = await self._conn.get("/api/v1/policies")
        policies = response.get("policies", response if isinstance(response, list) else [])
        return [Policy.from_dict(p) for p in policies]

    async def get(self, policy_id: str) -> Policy:
        response = await self._conn.get(f"/api/v1/policies/{policy_id}")
        return Policy.from_dict(response)
