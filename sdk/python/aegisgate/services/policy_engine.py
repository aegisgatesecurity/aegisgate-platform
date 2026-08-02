# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Policy Engine (OPA/Rego) service for the AegisGate Python SDK."""

from typing import Any, Dict, List, Optional
from aegisgate.connection import SyncConnection, AsyncConnection


class PolicyEngineService:
    """Synchronous policy engine service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def list_policies(self, framework: str = "") -> List[Dict[str, Any]]:
        path = "/api/v1/compliance/policy-engine"
        if framework:
            path += f"?framework={framework}"
        return self._conn.get(path)

    def evaluate(self, request=None, config=None, scan_result=None, environment=None, custom_data=None) -> Dict[str, Any]:
        body = {
            "request": request or {},
            "config": config or {},
            "scan_result": scan_result or {},
            "environment": environment or {},
            "custom_data": custom_data or {},
        }
        return self._conn.post("/api/v1/compliance/policy-engine/evaluate", body)


class AsyncPolicyEngineService:
    """Asynchronous policy engine service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def list_policies(self, framework: str = "") -> List[Dict[str, Any]]:
        path = "/api/v1/compliance/policy-engine"
        if framework:
            path += f"?framework={framework}"
        return await self._conn.get(path)

    async def evaluate(self, request=None, config=None, scan_result=None, environment=None, custom_data=None) -> Dict[str, Any]:
        body = {
            "request": request or {},
            "config": config or {},
            "scan_result": scan_result or {},
            "environment": environment or {},
            "custom_data": custom_data or {},
        }
        return await self._conn.post("/api/v1/compliance/policy-engine/evaluate", body)