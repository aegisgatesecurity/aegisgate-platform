# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""ML A/B Testing service for the AegisGate Python SDK."""

from typing import Any, Dict, List, Optional
from aegisgate.connection import SyncConnection, AsyncConnection


class ABTestService:
    """Synchronous ML A/B testing service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def list_tests(self, status: str = "") -> List[Dict[str, Any]]:
        path = "/api/v1/ml/ab-tests"
        if status:
            path += f"?status={status}"
        return self._conn.get(path)

    def create_test(self, name: str, champion_model_path: str, challenger_model_path: str,
                    champion_version: str = "", challenger_version: str = "",
                    traffic_split_pct: float = 10.0, min_sample_size: int = 1000,
                    confidence_level: float = 0.95) -> Dict[str, Any]:
        return self._conn.post("/api/v1/ml/ab-tests", {
            "name": name,
            "champion_model_path": champion_model_path,
            "challenger_model_path": challenger_model_path,
            "champion_version": champion_version,
            "challenger_version": challenger_version,
            "traffic_split_pct": traffic_split_pct,
            "min_sample_size": min_sample_size,
            "confidence_level": confidence_level,
        })

    def get_test_status(self, test_id: str) -> Dict[str, Any]:
        return self._conn.get(f"/api/v1/ml/ab-tests/{test_id}")

    def evaluate_test(self, test_id: str) -> Dict[str, Any]:
        return self._conn.post(f"/api/v1/ml/ab-tests/{test_id}/evaluate", {})


class AsyncABTestService:
    """Asynchronous ML A/B testing service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def list_tests(self, status: str = "") -> List[Dict[str, Any]]:
        path = "/api/v1/ml/ab-tests"
        if status:
            path += f"?status={status}"
        return await self._conn.get(path)

    async def create_test(self, name: str, champion_model_path: str, challenger_model_path: str,
                         champion_version: str = "", challenger_version: str = "",
                         traffic_split_pct: float = 10.0, min_sample_size: int = 1000,
                         confidence_level: float = 0.95) -> Dict[str, Any]:
        return await self._conn.post("/api/v1/ml/ab-tests", {
            "name": name,
            "champion_model_path": champion_model_path,
            "challenger_model_path": challenger_model_path,
            "champion_version": champion_version,
            "challenger_version": challenger_version,
            "traffic_split_pct": traffic_split_pct,
            "min_sample_size": min_sample_size,
            "confidence_level": confidence_level,
        })

    async def get_test_status(self, test_id: str) -> Dict[str, Any]:
        return await self._conn.get(f"/api/v1/ml/ab-tests/{test_id}")

    async def evaluate_test(self, test_id: str) -> Dict[str, Any]:
        return await self._conn.post(f"/api/v1/ml/ab-tests/{test_id}/evaluate", {})