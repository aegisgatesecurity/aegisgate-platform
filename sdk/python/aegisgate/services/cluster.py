# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Cluster service for the AegisGate Python SDK."""

from typing import Any, Dict
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import ClusterHealth


class ClusterService:
    """Synchronous cluster service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def health(self) -> ClusterHealth:
        response = self._conn.get("/api/v1/cluster/health")
        return ClusterHealth.from_dict(response)


class AsyncClusterService:
    """Asynchronous cluster service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def health(self) -> ClusterHealth:
        response = await self._conn.get("/api/v1/cluster/health")
        return ClusterHealth.from_dict(response)
