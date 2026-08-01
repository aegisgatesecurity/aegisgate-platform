# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""License service for the AegisGate Python SDK."""

from typing import Any, Dict
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import LicenseStatus


class LicenseService:
    """Synchronous license service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def get(self) -> LicenseStatus:
        response = self._conn.get("/api/v1/license/status")
        return LicenseStatus.from_dict(response)


class AsyncLicenseService:
    """Asynchronous license service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def get(self) -> LicenseStatus:
        response = await self._conn.get("/api/v1/license/status")
        return LicenseStatus.from_dict(response)
