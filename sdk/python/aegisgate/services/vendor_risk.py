# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Vendor Risk Assessment service for the AegisGate Python SDK."""

from typing import Any, Dict, List, Optional
from aegisgate.connection import SyncConnection, AsyncConnection


class VendorRiskService:
    """Synchronous vendor risk assessment service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def list_profiles(self) -> List[Dict[str, Any]]:
        return self._conn.get("/api/v1/compliance/vendor-risk")

    def get_profile(self, vendor: str) -> Dict[str, Any]:
        return self._conn.get(f"/api/v1/compliance/vendor-risk?vendor={vendor}")

    def assess(self, vendor_name: str, category: str = "") -> Dict[str, Any]:
        return self._conn.post("/api/v1/compliance/vendor-risk/assess", {"vendor_name": vendor_name, "category": category})


class AsyncVendorRiskService:
    """Asynchronous vendor risk assessment service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def list_profiles(self) -> List[Dict[str, Any]]:
        return await self._conn.get("/api/v1/compliance/vendor-risk")

    async def get_profile(self, vendor: str) -> Dict[str, Any]:
        return await self._conn.get(f"/api/v1/compliance/vendor-risk?vendor={vendor}")

    async def assess(self, vendor_name: str, category: str = "") -> Dict[str, Any]:
        return await self._conn.post("/api/v1/compliance/vendor-risk/assess", {"vendor_name": vendor_name, "category": category})