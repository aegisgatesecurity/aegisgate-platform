# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Attestation service for the AegisGate Python SDK."""

from typing import Any, Dict, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import AttestationResult


class AttestationService:
    """Synchronous attestation service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def verify(self, payload: str, signature: Optional[str] = None, key_id: Optional[str] = None) -> AttestationResult:
        data: Dict[str, Any] = {"payload": payload}
        if signature:
            data["signature"] = signature
        if key_id:
            data["key_id"] = key_id
        response = self._conn.post("/api/v1/attestation/verify", json_data=data)
        return AttestationResult.from_dict(response)

    def verify_online(self, payload: str, signature: Optional[str] = None, key_id: Optional[str] = None) -> AttestationResult:
        data: Dict[str, Any] = {"payload": payload}
        if signature:
            data["signature"] = signature
        if key_id:
            data["key_id"] = key_id
        response = self._conn.post("/api/v1/attestation/verify-online", json_data=data)
        return AttestationResult.from_dict(response)


class AsyncAttestationService:
    """Asynchronous attestation service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def verify(self, payload: str, signature: Optional[str] = None, key_id: Optional[str] = None) -> AttestationResult:
        data: Dict[str, Any] = {"payload": payload}
        if signature:
            data["signature"] = signature
        if key_id:
            data["key_id"] = key_id
        response = await self._conn.post("/api/v1/attestation/verify", json_data=data)
        return AttestationResult.from_dict(response)

    async def verify_online(self, payload: str, signature: Optional[str] = None, key_id: Optional[str] = None) -> AttestationResult:
        data: Dict[str, Any] = {"payload": payload}
        if signature:
            data["signature"] = signature
        if key_id:
            data["key_id"] = key_id
        response = await self._conn.post("/api/v1/attestation/verify-online", json_data=data)
        return AttestationResult.from_dict(response)
