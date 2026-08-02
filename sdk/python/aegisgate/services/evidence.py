# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Evidence Automation service for the AegisGate Python SDK."""

from typing import Any, Dict, List, Optional
from aegisgate.connection import SyncConnection, AsyncConnection


class EvidenceService:
    """Synchronous evidence automation service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def list_evidence(self, framework: str = "", control_id: str = "", evidence_type: str = "") -> List[Dict[str, Any]]:
        params = []
        if framework:
            params.append(f"framework={framework}")
        if control_id:
            params.append(f"control_id={control_id}")
        if evidence_type:
            params.append(f"type={evidence_type}")
        path = "/api/v1/compliance/evidence"
        if params:
            path += "?" + "&".join(params)
        return self._conn.get(path)

    def collect(self, framework: str, control_id: str = "", evidence_type: str = "") -> Dict[str, Any]:
        return self._conn.post("/api/v1/compliance/evidence/collect", {"framework": framework, "control_id": control_id, "type": evidence_type})

    def verify(self, evidence_id: str, verified_by: str) -> Dict[str, Any]:
        return self._conn.post("/api/v1/compliance/evidence/verify", {"id": evidence_id, "verified_by": verified_by})


class AsyncEvidenceService:
    """Asynchronous evidence automation service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def list_evidence(self, framework: str = "", control_id: str = "", evidence_type: str = "") -> List[Dict[str, Any]]:
        params = []
        if framework:
            params.append(f"framework={framework}")
        if control_id:
            params.append(f"control_id={control_id}")
        if evidence_type:
            params.append(f"type={evidence_type}")
        path = "/api/v1/compliance/evidence"
        if params:
            path += "?" + "&".join(params)
        return await self._conn.get(path)

    async def collect(self, framework: str, control_id: str = "", evidence_type: str = "") -> Dict[str, Any]:
        return await self._conn.post("/api/v1/compliance/evidence/collect", {"framework": framework, "control_id": control_id, "type": evidence_type})

    async def verify(self, evidence_id: str, verified_by: str) -> Dict[str, Any]:
        return await self._conn.post("/api/v1/compliance/evidence/verify", {"id": evidence_id, "verified_by": verified_by})