# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Incident service for the AegisGate Python SDK."""

from typing import Any, Dict, List, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import Incident, IncidentTriage, IncidentResolve


class IncidentService:
    """Synchronous incident service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def create(self, title: str, severity: str, description: Optional[str] = None, **kwargs: Any) -> Incident:
        data: Dict[str, Any] = {"title": title, "severity": severity}
        if description:
            data["description"] = description
        data.update(kwargs)
        response = self._conn.post("/api/v1/incidents", json_data=data)
        return Incident.from_dict(response)

    def get(self, incident_id: str) -> Incident:
        response = self._conn.get(f"/api/v1/incidents/{incident_id}")
        return Incident.from_dict(response)

    def triage(self, incident_id: str, priority: Optional[str] = None, assignee: Optional[str] = None) -> IncidentTriage:
        data: Dict[str, Any] = {}
        if priority:
            data["priority"] = priority
        if assignee:
            data["assignee"] = assignee
        response = self._conn.post(f"/api/v1/incidents/{incident_id}/triage", json_data=data)
        return IncidentTriage.from_dict(response)

    def resolve(self, incident_id: str, resolution: str, **kwargs: Any) -> IncidentResolve:
        data: Dict[str, Any] = {"resolution": resolution}
        data.update(kwargs)
        response = self._conn.post(f"/api/v1/incidents/{incident_id}/resolve", json_data=data)
        return IncidentResolve.from_dict(response)


class AsyncIncidentService:
    """Asynchronous incident service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def create(self, title: str, severity: str, description: Optional[str] = None, **kwargs: Any) -> Incident:
        data: Dict[str, Any] = {"title": title, "severity": severity}
        if description:
            data["description"] = description
        data.update(kwargs)
        response = await self._conn.post("/api/v1/incidents", json_data=data)
        return Incident.from_dict(response)

    async def get(self, incident_id: str) -> Incident:
        response = await self._conn.get(f"/api/v1/incidents/{incident_id}")
        return Incident.from_dict(response)

    async def triage(self, incident_id: str, priority: Optional[str] = None, assignee: Optional[str] = None) -> IncidentTriage:
        data: Dict[str, Any] = {}
        if priority:
            data["priority"] = priority
        if assignee:
            data["assignee"] = assignee
        response = await self._conn.post(f"/api/v1/incidents/{incident_id}/triage", json_data=data)
        return IncidentTriage.from_dict(response)

    async def resolve(self, incident_id: str, resolution: str, **kwargs: Any) -> IncidentResolve:
        data: Dict[str, Any] = {"resolution": resolution}
        data.update(kwargs)
        response = await self._conn.post(f"/api/v1/incidents/{incident_id}/resolve", json_data=data)
        return IncidentResolve.from_dict(response)
