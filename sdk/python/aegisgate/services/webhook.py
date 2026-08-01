# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
"""Webhook service for the AegisGate Python SDK."""

from typing import Any, Dict, List, Optional
from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import Webhook


class WebhookService:
    """Synchronous webhook service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def list(self) -> List[Webhook]:
        response = self._conn.get("/api/v1/webhooks")
        webhooks = response.get("webhooks", response if isinstance(response, list) else [])
        return [Webhook.from_dict(w) for w in webhooks]

    def create(self, url: str, events: List[str], **kwargs: Any) -> Webhook:
        data: Dict[str, Any] = {"url": url, "events": events}
        data.update(kwargs)
        response = self._conn.post("/api/v1/webhooks", json_data=data)
        return Webhook.from_dict(response)

    def delete(self, webhook_id: str) -> None:
        self._conn.delete(f"/api/v1/webhooks/{webhook_id}")

    def test(self, webhook_id: str) -> Dict[str, Any]:
        response = self._conn.post(f"/api/v1/webhooks/{webhook_id}/test")
        return response


class AsyncWebhookService:
    """Asynchronous webhook service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def list(self) -> List[Webhook]:
        response = await self._conn.get("/api/v1/webhooks")
        webhooks = response.get("webhooks", response if isinstance(response, list) else [])
        return [Webhook.from_dict(w) for w in webhooks]

    async def create(self, url: str, events: List[str], **kwargs: Any) -> Webhook:
        data: Dict[str, Any] = {"url": url, "events": events}
        data.update(kwargs)
        response = await self._conn.post("/api/v1/webhooks", json_data=data)
        return Webhook.from_dict(response)

    async def delete(self, webhook_id: str) -> None:
        await self._conn.delete(f"/api/v1/webhooks/{webhook_id}")

    async def test(self, webhook_id: str) -> Dict[str, Any]:
        response = await self._conn.post(f"/api/v1/webhooks/{webhook_id}/test")
        return response
