# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.

"""
Authentication service for the AegisGate Python SDK.
"""

from typing import Any, Dict, List, Optional

from aegisgate.connection import SyncConnection, AsyncConnection
from aegisgate.models import User


class AuthService:
    """Synchronous authentication service."""

    def __init__(self, connection: SyncConnection):
        self._conn = connection

    def login(self, username: str, password: str) -> Dict[str, Any]:
        response = self._conn.post(
            "/api/v1/auth/login",
            json_data={"username": username, "password": password},
        )
        return response

    def logout(self) -> None:
        self._conn.post("/api/v1/auth/logout")

    def validate_token(self, token: str) -> Dict[str, Any]:
        response = self._conn.post("/api/v1/auth/validate", json_data={"token": token})
        return response

    def list_users(self) -> List[User]:
        response = self._conn.get("/api/v1/users")
        users = response.get("users", [])
        return [User.from_dict(u) for u in users]

    def get_user(self, user_id: str) -> User:
        response = self._conn.get(f"/api/v1/users/{user_id}")
        return User.from_dict(response)

    def create_user(self, email: str, name: str, roles: List[str]) -> User:
        response = self._conn.post(
            "/api/v1/users",
            json_data={"email": email, "name": name, "roles": roles},
        )
        return User.from_dict(response)

    def update_user(self, user_id: str, **kwargs) -> User:
        response = self._conn.patch(f"/api/v1/users/{user_id}", json_data=kwargs)
        return User.from_dict(response)

    def delete_user(self, user_id: str) -> None:
        self._conn.delete(f"/api/v1/users/{user_id}")


class AsyncAuthService:
    """Asynchronous authentication service."""

    def __init__(self, connection: AsyncConnection):
        self._conn = connection

    async def login(self, username: str, password: str) -> Dict[str, Any]:
        response = await self._conn.post(
            "/api/v1/auth/login",
            json_data={"username": username, "password": password},
        )
        return response

    async def logout(self) -> None:
        await self._conn.post("/api/v1/auth/logout")

    async def validate_token(self, token: str) -> Dict[str, Any]:
        response = await self._conn.post("/api/v1/auth/validate", json_data={"token": token})
        return response

    async def list_users(self) -> List[User]:
        response = await self._conn.get("/api/v1/users")
        users = response.get("users", [])
        return [User.from_dict(u) for u in users]

    async def get_user(self, user_id: str) -> User:
        response = await self._conn.get(f"/api/v1/users/{user_id}")
        return User.from_dict(response)

    async def create_user(self, email: str, name: str, roles: List[str]) -> User:
        response = await self._conn.post(
            "/api/v1/users",
            json_data={"email": email, "name": name, "roles": roles},
        )
        return User.from_dict(response)

    async def update_user(self, user_id: str, **kwargs) -> User:
        response = await self._conn.patch(f"/api/v1/users/{user_id}", json_data=kwargs)
        return User.from_dict(response)

    async def delete_user(self, user_id: str) -> None:
        await self._conn.delete(f"/api/v1/users/{user_id}")