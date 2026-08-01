# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.

"""
HTTP connection handling for the AegisGate Python SDK.
"""

import asyncio
import json
import ssl
from typing import Any, Dict, Optional

import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ConnectionError(Exception):
    """Connection error."""
    pass


class APIError(Exception):
    """API error response."""
    def __init__(self, message: str, status_code: int, details: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details


class ConnectionConfig:
    """Connection configuration."""

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        verify_ssl: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.custom_headers = custom_headers or {}
        self.proxy = proxy

    def get_headers(self) -> Dict[str, str]:
        """Get default headers for requests."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "AegisGate-Python-SDK/3.6.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.update(self.custom_headers)
        return headers


class SyncConnection:
    """Synchronous HTTP connection handler."""

    def __init__(self, config: ConnectionConfig):
        self.config = config
        self._session: Optional[requests.Session] = None

    def _create_session(self) -> requests.Session:
        """Create a new session with retry handling."""
        session = requests.Session()

        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        if self.config.proxy:
            session.proxies = {
                "http": self.config.proxy,
                "https": self.config.proxy,
            }

        return session

    def connect(self) -> None:
        """Initialize the connection."""
        if self._session is None:
            self._session = self._create_session()

    def close(self) -> None:
        """Close the connection."""
        if self._session:
            self._session.close()
            self._session = None

    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Handle API response."""
        try:
            data = response.json()
        except json.JSONDecodeError:
            data = {"raw": response.text}

        if response.status_code >= 400:
            raise APIError(
                message=data.get("message", response.text),
                status_code=response.status_code,
                details=data,
            )

        return data

    def get(self, path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a GET request."""
        self.connect()
        assert self._session is not None
        response = self._session.get(
            f"{self.config.base_url}{path}",
            headers=self.config.get_headers(),
            params=params,
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
        )
        return self._handle_response(response)

    def post(self, path: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a POST request."""
        self.connect()
        assert self._session is not None
        response = self._session.post(
            f"{self.config.base_url}{path}",
            headers=self.config.get_headers(),
            data=data,
            json=json_data,
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
        )
        return self._handle_response(response)

    def put(self, path: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a PUT request."""
        self.connect()
        assert self._session is not None
        response = self._session.put(
            f"{self.config.base_url}{path}",
            headers=self.config.get_headers(),
            data=data,
            json=json_data,
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
        )
        return self._handle_response(response)

    def delete(self, path: str) -> Dict[str, Any]:
        """Make a DELETE request."""
        self.connect()
        assert self._session is not None
        response = self._session.delete(
            f"{self.config.base_url}{path}",
            headers=self.config.get_headers(),
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
        )
        return self._handle_response(response)

    def patch(self, path: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a PATCH request."""
        self.connect()
        assert self._session is not None
        response = self._session.patch(
            f"{self.config.base_url}{path}",
            headers=self.config.get_headers(),
            data=data,
            json=json_data,
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
        )
        return self._handle_response(response)


class AsyncConnection:
    """Asynchronous HTTP connection handler."""

    def __init__(self, config: ConnectionConfig):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._ssl_context: Optional[ssl.SSLContext] = None

    async def connect(self) -> None:
        """Initialize the async connection."""
        if self._session is None:
            if not self.config.verify_ssl:
                self._ssl_context = ssl.create_default_context()
                self._ssl_context.check_hostname = False
                self._ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=self._ssl_context)
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)

            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=self.config.get_headers(),
            )

    async def close(self) -> None:
        """Close the async connection."""
        if self._session:
            await self._session.close()
            self._session = None

    async def _handle_response(self, response: aiohttp.ClientResponse) -> Dict[str, Any]:
        """Handle async API response."""
        try:
            data = await response.json()
        except json.JSONDecodeError:
            data = {"raw": await response.text()}

        if response.status >= 400:
            raise APIError(
                message=data.get("message", str(response.status)),
                status_code=response.status,
                details=data,
            )

        return data

    async def get(self, path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make an async GET request."""
        await self.connect()
        assert self._session is not None
        async with self._session.get(
            f"{self.config.base_url}{path}",
            params=params,
        ) as response:
            return await self._handle_response(response)

    async def post(self, path: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make an async POST request."""
        await self.connect()
        assert self._session is not None
        async with self._session.post(
            f"{self.config.base_url}{path}",
            data=data,
            json=json_data,
        ) as response:
            return await self._handle_response(response)

    async def put(self, path: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make an async PUT request."""
        await self.connect()
        assert self._session is not None
        async with self._session.put(
            f"{self.config.base_url}{path}",
            data=data,
            json=json_data,
        ) as response:
            return await self._handle_response(response)

    async def delete(self, path: str) -> Dict[str, Any]:
        """Make an async DELETE request."""
        await self.connect()
        assert self._session is not None
        async with self._session.delete(
            f"{self.config.base_url}{path}",
        ) as response:
            return await self._handle_response(response)

    async def patch(self, path: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make an async PATCH request."""
        await self.connect()
        assert self._session is not None
        async with self._session.patch(
            f"{self.config.base_url}{path}",
            data=data,
            json=json_data,
        ) as response:
            return await self._handle_response(response)