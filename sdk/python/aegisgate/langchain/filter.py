# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.

"""
AegisGate LangChain content filter for v3.6.0.

Filters prompts and responses through AegisGate security scanning.
"""

import logging
from typing import Any, Dict, List, Optional

from aegisgate.client import Client

logger = logging.getLogger(__name__)


class AegisGateFilter:
    """LangChain content filter that uses AegisGate for security scanning.

    Usage:
        from aegisgate.langchain import AegisGateFilter

        filter = AegisGateFilter(
            base_url="http://localhost:8080",
            api_key="your-key",
        )

        # Filter a prompt
        safe_prompt = filter.filter_prompt("Hello, world!")

        # Filter a response
        safe_response = filter.filter_response("Here is the answer...")
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        block_on_violation: bool = True,
        replacement_text: str = "[BLOCKED BY AEGISGATE]",
        **kwargs,
    ):
        self._client = Client(base_url=base_url, api_key=api_key, **kwargs)
        self._block_on_violation = block_on_violation
        self._replacement_text = replacement_text
        self._filtered_count = 0

    @property
    def client(self) -> Client:
        """Access the underlying AegisGate client."""
        return self._client

    @property
    def filtered_count(self) -> int:
        """Number of content items filtered."""
        return self._filtered_count

    def filter_prompt(self, prompt: str) -> str:
        """Filter a user prompt through AegisGate.

        Returns the original prompt if safe, or replacement text if blocked.
        """
        if self._is_safe(prompt, context="prompt"):
            return prompt
        self._filtered_count += 1
        if self._block_on_violation:
            return self._replacement_text
        return prompt

    def filter_response(self, response: str) -> str:
        """Filter an LLM response through AegisGate.

        Returns the original response if safe, or replacement text if blocked.
        """
        if self._is_safe(response, context="response"):
            return response
        self._filtered_count += 1
        if self._block_on_violation:
            return self._replacement_text
        return response

    def _is_safe(self, content: str, context: str = "unknown") -> bool:
        """Check if content is safe using AegisGate scanning."""
        try:
            result = self._client.scan.scan(content=content)
            if hasattr(result, "blocked") and result.blocked:
                logger.warning(f"AegisGate filtered {context}: {getattr(result, 'reason', 'unknown')}")
                return False
            return True
        except Exception as e:
            logger.debug(f"AegisGate scan error ({context}): {e}")
            return True  # Fail open

    def close(self) -> None:
        """Close the underlying client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
