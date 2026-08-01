# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.

"""
AegisGate LangChain callback handler for v3.6.0.

Intercepts LLM and tool calls for security scanning.
"""

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from aegisgate.client import Client

logger = logging.getLogger(__name__)


class AegisGateCallback:
    """LangChain callback handler that scans prompts and responses through AegisGate.

    Usage:
        from aegisgate.langchain import AegisGateCallback

        callback = AegisGateCallback(
            base_url="http://localhost:8080",
            api_key="your-key",
        )

        # Use with LangChain
        agent = AgentExecutor.from_agent_and_tools(
            agent=agent,
            tools=tools,
            callbacks=[callback],
        )
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        block_on_violation: bool = True,
        log_violations: bool = True,
        **kwargs,
    ):
        self._client = Client(base_url=base_url, api_key=api_key, **kwargs)
        self._block_on_violation = block_on_violation
        self._log_violations = log_violations
        self._violations: List[Dict[str, Any]] = []

    @property
    def client(self) -> Client:
        """Access the underlying AegisGate client."""
        return self._client

    @property
    def violations(self) -> List[Dict[str, Any]]:
        """List of detected violations."""
        return self._violations

    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs) -> None:
        """Scan LLM prompts for security violations before sending."""
        for prompt in prompts:
            self._scan_content(prompt, context="llm_prompt")

    def on_llm_new_token(self, token: str, **kwargs) -> None:
        """Optionally scan LLM output tokens."""
        pass

    def on_llm_end(self, response: Any, **kwargs) -> None:
        """Scan LLM responses for security violations."""
        try:
            if hasattr(response, "generations"):
                for generation_list in response.generations:
                    for generation in generation_list:
                        if hasattr(generation, "text"):
                            self._scan_content(generation.text, context="llm_response")
        except Exception as e:
            logger.debug(f"Error scanning LLM response: {e}")

    def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs) -> None:
        """Scan tool inputs for security violations."""
        self._scan_content(input_str, context="tool_input")

    def on_tool_end(self, output: str, **kwargs) -> None:
        """Scan tool outputs for security violations."""
        self._scan_content(output, context="tool_output")

    def on_tool_error(self, error: Exception, **kwargs) -> None:
        """Handle tool errors."""
        logger.warning(f"Tool error: {error}")

    def on_agent_action(self, action: Any, **kwargs) -> None:
        """Scan agent actions."""
        if hasattr(action, "tool_input"):
            self._scan_content(str(action.tool_input), context="agent_action")

    def _scan_content(self, content: str, context: str = "unknown") -> bool:
        """Scan content through AegisGate. Returns True if blocked."""
        try:
            result = self._client.scan.scan(content=content)
            if hasattr(result, "blocked") and result.blocked:
                self._violations.append({
                    "content": content[:100],
                    "context": context,
                    "blocked": True,
                    "reason": getattr(result, "reason", "security_violation"),
                })
                if self._log_violations:
                    logger.warning(f"AegisGate blocked {context}: {getattr(result, 'reason', 'unknown')}")
                return True
        except Exception as e:
            logger.debug(f"AegisGate scan error ({context}): {e}")
        return False

    def close(self) -> None:
        """Close the underlying client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
