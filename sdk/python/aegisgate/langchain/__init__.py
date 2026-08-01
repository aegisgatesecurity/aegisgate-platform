# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 AegisGate Security. All rights reserved.

"""
AegisGate LangChain Integration for v3.6.0.

Provides security filtering and callback handling for LangChain agents.
"""

from aegisgate.langchain.callback import AegisGateCallback
from aegisgate.langchain.filter import AegisGateFilter

__all__ = ["AegisGateCallback", "AegisGateFilter"]
