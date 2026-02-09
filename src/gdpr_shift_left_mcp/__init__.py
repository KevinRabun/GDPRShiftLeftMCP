"""
GDPR Shift-Left MCP Server

An MCP (Model Context Protocol) server that provides GDPR compliance
guidance, code review, and audit tools with Azure-first recommendations.
"""

__version__ = "0.2.0"
__author__ = "GDPR Shift Left MCP Server Contributors"
__license__ = "MIT"

from .server import main

__all__ = ["main"]
