"""
GDPR Shift-Left MCP Server

This module implements an MCP server that provides GDPR compliance
guidance, Azure IaC/code review, and audit tools.
"""

import asyncio
import logging
import sys
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from .data_loader import get_data_loader
from .tools import register_tools

# Configure logging to stderr only (MCP requirement)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)

logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("GDPR Shift-Left Compliance Server")

# Initialize data loader
data_loader = get_data_loader()

# Register all tools
register_tools(mcp, data_loader)


# ─── Prompts ────────────────────────────────────────────────────────────────

@mcp.prompt()
async def gap_analysis() -> str:
    """
    Guide a GDPR gap analysis by identifying which articles and obligations
    apply to your system and what technical/organizational measures are needed.
    """
    from .prompts import load_prompt
    return load_prompt("gap_analysis")


@mcp.prompt()
async def dpia_assessment() -> str:
    """
    Walk through a Data Protection Impact Assessment (DPIA) per GDPR Art. 35,
    evaluating necessity, proportionality, and risk mitigation measures.
    """
    from .prompts import load_prompt
    return load_prompt("dpia_assessment")


@mcp.prompt()
async def compliance_roadmap() -> str:
    """
    Generate a phased GDPR compliance roadmap covering technical measures,
    organizational measures, and Azure-specific implementation guidance.
    """
    from .prompts import load_prompt
    return load_prompt("compliance_roadmap")


@mcp.prompt()
async def data_mapping() -> str:
    """
    Guide creation of a data-processing inventory (Art. 30 ROPA) by
    systematically identifying processing activities, purposes, and data flows.
    """
    from .prompts import load_prompt
    return load_prompt("data_mapping")


@mcp.prompt()
async def incident_response() -> str:
    """
    Framework for GDPR breach notification (Art. 33/34) including 72-hour
    supervisory authority notification and data-subject communication.
    """
    from .prompts import load_prompt
    return load_prompt("incident_response")


@mcp.prompt()
async def azure_privacy_review() -> str:
    """
    Review Azure architecture and IaC for GDPR compliance: data residency,
    encryption, access controls, logging, and retention policies.
    """
    from .prompts import load_prompt
    return load_prompt("azure_privacy_review")


@mcp.prompt()
async def vendor_assessment() -> str:
    """
    Evaluate third-party processors per GDPR Art. 28 including contractual
    requirements, technical safeguards, and sub-processor management.
    """
    from .prompts import load_prompt
    return load_prompt("vendor_assessment")


@mcp.prompt()
async def cross_border_transfers() -> str:
    """
    Guide compliance with GDPR Chapter V (Arts. 44-49) on international
    data transfers, including adequacy decisions, SCCs, and BCRs.
    """
    from .prompts import load_prompt
    return load_prompt("cross_border_transfers")


def main():
    """Run the GDPR Shift-Left MCP server."""
    logger.info("Starting GDPR Shift-Left MCP Server")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
