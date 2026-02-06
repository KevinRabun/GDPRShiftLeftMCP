"""
Entry point for running the GDPR Shift-Left MCP server as a module.

Usage:
    python -m gdpr_shift_left_mcp
    uv run gdpr-shift-left-mcp
"""

from .server import main

if __name__ == "__main__":
    main()
