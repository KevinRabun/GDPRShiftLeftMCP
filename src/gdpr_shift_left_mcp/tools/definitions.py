"""
GDPR Shift-Left MCP Server — Definitions Tools (Art. 4)
"""
import json
import logging
from typing import Any

from ..disclaimer import append_disclaimer

logger = logging.getLogger(__name__)


async def get_definition_impl(term: str, data_loader) -> str:
    """Get the GDPR definition for a specific term."""
    await data_loader.load_data()
    defn = data_loader.get_definition(term)
    if not defn:
        return append_disclaimer(
            f"Definition for '{term}' not found. Use `list_definitions` to see available terms "
            "or `search_definitions` to search by keyword."
        )
    result = f"# GDPR Definition: {defn['term']}\n\n"
    result += f"**Definition (Art. 4):** {defn['definition']}\n\n"
    result += f"*Reference: {defn.get('article_reference', 'Article 4')}*\n"
    return append_disclaimer(result)


async def list_definitions_impl(data_loader) -> str:
    """List all GDPR definitions from Article 4."""
    await data_loader.load_data()
    defs = data_loader.list_definitions()
    if not defs:
        return append_disclaimer("No definitions loaded.")

    result = "# GDPR Definitions (Article 4)\n\n"
    result += f"Found {len(defs)} definitions:\n\n"
    for d in sorted(defs, key=lambda x: x.get("term", "")):
        result += f"- **{d['term']}**: {d['definition'][:120]}...\n"
    return append_disclaimer(result)


async def search_definitions_impl(keywords: str, data_loader) -> str:
    """Search GDPR definitions by keywords."""
    await data_loader.load_data()
    results = data_loader.search_definitions(keywords)
    if not results:
        return append_disclaimer(f"No definitions match '{keywords}'.")

    output = f"# Definition Search: \"{keywords}\"\n\n"
    for d in results:
        output += f"## {d['term']}\n{d['definition']}\n\n"
    return append_disclaimer(output)
