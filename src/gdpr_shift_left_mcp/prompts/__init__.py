"""
GDPR Shift-Left MCP Server — Prompt Loader

Loads structured prompt templates from text files in this package directory.
"""
import importlib.resources
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_PROMPT_DIR = Path(__file__).parent


def load_prompt(name: str) -> Optional[str]:
    """Load a prompt template by name (without extension).

    Args:
        name: Prompt filename stem, e.g. "gap_analysis".

    Returns:
        The prompt text, or ``None`` if not found.
    """
    candidates = [_PROMPT_DIR / f"{name}.txt", _PROMPT_DIR / f"{name}.md"]
    for path in candidates:
        if path.exists():
            return path.read_text(encoding="utf-8")
    logger.warning("Prompt '%s' not found in %s", name, _PROMPT_DIR)
    return None


def list_prompts() -> list[str]:
    """List all available prompt names."""
    return sorted(
        p.stem for p in _PROMPT_DIR.glob("*.txt") if p.stem != "__init__"
    )
