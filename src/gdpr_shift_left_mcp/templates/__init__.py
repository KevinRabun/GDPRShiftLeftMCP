"""
GDPR Shift-Left MCP Server — Templates

Provides GDPR-aligned Azure infrastructure templates (Bicep, Terraform)
that can be used as starting points for compliant deployments.
"""
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent


def load_template(name: str) -> Optional[str]:
    """Load a template by name (with extension).

    Args:
        name: Template filename, e.g. "gdpr_storage.bicep".

    Returns:
        The template content, or ``None`` if not found.
    """
    path = _TEMPLATE_DIR / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    logger.warning("Template '%s' not found in %s", name, _TEMPLATE_DIR)
    return None


def list_templates() -> list[dict]:
    """List all available templates with metadata."""
    templates = []
    for ext in ("*.bicep", "*.tf", "*.json"):
        for path in _TEMPLATE_DIR.glob(ext):
            if path.stem.startswith("_"):
                continue
            templates.append({
                "name": path.name,
                "type": path.suffix.lstrip("."),
                "description": _extract_description(path),
            })
    return sorted(templates, key=lambda t: t["name"])


def _extract_description(path: Path) -> str:
    """Extract the first comment block as a description."""
    try:
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines()[:5]:
            stripped = line.strip()
            if stripped.startswith("//"):
                return stripped.lstrip("/ ").strip()
            if stripped.startswith("/*"):
                return stripped.lstrip("/* ").rstrip("*/").strip()
            if stripped.startswith("#"):
                return stripped.lstrip("# ").strip()
    except Exception:
        pass
    return ""
