"""
GDPR Shift-Left MCP Server — Articles & Regulation Tools

Core Q&A tools for querying GDPR articles, recitals, and Azure mappings.
"""
import json
import logging
from typing import Any

from ..disclaimer import append_disclaimer

logger = logging.getLogger(__name__)


async def get_article_impl(article_id: str, data_loader) -> str:
    """Get the full text and context of a specific GDPR article."""
    await data_loader.load_data()
    art = data_loader.get_article(article_id)
    if not art:
        return append_disclaimer(
            f"Article {article_id} not found. Use `search_gdpr` to find the correct article number."
        )

    result = f"# GDPR Article {art['article_number']}"
    if art.get("title"):
        result += f" — {art['title']}"
    result += "\n\n"
    result += f"**Chapter {art.get('chapter_number', '?')}**: {art.get('chapter_title', '')}\n\n"

    if art.get("text"):
        result += f"{art['text']}\n\n"

    if art.get("paragraphs"):
        for i, para in enumerate(art["paragraphs"], 1):
            text = para if isinstance(para, str) else para.get("text", para.get("content", ""))
            result += f"**({i})** {text}\n\n"

    # Add Azure mapping if available
    mapping = data_loader.get_azure_mapping(article_id)
    if mapping:
        result += "## Azure Implementation Guidance\n\n"
        for svc in mapping.get("azure_services", []):
            result += f"- {svc}\n"
        result += "\n"

    return append_disclaimer(result)


async def list_chapter_articles_impl(chapter: str, data_loader) -> str:
    """List all articles within a specific GDPR chapter."""
    await data_loader.load_data()
    articles = data_loader.list_chapter_articles(chapter)
    if not articles:
        CHAPTERS = {
            "1": "General Provisions (Arts. 1–4)",
            "2": "Principles (Arts. 5–11)",
            "3": "Rights of the Data Subject (Arts. 12–23)",
            "4": "Controller and Processor (Arts. 24–43)",
            "5": "Transfers to Third Countries (Arts. 44–50)",
            "6": "Independent Supervisory Authorities (Arts. 51–59)",
            "7": "Co-operation and Consistency (Arts. 60–76)",
            "8": "Remedies, Liability and Penalties (Arts. 77–84)",
            "9": "Specific Processing Situations (Arts. 85–91)",
            "10": "Delegated and Implementing Acts (Arts. 92–93)",
            "11": "Final Provisions (Arts. 94–99)",
        }
        chapters_list = "\n".join(f"- Chapter {k}: {v}" for k, v in CHAPTERS.items())
        return append_disclaimer(
            f"No articles found for chapter '{chapter}'. Available chapters:\n\n{chapters_list}"
        )

    result = f"# GDPR Chapter {chapter}\n\n"
    result += f"Found {len(articles)} articles:\n\n"
    for art in articles:
        result += f"- **Art. {art['article_number']}** — {art.get('title', 'Untitled')}\n"
    return append_disclaimer(result)


async def search_gdpr_impl(keywords: str, data_loader) -> str:
    """Search across GDPR articles and recitals by keywords."""
    await data_loader.load_data()
    articles = data_loader.search_articles(keywords)
    recitals = data_loader.search_recitals(keywords)

    result = f"# GDPR Search Results for: \"{keywords}\"\n\n"

    if articles:
        result += f"## Articles ({len(articles)} matches)\n\n"
        for art in articles[:15]:
            title = art.get("title", "Untitled")
            snippet = (art.get("text", "") or "")[:200]
            result += f"### Art. {art['article_number']} — {title}\n"
            result += f"{snippet}...\n\n"

    if recitals:
        result += f"## Recitals ({len(recitals)} matches)\n\n"
        for rec in recitals[:10]:
            snippet = (rec.get("text", "") or "")[:200]
            result += f"### Recital {rec['recital_number']}\n"
            result += f"{snippet}...\n\n"

    if not articles and not recitals:
        result += "No matches found. Try different keywords.\n"

    return append_disclaimer(result)


async def get_recital_impl(recital_number: str, data_loader) -> str:
    """Get the text of a specific GDPR recital."""
    await data_loader.load_data()
    rec = data_loader.get_recital(recital_number)
    if not rec:
        return append_disclaimer(f"Recital {recital_number} not found.")
    result = f"# GDPR Recital {rec['recital_number']}\n\n{rec.get('text', '')}\n"
    return append_disclaimer(result)


async def get_azure_mapping_impl(article_id: str, data_loader) -> str:
    """Get Azure service recommendations mapped to a specific GDPR article."""
    await data_loader.load_data()
    mapping = data_loader.get_azure_mapping(article_id)
    if not mapping:
        return append_disclaimer(
            f"No Azure mapping found for Article {article_id}. "
            "Mappings are available for key articles: 5, 25, 28, 30, 32, 33, 35, 44."
        )
    result = f"# Azure Mapping — {mapping.get('article', f'Art. {article_id}')}\n\n"
    result += "## Recommended Azure Services\n\n"
    for svc in mapping.get("azure_services", []):
        result += f"- {svc}\n"
    return append_disclaimer(result)
