"""
GDPR Shift-Left MCP Server — Data Loader

Fetches and caches GDPR regulation text (articles, recitals, definitions)
from authoritative sources. Supports online updates with configurable TTL.

Data sources:
  - Primary: Bundled GDPR knowledge base (vendored JSON)
  - Online:  EUR-Lex / structured GitHub mirror for updates
  - Supplementary: EDPB guideline summaries, ICO guidance references
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ─── Constants ──────────────────────────────────────────────────────────────

CACHE_DIR = Path(__file__).parent / "__gdpr_cache__"
CACHE_TTL_SECONDS = 3600  # 1 hour default

# Online source for structured GDPR text (placeholder — point to real endpoint)
GDPR_SOURCE_URL = os.environ.get(
    "GDPR_SOURCE_URL",
    "https://raw.githubusercontent.com/AustinMathuw/gdpr/master/gdpr.json",
)

# ─── Singleton ──────────────────────────────────────────────────────────────

_data_loader: Optional["GDPRDataLoader"] = None


def get_data_loader() -> "GDPRDataLoader":
    """Return the singleton data loader."""
    global _data_loader
    if _data_loader is None:
        _data_loader = GDPRDataLoader()
    return _data_loader


# ─── Data Loader ────────────────────────────────────────────────────────────


class GDPRDataLoader:
    """
    Load, cache, and index GDPR regulation data.

    Lifecycle:
        1. ``await loader.load_data()`` — fetch/cache then index.
        2. Use ``get_article``, ``search_articles``, etc.
    """

    def __init__(self, cache_dir: Optional[Path] = None, ttl: int = CACHE_TTL_SECONDS):
        self._cache_dir = cache_dir or CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._ttl = ttl
        self._loaded = False

        # Indexed data stores
        self._articles: Dict[str, Dict[str, Any]] = {}
        self._chapters: Dict[str, List[Dict[str, Any]]] = {}
        self._recitals: Dict[str, Dict[str, Any]] = {}
        self._definitions: Dict[str, Dict[str, Any]] = {}

        # Supplementary guidance
        self._edpb_guidelines: List[Dict[str, Any]] = []
        self._azure_mappings: Dict[str, Any] = {}

    # ── Public API ──────────────────────────────────────────────────────

    async def load_data(self) -> None:
        """Ensure data is loaded (idempotent)."""
        if self._loaded:
            return
        raw = await self._fetch_or_cache()
        self._index(raw)
        self._load_supplementary()
        self._loaded = True
        logger.info(
            "GDPR data loaded: %d articles, %d recitals, %d definitions",
            len(self._articles),
            len(self._recitals),
            len(self._definitions),
        )

    # ── Article helpers ─────────────────────────────────────────────────

    def get_article(self, article_id: str) -> Optional[Dict[str, Any]]:
        """Get a single GDPR article by id (e.g. '5', '25', '32')."""
        return self._articles.get(article_id.strip().lstrip("Art.").lstrip("Article").strip())

    def list_chapter_articles(self, chapter: str) -> List[Dict[str, Any]]:
        """Return all articles in a given chapter number."""
        return self._chapters.get(str(chapter).strip(), [])

    def search_articles(self, keywords: str) -> List[Dict[str, Any]]:
        """Full-text keyword search across article text."""
        kw = keywords.lower().split()
        if not kw:
            return []
        results = []
        for art in self._articles.values():
            text = json.dumps(art).lower()
            if all(k in text for k in kw):
                results.append(art)
        return results

    # ── Recital helpers ─────────────────────────────────────────────────

    def get_recital(self, recital_number: str) -> Optional[Dict[str, Any]]:
        return self._recitals.get(str(recital_number).strip())

    def search_recitals(self, keywords: str) -> List[Dict[str, Any]]:
        kw = keywords.lower().split()
        results = []
        for rec in self._recitals.values():
            text = json.dumps(rec).lower()
            if all(k in text for k in kw):
                results.append(rec)
        return results

    # ── Definition helpers ──────────────────────────────────────────────

    def get_definition(self, term: str) -> Optional[Dict[str, Any]]:
        return self._definitions.get(term.lower().strip())

    def list_definitions(self) -> List[Dict[str, Any]]:
        return list(self._definitions.values())

    def search_definitions(self, keywords: str) -> List[Dict[str, Any]]:
        kw = keywords.lower().split()
        results = []
        for defn in self._definitions.values():
            text = json.dumps(defn).lower()
            if all(k in text for k in kw):
                results.append(defn)
        return results

    # ── Supplementary ───────────────────────────────────────────────────

    def get_azure_mapping(self, article_id: str) -> Optional[Dict[str, Any]]:
        """Return Azure service mapping for a GDPR article."""
        return self._azure_mappings.get(str(article_id).strip())

    def get_edpb_guidelines(self) -> List[Dict[str, Any]]:
        return self._edpb_guidelines

    # ── Private — fetching ──────────────────────────────────────────────

    async def _fetch_or_cache(self) -> Dict[str, Any]:
        """Return cached data if fresh, otherwise fetch online."""
        cache_file = self._cache_dir / "gdpr_data.json"
        meta_file = self._cache_dir / "meta.json"

        if cache_file.exists() and meta_file.exists():
            meta = json.loads(meta_file.read_text())
            if time.time() - meta.get("fetched_at", 0) < self._ttl:
                logger.info("Using cached GDPR data (age %.0fs)", time.time() - meta["fetched_at"])
                return json.loads(cache_file.read_text())

        # Try online fetch
        try:
            data = await self._fetch_online()
            cache_file.write_text(json.dumps(data, ensure_ascii=False, indent=2))
            meta_file.write_text(json.dumps({"fetched_at": time.time(), "source": GDPR_SOURCE_URL}))
            logger.info("Fetched fresh GDPR data from %s", GDPR_SOURCE_URL)
            return data
        except Exception as exc:
            logger.warning("Online fetch failed (%s); falling back to bundled data", exc)
            if cache_file.exists():
                return json.loads(cache_file.read_text())
            return self._load_bundled()

    async def _fetch_online(self) -> Dict[str, Any]:
        """Fetch GDPR structured data from the configured URL."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(GDPR_SOURCE_URL)
            resp.raise_for_status()
            return resp.json()

    def _load_bundled(self) -> Dict[str, Any]:
        """Load the vendored fallback knowledge base."""
        bundled = Path(__file__).parent / "data" / "gdpr_bundled.json"
        if bundled.exists():
            return json.loads(bundled.read_text())
        # Return minimal skeleton so the server can still start
        logger.warning("No bundled GDPR data found; returning empty skeleton")
        return {"chapters": [], "recitals": [], "definitions": []}

    # ── Private — indexing ──────────────────────────────────────────────

    def _index(self, raw: Dict[str, Any]) -> None:
        """Build fast-lookup indices from the raw JSON."""
        # Index articles by number and group by chapter
        for chapter in raw.get("chapters", []):
            chapter_num = str(chapter.get("number", chapter.get("chapter_number", "")))
            chapter_title = chapter.get("title", chapter.get("chapter_title", ""))
            articles_in_chapter: List[Dict[str, Any]] = []

            for section in chapter.get("sections", [chapter]):
                for art in section.get("articles", chapter.get("articles", [])):
                    article_num = str(art.get("number", art.get("article_number", "")))
                    enriched = {
                        "article_number": article_num,
                        "title": art.get("title", art.get("article_title", "")),
                        "chapter_number": chapter_num,
                        "chapter_title": chapter_title,
                        "text": art.get("content", art.get("text", art.get("article_text", ""))),
                        "paragraphs": art.get("paragraphs", []),
                    }
                    self._articles[article_num] = enriched
                    articles_in_chapter.append(enriched)

            self._chapters[chapter_num] = articles_in_chapter

        # Index recitals
        for rec in raw.get("recitals", []):
            num = str(rec.get("number", rec.get("recital_number", "")))
            self._recitals[num] = {
                "recital_number": num,
                "text": rec.get("text", rec.get("recital_text", "")),
            }

        # Index definitions (Art. 4 terms)
        for defn in raw.get("definitions", []):
            term = defn.get("term", defn.get("name", "")).lower().strip()
            if term:
                self._definitions[term] = {
                    "term": defn.get("term", defn.get("name", "")),
                    "definition": defn.get("definition", defn.get("text", "")),
                    "article_reference": defn.get("article_reference", "Article 4"),
                }

        # If definitions weren't pre-extracted, try to parse Art. 4
        if not self._definitions and "4" in self._articles:
            self._extract_definitions_from_article_4()

    def _extract_definitions_from_article_4(self) -> None:
        """Best-effort parse of Art. 4 text into individual definitions."""
        art4 = self._articles.get("4", {})
        paragraphs = art4.get("paragraphs", [])
        if not paragraphs:
            text = art4.get("text", "")
            if text:
                paragraphs = [{"text": text}]

        KNOWN_TERMS = {
            "personal data": "any information relating to an identified or identifiable natural person ('data subject')",
            "processing": "any operation or set of operations performed on personal data",
            "controller": "the natural or legal person, public authority, agency or other body which determines the purposes and means of the processing of personal data",
            "processor": "a natural or legal person, public authority, agency or other body which processes personal data on behalf of the controller",
            "consent": "any freely given, specific, informed and unambiguous indication of the data subject's wishes",
            "personal data breach": "a breach of security leading to the accidental or unlawful destruction, loss, alteration, unauthorised disclosure of, or access to, personal data",
            "data concerning health": "personal data related to the physical or mental health of a natural person",
            "profiling": "any form of automated processing of personal data consisting of the use of personal data to evaluate certain personal aspects relating to a natural person",
            "pseudonymisation": "the processing of personal data in such a manner that the personal data can no longer be attributed to a specific data subject without the use of additional information",
            "filing system": "any structured set of personal data which are accessible according to specific criteria",
            "supervisory authority": "an independent public authority which is established by a Member State pursuant to Article 51",
            "cross-border processing": "processing of personal data which takes place in the context of activities of establishments in more than one Member State",
            "recipient": "a natural or legal person, public authority, agency or another body, to which the personal data are disclosed",
            "third party": "a natural or legal person, public authority, agency or body other than the data subject, controller, processor and persons who are authorised to process personal data under the direct authority of the controller or processor",
            "representative": "a natural or legal person established in the Union who is designated by the controller or processor to represent them",
            "enterprise": "a natural or legal person engaged in an economic activity, irrespective of its legal form",
            "binding corporate rules": "personal data protection policies adhered to by a controller or processor for transfers of personal data to a third country",
            "data protection officer": "a person designated by the controller or processor to assist with monitoring internal compliance with the GDPR",
        }
        for term, definition in KNOWN_TERMS.items():
            self._definitions[term] = {
                "term": term.title(),
                "definition": definition,
                "article_reference": "Article 4",
            }

    # ── Private — supplementary data ────────────────────────────────────

    def _load_supplementary(self) -> None:
        """Load EDPB guidelines summaries and Azure compliance mappings."""
        self._load_edpb_guidelines()
        self._load_azure_mappings()

    def _load_edpb_guidelines(self) -> None:
        """Load EDPB / ICO guideline summaries."""
        guidelines_file = Path(__file__).parent / "data" / "edpb_guidelines.json"
        if guidelines_file.exists():
            self._edpb_guidelines = json.loads(guidelines_file.read_text())
        else:
            # Provide a curated built-in set
            self._edpb_guidelines = [
                {
                    "id": "EDPB-01/2020",
                    "title": "Guidelines on processing of personal data in the context of connected vehicles",
                    "topic": "connected vehicles",
                    "url": "https://edpb.europa.eu/our-work-tools/documents/public-consultations/2020/guidelines-012020-processing-personal-data_en",
                },
                {
                    "id": "EDPB-07/2020",
                    "title": "Guidelines on the concepts of controller and processor",
                    "topic": "controller and processor",
                    "url": "https://edpb.europa.eu/our-work-tools/documents/public-consultations/2020/guidelines-072020-concepts-controller-and_en",
                },
                {
                    "id": "EDPB-04/2022",
                    "title": "Guidelines on the calculation of administrative fines under the GDPR",
                    "topic": "administrative fines",
                    "url": "https://edpb.europa.eu/our-work-tools/documents/public-consultations/2022/guidelines-042022-calculation-administrative_en",
                },
                {
                    "id": "EDPB-01/2022",
                    "title": "Guidelines on data subject rights — Right of access",
                    "topic": "right of access",
                    "url": "https://edpb.europa.eu/our-work-tools/documents/public-consultations/2022/guidelines-012022-data-subject-rights-right_en",
                },
            ]

    def _load_azure_mappings(self) -> None:
        """Load Azure service → GDPR article mappings."""
        mappings_file = Path(__file__).parent / "data" / "azure_gdpr_mappings.json"
        if mappings_file.exists():
            self._azure_mappings = json.loads(mappings_file.read_text())
        else:
            self._azure_mappings = {
                "5": {
                    "article": "Art. 5 — Principles",
                    "azure_services": [
                        "Azure Policy (enforce data residency, tagging)",
                        "Azure Purview / Microsoft Purview (data classification, lineage)",
                        "Azure Monitor (accountability, audit trails)",
                    ],
                },
                "25": {
                    "article": "Art. 25 — Data protection by design and by default",
                    "azure_services": [
                        "Azure Private Link (network isolation)",
                        "Azure Key Vault (encryption key management, CMK)",
                        "Azure API Management (minimum data exposure)",
                        "Microsoft Entra ID (least-privilege RBAC)",
                    ],
                },
                "28": {
                    "article": "Art. 28 — Processor",
                    "azure_services": [
                        "Azure compliance documentation (DPA, SOC 2, ISO 27701)",
                        "Microsoft Service Trust Portal",
                    ],
                },
                "30": {
                    "article": "Art. 30 — Records of processing activities",
                    "azure_services": [
                        "Microsoft Purview Compliance Manager",
                        "Azure Resource Graph (asset inventory)",
                        "Azure Tags (processing-purpose tagging)",
                    ],
                },
                "32": {
                    "article": "Art. 32 — Security of processing",
                    "azure_services": [
                        "Microsoft Defender for Cloud",
                        "Azure Key Vault (encryption at rest)",
                        "Azure Disk Encryption",
                        "Azure Private Link / Private Endpoints",
                        "Azure NSG / Azure Firewall",
                        "Azure Monitor + Log Analytics (logging)",
                        "Microsoft Sentinel (SIEM)",
                    ],
                },
                "33": {
                    "article": "Art. 33 — Notification of a personal data breach to supervisory authority",
                    "azure_services": [
                        "Microsoft Sentinel (breach detection)",
                        "Azure Logic Apps (automated notification workflows)",
                        "Azure Monitor Alerts",
                    ],
                },
                "35": {
                    "article": "Art. 35 — Data protection impact assessment",
                    "azure_services": [
                        "Microsoft Purview Compliance Manager (DPIA templates)",
                        "Azure Policy (enforce DPIA-required controls)",
                    ],
                },
                "44": {
                    "article": "Art. 44 — General principle for transfers",
                    "azure_services": [
                        "Azure data-residency regions (EU Data Boundary)",
                        "Azure Confidential Computing",
                        "Customer Lockbox for Azure",
                    ],
                },
            }
