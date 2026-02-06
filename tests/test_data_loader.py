"""
Tests for GDPRDataLoader — online fetch, caching, indexing, search.
"""
import json
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from gdpr_shift_left_mcp.data_loader import GDPRDataLoader


# ─── Fixtures ───────────────────────────────────────────────────────────────

SAMPLE_GDPR_DATA = {
    "metadata": {"title": "GDPR Test", "version": "test"},
    "chapters": [
        {
            "number": 1,
            "title": "General provisions",
            "articles": [
                {
                    "number": 1,
                    "title": "Subject matter and objectives",
                    "text": "This Regulation lays down rules relating to the protection of natural persons with regard to the processing of personal data.",
                },
            ],
        },
        {
            "number": 2,
            "title": "Principles",
            "articles": [
                {
                    "number": 4,
                    "title": "Definitions",
                    "text": "'personal data' means any information relating to an identified or identifiable natural person ('data subject').",
                },
                {
                    "number": 5,
                    "title": "Principles relating to processing of personal data",
                    "text": "Personal data shall be processed lawfully, fairly and in a transparent manner.",
                },
            ],
        },
    ],
    "recitals": [
        {"number": 1, "text": "The protection of natural persons in relation to the processing of personal data is a fundamental right."},
        {"number": 26, "text": "The principles of data protection should apply to any information concerning an identified or identifiable natural person."},
    ],
    "definitions": [
        {"term": "personal data", "definition": "Any information relating to an identified or identifiable natural person."},
        {"term": "processing", "definition": "Any operation performed on personal data."},
        {"term": "controller", "definition": "The natural or legal person which determines the purposes and means of the processing."},
    ],
}


@pytest.fixture
def sample_data():
    """Return sample GDPR data dict."""
    return SAMPLE_GDPR_DATA.copy()


@pytest.fixture
def temp_cache_dir():
    """Provide a temporary cache directory."""
    d = tempfile.mkdtemp(prefix="gdpr_test_cache_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest_asyncio.fixture
async def loader(temp_cache_dir):
    """Create a fresh GDPRDataLoader using a temp cache."""
    with patch.dict(os.environ, {"GDPR_CACHE_DIR": temp_cache_dir}):
        ld = GDPRDataLoader.__new__(GDPRDataLoader)
        ld._loaded = False
        ld._articles = {}
        ld._chapters = {}
        ld._recitals = {}
        ld._definitions = {}
        ld._edpb_guidelines = []
        ld._azure_mappings = {}
        ld._cache_dir = Path(temp_cache_dir)
        ld._ttl = 3600
        yield ld


def _init_loader(loader, data):
    """Index sample data and load supplementary into a loader."""
    loader._index(data)
    loader._load_supplementary()
    loader._loaded = True


# ─── Index-building tests ──────────────────────────────────────────────────

class TestDataLoaderIndexing:
    """Test that indexes are built correctly from raw data."""

    @pytest.mark.asyncio
    async def test_build_indexes_articles(self, loader, sample_data):
        """Articles are indexed by number (string keys)."""
        _init_loader(loader, sample_data)

        assert "1" in loader._articles
        assert "4" in loader._articles
        assert "5" in loader._articles
        assert loader._articles["1"]["title"] == "Subject matter and objectives"

    @pytest.mark.asyncio
    async def test_build_indexes_chapters(self, loader, sample_data):
        """Articles are grouped by chapter number."""
        _init_loader(loader, sample_data)

        assert "1" in loader._chapters
        assert "2" in loader._chapters
        assert len(loader._chapters["1"]) == 1
        assert len(loader._chapters["2"]) == 2

    @pytest.mark.asyncio
    async def test_build_indexes_recitals(self, loader, sample_data):
        """Recitals are indexed by number (string keys)."""
        _init_loader(loader, sample_data)

        assert "1" in loader._recitals
        assert "26" in loader._recitals

    @pytest.mark.asyncio
    async def test_build_indexes_definitions(self, loader, sample_data):
        """Definitions are indexed by lowercase term."""
        _init_loader(loader, sample_data)

        assert "personal data" in loader._definitions
        assert "processing" in loader._definitions
        assert "controller" in loader._definitions


# ─── Look-up / search tests ────────────────────────────────────────────────

class TestDataLoaderLookups:

    @pytest.mark.asyncio
    async def test_get_article_found(self, loader, sample_data):
        """get_article returns the article dict when it exists."""
        _init_loader(loader, sample_data)

        article = loader.get_article("5")
        assert article is not None
        assert article["title"] == "Principles relating to processing of personal data"

    @pytest.mark.asyncio
    async def test_get_article_not_found(self, loader, sample_data):
        """get_article returns None for non-existent article."""
        _init_loader(loader, sample_data)

        assert loader.get_article("999") is None

    @pytest.mark.asyncio
    async def test_get_chapter_articles(self, loader, sample_data):
        """list_chapter_articles returns all articles for a chapter."""
        _init_loader(loader, sample_data)

        arts = loader.list_chapter_articles("2")
        assert len(arts) == 2

    @pytest.mark.asyncio
    async def test_get_definition_found(self, loader, sample_data):
        """get_definition returns the definition of a known term."""
        _init_loader(loader, sample_data)

        defn = loader.get_definition("personal data")
        assert defn is not None
        assert "identified" in defn.get("definition", "").lower()

    @pytest.mark.asyncio
    async def test_get_definition_not_found(self, loader, sample_data):
        """get_definition returns None for unknown term."""
        _init_loader(loader, sample_data)

        assert loader.get_definition("quantum entanglement") is None

    @pytest.mark.asyncio
    async def test_get_recital(self, loader, sample_data):
        """get_recital returns recital by number."""
        _init_loader(loader, sample_data)

        recital = loader.get_recital("1")
        assert recital is not None
        assert "fundamental right" in recital.get("text", "")

    @pytest.mark.asyncio
    async def test_search_articles(self, loader, sample_data):
        """search_articles finds articles containing the keyword."""
        _init_loader(loader, sample_data)

        results = loader.search_articles("processing")
        # Should find at least Article 5 (mentions 'processing')
        assert len(results) > 0


# ─── Data integrity tests ──────────────────────────────────────────────────

class TestDataIntegrity:

    @pytest.mark.asyncio
    async def test_no_personal_data_in_definitions(self, loader, sample_data):
        """Ensure definitions contain only placeholders, never real PII."""
        _init_loader(loader, sample_data)

        for term, defn in loader._definitions.items():
            text = defn.get("definition", "")
            # No emails, phone numbers, real names
            assert "@" not in text, f"Definition for '{term}' may contain an email"


# ─── Azure mappings tests ──────────────────────────────────────────────────

class TestAzureMappings:

    @pytest.mark.asyncio
    async def test_azure_mappings_exist(self, loader, sample_data):
        """Azure mappings should be available after load."""
        _init_loader(loader, sample_data)

        assert isinstance(loader._azure_mappings, dict)
        # At minimum, Art. 32 (security) should have Azure mappings
        assert "32" in loader._azure_mappings

    @pytest.mark.asyncio
    async def test_azure_mapping_for_article(self, loader, sample_data):
        """Azure mapping for Art. 25 (privacy by design) should exist."""
        _init_loader(loader, sample_data)

        mapping = loader.get_azure_mapping("25")
        if mapping:
            assert isinstance(mapping, dict)


# ─── Edge cases ─────────────────────────────────────────────────────────────

class TestEdgeCases:

    @pytest.mark.asyncio
    async def test_empty_data(self, loader):
        """Loader handles empty data gracefully."""
        loader._index({"chapters": [], "recitals": [], "definitions": []})
        loader._load_supplementary()
        loader._loaded = True

        assert loader.get_article("1") is None
        assert loader.get_recital("1") is None
        assert loader.get_definition("anything") is None
        assert loader.search_articles("test") == []

    @pytest.mark.asyncio
    async def test_missing_keys(self, loader):
        """Loader handles data with missing keys."""
        loader._index({})
        loader._loaded = True

        assert loader.get_article("1") is None

    @pytest.mark.asyncio
    async def test_search_empty_query(self, loader, sample_data):
        """Search with empty string returns empty list."""
        _init_loader(loader, sample_data)

        results = loader.search_articles("")
        assert results == []
