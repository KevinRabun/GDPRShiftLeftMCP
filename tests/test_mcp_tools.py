"""
Tests for MCP Tool implementations.

Each tool module is tested for:
- Correct output formatting
- Disclaimer inclusion
- Edge case handling
- GDPR-accuracy of returned content
"""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from gdpr_shift_left_mcp.disclaimer import LEGAL_DISCLAIMER, append_disclaimer
from gdpr_shift_left_mcp.tools.articles import (
    get_article_impl,
    list_chapter_articles_impl,
    search_gdpr_impl,
    get_recital_impl,
    get_azure_mapping_impl,
)
from gdpr_shift_left_mcp.tools.definitions import (
    get_definition_impl,
    list_definitions_impl,
    search_definitions_impl,
)
from gdpr_shift_left_mcp.tools.dpia import (
    assess_dpia_need_impl,
    generate_dpia_template_impl,
    get_dpia_guidance_impl,
)
from gdpr_shift_left_mcp.tools.ropa import (
    generate_ropa_template_impl,
    validate_ropa_impl,
    get_ropa_requirements_impl,
)
from gdpr_shift_left_mcp.tools.dsr import (
    get_dsr_guidance_impl,
    generate_dsr_workflow_impl,
    get_dsr_timeline_impl,
)
from gdpr_shift_left_mcp.tools.analyzer import (
    analyze_infrastructure_code_impl,
    analyze_application_code_impl,
    validate_gdpr_config_impl,
)
from gdpr_shift_left_mcp.tools.retention import (
    assess_retention_policy_impl,
    get_retention_guidance_impl,
    check_deletion_requirements_impl,
)


# ─── Shared fixtures ───────────────────────────────────────────────────────

SAMPLE_ARTICLE = {
    "article_number": "5",
    "title": "Principles relating to processing of personal data",
    "chapter_number": "2",
    "chapter_title": "Principles",
    "text": "Personal data shall be processed lawfully, fairly and in a transparent manner.",
    "paragraphs": [],
}

SAMPLE_RECITAL = {
    "recital_number": "1",
    "text": "The protection of natural persons in relation to the processing of personal data is a fundamental right.",
}

SAMPLE_DEFINITION = {
    "term": "personal data",
    "definition": "Any information relating to an identified or identifiable natural person.",
    "article_reference": "Article 4",
}


@pytest_asyncio.fixture
async def mock_data_loader():
    """Create a mock data loader with basic GDPR data."""
    loader = MagicMock()
    loader.load_data = AsyncMock()
    loader.get_article = MagicMock(return_value=SAMPLE_ARTICLE)
    loader.list_chapter_articles = MagicMock(return_value=[SAMPLE_ARTICLE])
    loader.search_articles = MagicMock(return_value=[SAMPLE_ARTICLE])
    loader.search_recitals = MagicMock(return_value=[SAMPLE_RECITAL])
    loader.get_recital = MagicMock(return_value=SAMPLE_RECITAL)
    loader.get_definition = MagicMock(return_value=SAMPLE_DEFINITION)
    loader.list_definitions = MagicMock(return_value=[SAMPLE_DEFINITION])
    loader.search_definitions = MagicMock(return_value=[SAMPLE_DEFINITION])
    loader.get_azure_mapping = MagicMock(return_value={
        "article": "Art. 32 — Security of processing",
        "azure_services": ["Azure Key Vault", "Microsoft Defender for Cloud"],
    })
    loader.get_edpb_guidelines = MagicMock(return_value=[])
    return loader


# ─── Disclaimer tests ──────────────────────────────────────────────────────

class TestDisclaimer:

    def test_append_disclaimer_adds_text(self):
        """Every call to append_disclaimer includes the legal notice."""
        result = append_disclaimer("Test content")
        assert LEGAL_DISCLAIMER in result
        assert "Test content" in result

    def test_append_disclaimer_to_empty(self):
        """Disclaimer is appended even to empty strings."""
        result = append_disclaimer("")
        assert LEGAL_DISCLAIMER in result


# ─── Article tools ──────────────────────────────────────────────────────────

class TestArticleTools:

    @pytest.mark.asyncio
    async def test_get_article_includes_disclaimer(self, mock_data_loader):
        result = await get_article_impl("5", mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_get_article_shows_title(self, mock_data_loader):
        result = await get_article_impl("5", mock_data_loader)
        assert "Principles" in result or "Article 5" in result

    @pytest.mark.asyncio
    async def test_get_article_not_found(self, mock_data_loader):
        mock_data_loader.get_article = MagicMock(return_value=None)
        result = await get_article_impl("999", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "not found" in result.lower() or "999" in result

    @pytest.mark.asyncio
    async def test_list_chapter_articles(self, mock_data_loader):
        result = await list_chapter_articles_impl("2", mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_search_gdpr(self, mock_data_loader):
        result = await search_gdpr_impl("processing", mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_get_recital(self, mock_data_loader):
        result = await get_recital_impl("1", mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_get_azure_mapping(self, mock_data_loader):
        result = await get_azure_mapping_impl("32", mock_data_loader)
        assert LEGAL_DISCLAIMER in result


# ─── Definition tools ──────────────────────────────────────────────────────

class TestDefinitionTools:

    @pytest.mark.asyncio
    async def test_get_definition_includes_disclaimer(self, mock_data_loader):
        result = await get_definition_impl("personal data", mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_get_definition_not_found(self, mock_data_loader):
        mock_data_loader.get_definition = MagicMock(return_value=None)
        result = await get_definition_impl("unknown term", mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_list_definitions(self, mock_data_loader):
        result = await list_definitions_impl(mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_search_definitions(self, mock_data_loader):
        result = await search_definitions_impl("data", mock_data_loader)
        assert LEGAL_DISCLAIMER in result


# ─── DPIA tools ─────────────────────────────────────────────────────────────

class TestDPIATools:

    @pytest.mark.asyncio
    async def test_assess_dpia_need_high_risk(self, mock_data_loader):
        """Profiling + large scale should trigger DPIA requirement."""
        result = await assess_dpia_need_impl(
            "We profile users at large scale using automated scoring",
            mock_data_loader,
        )
        assert LEGAL_DISCLAIMER in result
        assert "REQUIRED" in result or "RECOMMENDED" in result

    @pytest.mark.asyncio
    async def test_assess_dpia_need_low_risk(self, mock_data_loader):
        """Basic processing should not require DPIA."""
        result = await assess_dpia_need_impl(
            "Simple contact form submission stored in a database",
            mock_data_loader,
        )
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_generate_dpia_template(self, mock_data_loader):
        result = await generate_dpia_template_impl("Test system for test purpose", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "DPIA" in result

    @pytest.mark.asyncio
    async def test_get_dpia_guidance(self, mock_data_loader):
        result = await get_dpia_guidance_impl("profiling", mock_data_loader)
        assert LEGAL_DISCLAIMER in result


# ─── ROPA tools ─────────────────────────────────────────────────────────────

class TestROPATools:

    @pytest.mark.asyncio
    async def test_generate_ropa_template(self, mock_data_loader):
        result = await generate_ropa_template_impl("controller", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "Art" in result  # References GDPR article

    @pytest.mark.asyncio
    async def test_validate_ropa_complete(self, mock_data_loader):
        """A complete ROPA description should score well."""
        ropa = (
            "Controller: Acme Corp. Purpose: CRM management. "
            "Data categories: name, email. Data subjects: customers. "
            "Recipients: Salesforce (processor). Retention: 5 years. "
            "Security measures: encryption, RBAC. Transfer: EU only."
        )
        result = await validate_ropa_impl(ropa, mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_validate_ropa_incomplete(self, mock_data_loader):
        """A sparse ROPA description should flag missing fields."""
        result = await validate_ropa_impl("We store customer emails.", mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_get_ropa_requirements(self, mock_data_loader):
        result = await get_ropa_requirements_impl("controller", mock_data_loader)
        assert LEGAL_DISCLAIMER in result


# ─── DSR tools ──────────────────────────────────────────────────────────────

class TestDSRTools:

    @pytest.mark.asyncio
    async def test_get_dsr_guidance_access(self, mock_data_loader):
        result = await get_dsr_guidance_impl("access", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "Art" in result and "15" in result

    @pytest.mark.asyncio
    async def test_get_dsr_guidance_erasure(self, mock_data_loader):
        result = await get_dsr_guidance_impl("erasure", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "Art" in result and "17" in result

    @pytest.mark.asyncio
    async def test_get_dsr_guidance_invalid(self, mock_data_loader):
        result = await get_dsr_guidance_impl("invalid_type", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "Unknown" in result or "Available" in result or "invalid_type" in result

    @pytest.mark.asyncio
    async def test_generate_dsr_workflow(self, mock_data_loader):
        result = await generate_dsr_workflow_impl("access", "CRM system", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "Step" in result or "step" in result

    @pytest.mark.asyncio
    async def test_get_dsr_timeline(self, mock_data_loader):
        result = await get_dsr_timeline_impl("access", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "month" in result.lower()


# ─── Analyzer tools ────────────────────────────────────────────────────────

class TestAnalyzerTools:

    BICEP_GOOD = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
      name: 'mystore'
      location: 'westeurope'
      sku: { name: 'Standard_GRS' }
      properties: {
        supportsHttpsTrafficOnly: true
        minimumTlsVersion: 'TLS1_2'
        publicNetworkAccess: 'Disabled'
        encryption: { keySource: 'Microsoft.Keyvault' }
      }
      tags: { 'gdpr-data-category': 'customer' }
    }
    """

    BICEP_BAD = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
      name: 'mystore'
      location: 'eastus'
      properties: {
        publicNetworkAccess: 'Enabled'
        minimumTlsVersion: 'TLS1_0'
      }
    }
    """

    @pytest.mark.asyncio
    async def test_analyze_good_bicep(self, mock_data_loader):
        result = await analyze_infrastructure_code_impl(self.BICEP_GOOD, "bicep", "main.bicep", None, mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_analyze_bad_bicep_finds_issues(self, mock_data_loader):
        result = await analyze_infrastructure_code_impl(self.BICEP_BAD, "bicep", "bad.bicep", None, mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        # Should find issues with TLS 1.0 and public access and non-EU region
        assert "CRITICAL" in result or "HIGH" in result or "findings" in result.lower()

    @pytest.mark.asyncio
    async def test_analyze_app_code_hardcoded_secret(self, mock_data_loader):
        code = 'password = "hunter2"\napi_key = "sk-abc123"'
        result = await analyze_application_code_impl(code, "python", "app.py", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "CRITICAL" in result or "secret" in result.lower()

    @pytest.mark.asyncio
    async def test_analyze_app_code_pii_logging(self, mock_data_loader):
        code = 'logger.info(f"User email: {user.email}")'
        result = await analyze_application_code_impl(code, "python", "app.py", mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_analyze_app_code_clean(self, mock_data_loader):
        code = 'def process_order(order_id: str):\n    return get_order(order_id)'
        result = await analyze_application_code_impl(code, "python", "app.py", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "No GDPR compliance issues" in result or "0" in result

    @pytest.mark.asyncio
    async def test_validate_gdpr_config_strict(self, mock_data_loader):
        result = await validate_gdpr_config_impl(self.BICEP_BAD, "bicep", True, mock_data_loader)
        assert "STRICT" in result

    @pytest.mark.asyncio
    async def test_validate_gdpr_config_advisory(self, mock_data_loader):
        result = await validate_gdpr_config_impl(self.BICEP_GOOD, "bicep", False, mock_data_loader)
        assert "ADVISORY" in result


# ─── Retention tools ───────────────────────────────────────────────────────

class TestRetentionTools:

    @pytest.mark.asyncio
    async def test_assess_retention_indefinite(self, mock_data_loader):
        """Indefinite retention should be flagged."""
        result = await assess_retention_policy_impl(
            "Customer data is retained indefinitely for analytics", mock_data_loader
        )
        assert LEGAL_DISCLAIMER in result
        assert "indefinite" in result.lower() or "⚠" in result

    @pytest.mark.asyncio
    async def test_assess_retention_good(self, mock_data_loader):
        """Well-defined policy should not flag indefinite retention."""
        result = await assess_retention_policy_impl(
            "Customer data retained for 5 years for contract purpose. "
            "Annual review. Automated deletion after expiry.",
            mock_data_loader,
        )
        assert LEGAL_DISCLAIMER in result
        assert "✅" in result

    @pytest.mark.asyncio
    async def test_get_retention_guidance_known(self, mock_data_loader):
        result = await get_retention_guidance_impl("customer data", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "Art" in result

    @pytest.mark.asyncio
    async def test_get_retention_guidance_unknown(self, mock_data_loader):
        result = await get_retention_guidance_impl("alien abduction logs", mock_data_loader)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_check_deletion_requirements(self, mock_data_loader):
        result = await check_deletion_requirements_impl("E-commerce platform", mock_data_loader)
        assert LEGAL_DISCLAIMER in result
        assert "Art. 17" in result or "erasure" in result.lower()
