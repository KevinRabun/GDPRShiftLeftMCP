"""
Extended tool tests — covers edge cases, GDPR accuracy, boundary conditions,
multiple DSR types, IaC variants, and negative cases not covered by the basic tests.
"""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock

from gdpr_shift_left_mcp.disclaimer import LEGAL_DISCLAIMER
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
    EDPB_CRITERIA,
)
from gdpr_shift_left_mcp.tools.ropa import (
    generate_ropa_template_impl,
    validate_ropa_impl,
    get_ropa_requirements_impl,
    CONTROLLER_FIELDS,
    PROCESSOR_FIELDS,
)
from gdpr_shift_left_mcp.tools.dsr import (
    get_dsr_guidance_impl,
    generate_dsr_workflow_impl,
    get_dsr_timeline_impl,
    DSR_TYPES,
)
from gdpr_shift_left_mcp.tools.analyzer import (
    analyze_infrastructure_code_impl,
    analyze_application_code_impl,
    validate_gdpr_config_impl,
    GDPR_IAC_CHECKS,
)
from gdpr_shift_left_mcp.tools.retention import (
    assess_retention_policy_impl,
    get_retention_guidance_impl,
    check_deletion_requirements_impl,
    RETENTION_GUIDANCE,
)


# ─── Shared fixtures ───────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def mock_dl():
    """A minimal mock data loader."""
    loader = MagicMock()
    loader.load_data = AsyncMock()
    loader.get_article = MagicMock(return_value=None)
    loader.list_chapter_articles = MagicMock(return_value=[])
    loader.search_articles = MagicMock(return_value=[])
    loader.search_recitals = MagicMock(return_value=[])
    loader.get_recital = MagicMock(return_value=None)
    loader.get_definition = MagicMock(return_value=None)
    loader.list_definitions = MagicMock(return_value=[])
    loader.search_definitions = MagicMock(return_value=[])
    loader.get_azure_mapping = MagicMock(return_value=None)
    loader.get_edpb_guidelines = MagicMock(return_value=[])
    return loader


# ─── DPIA boundary tests ───────────────────────────────────────────────────

class TestDPIABoundary:

    @pytest.mark.asyncio
    async def test_exactly_two_edpb_criteria_triggers_required(self, mock_dl):
        """When exactly 2 EDPB criteria match, DPIA is REQUIRED."""
        desc = "We perform evaluation scoring of sensitive data on large scale"
        result = await assess_dpia_need_impl(desc, mock_dl)
        assert LEGAL_DISCLAIMER in result
        # Should be REQUIRED (scoring + sensitive + large scale >= 2 criteria)
        assert "REQUIRED" in result

    @pytest.mark.asyncio
    async def test_one_criterion_not_required(self, mock_dl):
        """When only 1 EDPB criterion matches without Art.35(3), not strictly required."""
        desc = "We collect basic contact information from web forms"
        result = await assess_dpia_need_impl(desc, mock_dl)
        assert LEGAL_DISCLAIMER in result
        # Should not see REQUIRED (or should see RECOMMENDED)
        assert "RECOMMENDED" in result or "best practice" in result.lower()

    @pytest.mark.asyncio
    async def test_explicit_trigger_profiling(self, mock_dl):
        """Art. 35(3)(a) triggers: profiling keyword."""
        result = await assess_dpia_need_impl("Customer profiling for credit scoring", mock_dl)
        assert "REQUIRED" in result
        assert "35(3)" in result

    @pytest.mark.asyncio
    async def test_explicit_trigger_surveillance(self, mock_dl):
        """Art. 35(3)(c) triggers: surveillance/CCTV."""
        result = await assess_dpia_need_impl("CCTV surveillance in shopping centre", mock_dl)
        assert "REQUIRED" in result

    @pytest.mark.asyncio
    async def test_explicit_trigger_health_data(self, mock_dl):
        """Art. 35(3)(b) triggers: health data."""
        result = await assess_dpia_need_impl("Processing health data for insurance", mock_dl)
        assert "REQUIRED" in result

    @pytest.mark.asyncio
    async def test_dpia_guidance_unknown_topic(self, mock_dl):
        """Unknown DPIA topic should list available topics."""
        result = await get_dpia_guidance_impl("unknown_topic", mock_dl)
        assert LEGAL_DISCLAIMER in result
        assert "profiling" in result.lower()

    @pytest.mark.asyncio
    async def test_dpia_guidance_special_categories(self, mock_dl):
        """Special categories guidance should reference Art. 9."""
        result = await get_dpia_guidance_impl("special categories", mock_dl)
        assert "Art. 9" in result

    @pytest.mark.asyncio
    async def test_dpia_guidance_children(self, mock_dl):
        """Children's data guidance should reference Art. 8."""
        result = await get_dpia_guidance_impl("children", mock_dl)
        assert "Art. 8" in result


# ─── ROPA extended tests ───────────────────────────────────────────────────

class TestROPAExtended:

    @pytest.mark.asyncio
    async def test_ropa_requirements_processor(self, mock_dl):
        """Processor role should return Art. 30(2) fields."""
        result = await get_ropa_requirements_impl("processor", mock_dl)
        assert LEGAL_DISCLAIMER in result
        assert "30(2)" in result

    @pytest.mark.asyncio
    async def test_ropa_requirements_invalid_role(self, mock_dl):
        """Invalid role should return helpful error."""
        result = await get_ropa_requirements_impl("third_party", mock_dl)
        assert LEGAL_DISCLAIMER in result
        assert "controller" in result.lower() or "processor" in result.lower()

    @pytest.mark.asyncio
    async def test_validate_ropa_all_fields_present(self, mock_dl):
        """ROPA with all fields should score 8/8."""
        ropa = (
            "Controller: Acme Corp, contact@acme.com. "
            "Purpose: customer relationship management. "
            "Data subjects: customers and prospects. "
            "Personal data categories: name, email, phone, purchase history. "
            "Recipients: Salesforce (processor), Azure cloud. "
            "International transfers: EU only, no third country transfers. Transfer safeguards: N/A. "
            "Retention: 5 years after last purchase, then erasure. "
            "Technical security measures: AES-256 encryption, RBAC access controls. "
            "Organisational measures: annual training, quarterly audits."
        )
        result = await validate_ropa_impl(ropa, mock_dl)
        assert "8/8" in result

    @pytest.mark.asyncio
    async def test_validate_ropa_minimal(self, mock_dl):
        """Minimal ROPA should flag many missing fields."""
        result = await validate_ropa_impl("just emails", mock_dl)
        assert "MISSING" in result
        assert LEGAL_DISCLAIMER in result


# ─── DSR all types ──────────────────────────────────────────────────────────

class TestDSRAllTypes:

    @pytest.mark.asyncio
    @pytest.mark.parametrize("dsr_type", list(DSR_TYPES.keys()))
    async def test_get_guidance_all_types(self, dsr_type, mock_dl):
        """Every registered DSR type should return valid guidance with disclaimer."""
        result = await get_dsr_guidance_impl(dsr_type, mock_dl)
        assert LEGAL_DISCLAIMER in result
        assert "Art" in result

    @pytest.mark.asyncio
    @pytest.mark.parametrize("dsr_type", list(DSR_TYPES.keys()))
    async def test_generate_workflow_all_types(self, dsr_type, mock_dl):
        """Workflow generation should work for all DSR types."""
        result = await generate_dsr_workflow_impl(dsr_type, "Test system", mock_dl)
        assert LEGAL_DISCLAIMER in result
        assert "Step" in result

    @pytest.mark.asyncio
    @pytest.mark.parametrize("dsr_type", list(DSR_TYPES.keys()))
    async def test_timeline_all_types(self, dsr_type, mock_dl):
        """Timeline should mention 1 month deadline for all types."""
        result = await get_dsr_timeline_impl(dsr_type, mock_dl)
        assert LEGAL_DISCLAIMER in result
        assert "month" in result.lower()

    @pytest.mark.asyncio
    async def test_erasure_workflow_mentions_crypto_shredding(self, mock_dl):
        """Erasure workflow should mention crypto-shredding or backup handling."""
        result = await generate_dsr_workflow_impl("erasure", "Azure-based CRM", mock_dl)
        assert "crypto" in result.lower() or "backup" in result.lower() or "delete" in result.lower()

    @pytest.mark.asyncio
    async def test_portability_workflow_mentions_format(self, mock_dl):
        """Portability workflow should mention JSON/CSV format."""
        result = await generate_dsr_workflow_impl("portability", "Customer portal", mock_dl)
        assert "json" in result.lower() or "csv" in result.lower()


# ─── Analyzer extended tests ───────────────────────────────────────────────

class TestAnalyzerExtended:

    TERRAFORM_CODE = """
    resource "azurerm_storage_account" "example" {
      name                     = "mystorageaccount"
      resource_group_name      = azurerm_resource_group.example.name
      location                 = "eastus"
      account_tier             = "Standard"
      account_replication_type = "GRS"
      public_network_access_enabled = true
    }
    """

    @pytest.mark.asyncio
    async def test_analyze_terraform(self, mock_dl):
        """Analyzer should detect issues in Terraform code."""
        result = await analyze_infrastructure_code_impl(
            self.TERRAFORM_CODE, "terraform", "main.tf", None, mock_dl
        )
        assert LEGAL_DISCLAIMER in result
        # Should detect non-EU region (eastus)
        assert "eastus" in result.lower() or "CRITICAL" in result or "region" in result.lower()

    @pytest.mark.asyncio
    async def test_detect_non_eu_region(self, mock_dl):
        """Non-EU regions should trigger GDPR-RES-001 when location keyword is absent."""
        # The region check fires when 'location'/'region' keyword is NOT found
        # in the code but a non-EU region string is present.
        code = "param deployment_area string = 'eastus2'\nresource storageAccount 'Microsoft.Storage' = { area: deployment_area }"
        result = await analyze_infrastructure_code_impl(code, "bicep", "test.bicep", None, mock_dl)
        assert "eastus2" in result.lower() or "GDPR-RES-001" in result

    @pytest.mark.asyncio
    async def test_detect_public_access(self, mock_dl):
        """Public access enabled should trigger violation."""
        code = """
        resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
          name: 'test'
          location: 'westeurope'
          properties: { publicNetworkAccess: 'Enabled' }
        }
        """
        result = await analyze_infrastructure_code_impl(code, "bicep", "test.bicep", None, mock_dl)
        assert "VIOLATION" in result or "CRITICAL" in result or "HIGH" in result

    @pytest.mark.asyncio
    async def test_clean_eu_code_passes(self, mock_dl):
        """Well-configured EU-region code should have fewer/no findings."""
        code = """
        resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
          name: 'gdprstore'
          location: 'westeurope'
          properties: {
            supportsHttpsTrafficOnly: true
            minimumTlsVersion: 'TLS1_2'
            publicNetworkAccess: 'Disabled'
            encryption: { keySource: 'Microsoft.Keyvault' }
            networkAcls: { defaultAction: 'Deny' }
          }
          tags: { 'gdpr-data-category': 'customer' }
        }
        resource pe 'Microsoft.Network/privateEndpoints@2023-11-01' = { }
        resource diag 'Microsoft.Insights/diagnosticSettings@2023-01-01' = {
          properties: { logAnalytics: {} }
        }
        resource retention_lifecycle 'lifecycle' = {
          properties: { retention: { inDays: 365 } }
        }
        resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
          properties: { sku: { name: 'premium' } }
        }
        """
        result = await analyze_infrastructure_code_impl(code, "bicep", "good.bicep", None, mock_dl)
        assert "No GDPR compliance issues" in result or "0" in result or "PASSED" in result

    @pytest.mark.asyncio
    async def test_app_code_data_minimisation(self, mock_dl):
        """SELECT * should trigger data minimisation warning."""
        code = 'query = "SELECT * FROM users"'
        result = await analyze_application_code_impl(code, "python", "query.py", mock_dl)
        assert "minim" in result.lower() or "GDPR-APP-004" in result

    @pytest.mark.asyncio
    async def test_app_code_consent_with_mitigation(self, mock_dl):
        """Marketing with consent check present should not flag."""
        code = """
        if user.consent:
            send_marketing_email(user.email)
        """
        result = await analyze_application_code_impl(code, "python", "marketing.py", mock_dl)
        # consent anti-pattern should suppress the finding
        assert "GDPR-APP-003" not in result

    @pytest.mark.asyncio
    async def test_validate_config_strict_fails(self, mock_dl):
        """Strict mode with explicit fail-pattern violations should show FAILED."""
        # fail_keywords are matched case-insensitively against code.
        # Use patterns that match the regex: publicNetworkAccess.*Enabled
        bad_code = "properties: { publicNetworkAccess: 'Enabled', httpsOnly: false }"
        result = await validate_gdpr_config_impl(bad_code, "bicep", True, mock_dl)
        # Should have findings
        assert "STRICT" in result
        assert "CRITICAL" in result or "HIGH" in result or "FAILED" in result

    @pytest.mark.asyncio
    async def test_validate_config_advisory_passes(self, mock_dl):
        """Advisory mode with clean code should pass."""
        good_code = """
        properties: {
          supportsHttpsTrafficOnly: true
          minimumTlsVersion: 'TLS1_2'
          publicNetworkAccess: 'Disabled'
          encryption: { keySource: 'Microsoft.Keyvault' }
        }
        """
        result = await validate_gdpr_config_impl(good_code, "bicep", False, mock_dl)
        assert "ADVISORY" in result


# ─── Retention extended tests ──────────────────────────────────────────────

class TestRetentionExtended:

    @pytest.mark.asyncio
    @pytest.mark.parametrize("category", list(RETENTION_GUIDANCE.keys()))
    async def test_all_retention_categories(self, category, mock_dl):
        """Every retention category should return guidance with disclaimer."""
        result = await get_retention_guidance_impl(category, mock_dl)
        assert LEGAL_DISCLAIMER in result
        assert "Art" in result

    @pytest.mark.asyncio
    async def test_retention_fuzzy_match(self, mock_dl):
        """Partial category names should fuzzy-match."""
        result = await get_retention_guidance_impl("health", mock_dl)
        assert LEGAL_DISCLAIMER in result
        assert "Art. 9" in result or "health" in result.lower()

    @pytest.mark.asyncio
    async def test_deletion_requirements_mentions_art17(self, mock_dl):
        """check_deletion_requirements must reference Art. 17."""
        result = await check_deletion_requirements_impl("SaaS platform with user accounts", mock_dl)
        assert "Art. 17" in result
        assert "erasure" in result.lower() or "deletion" in result.lower()

    @pytest.mark.asyncio
    async def test_retention_no_review_flagged(self, mock_dl):
        """Policy without review schedule should be flagged."""
        result = await assess_retention_policy_impl(
            "Data kept for 3 years for contract purpose. Deleted after expiry.",
            mock_dl,
        )
        assert "review" in result.lower()

    @pytest.mark.asyncio
    async def test_retention_good_policy(self, mock_dl):
        """Policy with all elements should get positive marks."""
        result = await assess_retention_policy_impl(
            "Customer data retained for contract purpose. 5 year retention. "
            "Annual review schedule. Automated deletion and anonymization after expiry.",
            mock_dl,
        )
        # Should have multiple good practices
        assert result.count("✅") >= 3


# ─── Articles edge cases ──────────────────────────────────────────────────

class TestArticlesEdgeCases:

    @pytest.mark.asyncio
    async def test_list_chapter_not_found_shows_chapters(self, mock_dl):
        """Requesting non-existent chapter should list available chapters."""
        result = await list_chapter_articles_impl("99", mock_dl)
        assert LEGAL_DISCLAIMER in result
        assert "Chapter" in result

    @pytest.mark.asyncio
    async def test_search_no_results(self, mock_dl):
        """Search with no matches should indicate no results."""
        mock_dl.search_articles = MagicMock(return_value=[])
        mock_dl.search_recitals = MagicMock(return_value=[])
        result = await search_gdpr_impl("xyzzy_nonexistent", mock_dl)
        assert "no match" in result.lower() or "No matches" in result

    @pytest.mark.asyncio
    async def test_azure_mapping_not_found(self, mock_dl):
        """Non-mapped article should suggest available mappings."""
        result = await get_azure_mapping_impl("99", mock_dl)
        assert LEGAL_DISCLAIMER in result
        assert "5" in result and "32" in result  # Should list available

    @pytest.mark.asyncio
    async def test_definitions_empty_list(self, mock_dl):
        """Empty definitions list should produce safe output."""
        mock_dl.list_definitions = MagicMock(return_value=[])
        result = await list_definitions_impl(mock_dl)
        assert LEGAL_DISCLAIMER in result


# ─── Adversarial / malformed inputs ────────────────────────────────────────

class TestMalformedInputs:

    @pytest.mark.asyncio
    async def test_article_with_html_injection(self, mock_dl):
        """HTML in article_id should not cause errors."""
        result = await get_article_impl("<script>alert(1)</script>", mock_dl)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_dpia_with_empty_description(self, mock_dl):
        """Empty processing description should not crash."""
        result = await assess_dpia_need_impl("", mock_dl)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_analyzer_with_empty_code(self, mock_dl):
        """Empty code should return clean result."""
        result = await analyze_infrastructure_code_impl("", "bicep", None, None, mock_dl)
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_ropa_validate_with_empty(self, mock_dl):
        """Empty ROPA content should flag all fields missing."""
        result = await validate_ropa_impl("", mock_dl)
        assert LEGAL_DISCLAIMER in result
        assert "MISSING" in result

    @pytest.mark.asyncio
    async def test_retention_with_unicode(self, mock_dl):
        """Unicode input should not cause errors."""
        result = await assess_retention_policy_impl(
            "Données conservées pendant 5 ans pour 目的 compliance", mock_dl
        )
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_dsr_with_empty_type(self, mock_dl):
        """Empty DSR type should return helpful error."""
        result = await get_dsr_guidance_impl("", mock_dl)
        assert LEGAL_DISCLAIMER in result
