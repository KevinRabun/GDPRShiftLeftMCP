"""
Tests for Controller/Processor Role Classifier Tool.

Tests cover:
- Role assessment from service descriptions
- Role obligations lookup
- Code pattern analysis for role indicators
- DPA checklist generation
- Common scenarios lookup
- Edge cases and input validation
"""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock

from gdpr_shift_left_mcp.disclaimer import LEGAL_DISCLAIMER
from gdpr_shift_left_mcp.tools.role_classifier import (
    assess_controller_processor_role_impl,
    get_role_obligations_impl,
    analyze_code_for_role_indicators_impl,
    generate_dpa_checklist_impl,
    get_role_scenarios_impl,
    _calculate_text_scores,
    _calculate_code_scores,
    _determine_role,
    CONTROLLER_INDICATORS,
    PROCESSOR_INDICATORS,
    JOINT_CONTROLLER_INDICATORS,
    CODE_CONTROLLER_PATTERNS,
    CODE_PROCESSOR_PATTERNS,
    CONTROLLER_OBLIGATIONS,
    PROCESSOR_OBLIGATIONS,
    COMMON_SCENARIOS,
)


# ─── Fixtures ──────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def mock_data_loader():
    """Create a mock data loader."""
    loader = MagicMock()
    loader.load_data = AsyncMock()
    return loader


# ─── Helper function tests ─────────────────────────────────────────────────

class TestHelperFunctions:
    """Test internal helper functions for role classification."""

    def test_calculate_text_scores_controller_keywords(self):
        """Test that controller keywords are detected."""
        text = "We collect user data for our own purposes and determine the retention period."
        scores, matched = _calculate_text_scores(text)
        
        assert scores["controller"] > 0
        assert len(matched["controller"]) > 0

    def test_calculate_text_scores_processor_keywords(self):
        """Test that processor keywords are detected."""
        text = "We process data on behalf of our clients per their instructions."
        scores, matched = _calculate_text_scores(text)
        
        assert scores["processor"] > 0
        assert len(matched["processor"]) > 0

    def test_calculate_text_scores_joint_controller_keywords(self):
        """Test that joint controller keywords are detected."""
        text = "We jointly determine the purposes with our partner organization."
        scores, matched = _calculate_text_scores(text)
        
        assert scores["joint_controller"] > 0
        assert len(matched["joint_controller"]) > 0

    def test_calculate_text_scores_empty_text(self):
        """Test with empty text."""
        scores, matched = _calculate_text_scores("")
        
        assert scores["controller"] == 0
        assert scores["processor"] == 0
        assert scores["joint_controller"] == 0

    def test_calculate_code_scores_controller_patterns(self):
        """Test controller code patterns detection."""
        code = """
        def signup_user(email, password):
            if not check_consent(email):
                raise ConsentRequired()
            return create_account(email, password)
        """
        scores, matched = _calculate_code_scores(code)
        
        assert scores["controller"] > 0
        assert len(matched["controller"]) > 0

    def test_calculate_code_scores_processor_patterns(self):
        """Test processor code patterns detection."""
        code = """
        def process_webhook(tenant_id, data):
            client = get_client(tenant_id)
            return forward_to_client(client, data)
        """
        scores, matched = _calculate_code_scores(code)
        
        assert scores["processor"] > 0
        assert len(matched["processor"]) > 0

    def test_determine_role_controller(self):
        """Test role determination when controller scores higher."""
        scores = {"controller": 10.0, "processor": 2.0, "joint_controller": 0.0}
        role = _determine_role(scores)
        assert role == "controller"

    def test_determine_role_processor(self):
        """Test role determination when processor scores higher."""
        scores = {"controller": 2.0, "processor": 10.0, "joint_controller": 0.0}
        role = _determine_role(scores)
        assert role == "processor"

    def test_determine_role_joint_controller(self):
        """Test role determination for joint controller."""
        scores = {"controller": 5.0, "processor": 2.0, "joint_controller": 5.0}
        role = _determine_role(scores)
        assert role == "joint_controller"

    def test_determine_role_mixed(self):
        """Test role determination when scores are close."""
        scores = {"controller": 8.0, "processor": 7.0, "joint_controller": 0.0}
        role = _determine_role(scores)
        assert role == "mixed"

    def test_determine_role_undetermined(self):
        """Test undetermined when scores are equal and low."""
        scores = {"controller": 2.0, "processor": 2.0, "joint_controller": 0.0}
        role = _determine_role(scores)
        assert role == "undetermined"


# ─── assess_controller_processor_role tests ────────────────────────────────

class TestAssessControllerProcessorRole:
    """Test the main role assessment function."""

    @pytest.mark.asyncio
    async def test_controller_assessment(self, mock_data_loader):
        """Test assessment of a clear controller scenario."""
        description = """
        We operate an e-commerce platform where customers create accounts,
        make purchases, and provide personal data. We collect customer data
        for order fulfillment, marketing, and analytics purposes. We determine
        what data to collect and how long to retain it.
        """
        result = await assess_controller_processor_role_impl(description, mock_data_loader)
        
        assert "Controller" in result or "CONTROLLER" in result
        assert "Art. 4(7)" in result or "Article 4(7)" in result
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_processor_assessment(self, mock_data_loader):
        """Test assessment of a clear processor scenario."""
        description = """
        We provide cloud storage services to enterprise clients. We store
        and process data on behalf of our customers per their instructions.
        We do not access or use customer data for our own purposes. We have
        Data Processing Agreements with all clients.
        """
        result = await assess_controller_processor_role_impl(description, mock_data_loader)
        
        assert "Processor" in result or "PROCESSOR" in result
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_mixed_role_assessment(self, mock_data_loader):
        """Test assessment of a mixed role scenario."""
        description = """
        We provide marketing automation services to clients. We process 
        client contact lists per their instructions for email campaigns.
        However, we also collect analytics data for our own product improvement
        and determine retention for aggregated usage statistics.
        """
        result = await assess_controller_processor_role_impl(description, mock_data_loader)
        
        # Should detect both controller and processor indicators
        assert "Score" in result
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_empty_description(self, mock_data_loader):
        """Test with empty description."""
        result = await assess_controller_processor_role_impl("", mock_data_loader)
        
        assert "undetermined" in result.lower() or "more information" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_includes_gdpr_definitions(self, mock_data_loader):
        """Test that GDPR definitions are included in output."""
        description = "We process customer data for e-commerce."
        result = await assess_controller_processor_role_impl(description, mock_data_loader)
        
        assert "Art. 4(7)" in result or "Article 4(7)" in result
        assert "Art. 4(8)" in result or "Article 4(8)" in result


# ─── get_role_obligations tests ────────────────────────────────────────────

class TestGetRoleObligations:
    """Test role obligations lookup."""

    @pytest.mark.asyncio
    async def test_controller_obligations(self, mock_data_loader):
        """Test getting controller obligations."""
        result = await get_role_obligations_impl("controller", True, mock_data_loader)
        
        assert "Controller" in result
        assert "Art. 24" in result or "Article 24" in result
        assert "Art. 25" in result or "Article 25" in result
        assert "accountability" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_processor_obligations(self, mock_data_loader):
        """Test getting processor obligations."""
        result = await get_role_obligations_impl("processor", True, mock_data_loader)
        
        assert "Processor" in result
        assert "Art. 28" in result or "Article 28" in result
        assert "instruction" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_joint_controller_obligations(self, mock_data_loader):
        """Test getting joint controller obligations."""
        result = await get_role_obligations_impl("joint_controller", True, mock_data_loader)
        
        assert "Joint Controller" in result or "joint controller" in result.lower()
        assert "Art. 26" in result or "Article 26" in result
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_sub_processor_obligations(self, mock_data_loader):
        """Test getting sub-processor obligations."""
        result = await get_role_obligations_impl("sub_processor", True, mock_data_loader)
        
        assert "Sub-Processor" in result or "sub-processor" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_invalid_role(self, mock_data_loader):
        """Test with invalid role."""
        result = await get_role_obligations_impl("invalid_role", True, mock_data_loader)
        
        assert "Unknown role" in result or "unknown" in result.lower()

    @pytest.mark.asyncio
    async def test_azure_guidance_included(self, mock_data_loader):
        """Test that Azure guidance is included when requested."""
        result = await get_role_obligations_impl("controller", True, mock_data_loader)
        
        assert "Azure" in result

    @pytest.mark.asyncio
    async def test_azure_guidance_excluded(self, mock_data_loader):
        """Test that Azure guidance can be excluded."""
        result = await get_role_obligations_impl("controller", False, mock_data_loader)
        
        # Should still have core obligations but may have less Azure-specific content
        assert "Controller" in result
        assert LEGAL_DISCLAIMER in result


# ─── analyze_code_for_role_indicators tests ────────────────────────────────

class TestAnalyzeCodeForRoleIndicators:
    """Test code analysis for role indicators."""

    @pytest.mark.asyncio
    async def test_controller_code_patterns(self, mock_data_loader):
        """Test detection of controller patterns in code."""
        code = """
        class UserRegistration:
            def register(self, email, password):
                consent = self.collect_consent()
                if consent:
                    user = self.create_account(email, password)
                    self.send_newsletter(user)
                    return user
        """
        result = await analyze_code_for_role_indicators_impl(code, "python", mock_data_loader)
        
        assert "Controller" in result or "controller" in result.lower()
        assert "signup" in result.lower() or "registration" in result.lower() or "consent" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_processor_code_patterns(self, mock_data_loader):
        """Test detection of processor patterns in code."""
        code = """
        class WebhookHandler:
            def handle_webhook(self, tenant_id, payload):
                client = self.get_client_by_tenant(tenant_id)
                self.process_on_behalf_of(client, payload)
                return self.forward_to_client(tenant_id, result)
        """
        result = await analyze_code_for_role_indicators_impl(code, "python", mock_data_loader)
        
        assert "Processor" in result or "processor" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_typescript_code(self, mock_data_loader):
        """Test with TypeScript code."""
        code = """
        async function signup(email: string, password: string): Promise<User> {
            const consent = await collectGdprConsent(email);
            if (!consent) throw new Error('Consent required');
            return createUser(email, password);
        }
        """
        result = await analyze_code_for_role_indicators_impl(code, "typescript", mock_data_loader)
        
        assert "typescript" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_empty_code(self, mock_data_loader):
        """Test with empty code."""
        result = await analyze_code_for_role_indicators_impl("", "python", mock_data_loader)
        
        assert "Insufficient" in result or "insufficient" in result.lower() or "undetermined" in result.lower()
        assert LEGAL_DISCLAIMER in result


# ─── generate_dpa_checklist tests ──────────────────────────────────────────

class TestGenerateDpaChecklist:
    """Test DPA checklist generation."""

    @pytest.mark.asyncio
    async def test_dpa_checklist_content(self, mock_data_loader):
        """Test that DPA checklist contains required elements."""
        context = "Cloud storage provider processing customer files"
        result = await generate_dpa_checklist_impl(context, mock_data_loader)
        
        # Check for mandatory Art. 28 elements
        assert "Art. 28" in result or "Article 28" in result
        assert "documented instructions" in result.lower()
        assert "sub-processor" in result.lower()
        assert "security" in result.lower()
        assert "audit" in result.lower()
        assert "delete" in result.lower() or "return" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_dpa_checklist_includes_context(self, mock_data_loader):
        """Test that context is reflected in the checklist."""
        context = "HR management SaaS processing employee personal data"
        result = await generate_dpa_checklist_impl(context, mock_data_loader)
        
        assert "HR management" in result or context in result
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_dpa_checklist_azure_guidance(self, mock_data_loader):
        """Test that Azure guidance is included."""
        context = "Processing on Azure cloud"
        result = await generate_dpa_checklist_impl(context, mock_data_loader)
        
        assert "Azure" in result
        assert LEGAL_DISCLAIMER in result


# ─── get_role_scenarios tests ──────────────────────────────────────────────

class TestGetRoleScenarios:
    """Test common scenarios lookup."""

    @pytest.mark.asyncio
    async def test_all_scenarios(self, mock_data_loader):
        """Test getting all scenarios."""
        result = await get_role_scenarios_impl("all", mock_data_loader)
        
        assert "SaaS" in result
        assert "processor" in result.lower()
        assert "controller" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_filter_saas_scenarios(self, mock_data_loader):
        """Test filtering scenarios by type."""
        result = await get_role_scenarios_impl("saas", mock_data_loader)
        
        assert "SaaS" in result
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_filter_cloud_scenarios(self, mock_data_loader):
        """Test filtering cloud scenarios."""
        result = await get_role_scenarios_impl("cloud", mock_data_loader)
        
        assert "Cloud" in result or "cloud" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_unknown_filter_shows_all(self, mock_data_loader):
        """Test that unknown filter shows all scenarios."""
        result = await get_role_scenarios_impl("xyz_unknown", mock_data_loader)
        
        # Should fall back to showing all scenarios
        assert "Scenario" in result or "scenario" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_includes_key_principles(self, mock_data_loader):
        """Test that key principles are included."""
        result = await get_role_scenarios_impl("all", mock_data_loader)
        
        assert "purposes and means" in result.lower() or "determines" in result.lower()
        assert LEGAL_DISCLAIMER in result


# ─── Data structure validation tests ───────────────────────────────────────

class TestDataStructures:
    """Test that data structures are properly defined."""

    def test_controller_indicators_have_required_fields(self):
        """Test controller indicators have required fields."""
        for indicator in CONTROLLER_INDICATORS:
            assert "id" in indicator
            assert "indicator" in indicator
            assert "description" in indicator
            assert "weight" in indicator
            assert "keywords" in indicator
            assert isinstance(indicator["keywords"], list)
            assert indicator["weight"] > 0

    def test_processor_indicators_have_required_fields(self):
        """Test processor indicators have required fields."""
        for indicator in PROCESSOR_INDICATORS:
            assert "id" in indicator
            assert "indicator" in indicator
            assert "description" in indicator
            assert "weight" in indicator
            assert "keywords" in indicator
            assert isinstance(indicator["keywords"], list)
            assert indicator["weight"] > 0

    def test_code_patterns_have_required_fields(self):
        """Test code patterns have required fields."""
        for pattern in CODE_CONTROLLER_PATTERNS + CODE_PROCESSOR_PATTERNS:
            assert "id" in pattern
            assert "pattern" in pattern
            assert "description" in pattern
            assert "weight" in pattern

    def test_controller_obligations_structure(self):
        """Test controller obligations structure."""
        assert "core_articles" in CONTROLLER_OBLIGATIONS
        assert "obligations" in CONTROLLER_OBLIGATIONS
        assert len(CONTROLLER_OBLIGATIONS["obligations"]) > 0
        
        for obl in CONTROLLER_OBLIGATIONS["obligations"]:
            assert "article" in obl
            assert "title" in obl
            assert "description" in obl

    def test_processor_obligations_structure(self):
        """Test processor obligations structure."""
        assert "core_articles" in PROCESSOR_OBLIGATIONS
        assert "obligations" in PROCESSOR_OBLIGATIONS
        assert len(PROCESSOR_OBLIGATIONS["obligations"]) > 0
        
        for obl in PROCESSOR_OBLIGATIONS["obligations"]:
            assert "article" in obl
            assert "title" in obl
            assert "description" in obl

    def test_common_scenarios_structure(self):
        """Test common scenarios structure."""
        assert len(COMMON_SCENARIOS) > 0
        
        for scenario in COMMON_SCENARIOS:
            assert "scenario" in scenario
            assert "typical_role" in scenario
            assert "explanation" in scenario


# ─── Integration-style tests ───────────────────────────────────────────────

class TestIntegration:
    """Integration-style tests for role classification."""

    @pytest.mark.asyncio
    async def test_saas_provider_classification(self, mock_data_loader):
        """Test classification of a typical SaaS provider."""
        description = """
        Our company provides project management software as a service.
        Customers sign up, create projects, and invite their team members.
        We store customer data in our cloud infrastructure on behalf of our
        customers. We do not access customer project data except for support
        purposes per their request. We have DPAs with all enterprise customers.
        """
        result = await assess_controller_processor_role_impl(description, mock_data_loader)
        
        # SaaS typically leans processor but has controller elements
        assert "Score" in result  # Should show scoring
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_direct_to_consumer_classification(self, mock_data_loader):
        """Test classification of a direct-to-consumer service."""
        description = """
        We operate an online marketplace where consumers create accounts,
        list items for sale, and make purchases. We collect user email,
        address, and payment information. We use this data for order processing,
        marketing communications, and fraud prevention. We determine what
        data to collect and our own data retention policies.
        """
        result = await assess_controller_processor_role_impl(description, mock_data_loader)
        
        # D2C is clearly a controller
        assert "Controller" in result or "controller" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_api_service_classification(self, mock_data_loader):
        """Test classification of an API service."""
        description = """
        We provide an API for email delivery. Customers send us recipient
        email addresses and message content via our API, and we deliver
        the emails on their behalf. We process the data per customer
        instructions and delete it after delivery. We maintain delivery
        logs for troubleshooting.
        """
        result = await assess_controller_processor_role_impl(description, mock_data_loader)
        
        # API service is typically processor
        assert "Processor" in result or "processor" in result.lower()
        assert LEGAL_DISCLAIMER in result


# ─── Edge case tests ───────────────────────────────────────────────────────

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_very_long_description(self, mock_data_loader):
        """Test with very long service description."""
        description = "We process data. " * 1000  # Very repetitive
        result = await assess_controller_processor_role_impl(description, mock_data_loader)
        
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_special_characters(self, mock_data_loader):
        """Test with special characters in description."""
        description = "We process data <script>alert('xss')</script> & users' info."
        result = await assess_controller_processor_role_impl(description, mock_data_loader)
        
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_non_english_keywords(self, mock_data_loader):
        """Test with mixed language content."""
        description = "Wir verarbeiten Daten für unsere Kunden. We process on behalf of clients."
        result = await assess_controller_processor_role_impl(description, mock_data_loader)
        
        # Should still detect English keywords
        assert "processor" in result.lower() or "Processor" in result
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_code_with_comments(self, mock_data_loader):
        """Test code analysis with many comments."""
        code = """
        # This function handles user signup
        # GDPR compliant implementation
        def signup(email):
            # Collect consent per Art. 7
            consent = collect_consent(email)
            # Create account only if consent given
            return create_account(email) if consent else None
        """
        result = await analyze_code_for_role_indicators_impl(code, "python", mock_data_loader)
        
        assert "consent" in result.lower()
        assert LEGAL_DISCLAIMER in result

    @pytest.mark.asyncio
    async def test_role_case_insensitivity(self, mock_data_loader):
        """Test that role lookup is case-insensitive."""
        result1 = await get_role_obligations_impl("Controller", True, mock_data_loader)
        result2 = await get_role_obligations_impl("CONTROLLER", True, mock_data_loader)
        result3 = await get_role_obligations_impl("controller", True, mock_data_loader)
        
        # All should return controller obligations
        assert "Controller" in result1 or "controller" in result1.lower()
        assert "Controller" in result2 or "controller" in result2.lower()
        assert "Controller" in result3 or "controller" in result3.lower()
