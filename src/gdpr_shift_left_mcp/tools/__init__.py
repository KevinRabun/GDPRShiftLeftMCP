"""
GDPR Shift-Left MCP Server — Tools Module

This module organizes all MCP tool functions into logical groups.
Each submodule contains related tools that are registered with the MCP server.
"""
import json
import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP
    from ..data_loader import GDPRDataLoader

logger = logging.getLogger(__name__)


def register_tools(mcp: "FastMCP", data_loader: "GDPRDataLoader"):
    """
    Register all tool functions with the MCP server.

    Args:
        mcp: The FastMCP server instance
        data_loader: The data loader instance for accessing GDPR data
    """
    from . import articles, definitions, dpia, ropa, dsr, analyzer, retention, role_classifier
    from ..disclaimer import append_disclaimer

    # ── GDPR Article / Regulation Q&A ───────────────────────────────────

    @mcp.tool()
    async def get_article(article_id: str) -> str:
        """Get the full text and context of a specific GDPR article."""
        return await articles.get_article_impl(article_id, data_loader)

    @mcp.tool()
    async def list_chapter_articles(chapter: str) -> str:
        """List all articles within a specific GDPR chapter."""
        return await articles.list_chapter_articles_impl(chapter, data_loader)

    @mcp.tool()
    async def search_gdpr(keywords: str) -> str:
        """Search across GDPR articles and recitals by keywords."""
        return await articles.search_gdpr_impl(keywords, data_loader)

    @mcp.tool()
    async def get_recital(recital_number: str) -> str:
        """Get the text of a specific GDPR recital."""
        return await articles.get_recital_impl(recital_number, data_loader)

    @mcp.tool()
    async def get_azure_mapping(article_id: str) -> str:
        """Get Azure service recommendations mapped to a specific GDPR article."""
        return await articles.get_azure_mapping_impl(article_id, data_loader)

    # ── Definitions (Art. 4) ────────────────────────────────────────────

    @mcp.tool()
    async def get_definition(term: str) -> str:
        """Get the GDPR definition for a specific term (Art. 4)."""
        return await definitions.get_definition_impl(term, data_loader)

    @mcp.tool()
    async def list_definitions() -> str:
        """List all GDPR definitions from Article 4."""
        return await definitions.list_definitions_impl(data_loader)

    @mcp.tool()
    async def search_definitions(keywords: str) -> str:
        """Search GDPR definitions by keywords."""
        return await definitions.search_definitions_impl(keywords, data_loader)

    # ── DPIA (Art. 35 / 36) ─────────────────────────────────────────────

    @mcp.tool()
    async def assess_dpia_need(processing_description: str) -> str:
        """
        Assess whether a DPIA is required for a described processing activity.

        Args:
            processing_description: Free-text description of the data processing
        """
        return await dpia.assess_dpia_need_impl(processing_description, data_loader)

    @mcp.tool()
    async def generate_dpia_template(processing_description: str) -> str:
        """
        Generate a DPIA template pre-filled with guidance for the described
        processing activity, including risk assessment and mitigation measures.

        Args:
            processing_description: Free-text description of the data processing
        """
        return await dpia.generate_dpia_template_impl(processing_description, data_loader)

    @mcp.tool()
    async def get_dpia_guidance(topic: str) -> str:
        """
        Get detailed DPIA guidance for a specific topic or processing type.

        Args:
            topic: Topic area (e.g., 'profiling', 'large-scale monitoring',
                   'special categories', 'children')
        """
        return await dpia.get_dpia_guidance_impl(topic, data_loader)

    # ── Records of Processing / ROPA (Art. 30) ─────────────────────────

    @mcp.tool()
    async def generate_ropa_template(organization_context: str) -> str:
        """
        Generate a Records of Processing Activities (ROPA) template per Art. 30.

        Args:
            organization_context: Description of the organization, its role
                (controller/processor), and main processing activities
        """
        return await ropa.generate_ropa_template_impl(organization_context, data_loader)

    @mcp.tool()
    async def validate_ropa(ropa_content: str) -> str:
        """
        Validate a ROPA document against Art. 30 mandatory fields.

        Args:
            ropa_content: The ROPA content to validate (text/JSON/markdown)
        """
        return await ropa.validate_ropa_impl(ropa_content, data_loader)

    @mcp.tool()
    async def get_ropa_requirements(role: str = "controller") -> str:
        """
        Get the mandatory ROPA fields for a given organizational role.

        Args:
            role: 'controller' or 'processor' — determines required fields
        """
        return await ropa.get_ropa_requirements_impl(role, data_loader)

    # ── Data Subject Rights / DSR (Arts. 12–23) ─────────────────────────

    @mcp.tool()
    async def get_dsr_guidance(request_type: str) -> str:
        """
        Get guidance on handling a specific data-subject request.

        Args:
            request_type: Type of DSR — 'access', 'rectification', 'erasure',
                'restriction', 'portability', 'objection', 'automated_decision'
        """
        return await dsr.get_dsr_guidance_impl(request_type, data_loader)

    @mcp.tool()
    async def generate_dsr_workflow(request_type: str, system_context: str = "") -> str:
        """
        Generate a step-by-step DSR fulfilment workflow with Azure
        implementation notes.

        Args:
            request_type: Type of DSR
            system_context: Optional description of the system architecture
        """
        return await dsr.generate_dsr_workflow_impl(request_type, system_context, data_loader)

    @mcp.tool()
    async def get_dsr_timeline(request_type: str) -> str:
        """
        Get GDPR-mandated response timelines and extension rules for a DSR type.

        Args:
            request_type: Type of DSR
        """
        return await dsr.get_dsr_timeline_impl(request_type, data_loader)

    # ── Azure IaC & Code Analyzer ───────────────────────────────────────

    @mcp.tool()
    async def analyze_infrastructure_code(
        code: str,
        file_type: str,
        file_path: Optional[str] = None,
        context: Optional[str] = None,
    ) -> str:
        """
        Analyze Bicep/Terraform/ARM code for GDPR compliance issues.

        Checks data residency, encryption, access control, logging,
        retention, and privacy-by-design patterns.

        Args:
            code: The IaC code content
            file_type: 'bicep', 'terraform', or 'arm'
            file_path: Optional file path for reporting
            context: Optional additional context
        """
        return await analyzer.analyze_infrastructure_code_impl(
            code, file_type, file_path, context, data_loader
        )

    @mcp.tool()
    async def analyze_application_code(
        code: str,
        language: str,
        file_path: Optional[str] = None,
    ) -> str:
        """
        Analyze application code for GDPR compliance issues such as missing
        consent checks, PII logging, insecure data handling, and missing
        encryption.

        Args:
            code: The application code content
            language: 'python', 'csharp', 'java', 'typescript', or 'javascript'
            file_path: Optional file path for reporting
        """
        return await analyzer.analyze_application_code_impl(
            code, language, file_path, data_loader
        )

    @mcp.tool()
    async def validate_gdpr_config(
        code: str,
        file_type: str,
        strict_mode: bool = True,
    ) -> str:
        """
        Validate IaC configuration against GDPR mandatory requirements
        BEFORE deploying.

        Checks for: missing encryption at rest/in transit, public endpoints
        without justification, insufficient log retention, missing data
        classification tags, non-EU data residency.

        Args:
            code: The IaC code content
            file_type: 'bicep', 'terraform', or 'arm'
            strict_mode: If True, fail on any GDPR violation
        """
        return await analyzer.validate_gdpr_config_impl(
            code, file_type, strict_mode, data_loader
        )

    @mcp.tool()
    async def analyze_dsr_capabilities(
        code: str,
        language: str,
        file_path: Optional[str] = None,
    ) -> str:
        """
        Analyze code for Data Subject Rights (DSR) implementation capabilities.

        Detects patterns indicating support for GDPR rights:
        - Art. 15: Right of access
        - Art. 16: Right to rectification
        - Art. 17: Right to erasure
        - Art. 18: Right to restriction
        - Art. 20: Right to data portability
        - Art. 21: Right to object
        - Art. 22: Automated decision-making safeguards

        Args:
            code: The application code content
            language: Programming language ('python', 'typescript', 'csharp', etc.)
            file_path: Optional file path for reporting
        """
        return await analyzer.analyze_dsr_capabilities_impl(
            code, language, file_path, data_loader
        )

    @mcp.tool()
    async def analyze_cross_border_transfers(
        code: str,
        language: str,
        file_path: Optional[str] = None,
    ) -> str:
        """
        Analyze code for potential cross-border data transfers under GDPR Chapter V.

        Detects:
        - Third-party API calls to non-EU services (OpenAI, Stripe, Twilio, etc.)
        - SDK imports for US-based services
        - Webhook/integration patterns that may involve data export

        Provides guidance on SCCs, DPAs, and Transfer Impact Assessments.

        Args:
            code: The application code content
            language: Programming language ('python', 'typescript', 'csharp', etc.)
            file_path: Optional file path for reporting
        """
        return await analyzer.analyze_cross_border_transfers_impl(
            code, language, file_path, data_loader
        )

    @mcp.tool()
    async def analyze_breach_readiness(
        code: str,
        language: str,
        file_path: Optional[str] = None,
    ) -> str:
        """
        Analyze code for breach notification readiness under GDPR Art. 33-34.

        Assesses:
        - Security logging capabilities
        - Alerting mechanisms
        - Incident tracking systems
        - 72-hour notification process references
        - Data subject notification capabilities

        Args:
            code: The application code content
            language: Programming language ('python', 'typescript', 'csharp', etc.)
            file_path: Optional file path for reporting
        """
        return await analyzer.analyze_breach_readiness_impl(
            code, language, file_path, data_loader
        )

    @mcp.tool()
    async def analyze_data_flow(
        code: str,
        language: str,
        file_path: Optional[str] = None,
    ) -> str:
        """
        Analyze code for personal data flow patterns to support ROPA documentation.

        Maps the data lifecycle:
        - Collection: Where PII enters the system
        - Storage: Where PII is persisted
        - Transmission: Where PII is sent externally
        - Deletion: Where PII is removed

        Helps identify GDPR compliance touchpoints for Art. 30 ROPA.

        Args:
            code: The application code content
            language: Programming language ('python', 'typescript', 'csharp', etc.)
            file_path: Optional file path for reporting
        """
        return await analyzer.analyze_data_flow_impl(
            code, language, file_path, data_loader
        )

    # ── Data Retention & Deletion (Art. 5(1)(e), Art. 17) ───────────────

    @mcp.tool()
    async def assess_retention_policy(policy_description: str) -> str:
        """
        Assess a data-retention policy against GDPR storage-limitation
        principle (Art. 5(1)(e)) and right to erasure (Art. 17).

        Args:
            policy_description: Description of the retention policy
        """
        return await retention.assess_retention_policy_impl(policy_description, data_loader)

    @mcp.tool()
    async def get_retention_guidance(data_category: str) -> str:
        """
        Get GDPR-aligned retention guidance for a specific data category.

        Args:
            data_category: Category of data (e.g., 'employee records',
                'customer data', 'marketing consent', 'health data',
                'financial transactions')
        """
        return await retention.get_retention_guidance_impl(data_category, data_loader)

    @mcp.tool()
    async def check_deletion_requirements(system_context: str) -> str:
        """
        Check what deletion/anonymization capabilities a system must
        support per GDPR.

        Args:
            system_context: Description of the system and data it holds
        """
        return await retention.check_deletion_requirements_impl(system_context, data_loader)

    # ── Controller/Processor Role Classification (Art. 4(7), 4(8), 26, 28) ───

    @mcp.tool()
    async def assess_controller_processor_role(service_description: str) -> str:
        """
        Assess whether a service/system acts as data controller, processor,
        joint controller, or has a mixed role under GDPR.

        Analyzes the service description against GDPR definitions and EDPB
        guidance to determine the likely role and associated obligations.

        Args:
            service_description: Description of the service, data flows,
                business relationships, and processing activities
        """
        return await role_classifier.assess_controller_processor_role_impl(
            service_description, data_loader
        )

    @mcp.tool()
    async def get_role_obligations(role: str, include_azure: bool = True) -> str:
        """
        Get GDPR obligations specific to a controller/processor role.

        Returns detailed obligations from relevant GDPR articles with
        optional Azure implementation guidance.

        Args:
            role: 'controller', 'processor', 'joint_controller', or 'sub_processor'
            include_azure: Include Azure-specific implementation guidance
        """
        return await role_classifier.get_role_obligations_impl(
            role, include_azure, data_loader
        )

    @mcp.tool()
    async def analyze_code_for_role_indicators(
        code: str,
        language: str,
    ) -> str:
        """
        Analyze source code for patterns indicating controller vs processor role.

        Detects patterns like: direct user data collection, consent mechanisms,
        multi-tenant isolation, webhook receivers, data forwarding, etc.

        Args:
            code: The source code to analyze
            language: Programming language ('python', 'typescript', 'csharp', etc.)
        """
        return await role_classifier.analyze_code_for_role_indicators_impl(
            code, language, data_loader
        )

    @mcp.tool()
    async def generate_dpa_checklist(context: str) -> str:
        """
        Generate an Article 28 Data Processing Agreement (DPA) checklist.

        Provides a comprehensive checklist of mandatory and recommended
        DPA clauses with Azure-specific considerations.

        Args:
            context: Description of the processing relationship and context
        """
        return await role_classifier.generate_dpa_checklist_impl(context, data_loader)

    @mcp.tool()
    async def get_role_scenarios(scenario_type: str = "all") -> str:
        """
        Get common controller/processor scenarios and role determinations.

        Returns typical scenarios (SaaS, API services, cloud infrastructure, etc.)
        with guidance on typical role classification and exceptions.

        Args:
            scenario_type: Filter scenarios by type (e.g., 'saas', 'api', 'cloud')
                          or 'all' for all scenarios
        """
        return await role_classifier.get_role_scenarios_impl(scenario_type, data_loader)

    # ── AST-Based Code Analysis ─────────────────────────────────────────

    from . import ast_analyzer

    @mcp.tool()
    async def analyze_code_ast(
        code: str,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
        deep_analysis: bool = False,
    ) -> str:
        """
        Analyze code using AST for GDPR compliance (Python, JavaScript, TypeScript).

        AST analysis provides higher accuracy than regex by:
        - Filtering out comments and string literals (reducing false positives)
        - Tracking variable assignments and data flow
        - Identifying function definitions and call sites
        - Verifying semantic intent of GDPR-related code

        Detects:
        - Cross-border data transfers (third-party API imports)
        - PII handling in function parameters
        - PII logging violations
        - DSR implementation patterns (Art. 15-22)

        Args:
            code: Source code to analyze
            file_path: Optional file path for automatic language detection
            language: Override language (python, javascript, typescript)
            deep_analysis: Include detailed function, import, and data flow info
        """
        return await ast_analyzer.analyze_code_ast_impl(
            code, file_path, language, deep_analysis, data_loader
        )

    @mcp.tool()
    async def get_ast_capabilities() -> str:
        """
        Get information about AST analysis capabilities.

        Returns supported languages, analysis categories, detected patterns,
        and configuration options for the AST-based code analyzer.
        """
        return await ast_analyzer.get_ast_capabilities_impl(data_loader)

    logger.info("Registered 34 GDPR tools across 9 modules")
