"""
GDPR Shift-Left MCP Server — Comprehensive Judge Checks

End-to-end behavioural judges that validate:
  - Actual tool invocations produce correct output
  - Error/adversarial input is handled gracefully
  - GDPR data accuracy (article count, key article content)
  - Disclaimer present in every tool output
  - Azure mappings are correct
  - Search returns relevant results
  - Data loader integrity
"""
import json
import os
import sys
from typing import List
from unittest.mock import AsyncMock, MagicMock

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
from gdpr_shift_left_mcp.tools.dpia import assess_dpia_need_impl, generate_dpia_template_impl
from gdpr_shift_left_mcp.tools.ropa import (
    generate_ropa_template_impl,
    validate_ropa_impl,
    get_ropa_requirements_impl,
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
)
from gdpr_shift_left_mcp.tools.retention import (
    assess_retention_policy_impl,
    get_retention_guidance_impl,
    check_deletion_requirements_impl,
)
from gdpr_shift_left_mcp.data_loader import GDPRDataLoader

from .judge import Judge, JudgeResult, judge


def _make_mock_dl():
    """Create a minimal mock data loader for non-data-dependent tests."""
    dl = MagicMock()
    dl.load_data = AsyncMock()
    dl.get_article = MagicMock(return_value=None)
    dl.list_chapter_articles = MagicMock(return_value=[])
    dl.search_articles = MagicMock(return_value=[])
    dl.search_recitals = MagicMock(return_value=[])
    dl.get_recital = MagicMock(return_value=None)
    dl.get_definition = MagicMock(return_value=None)
    dl.list_definitions = MagicMock(return_value=[])
    dl.search_definitions = MagicMock(return_value=[])
    dl.get_azure_mapping = MagicMock(return_value=None)
    dl.get_edpb_guidelines = MagicMock(return_value=[])
    return dl


# ─── Judge: End-to-End Tool Invocation ──────────────────────────────────────

@judge.register
async def judge_tool_invocation_e2e(**kwargs) -> List[JudgeResult]:
    """Invoke every tool family and verify output structure (non-empty, disclaimer)."""
    results: List[JudgeResult] = []
    dl = _make_mock_dl()

    tool_calls = [
        ("get_article", lambda: get_article_impl("5", dl)),
        ("list_chapter_articles", lambda: list_chapter_articles_impl("1", dl)),
        ("search_gdpr", lambda: search_gdpr_impl("consent", dl)),
        ("get_recital", lambda: get_recital_impl("1", dl)),
        ("get_azure_mapping", lambda: get_azure_mapping_impl("5", dl)),
        ("get_definition", lambda: get_definition_impl("personal data", dl)),
        ("list_definitions", lambda: list_definitions_impl(dl)),
        ("search_definitions", lambda: search_definitions_impl("consent", dl)),
        ("assess_dpia_need", lambda: assess_dpia_need_impl("profiling users", dl)),
        ("generate_dpia_template", lambda: generate_dpia_template_impl("Processing health data", dl)),
        ("generate_ropa_template", lambda: generate_ropa_template_impl("controller", dl)),
        ("validate_ropa", lambda: validate_ropa_impl("Test record", dl)),
        ("get_ropa_requirements", lambda: get_ropa_requirements_impl("controller", dl)),
        ("get_dsr_guidance", lambda: get_dsr_guidance_impl("access", dl)),
        ("generate_dsr_workflow", lambda: generate_dsr_workflow_impl("erasure", "Test", dl)),
        ("get_dsr_timeline", lambda: get_dsr_timeline_impl("access", dl)),
        ("analyze_iac", lambda: analyze_infrastructure_code_impl("resource r {}", "bicep", None, None, dl)),
        ("analyze_app", lambda: analyze_application_code_impl("print('hello')", "python", None, dl)),
        ("validate_config", lambda: validate_gdpr_config_impl("config: test", "bicep", False, dl)),
        ("assess_retention", lambda: assess_retention_policy_impl("5 years customer data", dl)),
        ("get_retention_guidance", lambda: get_retention_guidance_impl("customer data", dl)),
        ("check_deletion", lambda: check_deletion_requirements_impl("SaaS platform", dl)),
    ]

    for tool_name, call in tool_calls:
        try:
            result = await call()
            has_output = bool(result) and len(result) > 20
            has_disclaimer = LEGAL_DISCLAIMER in result
            passed = has_output and has_disclaimer
            results.append(JudgeResult(
                name=f"e2e_{tool_name}",
                passed=passed,
                message=f"{tool_name}: output={'OK' if has_output else 'EMPTY'}, disclaimer={'OK' if has_disclaimer else 'MISSING'}",
            ))
        except Exception as exc:
            results.append(JudgeResult(
                name=f"e2e_{tool_name}",
                passed=False,
                message=f"{tool_name} crashed: {type(exc).__name__}: {exc}",
            ))

    return results


# ─── Judge: Adversarial / Error Handling ────────────────────────────────────

@judge.register
async def judge_error_handling(**kwargs) -> List[JudgeResult]:
    """Verify tools handle malformed / adversarial input gracefully."""
    results: List[JudgeResult] = []
    dl = _make_mock_dl()

    adversarial_inputs = [
        ("article_html_inject", lambda: get_article_impl("<script>alert(1)</script>", dl)),
        ("dpia_empty", lambda: assess_dpia_need_impl("", dl)),
        ("iac_empty_code", lambda: analyze_infrastructure_code_impl("", "bicep", None, None, dl)),
        ("ropa_empty", lambda: validate_ropa_impl("", dl)),
        ("dsr_empty_type", lambda: get_dsr_guidance_impl("", dl)),
        ("definition_nonexistent", lambda: get_definition_impl("xyzzy_not_a_gdpr_term", dl)),
        ("search_empty", lambda: search_gdpr_impl("", dl)),
        ("retention_unicode", lambda: assess_retention_policy_impl("données 日本語 ñ", dl)),
    ]

    for name, call in adversarial_inputs:
        try:
            result = await call()
            # Must not crash and must contain disclaimer
            passed = isinstance(result, str) and LEGAL_DISCLAIMER in result
            results.append(JudgeResult(
                name=f"adversarial_{name}",
                passed=passed,
                message=f"{name}: handled gracefully" if passed else f"{name}: missing disclaimer or invalid return",
            ))
        except Exception as exc:
            results.append(JudgeResult(
                name=f"adversarial_{name}",
                passed=False,
                message=f"{name} crashed: {type(exc).__name__}: {exc}",
            ))

    return results


# ─── Judge: Data Loader Integrity ───────────────────────────────────────────

@judge.register
async def judge_data_loader_integrity(**kwargs) -> List[JudgeResult]:
    """Verify bundled data loads correctly with expected counts."""
    results: List[JudgeResult] = []

    try:
        loader = GDPRDataLoader()
        await loader.load_data()

        # 99 articles
        art_count = len(loader._articles)
        results.append(JudgeResult(
            name="bundled_article_count",
            passed=art_count >= 90,
            message=f"Bundled data has {art_count} articles (expected ~99)",
        ))

        # Recitals
        rec_count = len(loader._recitals)
        results.append(JudgeResult(
            name="bundled_recital_count",
            passed=rec_count >= 100,
            message=f"Bundled data has {rec_count} recitals (expected ~173)",
        ))

        # Definitions
        def_count = len(loader._definitions)
        results.append(JudgeResult(
            name="bundled_definition_count",
            passed=def_count >= 10,
            message=f"Bundled data has {def_count} definitions (expected ~26)",
        ))

        # Key articles exist
        for art_num in ["5", "6", "7", "12", "13", "14", "15", "17", "25", "28", "30", "32", "33", "35", "44"]:
            art = loader.get_article(art_num)
            exists = art is not None
            results.append(JudgeResult(
                name=f"key_article_{art_num}_exists",
                passed=exists,
                message=f"Article {art_num} {'found' if exists else 'MISSING'} in bundled data",
            ))

        # Article 5 should mention "lawfulness" or principles
        art5 = loader.get_article("5")
        if art5:
            text = str(art5).lower()
            mentions_principles = "lawful" in text or "principle" in text or "purpose" in text
            results.append(JudgeResult(
                name="article5_content_accuracy",
                passed=mentions_principles,
                message=f"Article 5 {'mentions' if mentions_principles else 'does NOT mention'} GDPR principles",
            ))

        # Article 17 should mention right to erasure
        art17 = loader.get_article("17")
        if art17:
            text = str(art17).lower()
            mentions_erasure = "erasure" in text or "forgotten" in text or "delete" in text
            results.append(JudgeResult(
                name="article17_content_accuracy",
                passed=mentions_erasure,
                message=f"Article 17 {'mentions' if mentions_erasure else 'does NOT mention'} right to erasure",
            ))

    except Exception as exc:
        results.append(JudgeResult(
            name="data_loader_integrity",
            passed=False,
            message=f"Data loader failed: {type(exc).__name__}: {exc}",
        ))

    return results


# ─── Judge: Azure Mappings Correctness ──────────────────────────────────────

@judge.register
async def judge_azure_mappings(**kwargs) -> List[JudgeResult]:
    """Verify Azure service mappings exist for key GDPR articles."""
    results: List[JudgeResult] = []

    try:
        loader = GDPRDataLoader()
        await loader.load_data()

        expected_mappings = {
            "5": "Azure Policy",
            "25": "Privacy",
            "28": "Azure",
            "30": "Azure",
            "32": "Azure Security",
            "33": "Azure",
            "35": "Azure",
            "44": "Azure",
        }

        for art_num, keyword in expected_mappings.items():
            mapping = loader.get_azure_mapping(art_num)
            has_mapping = mapping is not None and len(mapping) > 0
            results.append(JudgeResult(
                name=f"azure_mapping_art{art_num}",
                passed=has_mapping,
                message=f"Art. {art_num} has Azure mapping ({len(mapping) if mapping else 0} entries)" if has_mapping else f"Art. {art_num} MISSING Azure mapping",
            ))

    except Exception as exc:
        results.append(JudgeResult(
            name="azure_mappings",
            passed=False,
            message=f"Azure mappings check failed: {exc}",
        ))

    return results


# ─── Judge: Search Functionality ────────────────────────────────────────────

@judge.register
async def judge_search_functionality(**kwargs) -> List[JudgeResult]:
    """Verify search returns relevant results for key GDPR terms."""
    results: List[JudgeResult] = []

    try:
        loader = GDPRDataLoader()
        await loader.load_data()

        search_tests = [
            ("consent", True),
            ("data protection officer", True),
            ("erasure", True),
            ("transfer", True),
            ("xyzzy_not_real_term", False),
        ]

        for term, should_find in search_tests:
            found = loader.search_articles(term)
            has_results = len(found) > 0
            passed = has_results == should_find
            results.append(JudgeResult(
                name=f"search_{term.replace(' ', '_')[:20]}",
                passed=passed,
                message=f"Search '{term}': {len(found)} results ({'expected' if passed else 'unexpected'})",
            ))

    except Exception as exc:
        results.append(JudgeResult(
            name="search_functionality",
            passed=False,
            message=f"Search functionality check failed: {exc}",
        ))

    return results


# ─── Judge: DPIA Logic Correctness ─────────────────────────────────────────

@judge.register
async def judge_dpia_logic(**kwargs) -> List[JudgeResult]:
    """Verify DPIA assessment triggers correctly for known scenarios."""
    results: List[JudgeResult] = []
    dl = _make_mock_dl()

    # Profiling should trigger REQUIRED
    profiling_result = await assess_dpia_need_impl("Customer profiling for credit scoring", dl)
    profiling_required = "REQUIRED" in profiling_result
    results.append(JudgeResult(
        name="dpia_profiling_required",
        passed=profiling_required,
        message="Profiling correctly triggers DPIA REQUIRED" if profiling_required else "Profiling should trigger DPIA REQUIRED",
    ))

    # Surveillance should trigger REQUIRED
    surveillance_result = await assess_dpia_need_impl("CCTV surveillance in shopping centre", dl)
    surveillance_required = "REQUIRED" in surveillance_result
    results.append(JudgeResult(
        name="dpia_surveillance_required",
        passed=surveillance_required,
        message="Surveillance correctly triggers DPIA REQUIRED" if surveillance_required else "Surveillance should trigger DPIA REQUIRED",
    ))

    # Simple contact form should NOT be REQUIRED
    simple_result = await assess_dpia_need_impl("Collecting contact information via web form", dl)
    simple_not_required = "REQUIRED" not in simple_result or "RECOMMENDED" in simple_result
    results.append(JudgeResult(
        name="dpia_simple_not_required",
        passed=simple_not_required,
        message="Simple processing correctly not requiring DPIA" if simple_not_required else "Simple processing should not require DPIA",
    ))

    return results


# ─── Judge: DSR Workflow Completeness ───────────────────────────────────────

@judge.register
async def judge_dsr_workflows(**kwargs) -> List[JudgeResult]:
    """Verify DSR workflows have proper step structure for all types."""
    results: List[JudgeResult] = []
    dl = _make_mock_dl()

    for dsr_type in DSR_TYPES:
        workflow = await generate_dsr_workflow_impl(dsr_type, "Test System", dl)
        has_steps = "Step" in workflow
        has_disclaimer = LEGAL_DISCLAIMER in workflow
        passed = has_steps and has_disclaimer
        results.append(JudgeResult(
            name=f"dsr_workflow_{dsr_type}",
            passed=passed,
            message=f"DSR workflow '{dsr_type}': steps={'OK' if has_steps else 'MISSING'}, disclaimer={'OK' if has_disclaimer else 'MISSING'}",
        ))

    return results
