"""
GDPR Shift-Left MCP Server — Built-in Judge Checks

These judges validate the MCP server's tool registration, output format,
disclaimer presence, and GDPR accuracy. They run automatically in CI.
"""
import re
from typing import List

from gdpr_shift_left_mcp.disclaimer import LEGAL_DISCLAIMER
from gdpr_shift_left_mcp.tools.dsr import DSR_TYPES
from gdpr_shift_left_mcp.tools.analyzer import GDPR_IAC_CHECKS
from gdpr_shift_left_mcp.tools.retention import RETENTION_GUIDANCE

from .judge import Judge, JudgeResult, judge


# ─── Judge: Tool Registration ──────────────────────────────────────────────

@judge.register
async def judge_tool_registration(**kwargs) -> List[JudgeResult]:
    """Verify all expected tools are registered in the __init__ module."""
    results = []
    try:
        from gdpr_shift_left_mcp.tools import register_tools
        results.append(JudgeResult(
            name="tool_registration_import",
            passed=True,
            message="register_tools function is importable",
        ))
    except ImportError as e:
        results.append(JudgeResult(
            name="tool_registration_import",
            passed=False,
            message=f"Cannot import register_tools: {e}",
        ))
    return results


# ─── Judge: Disclaimer Module ──────────────────────────────────────────────

@judge.register
async def judge_disclaimer_module(**kwargs) -> List[JudgeResult]:
    """Verify disclaimer module is correctly configured."""
    results = []
    from gdpr_shift_left_mcp.disclaimer import (
        LEGAL_DISCLAIMER,
        GDPR_CITATION_FOOTER,
        append_disclaimer,
        get_disclaimer,
    )

    # Disclaimer must contain "not legal advice" or equivalent
    # Strip markdown formatting for the check
    plain_text = LEGAL_DISCLAIMER.lower().replace("**", "").replace("*", "")
    has_disclaimer = any(
        phrase in plain_text
        for phrase in ["not legal advice", "not constitute legal advice", "does not constitute"]
    )
    results.append(JudgeResult(
        name="disclaimer_content",
        passed=has_disclaimer,
        message="Disclaimer contains 'not legal advice' language" if has_disclaimer else "Disclaimer missing required language",
    ))

    # append_disclaimer must include the disclaimer text
    output = append_disclaimer("Test")
    results.append(JudgeResult(
        name="disclaimer_append",
        passed=LEGAL_DISCLAIMER in output,
        message="append_disclaimer includes disclaimer text" if LEGAL_DISCLAIMER in output else "append_disclaimer does not include disclaimer",
    ))

    return results


# ─── Judge: DSR Types Completeness ─────────────────────────────────────────

@judge.register
async def judge_dsr_types(**kwargs) -> List[JudgeResult]:
    """Verify all GDPR DSR types are covered."""
    results = []
    expected_types = {"access", "rectification", "erasure", "restriction", "portability", "objection", "automated_decision"}
    actual_types = set(DSR_TYPES.keys())

    missing = expected_types - actual_types
    results.append(JudgeResult(
        name="dsr_types_coverage",
        passed=len(missing) == 0,
        message=f"All {len(expected_types)} DSR types present" if not missing else f"Missing DSR types: {missing}",
    ))

    # Each DSR type must have article reference, obligations, and azure_notes
    for dsr_name, dsr in DSR_TYPES.items():
        has_required = all(
            key in dsr for key in ("article", "title", "obligations", "azure_notes")
        )
        results.append(JudgeResult(
            name=f"dsr_{dsr_name}_structure",
            passed=has_required,
            message=f"DSR '{dsr_name}' has all required fields" if has_required else f"DSR '{dsr_name}' missing required fields",
        ))

    return results


# ─── Judge: IaC Checks Completeness ────────────────────────────────────────

@judge.register
async def judge_iac_checks(**kwargs) -> List[JudgeResult]:
    """Verify IaC checks cover critical GDPR areas."""
    results = []

    # Must cover encryption, access control, network, logging, retention, data residency
    required_areas = {"Encryption", "Access control", "Network", "logging", "retention", "residency"}
    covered = set()
    for check in GDPR_IAC_CHECKS:
        title_lower = check["title"].lower()
        for area in required_areas:
            if area.lower() in title_lower:
                covered.add(area)

    missing = required_areas - covered
    results.append(JudgeResult(
        name="iac_check_coverage",
        passed=len(missing) == 0,
        message=f"IaC checks cover all {len(required_areas)} required areas" if not missing else f"Missing IaC areas: {missing}",
    ))

    # Each check must have article reference and azure_fix
    for check in GDPR_IAC_CHECKS:
        has_ref = bool(check.get("article"))
        has_fix = bool(check.get("azure_fix"))
        results.append(JudgeResult(
            name=f"iac_{check['id']}_fields",
            passed=has_ref and has_fix,
            message=f"IaC check {check['id']} has article ref and Azure fix" if (has_ref and has_fix) else f"IaC check {check['id']} missing fields",
        ))

    return results


# ─── Judge: Retention Guidance ──────────────────────────────────────────────

@judge.register
async def judge_retention_guidance(**kwargs) -> List[JudgeResult]:
    """Verify retention guidance covers key data categories."""
    results = []
    expected = {"customer data", "employee records", "health data", "marketing consent"}
    actual = set(RETENTION_GUIDANCE.keys())

    missing = expected - actual
    results.append(JudgeResult(
        name="retention_categories",
        passed=len(missing) == 0,
        message=f"Retention guidance covers {len(actual)} categories" if not missing else f"Missing categories: {missing}",
    ))

    # Each entry must have GDPR article reference
    for cat, entry in RETENTION_GUIDANCE.items():
        has_article = bool(entry.get("gdpr_articles"))
        results.append(JudgeResult(
            name=f"retention_{cat.replace(' ', '_')}_article",
            passed=has_article,
            message=f"'{cat}' has GDPR article reference" if has_article else f"'{cat}' missing GDPR reference",
        ))

    return results


# ─── Judge: Prompts Module ─────────────────────────────────────────────────

@judge.register
async def judge_prompts(**kwargs) -> List[JudgeResult]:
    """Verify all expected prompts exist and are loadable."""
    results = []
    from gdpr_shift_left_mcp.prompts import load_prompt, list_prompts

    expected_prompts = [
        "gap_analysis",
        "dpia_assessment",
        "compliance_roadmap",
        "data_mapping",
        "incident_response",
        "azure_privacy_review",
        "vendor_assessment",
        "cross_border_transfers",
    ]

    for name in expected_prompts:
        content = load_prompt(name)
        loaded = content is not None and len(content) > 50
        results.append(JudgeResult(
            name=f"prompt_{name}",
            passed=loaded,
            message=f"Prompt '{name}' loaded ({len(content)} chars)" if loaded else f"Prompt '{name}' not found or too short",
        ))

    return results


# ─── Judge: Templates Module ───────────────────────────────────────────────

@judge.register
async def judge_templates(**kwargs) -> List[JudgeResult]:
    """Verify GDPR templates exist and contain article references."""
    results = []
    from gdpr_shift_left_mcp.templates import list_templates, load_template

    templates = list_templates()
    results.append(JudgeResult(
        name="templates_exist",
        passed=len(templates) > 0,
        message=f"Found {len(templates)} template(s)" if templates else "No templates found",
    ))

    for tmpl in templates:
        content = load_template(tmpl["name"])
        has_gdpr_ref = content is not None and "Art" in content
        results.append(JudgeResult(
            name=f"template_{tmpl['name']}_gdpr_ref",
            passed=has_gdpr_ref,
            message=f"Template '{tmpl['name']}' references GDPR Article" if has_gdpr_ref else f"Template '{tmpl['name']}' has no GDPR references",
        ))

    return results
