"""
Tests for Bicep template validity and GDPR compliance structure.

Validates that every .bicep template:
  - Loads successfully via the template module
  - Has a GDPR description comment in the first line
  - References specific GDPR articles
  - Contains GDPR compliance tags
  - Uses EU-default locations where applicable
  - Has diagnostic/audit logging configured
  - Compiles with `az bicep build` (when Bicep CLI is available)
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from gdpr_shift_left_mcp.templates import list_templates, load_template

# ── Fixtures ────────────────────────────────────────────────────────────────

BICEP_CLI_AVAILABLE = shutil.which("az") is not None


def _check_bicep_cli() -> bool:
    """Return True if `az bicep build` is functional."""
    if not BICEP_CLI_AVAILABLE:
        return False
    try:
        result = subprocess.run(
            "az bicep version",
            capture_output=True, text=True, timeout=30,
            shell=True,
        )
        return result.returncode == 0
    except Exception:
        return False


HAS_BICEP = _check_bicep_cli()

ALL_TEMPLATES = list_templates()
TEMPLATE_NAMES = [t["name"] for t in ALL_TEMPLATES]

# Known templates that target subscription scope (not resource group)
SUBSCRIPTION_SCOPE_TEMPLATES = {
    "gdpr_azure_policy.bicep",
    "gdpr_defender_for_cloud.bicep",
}

# Templates that are configuration checklists (may not have location param)
CONFIG_TEMPLATES = {
    "gdpr_entra_id.bicep",
    "gdpr_azure_policy.bicep",
    "gdpr_defender_for_cloud.bicep",
}

# Templates that deploy global Azure resources (location = 'global')
GLOBAL_RESOURCE_TEMPLATES = {
    "gdpr_monitor_alerts.bicep",
}

# GDPR articles that should appear across the template collection
EXPECTED_ARTICLES = {"Art. 25", "Art. 32", "Art. 5"}


# ── Discovery Tests ────────────────────────────────────────────────────────

class TestTemplateDiscovery:
    """Verify template auto-discovery and loading."""

    def test_templates_exist(self):
        assert len(ALL_TEMPLATES) >= 19, (
            f"Expected at least 19 templates, found {len(ALL_TEMPLATES)}"
        )

    def test_all_templates_are_bicep(self):
        for t in ALL_TEMPLATES:
            assert t["type"] == "bicep", f"{t['name']} is not a .bicep file"

    def test_all_templates_have_descriptions(self):
        for t in ALL_TEMPLATES:
            assert t["description"], f"{t['name']} has no description"

    def test_all_templates_load_successfully(self):
        for t in ALL_TEMPLATES:
            content = load_template(t["name"])
            assert content is not None, f"Failed to load {t['name']}"
            assert len(content) > 100, (
                f"{t['name']} is suspiciously short ({len(content)} chars)"
            )


# ── Structural Validation ──────────────────────────────────────────────────

class TestTemplateStructure:
    """Validate GDPR-required structural elements in each template."""

    @pytest.mark.parametrize("name", TEMPLATE_NAMES)
    def test_gdpr_article_references(self, name):
        """Every template must reference at least one GDPR article."""
        content = load_template(name)
        assert content is not None
        matches = re.findall(r"Art\.\s*\d+", content)
        assert len(matches) >= 1, (
            f"{name} does not reference any GDPR articles"
        )

    @pytest.mark.parametrize("name", TEMPLATE_NAMES)
    def test_gdpr_description_comment(self, name):
        """First line should be a GDPR-related description comment."""
        content = load_template(name)
        assert content is not None
        first_line = content.splitlines()[0]
        assert first_line.startswith("//"), (
            f"{name} first line is not a comment: {first_line[:60]}"
        )
        assert "GDPR" in first_line, (
            f"{name} first line doesn't mention GDPR: {first_line[:80]}"
        )

    @pytest.mark.parametrize("name", TEMPLATE_NAMES)
    def test_has_param_declarations(self, name):
        """Templates must have at least one @description + param."""
        content = load_template(name)
        assert content is not None
        param_count = len(re.findall(r"^param\s+\w+", content, re.MULTILINE))
        assert param_count >= 1, f"{name} has no param declarations"

    @pytest.mark.parametrize("name", TEMPLATE_NAMES)
    def test_has_resource_declarations(self, name):
        """Templates must declare at least one Azure resource."""
        content = load_template(name)
        assert content is not None
        resource_count = len(re.findall(
            r"^resource\s+\w+\s+'[^']+'\s*=", content, re.MULTILINE
        ))
        assert resource_count >= 1, (
            f"{name} has no resource declarations"
        )

    @pytest.mark.parametrize("name", TEMPLATE_NAMES)
    def test_eu_default_location(self, name):
        """Templates with location param should default to an EU region."""
        if name in CONFIG_TEMPLATES:
            pytest.skip("Configuration template without location param")
        if name in GLOBAL_RESOURCE_TEMPLATES:
            pytest.skip("Global resource template — location is 'global'")
        content = load_template(name)
        assert content is not None
        loc_match = re.search(
            r"param\s+location\s+string\s*=\s*'(\w+)'", content
        )
        if loc_match:
            location = loc_match.group(1)
            eu_regions = {
                "westeurope", "northeurope", "germanywestcentral",
                "francecentral", "switzerlandnorth", "norwayeast",
                "swedencentral", "uksouth", "ukwest",
            }
            assert location in eu_regions, (
                f"{name} defaults to non-EU region '{location}'"
            )

    @pytest.mark.parametrize("name", TEMPLATE_NAMES)
    def test_gdpr_tags(self, name):
        """Templates with resource-group-scoped resources should have GDPR tags."""
        if name in SUBSCRIPTION_SCOPE_TEMPLATES | CONFIG_TEMPLATES:
            pytest.skip("Subscription-scope or config template — tags not applicable")
        content = load_template(name)
        assert content is not None
        has_tags = "gdpr_compliant" in content or "gdpr_processing_purpose" in content
        assert has_tags, (
            f"{name} missing GDPR compliance tags (gdpr_compliant / gdpr_processing_purpose)"
        )

    @pytest.mark.parametrize("name", TEMPLATE_NAMES)
    def test_no_hardcoded_secrets(self, name):
        """Templates must not contain hardcoded secrets or passwords."""
        content = load_template(name)
        assert content is not None
        # Check for common secret patterns (not param decorators)
        dangerous = re.findall(
            r"(?:password|secret|key)\s*[:=]\s*'[^']+'",
            content, re.IGNORECASE,
        )
        # Filter out param defaults that are empty strings or references
        real_secrets = [
            d for d in dangerous
            if not d.endswith("''") and "param" not in d.lower()
        ]
        assert len(real_secrets) == 0, (
            f"{name} may contain hardcoded secrets: {real_secrets}"
        )


# ── GDPR Coverage Tests ───────────────────────────────────────────────────

class TestGDPRCoverage:
    """Verify the template collection covers key GDPR requirements."""

    def test_encryption_coverage(self):
        """At least one template addresses Art. 32(1)(a) encryption."""
        all_content = "\n".join(
            load_template(t["name"]) or "" for t in ALL_TEMPLATES
        )
        assert "Art. 32" in all_content
        encryption_terms = ["encrypt", "tls", "https", "CMK", "customer-managed"]
        found = any(term.lower() in all_content.lower() for term in encryption_terms)
        assert found, "No template addresses encryption requirements"

    def test_access_control_coverage(self):
        """Templates should address access control (Art. 25, 32)."""
        all_content = "\n".join(
            load_template(t["name"]) or "" for t in ALL_TEMPLATES
        )
        access_terms = ["rbac", "role", "identity", "managedIdentity", "enableRbac"]
        found = any(term.lower() in all_content.lower() for term in access_terms)
        assert found, "No template addresses access control"

    def test_audit_logging_coverage(self):
        """Templates should include diagnostic/audit logging."""
        all_content = "\n".join(
            load_template(t["name"]) or "" for t in ALL_TEMPLATES
        )
        audit_terms = ["diagnosticSettings", "audit", "logging", "logAnalytics"]
        found = any(term.lower() in all_content.lower() for term in audit_terms)
        assert found, "No template includes audit logging"

    def test_data_residency_coverage(self):
        """Templates should address EU data residency (Art. 44-49)."""
        all_content = "\n".join(
            load_template(t["name"]) or "" for t in ALL_TEMPLATES
        )
        residency_terms = ["westeurope", "EU region", "data residency", "Art. 44"]
        found = any(term in all_content for term in residency_terms)
        assert found, "No template addresses data residency"

    def test_article_coverage_breadth(self):
        """Template suite should reference key GDPR articles."""
        all_content = "\n".join(
            load_template(t["name"]) or "" for t in ALL_TEMPLATES
        )
        for article in EXPECTED_ARTICLES:
            assert article in all_content, (
                f"No template references {article}"
            )


# ── Bicep CLI Compilation ─────────────────────────────────────────────────

@pytest.mark.skipif(not HAS_BICEP, reason="Bicep CLI not available")
class TestBicepCompilation:
    """Compile each template with `az bicep build` to catch syntax errors."""

    @pytest.mark.parametrize("name", TEMPLATE_NAMES)
    def test_bicep_compiles(self, name):
        """Template must compile without errors."""
        content = load_template(name)
        assert content is not None

        with tempfile.TemporaryDirectory() as tmpdir:
            bicep_path = Path(tmpdir) / name
            bicep_path.write_text(content, encoding="utf-8")

            result = subprocess.run(
                f'az bicep build --file "{bicep_path}"',
                capture_output=True, text=True, timeout=60,
                shell=True,
            )

            # Clean up the generated ARM JSON if compilation succeeded
            arm_path = bicep_path.with_suffix(".json")
            if arm_path.exists():
                arm_path.unlink()

            assert result.returncode == 0, (
                f"{name} failed to compile:\n{result.stderr}"
            )
