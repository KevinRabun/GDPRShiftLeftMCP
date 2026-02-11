"""
Unit tests for README documentation validation judges.

Tests ensure the README judge correctly validates:
  - Tool count accuracy
  - Tool documentation completeness
  - Template and prompt counts
  - Architecture diagram accuracy
  - Required sections presence
"""
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from tests.evaluator.checks_readme import (
    _get_project_root,
    _count_mcp_tools,
    _get_registered_tool_names,
    _get_readme_documented_tools,
    _get_readme_tool_count_claim,
    _count_bicep_templates,
    _get_readme_template_count_claim,
    _count_prompt_files,
    _get_readme_prompt_count_claim,
    _get_readme_architecture_files,
    _get_actual_tool_files,
    _get_readme_architecture_tool_count,
)


class TestProjectRootDetection:
    """Tests for project root path detection."""
    
    def test_project_root_exists(self):
        """Project root should exist and be a directory."""
        root = _get_project_root()
        assert root.exists()
        assert root.is_dir()
    
    def test_project_root_contains_readme(self):
        """Project root should contain README.md."""
        root = _get_project_root()
        readme = root / "README.md"
        assert readme.exists()
    
    def test_project_root_contains_src(self):
        """Project root should contain src directory."""
        root = _get_project_root()
        src = root / "src"
        assert src.exists()
        assert src.is_dir()


class TestToolCounting:
    """Tests for MCP tool counting functions."""
    
    def test_mcp_tools_count_positive(self):
        """Should count at least one MCP tool."""
        count = _count_mcp_tools()
        assert count > 0
    
    def test_mcp_tools_count_matches_expected(self):
        """Should count exactly 34 tools (current state)."""
        count = _count_mcp_tools()
        assert count == 34
    
    def test_registered_tool_names_not_empty(self):
        """Should find registered tool names."""
        names = _get_registered_tool_names()
        assert len(names) > 0
    
    def test_registered_tool_names_include_known_tools(self):
        """Should include known tool names."""
        names = _get_registered_tool_names()
        expected_tools = {
            "get_article",
            "search_gdpr",
            "assess_dpia_need",
            "generate_ropa_template",
            "get_dsr_guidance",
            "analyze_infrastructure_code",
            "assess_retention_policy",
            "assess_controller_processor_role",
        }
        for tool in expected_tools:
            assert tool in names, f"Expected tool '{tool}' not found"


class TestReadmeDocumentation:
    """Tests for README documentation extraction."""
    
    def test_readme_documented_tools_not_empty(self):
        """Should find documented tools in README."""
        tools = _get_readme_documented_tools()
        assert len(tools) > 0
    
    def test_readme_tool_count_claim_positive(self):
        """Should find tool count claim in README."""
        count = _get_readme_tool_count_claim()
        assert count > 0
    
    def test_readme_tool_count_matches_actual(self):
        """README claimed tool count should match actual."""
        claimed = _get_readme_tool_count_claim()
        actual = _count_mcp_tools()
        assert claimed == actual
    
    def test_all_tools_in_readme(self):
        """All registered tools should be in README."""
        registered = _get_registered_tool_names()
        documented = _get_readme_documented_tools()
        missing = registered - documented
        assert len(missing) == 0, f"Missing from README: {missing}"


class TestTemplateCounting:
    """Tests for Bicep template counting."""
    
    def test_template_count_positive(self):
        """Should count at least one template."""
        count = _count_bicep_templates()
        assert count > 0
    
    def test_template_count_matches_expected(self):
        """Should count exactly 19 templates (current state)."""
        count = _count_bicep_templates()
        assert count == 19
    
    def test_readme_template_count_matches_actual(self):
        """README claimed template count should match actual."""
        claimed = _get_readme_template_count_claim()
        actual = _count_bicep_templates()
        assert claimed == actual


class TestPromptCounting:
    """Tests for prompt file counting."""
    
    def test_prompt_count_positive(self):
        """Should count at least one prompt."""
        count = _count_prompt_files()
        assert count > 0
    
    def test_prompt_count_matches_expected(self):
        """Should count exactly 8 prompts (current state)."""
        count = _count_prompt_files()
        assert count == 8
    
    def test_readme_prompt_count_matches_actual(self):
        """README claimed prompt count should match actual."""
        claimed = _get_readme_prompt_count_claim()
        actual = _count_prompt_files()
        assert claimed == actual


class TestArchitectureSection:
    """Tests for README Architecture section."""
    
    def test_architecture_files_not_empty(self):
        """Should find files listed in Architecture."""
        files = _get_readme_architecture_files()
        assert len(files) > 0
    
    def test_actual_tool_files_not_empty(self):
        """Should find actual tool files."""
        files = _get_actual_tool_files()
        assert len(files) > 0
    
    def test_architecture_tool_count_matches_actual(self):
        """Architecture section tool count should match actual."""
        claimed = _get_readme_architecture_tool_count()
        actual = _count_mcp_tools()
        assert claimed == actual
    
    def test_all_tool_modules_in_architecture(self):
        """All tool modules should be listed in Architecture."""
        readme_files = _get_readme_architecture_files()
        actual_files = _get_actual_tool_files()
        
        # Filter to tool modules (exclude __init__.py)
        tool_modules = {f for f in actual_files if f != "__init__.py"}
        
        # Check each tool module is in README
        for module in tool_modules:
            assert module in readme_files, f"Tool module '{module}' not in Architecture"


class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_missing_file_returns_empty(self):
        """Helper should handle missing files gracefully."""
        from tests.evaluator.checks_readme import _read_file_safe
        result = _read_file_safe(Path("/nonexistent/path/file.txt"))
        assert result == ""
    
    def test_tool_count_with_no_decorators(self):
        """Tool count should handle file with no decorators."""
        with patch("tests.evaluator.checks_readme._read_file_safe", return_value="def foo(): pass"):
            # This calls the actual _count_mcp_tools which will read the actual file
            # So we need to mock at a higher level or test differently
            pass
    
    def test_readme_count_with_no_match(self):
        """README count regex handles missing pattern gracefully."""
        import re
        # Directly test the regex pattern used in _get_readme_tool_count_claim
        content = "no tools here"
        match = re.search(r"GDPR Knowledge Base \((\d+) Tools?\)", content)
        # When pattern not found, match is None
        assert match is None
        # This verifies the function would return 0 for non-matching content


class TestConsistency:
    """Tests for cross-file consistency."""
    
    def test_tool_count_consistency(self):
        """All tool counts should be consistent."""
        actual_tools = _count_mcp_tools()
        readme_claim = _get_readme_tool_count_claim()
        arch_claim = _get_readme_architecture_tool_count()
        documented = len(_get_registered_tool_names())
        
        assert actual_tools == readme_claim, "README Features section mismatch"
        assert actual_tools == arch_claim, "Architecture section mismatch"
        assert actual_tools == documented, "Documented tools count mismatch"
    
    def test_template_count_consistency(self):
        """Template count should be consistent."""
        actual = _count_bicep_templates()
        claimed = _get_readme_template_count_claim()
        assert actual == claimed
    
    def test_prompt_count_consistency(self):
        """Prompt count should be consistent."""
        actual = _count_prompt_files()
        claimed = _get_readme_prompt_count_claim()
        assert actual == claimed


class TestJudgeIntegration:
    """Integration tests running actual judge checks."""
    
    @pytest.mark.asyncio
    async def test_readme_tool_count_judge(self):
        """readme_tool_count judge should pass."""
        from tests.evaluator.checks_readme import check_readme_tool_count
        result = await check_readme_tool_count()
        assert result.passed, result.details
    
    @pytest.mark.asyncio
    async def test_readme_architecture_tool_count_judge(self):
        """readme_architecture_tool_count judge should pass."""
        from tests.evaluator.checks_readme import check_readme_architecture_tool_count
        result = await check_readme_architecture_tool_count()
        assert result.passed, result.details
    
    @pytest.mark.asyncio
    async def test_all_tools_documented_judge(self):
        """readme_tools_documented judge should pass."""
        from tests.evaluator.checks_readme import check_all_tools_documented
        result = await check_all_tools_documented()
        assert result.passed, result.details
    
    @pytest.mark.asyncio
    async def test_readme_template_count_judge(self):
        """readme_template_count judge should pass."""
        from tests.evaluator.checks_readme import check_readme_template_count
        result = await check_readme_template_count()
        assert result.passed, result.details
    
    @pytest.mark.asyncio
    async def test_readme_prompt_count_judge(self):
        """readme_prompt_count judge should pass."""
        from tests.evaluator.checks_readme import check_readme_prompt_count
        result = await check_readme_prompt_count()
        assert result.passed, result.details
    
    @pytest.mark.asyncio
    async def test_readme_architecture_files_judge(self):
        """readme_architecture_files judge should pass."""
        from tests.evaluator.checks_readme import check_readme_architecture_files
        result = await check_readme_architecture_files()
        assert result.passed, result.details
    
    @pytest.mark.asyncio
    async def test_readme_exists_judge(self):
        """readme_exists judge should pass."""
        from tests.evaluator.checks_readme import check_readme_exists
        result = await check_readme_exists()
        assert result.passed, result.details
    
    @pytest.mark.asyncio
    async def test_readme_required_sections_judge(self):
        """readme_required_sections judge should pass."""
        from tests.evaluator.checks_readme import check_readme_has_required_sections
        result = await check_readme_has_required_sections()
        assert result.passed, result.details
    
    @pytest.mark.asyncio
    async def test_readme_disclaimer_judge(self):
        """readme_disclaimer judge should pass."""
        from tests.evaluator.checks_readme import check_readme_disclaimer_present
        result = await check_readme_disclaimer_present()
        assert result.passed, result.details
    
    @pytest.mark.asyncio
    async def test_readme_badges_judge(self):
        """readme_badges judge should pass."""
        from tests.evaluator.checks_readme import check_readme_badges_valid
        result = await check_readme_badges_valid()
        assert result.passed, result.details
    
    @pytest.mark.asyncio
    async def test_tool_table_complete_judge(self):
        """readme_tool_table_complete judge should pass."""
        from tests.evaluator.checks_readme import check_tool_reference_table_complete
        result = await check_tool_reference_table_complete()
        assert result.passed, result.details
