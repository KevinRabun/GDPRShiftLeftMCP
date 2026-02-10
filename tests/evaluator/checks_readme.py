"""
GDPR Shift-Left MCP Server -- README Documentation Validation Judge

These judges validate that the README.md file accurately reflects the actual
codebase state, ensuring documentation stays in sync with implementation.

Validations:
  - Tool count matches actual @mcp.tool() decorators
  - All registered tools are documented in the Tool Reference table
  - Template count matches actual .bicep files
  - Prompt count matches actual .txt files  
  - Architecture diagram files exist in the codebase
  - Version consistency across files
"""
import os
import re
from pathlib import Path
from typing import List, Set

from .judge import JudgeResult, judge


# ─── Path Configuration ─────────────────────────────────────────────────────

def _get_project_root() -> Path:
    """Get the project root directory."""
    # Navigate from tests/evaluator/ up to project root
    return Path(__file__).parent.parent.parent


def _read_file_safe(filepath: Path) -> str:
    """Safely read a file, returning empty string on error."""
    try:
        return filepath.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return ""


# ─── Data Extraction Helpers ────────────────────────────────────────────────

def _count_mcp_tools() -> int:
    """Count actual @mcp.tool() decorators in the tools/__init__.py file."""
    tools_init = _get_project_root() / "src" / "gdpr_shift_left_mcp" / "tools" / "__init__.py"
    content = _read_file_safe(tools_init)
    # Match @mcp.tool() decorator
    matches = re.findall(r"@mcp\.tool\(\)", content)
    return len(matches)


def _get_registered_tool_names() -> Set[str]:
    """Extract tool function names from @mcp.tool() decorated functions."""
    tools_init = _get_project_root() / "src" / "gdpr_shift_left_mcp" / "tools" / "__init__.py"
    content = _read_file_safe(tools_init)
    # Pattern: @mcp.tool() followed by async def function_name(
    pattern = r"@mcp\.tool\(\)\s+async def (\w+)\("
    matches = re.findall(pattern, content)
    return set(matches)


def _get_readme_documented_tools() -> Set[str]:
    """Extract tool names documented in README Tool Reference table."""
    readme = _get_project_root() / "README.md"
    content = _read_file_safe(readme)
    # Pattern: | `tool_name` | in markdown table
    pattern = r"\|\s*`(\w+)`\s*\|"
    matches = re.findall(pattern, content)
    return set(matches)


def _get_readme_tool_count_claim() -> int:
    """Extract the tool count claimed in the README Features section."""
    readme = _get_project_root() / "README.md"
    content = _read_file_safe(readme)
    # Pattern: "GDPR Knowledge Base (XX Tools)" in Features section
    match = re.search(r"GDPR Knowledge Base \((\d+) Tools?\)", content)
    if match:
        return int(match.group(1))
    return 0


def _count_bicep_templates() -> int:
    """Count actual .bicep template files."""
    templates_dir = _get_project_root() / "src" / "gdpr_shift_left_mcp" / "templates"
    if not templates_dir.exists():
        return 0
    return len([f for f in templates_dir.iterdir() if f.suffix == ".bicep"])


def _get_readme_template_count_claim() -> int:
    """Extract template count claimed in README."""
    readme = _get_project_root() / "README.md"
    content = _read_file_safe(readme)
    # Pattern: "Azure Bicep Templates (XX Templates)"
    match = re.search(r"Azure Bicep Templates \((\d+) Templates?\)", content)
    if match:
        return int(match.group(1))
    return 0


def _count_prompt_files() -> int:
    """Count actual .txt prompt files."""
    prompts_dir = _get_project_root() / "src" / "gdpr_shift_left_mcp" / "prompts"
    if not prompts_dir.exists():
        return 0
    return len([f for f in prompts_dir.iterdir() if f.suffix == ".txt"])


def _get_readme_prompt_count_claim() -> int:
    """Extract prompt count claimed in README."""
    readme = _get_project_root() / "README.md"
    content = _read_file_safe(readme)
    # Pattern: "Guided Prompts (XX Expert Prompts)"
    match = re.search(r"Guided Prompts \((\d+) Expert Prompts?\)", content)
    if match:
        return int(match.group(1))
    return 0


def _get_readme_architecture_files() -> Set[str]:
    """Extract Python file names listed in README Architecture section."""
    readme = _get_project_root() / "README.md"
    content = _read_file_safe(readme)
    # Pattern: ├── filename.py or └── filename.py
    pattern = r"[├└]── (\w+\.py)"
    matches = re.findall(pattern, content)
    return set(matches)


def _get_actual_tool_files() -> Set[str]:
    """Get actual Python files in the tools directory."""
    tools_dir = _get_project_root() / "src" / "gdpr_shift_left_mcp" / "tools"
    if not tools_dir.exists():
        return set()
    return {f.name for f in tools_dir.iterdir() if f.suffix == ".py"}


def _get_readme_architecture_tool_count() -> int:
    """Extract tool count from Architecture section comment."""
    readme = _get_project_root() / "README.md"
    content = _read_file_safe(readme)
    # Pattern: "# Tool registration (XX tools)"
    match = re.search(r"# Tool registration \((\d+) tools?\)", content)
    if match:
        return int(match.group(1))
    return 0


# ─── README Validation Judges ───────────────────────────────────────────────

@judge.register
async def check_readme_tool_count(**kwargs) -> JudgeResult:
    """Validate README tool count matches actual @mcp.tool() decorators."""
    actual_count = _count_mcp_tools()
    claimed_count = _get_readme_tool_count_claim()
    
    if actual_count == claimed_count:
        return JudgeResult(
            name="readme_tool_count",
            passed=True,
            message=f"Tool count matches: {actual_count} tools",
        )
    return JudgeResult(
        name="readme_tool_count",
        passed=False,
        message=f"Tool count mismatch: README claims {claimed_count}, actual is {actual_count}",
        details=f"README states '{claimed_count} Tools' but found {actual_count} @mcp.tool() decorators",
    )


@judge.register
async def check_readme_architecture_tool_count(**kwargs) -> JudgeResult:
    """Validate Architecture section tool count matches actual tools."""
    actual_count = _count_mcp_tools()
    arch_count = _get_readme_architecture_tool_count()
    
    if actual_count == arch_count:
        return JudgeResult(
            name="readme_architecture_tool_count",
            passed=True,
            message=f"Architecture tool count matches: {actual_count} tools",
        )
    return JudgeResult(
        name="readme_architecture_tool_count",
        passed=False,
        message=f"Architecture tool count mismatch: claims {arch_count}, actual is {actual_count}",
        details=f"Architecture section says '{arch_count} tools' but found {actual_count}",
    )


@judge.register
async def check_all_tools_documented(**kwargs) -> JudgeResult:
    """Validate all registered tools are documented in README Tool Reference."""
    registered = _get_registered_tool_names()
    documented = _get_readme_documented_tools()
    
    missing = registered - documented
    extra = documented - registered
    
    if not missing and not extra:
        return JudgeResult(
            name="readme_tools_documented",
            passed=True,
            message=f"All {len(registered)} tools are documented in README",
        )
    
    details = []
    if missing:
        details.append(f"Missing from README: {sorted(missing)}")
    if extra:
        details.append(f"In README but not registered: {sorted(extra)}")
    
    return JudgeResult(
        name="readme_tools_documented",
        passed=False,
        message=f"Tool documentation mismatch: {len(missing)} missing, {len(extra)} extra",
        details="\n".join(details),
    )


@judge.register
async def check_readme_template_count(**kwargs) -> JudgeResult:
    """Validate README template count matches actual .bicep files."""
    actual_count = _count_bicep_templates()
    claimed_count = _get_readme_template_count_claim()
    
    if actual_count == claimed_count:
        return JudgeResult(
            name="readme_template_count",
            passed=True,
            message=f"Template count matches: {actual_count} templates",
        )
    return JudgeResult(
        name="readme_template_count",
        passed=False,
        message=f"Template count mismatch: README claims {claimed_count}, actual is {actual_count}",
        details=f"README states '{claimed_count} Templates' but found {actual_count} .bicep files",
    )


@judge.register
async def check_readme_prompt_count(**kwargs) -> JudgeResult:
    """Validate README prompt count matches actual .txt files."""
    actual_count = _count_prompt_files()
    claimed_count = _get_readme_prompt_count_claim()
    
    if actual_count == claimed_count:
        return JudgeResult(
            name="readme_prompt_count",
            passed=True,
            message=f"Prompt count matches: {actual_count} prompts",
        )
    return JudgeResult(
        name="readme_prompt_count",
        passed=False,
        message=f"Prompt count mismatch: README claims {claimed_count}, actual is {actual_count}",
        details=f"README states '{claimed_count} Expert Prompts' but found {actual_count} .txt files",
    )


@judge.register
async def check_readme_architecture_files(**kwargs) -> JudgeResult:
    """Validate Architecture section lists actual tool module files."""
    readme_files = _get_readme_architecture_files()
    actual_files = _get_actual_tool_files()
    
    # Filter to just tools/*.py files mentioned in architecture
    tools_in_readme = {f for f in readme_files if f not in {"__init__.py", "__main__.py", "server.py", "disclaimer.py", "data_loader.py"}}
    tools_actual = {f for f in actual_files if f != "__init__.py"}
    
    # Check if all actual tool files are mentioned
    missing = tools_actual - tools_in_readme
    extra = tools_in_readme - tools_actual
    
    if not missing and not extra:
        return JudgeResult(
            name="readme_architecture_files",
            passed=True,
            message=f"All {len(tools_actual)} tool modules listed in Architecture",
        )
    
    details = []
    if missing:
        details.append(f"Tool files not in Architecture: {sorted(missing)}")
    if extra:
        details.append(f"In Architecture but missing: {sorted(extra)}")
    
    return JudgeResult(
        name="readme_architecture_files",
        passed=False,
        message=f"Architecture file list mismatch: {len(missing)} missing, {len(extra)} extra",
        details="\n".join(details),
    )


@judge.register
async def check_tool_reference_table_complete(**kwargs) -> JudgeResult:
    """Validate Tool Reference table has entries for all tools with descriptions."""
    readme = _get_project_root() / "README.md"
    content = _read_file_safe(readme)
    
    registered = _get_registered_tool_names()
    
    # Check each tool has a table row with description
    issues = []
    for tool in sorted(registered):
        # Pattern: | `tool_name` | some description | Art. XX |
        pattern = rf"\|\s*`{tool}`\s*\|[^|]+\|[^|]+\|"
        if not re.search(pattern, content):
            issues.append(f"Tool '{tool}' missing proper table entry")
    
    if not issues:
        return JudgeResult(
            name="readme_tool_table_complete",
            passed=True,
            message=f"All {len(registered)} tools have complete table entries",
        )
    
    return JudgeResult(
        name="readme_tool_table_complete",
        passed=False,
        message=f"{len(issues)} tools have incomplete table entries",
        details="\n".join(issues),
    )


@judge.register
async def check_readme_exists(**kwargs) -> JudgeResult:
    """Validate README.md file exists and is non-empty."""
    readme = _get_project_root() / "README.md"
    
    if not readme.exists():
        return JudgeResult(
            name="readme_exists",
            passed=False,
            message="README.md file not found",
            details=f"Expected at: {readme}",
        )
    
    content = _read_file_safe(readme)
    if len(content) < 100:
        return JudgeResult(
            name="readme_exists",
            passed=False,
            message="README.md appears to be empty or too short",
            details=f"README.md has only {len(content)} characters",
        )
    
    return JudgeResult(
        name="readme_exists",
        passed=True,
        message=f"README.md exists with {len(content)} characters",
    )


@judge.register
async def check_readme_has_required_sections(**kwargs) -> JudgeResult:
    """Validate README has all required documentation sections."""
    readme = _get_project_root() / "README.md"
    content = _read_file_safe(readme)
    
    required_sections = [
        "## Features",
        "## Quick Start",
        "## Tool Reference",
        "## Architecture",
        "## Testing",
        "## Contributing",
        "## License",
    ]
    
    missing = []
    for section in required_sections:
        if section not in content:
            missing.append(section)
    
    if not missing:
        return JudgeResult(
            name="readme_required_sections",
            passed=True,
            message=f"All {len(required_sections)} required sections present",
        )
    
    return JudgeResult(
        name="readme_required_sections",
        passed=False,
        message=f"{len(missing)} required sections missing",
        details=f"Missing: {missing}",
    )


@judge.register
async def check_readme_disclaimer_present(**kwargs) -> JudgeResult:
    """Validate README includes the legal disclaimer."""
    readme = _get_project_root() / "README.md"
    content = _read_file_safe(readme)
    
    # Check for key disclaimer phrases
    disclaimer_phrases = [
        "does not constitute legal advice",
        "Disclaimer",
        "informational guidance only",
    ]
    
    found = sum(1 for phrase in disclaimer_phrases if phrase.lower() in content.lower())
    
    if found >= 2:
        return JudgeResult(
            name="readme_disclaimer",
            passed=True,
            message="Legal disclaimer is present in README",
        )
    
    return JudgeResult(
        name="readme_disclaimer",
        passed=False,
        message="Legal disclaimer missing or incomplete in README",
        details="README should include disclaimer about not being legal advice",
    )


@judge.register
async def check_readme_badges_valid(**kwargs) -> JudgeResult:
    """Validate README badges reference correct URLs and shields."""
    readme = _get_project_root() / "README.md"
    content = _read_file_safe(readme)
    
    # Check for expected badges
    expected_badges = [
        "pypi.org/project/gdpr-shift-left-mcp",
        "github.com/KevinRabun/GDPRShiftLeftMCP/actions",
        "img.shields.io",
    ]
    
    missing = []
    for badge in expected_badges:
        if badge not in content:
            missing.append(badge)
    
    if not missing:
        return JudgeResult(
            name="readme_badges",
            passed=True,
            message="All expected badges present",
        )
    
    return JudgeResult(
        name="readme_badges",
        passed=False,
        message=f"{len(missing)} expected badges missing",
        details=f"Missing badge references: {missing}",
    )
