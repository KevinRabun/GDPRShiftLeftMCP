# Contributing to GDPR Shift-Left MCP Server

Thank you for considering a contribution! This document outlines the workflow and standards for contributing.

## Code of Conduct

Be respectful, constructive, and inclusive. No personal data should appear in code, tests, or documentation — use placeholders only.

## Getting Started

```bash
# Fork and clone
git clone https://github.com/<your-fork>/GDPRShiftLeftMCP.git
cd GDPRShiftLeftMCP

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # macOS/Linux

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests to verify setup
pytest
```

## Branching Policy (Git Flow)

All work must be done on branches:

| Branch | Purpose |
|--------|---------|
| `feature/<name>` | New features |
| `bugfix/<name>` | Bug fixes |
| `release/<version>` | Release staging |
| `hotfix/<name>` | Production fixes |

**Direct commits to `main` are prohibited.**

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Branch follows Git Flow naming (`feature/`, `bugfix/`, etc.)
- [ ] All existing tests pass (`pytest`)
- [ ] New tests are added for new functionality
- [ ] Judges pass (`python -m tests.evaluator.run_judges`)
- [ ] No personal data in code, tests, or documentation
- [ ] Legal disclaimer is present on all tool outputs
- [ ] GDPR article references are accurate
- [ ] Code is linted and formatted
- [ ] PR description clearly explains changes

## Testing Requirements

### Unit Tests
Every new feature must include tests covering:
- Happy path
- Edge cases and error handling
- Disclaimer inclusion in outputs
- GDPR article accuracy

### Judges (Evaluators)
If you add or modify MCP tools:
1. Add corresponding judge checks in `tests/evaluator/checks.py`
2. Run `python -m tests.evaluator.run_judges` to verify
3. Judges must pass before merging

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=gdpr_shift_left_mcp --cov-report=term-missing

# Judges only
python -m tests.evaluator.run_judges

# Security scan
bandit -r src/
safety check
```

## Code Standards

### Python
- Python 3.11+
- Type hints on all public functions
- Docstrings on all public functions and classes
- Async where I/O is involved

### GDPR Accuracy
- Cite specific GDPR Articles (e.g., "Art. 5(1)(e)")
- Use official terminology from Art. 4 definitions
- Reference EDPB guidelines where applicable
- Never speculate on GDPR interpretation — state the regulation text

### Security
- No secrets, credentials, or PII in code
- No logging of personal data
- Use Azure Key Vault references for sensitive configuration
- Input validation on all tool parameters

## Architecture Guidelines

- **Tools** go in `src/gdpr_shift_left_mcp/tools/`
- **Prompts** go in `src/gdpr_shift_left_mcp/prompts/` as `.txt` files
- **Templates** go in `src/gdpr_shift_left_mcp/templates/`
- All tool outputs must call `append_disclaimer()` before returning
- Data access goes through `GDPRDataLoader` singleton

## Release Process

1. Create `release/<version>` branch from `main`
2. Update version in `pyproject.toml` and `__init__.py`
3. Update CHANGELOG
4. PR to `main` — all tests and judges must pass
5. Tag the merge commit with `v<version>`

## Questions?

Open an issue or start a discussion on GitHub.
