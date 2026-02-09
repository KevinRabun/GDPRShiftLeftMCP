# GDPR Shift-Left MCP Server

<!-- mcp-name: io.github.KevinRabun/GDPRShiftLeftMCP -->

[![Tests & Judges](https://github.com/KevinRabun/GDPRShiftLeftMCP/actions/workflows/test.yml/badge.svg)](https://github.com/KevinRabun/GDPRShiftLeftMCP/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/gdpr-shift-left-mcp)](https://pypi.org/project/gdpr-shift-left-mcp/)
[![Python versions](https://img.shields.io/pypi/pyversions/gdpr-shift-left-mcp)](https://pypi.org/project/gdpr-shift-left-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server that brings **GDPR compliance knowledge directly into your IDE**, enabling developers and compliance teams to "shift left" — identifying and addressing data protection requirements early in the development lifecycle.

> **⚠️ Disclaimer:** This tool provides informational guidance only and **does not constitute legal advice**. Organisations should consult qualified legal counsel for binding GDPR compliance decisions.

## Features

### 🔍 GDPR Knowledge Base (23 Tools)
- **Article Lookup** — Retrieve any GDPR article by number, search across all 99 articles and 173 recitals
- **Definitions** — Art. 4 term definitions with contextual explanations
- **Chapter Navigation** — Browse articles by chapter with full directory
- **Azure Mappings** — Map GDPR articles to Azure services and controls

### 📋 Compliance Workflows
- **DPIA Assessment** — Assess whether a DPIA is required (EDPB 9-criteria test), generate Art. 35 templates
- **ROPA Builder** — Generate and validate Art. 30 Records of Processing Activities
- **DSR Guidance** — Step-by-step workflows for all 7 data subject rights (Arts. 12–23)
- **Retention Analysis** — Assess retention policies against Art. 5(1)(e) storage limitation

### 🏗️ Infrastructure & Code Review
- **Bicep/Terraform/ARM Analyzer** — Scan IaC for GDPR violations (encryption, access, network, residency, logging, retention)
- **Application Code Analyzer** — Detect PII logging, hardcoded secrets, missing consent checks, data minimisation issues
- **GDPR Config Validator** — Pass/fail validation in strict or advisory mode

### 📝 Guided Prompts (8 Expert Prompts)
- Gap Analysis, DPIA Assessment, Compliance Roadmap, Data Mapping
- Incident Response, Azure Privacy Review, Vendor Assessment, Cross-Border Transfers

### 📐 Azure Bicep Templates (19 Templates)
- **Storage Account** — CMK encryption, Private Endpoint, lifecycle policies (Art. 5, 25, 32, 44-49)
- **Key Vault** — HSM-backed Premium, purge protection, RBAC (Art. 25, 32)
- **Azure SQL** — Entra-only auth, TDE, auditing (Art. 25, 32)
- **Log Analytics** — 365-day retention, saved GDPR queries for breach/access/erasure tracking (Art. 5(2), 30, 33)
- **Cosmos DB** — EU-only regions, strong consistency, continuous backup, TTL-enabled ROPA container (Art. 25, 32, 44-49)
- **App Service** — Managed identity, TLS 1.2, VNet integration, staging slot, full audit logging (Art. 25, 32)
- **Virtual Network** — 3 subnets, NSGs with least-privilege rules, service endpoints (Art. 25, 32, 5(1)(f))
- **Container Apps** — Internal ingress, mutual TLS, zone redundancy, managed identity (Art. 25, 32)
- **Monitor Alerts** — DPO action group, 4 scheduled alerts for sign-in/exfiltration/escalation/Key Vault (Art. 33, 34, 32)
- **PostgreSQL Flexible Server** — Zone-redundant HA, Entra ID auth, pgaudit, geo-redundant backups (Art. 25, 32, 5(1)(e))
- **Service Bus Premium** — CMK encryption, GDPR queues for DSR/consent/breach/retention (Art. 25, 32, 5(1)(f))
- **AKS** — Private cluster, Azure CNI, Defender for Containers, workload identity, network policies (Art. 25, 32, 5(1)(f))
- **Confidential Ledger** — TEE-backed tamper-proof audit trail for GDPR accountability records (Art. 5(2), 30, 33)
- **Confidential VM** — AMD SEV-SNP encrypted memory, vTPM, secure boot, ephemeral OS disk (Art. 25, 32, 5(1)(f))
- **Entra ID Configuration** — Audit log routing, sign-in monitoring, Conditional Access checklist (Art. 32, 5(2))
- **Azure Policy** — EU region restriction, CMK enforcement, tag requirements, HTTPS-only (Art. 25, 32, 44)
- **Defender for Cloud** — All Defender plans, security contacts, auto-provisioning, GDPR compliance dashboard (Art. 32, 33)
- **API Management** — Internal VNet, TLS 1.2+, rate limiting, data masking policies, audit logging (Art. 25, 32, 30)
- **Front Door with WAF** — OWASP rules, EU/EEA geo-filtering, bot protection, rate limiting (Art. 25, 32, 44)

## Quick Start

### Prerequisites
- Python 3.10+
- VS Code with GitHub Copilot

### Installation

```bash
# Clone the repository
git clone https://github.com/KevinRabun/GDPRShiftLeftMCP.git
cd GDPRShiftLeftMCP

# Install in development mode
pip install -e ".[dev]"
```

### VS Code Integration

The repository includes `.vscode/mcp.json` for automatic MCP server registration. After installation, the GDPR tools appear in GitHub Copilot's tool list.

To configure manually, add to your VS Code settings:

```json
{
  "mcp": {
    "servers": {
      "gdpr-shift-left-mcp": {
        "type": "stdio",
        "command": "python",
        "args": ["-m", "gdpr_shift_left_mcp"]
      }
    }
  }
}
```

### Running the Server

```bash
# Run directly
python -m gdpr_shift_left_mcp

# Or via the installed entry point
gdpr-shift-left-mcp
```

## Tool Reference

| Tool | Description | GDPR Articles |
|------|-------------|---------------|
| `get_article` | Retrieve a GDPR article by number | All |
| `list_chapter_articles` | List all articles in a chapter | All |
| `search_gdpr` | Full-text search across GDPR | All |
| `get_recital` | Retrieve a recital by number | All |
| `get_azure_mapping` | Azure services for a GDPR article | All |
| `get_definition` | Art. 4 term definition | Art. 4 |
| `list_definitions` | List all definitions | Art. 4 |
| `search_definitions` | Search definitions | Art. 4 |
| `assess_dpia_need` | Check if DPIA is required | Art. 35 |
| `generate_dpia_template` | Generate DPIA document | Art. 35 |
| `get_dpia_guidance` | DPIA area guidance | Art. 35–36 |
| `generate_ropa_template` | Art. 30 ROPA template | Art. 30 |
| `validate_ropa` | Validate ROPA completeness | Art. 30 |
| `get_ropa_requirements` | ROPA field requirements | Art. 30 |
| `get_dsr_guidance` | DSR handling guidance | Arts. 12–23 |
| `generate_dsr_workflow` | DSR fulfilment workflow | Arts. 12–23 |
| `get_dsr_timeline` | DSR response timelines | Art. 12(3) |
| `analyze_infrastructure_code` | Scan IaC for GDPR issues | Art. 25, 32, 44 |
| `analyze_application_code` | Scan app code for GDPR issues | Art. 5, 25, 32 |
| `validate_gdpr_config` | Pass/fail GDPR validation | All |
| `assess_retention_policy` | Assess retention policy | Art. 5(1)(e) |
| `get_retention_guidance` | Category-specific retention | Art. 5(1)(e) |
| `check_deletion_requirements` | Deletion capability checklist | Art. 17 |

## Architecture

```
src/gdpr_shift_left_mcp/
├── __init__.py              # Package init
├── __main__.py              # Entry point
├── server.py                # FastMCP server + prompt registration
├── disclaimer.py            # Legal disclaimer utility
├── data_loader.py           # Online GDPR data fetching + caching
├── tools/
│   ├── __init__.py          # Tool registration (23 tools)
│   ├── articles.py          # Article/recital/search tools
│   ├── definitions.py       # Art. 4 definition tools
│   ├── dpia.py              # DPIA assessment tools
│   ├── ropa.py              # ROPA builder tools
│   ├── dsr.py               # Data subject rights tools
│   ├── analyzer.py          # IaC + app code analyzer
│   └── retention.py         # Retention/deletion tools
├── prompts/
│   ├── __init__.py          # Prompt loader
│   └── *.txt                # 8 expert prompt templates
└── templates/
    ├── __init__.py           # Template loader
    └── *.bicep               # GDPR-aligned Azure Bicep templates
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=gdpr_shift_left_mcp --cov-report=html

# Run judges (end-to-end evaluators)
python -m tests.evaluator.run_judges
```

## Online Updates

The server fetches GDPR data from a configurable online source, with local caching:

- **Source URL:** Set via `GDPR_SOURCE_URL` environment variable
- **Cache TTL:** Default 1 hour (configurable via `GDPR_CACHE_TTL`)
- **Cache directory:** `__gdpr_cache__/` (configurable via `GDPR_CACHE_DIR`)
- **Fallback:** Built-in data if online fetch fails

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. This project follows Git Flow branching:

- `feature/<name>` for new features
- `bugfix/<name>` for fixes
- `release/<version>` for releases
- `hotfix/<name>` for production fixes

All PRs must pass automated tests and judges before merging.

## License

MIT — see [LICENSE](LICENSE) for details.

## Acknowledgements

- Architecture inspired by [FedRAMP20xMCP](https://github.com/KevinRabun/FedRAMP20xMCP)
- GDPR text from [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- EDPB guidelines from [edpb.europa.eu](https://www.edpb.europa.eu/)
