"""
GDPR Shift-Left MCP Server — Azure IaC & Code Analyzer

Analyzes Bicep / Terraform / ARM and application code for GDPR compliance.
Focus areas: data residency, encryption, access control, logging, retention,
privacy-by-design, and data minimisation.
"""
import json
import logging
import re
from typing import Any, Dict, List, Optional

from ..disclaimer import append_disclaimer

logger = logging.getLogger(__name__)

# ─── GDPR-relevant IaC checks ──────────────────────────────────────────────

GDPR_IAC_CHECKS: List[Dict[str, Any]] = [
    {
        "id": "GDPR-ENC-001",
        "article": "Art. 32(1)(a)",
        "title": "Encryption at rest",
        "severity": "CRITICAL",
        "check_keywords": ["encryption", "customerManagedKey", "cmk", "sse", "tde", "disk_encryption"],
        "fail_keywords": ["encryption.*disabled", "sse.*false"],
        "message": "Ensure all data stores use encryption at rest (Art. 32 — security of processing).",
        "azure_fix": "Enable Azure Storage SSE with CMK, Azure SQL TDE, Azure Disk Encryption.",
    },
    {
        "id": "GDPR-ENC-002",
        "article": "Art. 32(1)(a)",
        "title": "Encryption in transit",
        "severity": "CRITICAL",
        "check_keywords": ["https", "tls", "minTlsVersion", "minimum_tls_version", "httpsOnly"],
        "fail_keywords": ["httpsOnly.*false", "http_only.*false", "minTlsVersion.*1\\.0"],
        "message": "Enforce TLS 1.2+ for all data in transit (Art. 32 — security of processing).",
        "azure_fix": "Set minTlsVersion to '1.2', enable httpsOnly on App Services and Storage.",
    },
    {
        "id": "GDPR-ACC-001",
        "article": "Art. 25, Art. 32(1)(b)",
        "title": "Access control / RBAC",
        "severity": "HIGH",
        "check_keywords": ["roleAssignment", "role_assignment", "rbac", "accessPolicies", "access_policy"],
        "fail_keywords": ["publicAccess.*true", "public_access.*enabled", "publicNetworkAccess.*Enabled"],
        "message": "Restrict access to personal data via RBAC and disable public access (Art. 25/32).",
        "azure_fix": "Use Microsoft Entra RBAC, disable public network access, use Private Link.",
    },
    {
        "id": "GDPR-NET-001",
        "article": "Art. 25, Art. 32",
        "title": "Network isolation",
        "severity": "HIGH",
        "check_keywords": ["privateEndpoint", "private_endpoint", "privateLink", "networkAcls"],
        "fail_keywords": ["publicNetworkAccess.*Enabled", "defaultAction.*Allow"],
        "message": "Use private endpoints / network isolation for data stores (privacy by design).",
        "azure_fix": "Deploy Azure Private Link / Private Endpoints for all data services.",
    },
    {
        "id": "GDPR-LOG-001",
        "article": "Art. 5(2), Art. 30",
        "title": "Diagnostic logging",
        "severity": "HIGH",
        "check_keywords": ["diagnosticSettings", "diagnostic_setting", "log_analytics", "logAnalytics"],
        "fail_keywords": [],
        "message": "Enable diagnostic logging for accountability and ROPA evidence (Art. 5(2)).",
        "azure_fix": "Configure Azure Monitor diagnostic settings to Log Analytics workspace.",
    },
    {
        "id": "GDPR-RET-001",
        "article": "Art. 5(1)(e)",
        "title": "Data retention / lifecycle",
        "severity": "HIGH",
        "check_keywords": ["retention", "lifecycle", "retentionInDays", "retention_in_days"],
        "fail_keywords": [],
        "message": "Define data retention periods aligned with purpose limitation (Art. 5(1)(e)).",
        "azure_fix": "Set retentionInDays on Log Analytics, lifecycle management on Blob Storage.",
    },
    {
        "id": "GDPR-RES-001",
        "article": "Art. 44-49",
        "title": "Data residency / region",
        "severity": "CRITICAL",
        "check_keywords": ["location", "region"],
        "fail_keywords": [],
        "message": "Ensure data is stored in EU/EEA regions unless adequate safeguards exist (Chapter V).",
        "azure_fix": "Deploy resources in EU regions (westeurope, northeurope, etc.) or use EU Data Boundary.",
        "region_check": True,
    },
    {
        "id": "GDPR-TAG-001",
        "article": "Art. 30",
        "title": "Data classification tags",
        "severity": "MEDIUM",
        "check_keywords": ["tags", "gdpr", "data-classification", "processing-purpose"],
        "fail_keywords": [],
        "message": "Tag resources with GDPR metadata (processing purpose, data category, retention) for ROPA.",
        "azure_fix": "Apply Azure tags: gdpr-processing-purpose, gdpr-data-category, gdpr-retention-days.",
    },
    {
        "id": "GDPR-KV-001",
        "article": "Art. 32(1)(a)",
        "title": "Key management",
        "severity": "HIGH",
        "check_keywords": ["keyVault", "key_vault", "Microsoft.KeyVault"],
        "fail_keywords": ["sku.*standard"],
        "message": "Use Azure Key Vault Premium (HSM-backed) for cryptographic key management.",
        "azure_fix": "Deploy Key Vault with sku: 'premium' and enable soft-delete + purge protection.",
    },
]

# Non-EU Azure regions (simplified check)
NON_EU_REGIONS = [
    "eastus", "eastus2", "westus", "westus2", "westus3", "centralus",
    "southcentralus", "northcentralus", "westcentralus",
    "canadacentral", "canadaeast",
    "brazilsouth",
    "eastasia", "southeastasia",
    "japaneast", "japanwest",
    "koreacentral", "koreasouth",
    "australiaeast", "australiasoutheast", "australiacentral",
    "centralindia", "southindia", "westindia",
    "southafricanorth", "southafricawest",
    "uaenorth", "uaecentral",
]


async def analyze_infrastructure_code_impl(
    code: str, file_type: str, file_path: Optional[str], context: Optional[str], data_loader
) -> str:
    """Analyze Bicep/Terraform/ARM code for GDPR compliance issues."""
    await data_loader.load_data()
    code_lower = code.lower()

    findings: List[Dict[str, Any]] = []

    for check in GDPR_IAC_CHECKS:
        # Check for fail patterns (explicit misconfigurations)
        for fail_pat in check.get("fail_keywords", []):
            if re.search(fail_pat, code_lower):
                findings.append({
                    "id": check["id"],
                    "severity": check["severity"],
                    "article": check["article"],
                    "title": check["title"],
                    "type": "VIOLATION",
                    "message": check["message"],
                    "fix": check["azure_fix"],
                })
                break

        # Check for absence of required patterns
        has_keyword = any(kw in code_lower for kw in check["check_keywords"])
        if not has_keyword and check["check_keywords"]:
            # Special handling for region check
            if check.get("region_check"):
                # Look for non-EU regions
                for region in NON_EU_REGIONS:
                    if region in code_lower:
                        findings.append({
                            "id": check["id"],
                            "severity": "CRITICAL",
                            "article": check["article"],
                            "title": check["title"],
                            "type": "VIOLATION",
                            "message": f"Non-EU region '{region}' detected. {check['message']}",
                            "fix": check["azure_fix"],
                        })
                        break
            elif check["severity"] in ("CRITICAL", "HIGH"):
                findings.append({
                    "id": check["id"],
                    "severity": check["severity"],
                    "article": check["article"],
                    "title": check["title"],
                    "type": "MISSING",
                    "message": check["message"],
                    "fix": check["azure_fix"],
                })

    # Format output
    result = f"# GDPR Infrastructure Code Analysis\n\n"
    result += f"**File:** {file_path or 'inline'} ({file_type})\n\n"

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]

    result += f"## Summary\n\n"
    result += f"- 🔴 Critical: {len(critical)}\n"
    result += f"- 🟠 High: {len(high)}\n"
    result += f"- 🟡 Medium: {len(medium)}\n"
    result += f"- **Total findings: {len(findings)}**\n\n"

    if not findings:
        result += "✅ No GDPR compliance issues detected in the provided code.\n\n"
        result += "*Note: This analysis checks common patterns; it does not guarantee full GDPR compliance.*\n"
    else:
        result += "## Findings\n\n"
        for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3)):
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
            result += f"### {icon} [{f['id']}] {f['title']} ({f['severity']})\n\n"
            result += f"**GDPR Reference:** {f['article']}\n\n"
            result += f"**Issue:** {f['message']}\n\n"
            result += f"**Remediation:** {f['fix']}\n\n"

    return append_disclaimer(result)


# ─── Application code checks ───────────────────────────────────────────────

APP_CODE_PATTERNS = [
    {
        "id": "GDPR-APP-001",
        "article": "Art. 32",
        "title": "Hardcoded secrets / PII in source",
        "severity": "CRITICAL",
        "patterns": [
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"api_key\s*=\s*['\"][^'\"]+['\"]",
            r"connection_string\s*=\s*['\"][^'\"]+['\"]",
            r"secret\s*=\s*['\"][^'\"]+['\"]",
        ],
        "message": "Hardcoded secrets detected. Use Azure Key Vault for secret management.",
    },
    {
        "id": "GDPR-APP-002",
        "article": "Art. 5(1)(f), Art. 32",
        "title": "PII logging",
        "severity": "HIGH",
        "patterns": [
            r"log.*email",
            r"log.*password",
            r"log.*ssn",
            r"log.*credit.?card",
            r"log.*phone.?number",
            r"print.*email",
            r"console\.log.*email",
            r"logger\.info.*personal",
        ],
        "message": "Potential PII in log output. GDPR requires confidentiality of personal data.",
    },
    {
        "id": "GDPR-APP-003",
        "article": "Art. 7, Art. 6(1)(a)",
        "title": "Missing consent verification",
        "severity": "MEDIUM",
        "patterns": [
            r"send.*marketing",
            r"newsletter",
            r"tracking",
            r"analytics.*collect",
        ],
        "anti_patterns": [
            r"consent",
            r"opt.?in",
            r"gdpr",
            r"permission",
        ],
        "message": "Processing that may require consent detected without visible consent checks.",
    },
    {
        "id": "GDPR-APP-004",
        "article": "Art. 25",
        "title": "Data minimisation concern",
        "severity": "MEDIUM",
        "patterns": [
            r"select\s+\*\s+from",
            r"SELECT\s+\*\s+FROM",
            r"\.find\(\{\}\)",
            r"\.findAll\(\)",
        ],
        "message": "Querying all fields may violate data minimisation (Art. 25 — privacy by design).",
    },
]


async def analyze_application_code_impl(
    code: str, language: str, file_path: Optional[str], data_loader
) -> str:
    """Analyze application code for GDPR compliance issues."""
    await data_loader.load_data()

    findings: List[Dict[str, Any]] = []
    code_lower = code.lower()

    for check in APP_CODE_PATTERNS:
        matched = False
        for pat in check["patterns"]:
            if re.search(pat, code, re.IGNORECASE):
                matched = True
                break

        # Anti-patterns (mitigating controls present)
        if matched and "anti_patterns" in check:
            if any(re.search(ap, code, re.IGNORECASE) for ap in check["anti_patterns"]):
                matched = False

        if matched:
            findings.append({
                "id": check["id"],
                "severity": check["severity"],
                "article": check["article"],
                "title": check["title"],
                "message": check["message"],
            })

    result = f"# GDPR Application Code Analysis\n\n"
    result += f"**File:** {file_path or 'inline'} ({language})\n\n"
    result += f"**Findings:** {len(findings)}\n\n"

    if not findings:
        result += "✅ No GDPR compliance issues detected.\n"
    else:
        for f in findings:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
            result += f"### {icon} [{f['id']}] {f['title']} ({f['severity']})\n\n"
            result += f"**GDPR Reference:** {f['article']}\n\n"
            result += f"{f['message']}\n\n"

    return append_disclaimer(result)


async def validate_gdpr_config_impl(
    code: str, file_type: str, strict_mode: bool, data_loader
) -> str:
    """Validate IaC configuration against mandatory GDPR requirements."""
    await data_loader.load_data()

    # Run the infrastructure analysis
    analysis_result = await analyze_infrastructure_code_impl(
        code, file_type, None, None, data_loader
    )

    # In strict mode, prepend a pass/fail banner
    code_lower = code.lower()
    violations = []
    for check in GDPR_IAC_CHECKS:
        for fail_pat in check.get("fail_keywords", []):
            if re.search(fail_pat, code_lower):
                violations.append(check)
                break

    passed = len(violations) == 0

    result = f"# GDPR Configuration Validation ({'STRICT' if strict_mode else 'ADVISORY'} Mode)\n\n"
    if passed:
        result += "## ✅ PASSED — No mandatory GDPR violations detected\n\n"
    else:
        result += f"## ❌ FAILED — {len(violations)} mandatory violation(s) found\n\n"
        if strict_mode:
            result += "⚠️ **Do NOT deploy this configuration until violations are resolved.**\n\n"

    result += analysis_result
    return result  # disclaimer already appended by analyze_infrastructure_code_impl
