"""
GDPR Shift-Left MCP Server — Azure IaC & Code Analyzer

Analyzes Bicep / Terraform / ARM and application code for GDPR compliance.
Focus areas: data residency, encryption, access control, logging, retention,
privacy-by-design, data minimisation, DSR capabilities, cross-border transfers,
and breach notification readiness.
"""
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

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
        "fail_keywords": [r"httpsOnly.*false", r"http_only.*false", r"minTlsVersion.*1\.0", r"minimum_tls_version.*1\.0", r"minimumTlsVersion.*1[._]0", r"TLS1[._]0"],
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
            if re.search(fail_pat, code_lower, re.IGNORECASE):
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
        elif has_keyword and check.get("region_check"):
            # location/region keyword IS present — still check for non-EU regions
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

# ─── DSR Capability Patterns ────────────────────────────────────────────────

DSR_CAPABILITY_PATTERNS = {
    "access": {
        "article": "Art. 15",
        "right": "Right of access",
        "positive_patterns": [
            r"(get|fetch|export|download).*(user|personal|my).?(data|info|profile)",
            r"data.?export",
            r"export.?personal",
            r"subject.?access.?request",
            r"sar.?(handler|endpoint|request)",
            r"dsr.?(access|export)",
            r"/api/.*(export|download|my-data)",
            r"get_user_data",
            r"fetchUserProfile",
            r"exportPersonalData",
        ],
        "description": "Data subject access request (SAR) capability",
    },
    "erasure": {
        "article": "Art. 17",
        "right": "Right to erasure",
        "positive_patterns": [
            r"(delete|erase|remove).*(user|personal|account|my).?(data)?",
            r"right.?to.?(be.?)?forget",
            r"gdpr.?(delete|erasure)",
            r"purge.?user",
            r"anonymi[sz]e",
            r"data.?deletion",
            r"delete.?account",
            r"dsr.?(delete|erasure|remove)",
            r"/api/.*delete",
            r"erasePersonalData",
            r"removeUserData",
        ],
        "description": "Right to erasure (right to be forgotten) capability",
    },
    "rectification": {
        "article": "Art. 16",
        "right": "Right to rectification",
        "positive_patterns": [
            r"(update|correct|rectif|edit|modify).*(user|personal|profile|my).?(data|info)?",
            r"rectification",
            r"data.?correction",
            r"fix.?personal",
            r"dsr.?(rectif|correct|update)",
            r"updateProfile",
            r"editUserData",
        ],
        "description": "Right to rectification capability",
    },
    "portability": {
        "article": "Art. 20",
        "right": "Right to data portability",
        "positive_patterns": [
            r"data.?portability",
            r"export.*(json|xml|csv|machine.?readable)",
            r"download.?my.?data",
            r"portable.?format",
            r"structured.?format",
            r"dsr.?portability",
            r"transferable",
            r"exportToJson",
            r"downloadAsCSV",
        ],
        "description": "Right to data portability capability",
    },
    "restriction": {
        "article": "Art. 18",
        "right": "Right to restriction",
        "positive_patterns": [
            r"restrict.?process",
            r"pause.?processing",
            r"suspend.?account",
            r"freeze.?data",
            r"processing.?hold",
            r"dsr.?restrict",
            r"limitProcessing",
        ],
        "description": "Right to restriction of processing capability",
    },
    "objection": {
        "article": "Art. 21",
        "right": "Right to object",
        "positive_patterns": [
            r"opt.?out",
            r"unsubscribe",
            r"object.?to.?process",
            r"stop.?marketing",
            r"withdraw.?consent",
            r"do.?not.?(track|sell|share)",
            r"dsr.?objection",
            r"preferenceCenter",
            r"marketingOptOut",
        ],
        "description": "Right to object capability",
    },
    "automated_decision": {
        "article": "Art. 22",
        "right": "Rights related to automated decision-making",
        "positive_patterns": [
            r"human.?review",
            r"manual.?override",
            r"appeal.?decision",
            r"contest.?automated",
            r"explain.?decision",
            r"algorithmic.?transparency",
            r"decision.?explanation",
            r"requestHumanReview",
        ],
        "description": "Automated decision-making oversight capability",
    },
}

# ─── Cross-Border Transfer Patterns ─────────────────────────────────────────

CROSS_BORDER_PATTERNS = {
    "third_party_apis": [
        {
            "pattern": r"(googleapis|google\.com/api|sheets\.google)",
            "provider": "Google APIs",
            "region": "US (with EU data processing option)",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(api\.openai|openai\.com)",
            "provider": "OpenAI",
            "region": "US",
            "risk": "HIGH",
        },
        {
            "pattern": r"(api\.anthropic|anthropic\.com)",
            "provider": "Anthropic",
            "region": "US",
            "risk": "HIGH",
        },
        {
            "pattern": r"(aws\.amazon|amazonaws\.com)",
            "provider": "AWS",
            "region": "Variable (check region config)",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(api\.stripe|stripe\.com)",
            "provider": "Stripe",
            "region": "US (EU processing available)",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(api\.twilio|twilio\.com)",
            "provider": "Twilio",
            "region": "US",
            "risk": "HIGH",
        },
        {
            "pattern": r"(sendgrid\.com|api\.sendgrid)",
            "provider": "SendGrid",
            "region": "US",
            "risk": "HIGH",
        },
        {
            "pattern": r"(mailchimp\.com|api\.mailchimp)",
            "provider": "Mailchimp",
            "region": "US",
            "risk": "HIGH",
        },
        {
            "pattern": r"(salesforce\.com|api\.salesforce)",
            "provider": "Salesforce",
            "region": "US (EU instances available)",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(hubspot\.com|api\.hubspot)",
            "provider": "HubSpot",
            "region": "US (EU data center available)",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(zendesk\.com|api\.zendesk)",
            "provider": "Zendesk",
            "region": "US (EU data center available)",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(intercom\.com|api\.intercom)",
            "provider": "Intercom",
            "region": "US",
            "risk": "HIGH",
        },
        {
            "pattern": r"(segment\.com|api\.segment)",
            "provider": "Segment",
            "region": "US",
            "risk": "HIGH",
        },
        {
            "pattern": r"(mixpanel\.com|api\.mixpanel)",
            "provider": "Mixpanel",
            "region": "US (EU available)",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(amplitude\.com|api\.amplitude)",
            "provider": "Amplitude",
            "region": "US (EU available)",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(github\.com/api|api\.github)",
            "provider": "GitHub",
            "region": "US",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(cloudflare\.com|api\.cloudflare)",
            "provider": "Cloudflare",
            "region": "Global (edge locations)",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(firebase\.google|firebaseio\.com)",
            "provider": "Firebase",
            "region": "US (multi-region available)",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(mongodb\.com|atlas\.mongodb)",
            "provider": "MongoDB Atlas",
            "region": "Variable (check cluster region)",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"(supabase\.co|api\.supabase)",
            "provider": "Supabase",
            "region": "Variable (check project region)",
            "risk": "MEDIUM",
        },
    ],
    "sdk_patterns": [
        {
            "pattern": r"from\s+openai\s+import|import\s+openai",
            "sdk": "OpenAI Python SDK",
            "provider": "OpenAI",
            "risk": "HIGH",
        },
        {
            "pattern": r"from\s+anthropic\s+import|import\s+anthropic",
            "sdk": "Anthropic Python SDK",
            "provider": "Anthropic",
            "risk": "HIGH",
        },
        {
            "pattern": r"from\s+google\.cloud|import\s+google\.cloud",
            "sdk": "Google Cloud SDK",
            "provider": "Google Cloud",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"import\s+boto3|from\s+boto3",
            "sdk": "AWS SDK (boto3)",
            "provider": "AWS",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"require\(['\"]aws-sdk|from\s+['\"]@aws-sdk",
            "sdk": "AWS SDK (JavaScript)",
            "provider": "AWS",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"import\s+stripe|from\s+stripe|require\(['\"]stripe",
            "sdk": "Stripe SDK",
            "provider": "Stripe",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"import\s+twilio|from\s+twilio",
            "sdk": "Twilio SDK",
            "provider": "Twilio",
            "risk": "HIGH",
        },
        {
            "pattern": r"@sendgrid|import\s+sendgrid",
            "sdk": "SendGrid SDK",
            "provider": "SendGrid",
            "risk": "HIGH",
        },
        {
            "pattern": r"import\s+firebase|from\s+firebase",
            "sdk": "Firebase SDK",
            "provider": "Firebase",
            "risk": "MEDIUM",
        },
        {
            "pattern": r"import\s+segment|from\s+segment|analytics-node",
            "sdk": "Segment SDK",
            "provider": "Segment",
            "risk": "HIGH",
        },
    ],
}

# ─── Breach Notification Patterns ───────────────────────────────────────────

BREACH_NOTIFICATION_PATTERNS = {
    "security_logging": {
        "article": "Art. 33, 34",
        "description": "Security event logging for breach detection",
        "positive_patterns": [
            r"security.?log",
            r"audit.?log",
            r"access.?log",
            r"authentication.?(log|event)",
            r"failed.?login",
            r"suspicious.?activity",
            r"anomaly.?detect",
            r"intrusion.?detect",
            r"IDS|SIEM",
            r"security.?event",
            r"logSecurityEvent",
            r"auditTrail",
        ],
    },
    "alerting": {
        "article": "Art. 33(1)",
        "description": "Alerting mechanisms for breach notification",
        "positive_patterns": [
            r"alert.?(admin|security|dpo|team)",
            r"notify.?(breach|incident|security)",
            r"incident.?response",
            r"escalat",
            r"pager.?duty|opsgenie|victorops",
            r"slack.?notify|teams.?notify",
            r"sendAlert",
            r"notifySecurityTeam",
            r"breachNotification",
        ],
    },
    "incident_tracking": {
        "article": "Art. 33(5)",
        "description": "Incident documentation and tracking",
        "positive_patterns": [
            r"incident.?(ticket|record|log|track)",
            r"breach.?(record|document|report)",
            r"security.?incident",
            r"post.?mortem",
            r"root.?cause",
            r"incident.?severity",
            r"createIncident",
            r"logBreach",
        ],
    },
    "72_hour_process": {
        "article": "Art. 33(1)",
        "description": "72-hour notification process references",
        "positive_patterns": [
            r"72.?hour",
            r"notify.?authority",
            r"dpa.?notification",
            r"supervisory.?authority",
            r"data.?protection.?officer",
            r"dpo.?(notify|alert|contact)",
            r"regulat.*(notify|report)",
        ],
    },
    "subject_notification": {
        "article": "Art. 34",
        "description": "Data subject breach notification",
        "positive_patterns": [
            r"notify.?(user|customer|subject|affected)",
            r"breach.?(email|notification|letter)",
            r"user.?notification",
            r"affected.?parties",
            r"mass.?notification",
            r"notifyAffectedUsers",
            r"sendBreachNotice",
        ],
    },
}

# ─── Data Flow Patterns ─────────────────────────────────────────────────────

DATA_FLOW_PATTERNS = {
    "pii_collection": {
        "description": "Personal data collection points",
        "patterns": [
            r"(request|req)\.(body|form|json)\.(email|name|phone|address|ssn|dob)",
            r"getParameter\(['\"]?(email|name|phone|ssn)",
            r"formData\.(get|append)\(['\"]?(email|name|phone)",
            r"input.*name=['\"]?(email|password|phone|ssn|credit)",
            r"(email|phone|address|name)\s*=\s*(request|req|form)",
        ],
    },
    "pii_storage": {
        "description": "Personal data storage operations",
        "patterns": [
            r"(save|store|insert|create|put).*(user|personal|customer|profile)",
            r"\.insert(One|Many)?\(.*email",
            r"\.save\(.*personal",
            r"db\.(users|customers|profiles)",
            r"Redis.*personal|personal.*Redis",
            r"cache\.(set|put).*user",
        ],
    },
    "pii_transmission": {
        "description": "Personal data transmission",
        "patterns": [
            r"(http|fetch|axios|request)\.(post|put|patch).*user",
            r"send.*(email|personal|user.?data)",
            r"api.?call.*personal",
            r"webhook.*user",
            r"queue\.(send|publish).*user",
            r"kafka.*personal|rabbitmq.*user",
        ],
    },
    "pii_deletion": {
        "description": "Personal data deletion operations",
        "patterns": [
            r"(delete|remove|purge|destroy).*(user|personal|account|profile)",
            r"\.delete(One|Many)?\(.*user",
            r"\.remove\(.*personal",
            r"TRUNCATE.*user|DROP.*personal",
            r"anonymize.*user",
        ],
    },
}


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

    # Add role indicator hints
    role_hints = _detect_role_hints(code)
    if role_hints:
        result += "---\n\n## Role Indicators Detected\n\n"
        result += "*These patterns may indicate whether your service acts as a controller or processor.*\n\n"
        if role_hints.get("controller"):
            result += "**Controller patterns:**\n"
            for hint in role_hints["controller"][:3]:
                result += f"- {hint}\n"
            result += "\n"
        if role_hints.get("processor"):
            result += "**Processor patterns:**\n"
            for hint in role_hints["processor"][:3]:
                result += f"- {hint}\n"
            result += "\n"
        result += "*Use `assess_controller_processor_role` or `analyze_code_for_role_indicators` for detailed role analysis.*\n\n"

    return append_disclaimer(result)


def _detect_role_hints(code: str) -> Dict[str, List[str]]:
    """Detect patterns that hint at controller vs processor role."""
    hints = {"controller": [], "processor": []}
    code_lower = code.lower()

    # Controller patterns
    if re.search(r"(signup|register|create.?account)", code_lower):
        hints["controller"].append("User registration/signup code detected")
    if re.search(r"(consent|gdpr.?consent|cookie.?consent|opt.?in)", code_lower):
        hints["controller"].append("Consent collection mechanisms detected")
    if re.search(r"(analytics|tracking|telemetry)", code_lower):
        hints["controller"].append("Analytics/tracking code detected (may indicate own-purpose processing)")
    if re.search(r"(privacy.?policy|terms.?of.?service)", code_lower):
        hints["controller"].append("Privacy policy / ToS references detected")
    if re.search(r"(marketing|newsletter|promotional)", code_lower):
        hints["controller"].append("Marketing/newsletter functionality detected")

    # Processor patterns
    if re.search(r"(tenant.?id|organization.?id|client.?id)", code_lower):
        hints["processor"].append("Multi-tenant architecture (client isolation) detected")
    if re.search(r"(webhook|callback|event.?handler)", code_lower):
        hints["processor"].append("Webhook/callback receivers detected (client data ingestion)")
    if re.search(r"(api.?key|client.?secret|bearer.?token)", code_lower):
        hints["processor"].append("Client authentication mechanisms detected")
    if re.search(r"(on.?behalf.?of|for.?client|customer.?data)", code_lower):
        hints["processor"].append("'On behalf of' / client data references detected")

    # Filter out empty categories
    return {k: v for k, v in hints.items() if v}


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


# ─── DSR Capability Analysis ────────────────────────────────────────────────

async def analyze_dsr_capabilities_impl(
    code: str, language: str, file_path: Optional[str], data_loader
) -> str:
    """
    Analyze code for Data Subject Rights (DSR) implementation capabilities.
    
    Detects patterns indicating support for:
    - Art. 15: Right of access
    - Art. 16: Right to rectification
    - Art. 17: Right to erasure
    - Art. 18: Right to restriction
    - Art. 20: Right to data portability
    - Art. 21: Right to object
    - Art. 22: Automated decision-making safeguards
    """
    await data_loader.load_data()

    capabilities_found: Dict[str, List[str]] = {}
    capabilities_missing: List[str] = []

    for dsr_type, config in DSR_CAPABILITY_PATTERNS.items():
        matches = []
        for pattern in config["positive_patterns"]:
            found = re.findall(pattern, code, re.IGNORECASE)
            if found:
                matches.extend(found if isinstance(found[0], str) else [m[0] for m in found])
        
        if matches:
            capabilities_found[dsr_type] = {
                "article": config["article"],
                "right": config["right"],
                "description": config["description"],
                "matches": list(set(matches))[:5],  # Limit to 5 unique matches
            }
        else:
            capabilities_missing.append({
                "type": dsr_type,
                "article": config["article"],
                "right": config["right"],
                "description": config["description"],
            })

    # Format output
    result = "# DSR Capability Analysis\n\n"
    result += f"**File:** {file_path or 'inline'} ({language})\n\n"

    total_rights = len(DSR_CAPABILITY_PATTERNS)
    found_count = len(capabilities_found)
    coverage = (found_count / total_rights) * 100

    result += "## Summary\n\n"
    result += f"- **DSR Rights Coverage:** {found_count}/{total_rights} ({coverage:.0f}%)\n"
    result += f"- ✅ Capabilities Detected: {found_count}\n"
    result += f"- ⚠️ Capabilities Not Found: {len(capabilities_missing)}\n\n"

    if coverage >= 80:
        result += "🟢 **Good DSR coverage** — Most data subject rights appear to be supported.\n\n"
    elif coverage >= 50:
        result += "🟡 **Partial DSR coverage** — Some key rights may be missing implementation.\n\n"
    else:
        result += "🔴 **Low DSR coverage** — Consider implementing more DSR capabilities.\n\n"

    if capabilities_found:
        result += "## ✅ Detected Capabilities\n\n"
        for dsr_type, info in capabilities_found.items():
            result += f"### {info['article']}: {info['right']}\n\n"
            result += f"*{info['description']}*\n\n"
            result += f"**Patterns found:** `{'`, `'.join(info['matches'][:3])}`\n\n"

    if capabilities_missing:
        result += "## ⚠️ Missing or Undetected Capabilities\n\n"
        result += "*These rights should be implemented to ensure GDPR compliance:*\n\n"
        for missing in capabilities_missing:
            result += f"### {missing['article']}: {missing['right']}\n\n"
            result += f"*{missing['description']}*\n\n"
            result += f"**Recommendation:** Implement API endpoints or functions to support this right.\n\n"

    result += "---\n\n"
    result += "## DSR Implementation Checklist\n\n"
    result += "| Right | Article | Status |\n"
    result += "|-------|---------|--------|\n"
    for dsr_type, config in DSR_CAPABILITY_PATTERNS.items():
        status = "✅ Detected" if dsr_type in capabilities_found else "❌ Not found"
        result += f"| {config['right']} | {config['article']} | {status} |\n"

    return append_disclaimer(result)


# ─── Cross-Border Transfer Analysis ─────────────────────────────────────────

async def analyze_cross_border_transfers_impl(
    code: str, language: str, file_path: Optional[str], data_loader
) -> str:
    """
    Analyze code for potential cross-border data transfers.
    
    Detects:
    - Third-party API calls to non-EU services
    - SDK imports for US-based services
    - Webhook/integration patterns that may involve data export
    
    GDPR Chapter V (Art. 44-49) requires adequate safeguards for transfers
    to countries without an adequacy decision.
    """
    await data_loader.load_data()

    api_findings: List[Dict[str, Any]] = []
    sdk_findings: List[Dict[str, Any]] = []

    # Check for third-party API patterns
    for api_config in CROSS_BORDER_PATTERNS["third_party_apis"]:
        if re.search(api_config["pattern"], code, re.IGNORECASE):
            api_findings.append({
                "provider": api_config["provider"],
                "region": api_config["region"],
                "risk": api_config["risk"],
            })

    # Check for SDK imports
    for sdk_config in CROSS_BORDER_PATTERNS["sdk_patterns"]:
        if re.search(sdk_config["pattern"], code, re.IGNORECASE):
            sdk_findings.append({
                "sdk": sdk_config["sdk"],
                "provider": sdk_config["provider"],
                "risk": sdk_config["risk"],
            })

    # Deduplicate by provider
    seen_providers = set()
    unique_api = []
    for f in api_findings:
        if f["provider"] not in seen_providers:
            seen_providers.add(f["provider"])
            unique_api.append(f)

    unique_sdk = []
    for f in sdk_findings:
        if f["provider"] not in seen_providers:
            seen_providers.add(f["provider"])
            unique_sdk.append(f)

    total_findings = len(unique_api) + len(unique_sdk)
    high_risk = sum(1 for f in unique_api + unique_sdk if f["risk"] == "HIGH")

    # Format output
    result = "# Cross-Border Transfer Analysis\n\n"
    result += f"**File:** {file_path or 'inline'} ({language})\n\n"
    result += f"**GDPR Reference:** Chapter V (Art. 44-49) — Transfers to third countries\n\n"

    result += "## Summary\n\n"
    result += f"- **Third-party services detected:** {total_findings}\n"
    result += f"- 🔴 High-risk transfers: {high_risk}\n"
    result += f"- 🟡 Medium-risk transfers: {total_findings - high_risk}\n\n"

    if total_findings == 0:
        result += "✅ No obvious cross-border transfer patterns detected.\n\n"
        result += "*Note: This analysis is pattern-based and may not detect all transfers.*\n"
    else:
        if high_risk > 0:
            result += "⚠️ **Action Required:** High-risk transfers detected. Ensure proper safeguards:\n\n"
            result += "- Standard Contractual Clauses (SCCs)\n"
            result += "- Binding Corporate Rules (BCRs)\n"
            result += "- Explicit consent for specific transfers\n"
            result += "- Transfer Impact Assessment (TIA)\n\n"

        if unique_api:
            result += "## Third-Party APIs Detected\n\n"
            result += "| Provider | Region | Risk Level | Required Action |\n"
            result += "|----------|--------|------------|----------------|\n"
            for f in sorted(unique_api, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["risk"], 3)):
                risk_icon = "🔴" if f["risk"] == "HIGH" else "🟡"
                action = "SCCs + TIA required" if f["risk"] == "HIGH" else "Verify DPA in place"
                result += f"| {f['provider']} | {f['region']} | {risk_icon} {f['risk']} | {action} |\n"
            result += "\n"

        if unique_sdk:
            result += "## SDK/Library Imports Detected\n\n"
            result += "| SDK | Provider | Risk Level | Recommendation |\n"
            result += "|-----|----------|------------|----------------|\n"
            for f in sorted(unique_sdk, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["risk"], 3)):
                risk_icon = "🔴" if f["risk"] == "HIGH" else "🟡"
                rec = "Verify EU data residency option" if f["risk"] == "MEDIUM" else "Consider EU alternative"
                result += f"| {f['sdk']} | {f['provider']} | {risk_icon} {f['risk']} | {rec} |\n"
            result += "\n"

        result += "## Compliance Requirements\n\n"
        result += "For each detected service, ensure:\n\n"
        result += "1. **Data Processing Agreement (DPA)** is in place\n"
        result += "2. **Standard Contractual Clauses (SCCs)** for non-EU transfers\n"
        result += "3. **Transfer Impact Assessment** completed for high-risk transfers\n"
        result += "4. **Record in ROPA** all third-party processors\n"
        result += "5. **Privacy Notice** discloses international transfers\n"

    return append_disclaimer(result)


# ─── Breach Notification Readiness Analysis ─────────────────────────────────

async def analyze_breach_readiness_impl(
    code: str, language: str, file_path: Optional[str], data_loader
) -> str:
    """
    Analyze code for breach notification readiness under GDPR Art. 33-34.
    
    Assesses:
    - Security logging capabilities
    - Alerting mechanisms
    - Incident tracking systems
    - 72-hour notification process
    - Data subject notification capabilities
    """
    await data_loader.load_data()

    capabilities_found: Dict[str, Dict[str, Any]] = {}

    for category, config in BREACH_NOTIFICATION_PATTERNS.items():
        matches = []
        for pattern in config["positive_patterns"]:
            found = re.findall(pattern, code, re.IGNORECASE)
            if found:
                matches.extend(found if isinstance(found[0], str) else [str(m) for m in found])
        
        if matches:
            capabilities_found[category] = {
                "article": config["article"],
                "description": config["description"],
                "matches": list(set(matches))[:5],
            }

    total_categories = len(BREACH_NOTIFICATION_PATTERNS)
    found_count = len(capabilities_found)
    readiness_score = (found_count / total_categories) * 100

    # Format output
    result = "# Breach Notification Readiness Analysis\n\n"
    result += f"**File:** {file_path or 'inline'} ({language})\n\n"
    result += f"**GDPR Reference:** Art. 33 (Notification to authority), Art. 34 (Communication to data subjects)\n\n"

    result += "## Summary\n\n"
    result += f"- **Readiness Score:** {readiness_score:.0f}%\n"
    result += f"- ✅ Capabilities Detected: {found_count}/{total_categories}\n\n"

    if readiness_score >= 80:
        result += "🟢 **Good breach readiness** — Key notification capabilities appear to be in place.\n\n"
    elif readiness_score >= 50:
        result += "🟡 **Partial readiness** — Some breach notification capabilities missing.\n\n"
    else:
        result += "🔴 **Low readiness** — Significant gaps in breach notification capabilities.\n\n"

    result += "## Capability Assessment\n\n"
    result += "| Capability | Article | Status | Details |\n"
    result += "|------------|---------|--------|----------|\n"

    for category, config in BREACH_NOTIFICATION_PATTERNS.items():
        if category in capabilities_found:
            matches = capabilities_found[category]["matches"][:2]
            match_str = f"`{'`, `'.join(matches)}`"
            result += f"| {config['description']} | {config['article']} | ✅ Detected | {match_str} |\n"
        else:
            result += f"| {config['description']} | {config['article']} | ❌ Not found | — |\n"

    result += "\n"

    # Missing capabilities recommendations
    missing = [cat for cat in BREACH_NOTIFICATION_PATTERNS if cat not in capabilities_found]
    if missing:
        result += "## ⚠️ Recommended Improvements\n\n"
        for cat in missing:
            config = BREACH_NOTIFICATION_PATTERNS[cat]
            result += f"### {config['description']}\n\n"
            result += f"**{config['article']}** requires this capability.\n\n"
            
            if cat == "security_logging":
                result += "**Implementation:** Add security event logging with audit trails.\n"
                result += "```python\n"
                result += "logger.security_event('login_failed', user_id=user_id, ip=ip_address)\n"
                result += "```\n\n"
            elif cat == "alerting":
                result += "**Implementation:** Configure alerting for security incidents.\n"
                result += "```python\n"
                result += "alert_service.notify_security_team(incident_type='breach_suspected')\n"
                result += "```\n\n"
            elif cat == "incident_tracking":
                result += "**Implementation:** Create incident tracking records.\n"
                result += "```python\n"
                result += "incident = create_incident(severity='high', type='data_breach')\n"
                result += "```\n\n"
            elif cat == "72_hour_process":
                result += "**Implementation:** Implement 72-hour DPA notification workflow.\n\n"
            elif cat == "subject_notification":
                result += "**Implementation:** Add capability to notify affected data subjects.\n\n"

    result += "## Art. 33/34 Compliance Checklist\n\n"
    result += "- [ ] Security monitoring detects potential breaches\n"
    result += "- [ ] Alerting notifies security team immediately\n"
    result += "- [ ] Incident tracking documents breach details\n"
    result += "- [ ] 72-hour countdown triggers DPA notification\n"
    result += "- [ ] High-risk breaches notify affected users\n"
    result += "- [ ] Documentation retained for accountability\n"

    return append_disclaimer(result)


# ─── Data Flow Analysis ─────────────────────────────────────────────────────

async def analyze_data_flow_impl(
    code: str, language: str, file_path: Optional[str], data_loader
) -> str:
    """
    Analyze code for personal data flow patterns.
    
    Maps the data lifecycle:
    - Collection: Where PII enters the system
    - Storage: Where PII is persisted
    - Transmission: Where PII is sent externally
    - Deletion: Where PII is removed
    
    Helps identify GDPR compliance touchpoints for Art. 30 ROPA.
    """
    await data_loader.load_data()

    flow_findings: Dict[str, List[str]] = {}

    for flow_type, config in DATA_FLOW_PATTERNS.items():
        matches = []
        for pattern in config["patterns"]:
            found = re.findall(pattern, code, re.IGNORECASE)
            if found:
                # Flatten and stringify matches
                for match in found:
                    if isinstance(match, tuple):
                        matches.append(match[0] if match[0] else str(match))
                    else:
                        matches.append(str(match))
        
        if matches:
            flow_findings[flow_type] = {
                "description": config["description"],
                "matches": list(set(matches))[:5],
            }

    # Format output
    result = "# Data Flow Analysis\n\n"
    result += f"**File:** {file_path or 'inline'} ({language})\n\n"
    result += f"**Purpose:** Map personal data lifecycle for Art. 30 ROPA documentation\n\n"

    result += "## Data Lifecycle Summary\n\n"

    lifecycle_stages = ["pii_collection", "pii_storage", "pii_transmission", "pii_deletion"]
    stage_icons = {"pii_collection": "📥", "pii_storage": "💾", "pii_transmission": "📤", "pii_deletion": "🗑️"}
    stage_names = {
        "pii_collection": "Collection",
        "pii_storage": "Storage", 
        "pii_transmission": "Transmission",
        "pii_deletion": "Deletion"
    }

    result += "```\n"
    result += "Personal Data Flow:\n"
    result += "┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐\n"
    
    flow_line = "│"
    for stage in lifecycle_stages:
        status = "✓" if stage in flow_findings else "?"
        flow_line += f" {stage_names[stage]:^9} {status} │    "
    result += flow_line.rstrip() + "\n"
    result += "└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘\n"
    result += "```\n\n"

    detected_count = sum(1 for stage in lifecycle_stages if stage in flow_findings)
    result += f"**Stages Detected:** {detected_count}/4\n\n"

    if detected_count == 0:
        result += "ℹ️ No obvious data flow patterns detected. This may indicate:\n"
        result += "- Code doesn't handle personal data directly\n"
        result += "- Non-standard patterns are used\n"
        result += "- Analysis scope is limited\n\n"
    else:
        for stage in lifecycle_stages:
            icon = stage_icons[stage]
            name = stage_names[stage]
            
            if stage in flow_findings:
                info = flow_findings[stage]
                result += f"## {icon} {name}\n\n"
                result += f"*{info['description']}*\n\n"
                result += f"**Patterns detected:**\n"
                for match in info["matches"][:5]:
                    result += f"- `{match}`\n"
                result += "\n"

                # Add GDPR recommendations per stage
                if stage == "pii_collection":
                    result += "**GDPR Requirements:**\n"
                    result += "- Art. 13/14: Provide privacy notice at point of collection\n"
                    result += "- Art. 5(1)(c): Collect only necessary data (minimisation)\n"
                    result += "- Art. 6: Ensure lawful basis for processing\n\n"
                elif stage == "pii_storage":
                    result += "**GDPR Requirements:**\n"
                    result += "- Art. 32: Implement appropriate security measures\n"
                    result += "- Art. 5(1)(e): Define retention periods\n"
                    result += "- Art. 30: Document in ROPA\n\n"
                elif stage == "pii_transmission":
                    result += "**GDPR Requirements:**\n"
                    result += "- Art. 44-49: Ensure lawful basis for transfers\n"
                    result += "- Art. 28: Data processing agreements with recipients\n"
                    result += "- Art. 32: Encryption in transit\n\n"
                elif stage == "pii_deletion":
                    result += "**GDPR Requirements:**\n"
                    result += "- Art. 17: Support right to erasure\n"
                    result += "- Art. 5(1)(e): Enforce retention limits\n"
                    result += "- Complete deletion from all systems\n\n"

    # Missing stages
    missing_stages = [s for s in lifecycle_stages if s not in flow_findings]
    if missing_stages and detected_count > 0:
        result += "## ⚠️ Stages Not Detected\n\n"
        for stage in missing_stages:
            name = stage_names[stage]
            result += f"- **{name}:** No patterns found. "
            if stage == "pii_deletion":
                result += "Consider implementing data deletion capabilities for Art. 17 compliance.\n"
            elif stage == "pii_collection":
                result += "Verify how personal data enters the system.\n"
            elif stage == "pii_storage":
                result += "Identify where personal data is persisted.\n"
            elif stage == "pii_transmission":
                result += "Map external data sharing points.\n"
        result += "\n"

    result += "## ROPA Documentation Guidance\n\n"
    result += "Use these findings to populate your Art. 30 Records of Processing Activities:\n\n"
    result += "| ROPA Field | Source from Analysis |\n"
    result += "|------------|---------------------|\n"
    result += "| Categories of personal data | Collection patterns |\n"
    result += "| Categories of recipients | Transmission patterns |\n"
    result += "| Envisaged time limits for erasure | Deletion patterns |\n"
    result += "| Technical security measures | Storage patterns |\n"

    return append_disclaimer(result)
