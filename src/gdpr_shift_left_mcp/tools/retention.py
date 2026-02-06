"""
GDPR Shift-Left MCP Server — Data Retention & Deletion Tools

Guidance for GDPR storage limitation (Art. 5(1)(e)) and right to erasure (Art. 17).
"""
import json
import logging
from typing import Any

from ..disclaimer import append_disclaimer

logger = logging.getLogger(__name__)

RETENTION_GUIDANCE = {
    "employee records": {
        "category": "Employee / HR Records",
        "gdpr_articles": "Art. 5(1)(e), Art. 6(1)(b)/(c)",
        "typical_retention": "Duration of employment + statutory retention (varies by Member State, often 5-10 years post-termination)",
        "legal_bases": [
            "Contract performance (Art. 6(1)(b)) during employment",
            "Legal obligation (Art. 6(1)(c)) for tax/employment law retention",
        ],
        "azure_guidance": [
            "Use Azure SQL with row-level security for HR data",
            "Implement automated lifecycle policies to flag records for review post-termination",
            "Azure Purview for HR data classification and lineage",
        ],
        "deletion_notes": "Must delete or anonymize data that is no longer required for any lawful purpose. Payroll/tax records may have statutory minimums.",
    },
    "customer data": {
        "category": "Customer / CRM Data",
        "gdpr_articles": "Art. 5(1)(e), Art. 6(1)(b), Art. 17",
        "typical_retention": "Duration of contract + reasonable post-contract period (typically 2-6 years for warranty/legal claims)",
        "legal_bases": [
            "Contract performance (Art. 6(1)(b)) during active relationship",
            "Legitimate interest (Art. 6(1)(f)) for limited post-contract retention",
            "Legal obligation (Art. 6(1)(c)) for invoicing/tax records",
        ],
        "azure_guidance": [
            "Azure Cosmos DB TTL for automatic document expiration",
            "Azure Blob Storage lifecycle management for file attachments",
            "Tag customer records with retention-expiry date via Azure tags",
        ],
        "deletion_notes": "Implement erasure workflows for Art. 17 requests. Consider crypto-shredding for backups.",
    },
    "marketing consent": {
        "category": "Marketing / Consent Records",
        "gdpr_articles": "Art. 5(1)(e), Art. 7, Art. 21",
        "typical_retention": "Active consent: until withdrawn. Proof of consent: retain for statute of limitations period (2-6 years depending on jurisdiction).",
        "legal_bases": [
            "Consent (Art. 6(1)(a)) for marketing processing",
            "Legitimate interest (Art. 6(1)(f)) for proof-of-consent retention",
        ],
        "azure_guidance": [
            "Store consent records in immutable Azure Blob Storage (WORM policies)",
            "Use Azure Communication Services with integrated suppression lists",
            "Implement consent management via Azure AD B2C custom policies",
        ],
        "deletion_notes": "When consent is withdrawn, stop processing immediately. Retain proof of prior consent for legal defence.",
    },
    "health data": {
        "category": "Health / Medical Data (Art. 9 Special Category)",
        "gdpr_articles": "Art. 5(1)(e), Art. 9, Art. 35",
        "typical_retention": "Governed by national health legislation (often 10-30 years for medical records). DPIA required.",
        "legal_bases": [
            "Explicit consent (Art. 9(2)(a)) or healthcare provision (Art. 9(2)(h))",
            "Legal obligation under national health law (Art. 9(2)(b)/(i))",
        ],
        "azure_guidance": [
            "Azure Health Data Services (FHIR API) with built-in compliance",
            "Azure Confidential Computing for sensitive processing",
            "Customer-Managed Keys in Azure Key Vault (Premium/HSM)",
            "Azure Private Link for all health data endpoints",
        ],
        "deletion_notes": "National law typically specifies minimum retention. After statutory period, secure deletion is mandatory. DPIA must document retention rationale.",
    },
    "financial transactions": {
        "category": "Financial / Payment Data",
        "gdpr_articles": "Art. 5(1)(e), Art. 6(1)(c)",
        "typical_retention": "Tax/accounting records: 6-10 years depending on Member State. Payment card data: PCI DSS requirements apply in parallel.",
        "legal_bases": [
            "Legal obligation (Art. 6(1)(c)) for tax/anti-money-laundering retention",
            "Contract performance (Art. 6(1)(b)) during active relationship",
        ],
        "azure_guidance": [
            "Azure SQL with Transparent Data Encryption and audit logging",
            "Azure Key Vault for payment-related encryption keys",
            "Implement Azure Policy to enforce minimum retention on financial data stores",
        ],
        "deletion_notes": "Cannot delete before statutory minimum. After statutory period, delete or anonymize. Tokenize card data to minimize GDPR scope.",
    },
    "website analytics": {
        "category": "Website / App Analytics",
        "gdpr_articles": "Art. 5(1)(e), Art. 6(1)(a)/(f)",
        "typical_retention": "Typically 14-26 months for analytics data. IP addresses should be anonymized within 24-48 hours.",
        "legal_bases": [
            "Consent (Art. 6(1)(a)) for tracking cookies (per ePrivacy Directive)",
            "Legitimate interest (Art. 6(1)(f)) for essential analytics only",
        ],
        "azure_guidance": [
            "Application Insights — configure data retention settings (30-730 days)",
            "Implement IP anonymization in Application Insights",
            "Use Azure Front Door for managed cookie consent banner integration",
        ],
        "deletion_notes": "Anonymize or aggregate data beyond the consent scope. Honour opt-out / cookie consent withdrawal.",
    },
}


async def assess_retention_policy_impl(policy_description: str, data_loader) -> str:
    """Assess a data-retention policy against GDPR storage-limitation principle."""
    await data_loader.load_data()
    desc_lower = policy_description.lower()

    result = "# GDPR Retention Policy Assessment\n\n"
    result += f"**Policy description:** {policy_description}\n\n"

    issues = []
    good_practices = []

    # Check for indefinite retention
    if any(term in desc_lower for term in ["indefinite", "forever", "no expir", "unlimited", "permanent"]):
        issues.append(
            "⚠️ **Indefinite retention detected.** Art. 5(1)(e) requires data to be kept only "
            "for as long as necessary for the purpose. Define specific retention periods."
        )

    # Check for purpose linkage
    if any(term in desc_lower for term in ["purpose", "reason", "justif", "legal basis"]):
        good_practices.append("✅ Retention linked to purpose — matches Art. 5(1)(e).")
    else:
        issues.append("⚠️ No explicit purpose linkage found. Retention periods must be justified by processing purpose.")

    # Check for deletion/anonymization mechanism
    if any(term in desc_lower for term in ["delet", "anonymi", "purg", "eras", "destroy"]):
        good_practices.append("✅ Deletion/anonymization mechanism mentioned.")
    else:
        issues.append("⚠️ No deletion or anonymization mechanism described. Ensure automated end-of-life processing.")

    # Check for review schedule
    if any(term in desc_lower for term in ["review", "periodic", "annual", "quarterly"]):
        good_practices.append("✅ Periodic review mentioned — good practice per accountability principle.")
    else:
        issues.append("⚠️ No periodic review schedule. Recommend at least annual retention policy reviews.")

    if issues:
        result += "## Issues Found\n\n"
        for issue in issues:
            result += f"- {issue}\n"
        result += "\n"

    if good_practices:
        result += "## Good Practices Identified\n\n"
        for gp in good_practices:
            result += f"- {gp}\n"
        result += "\n"

    result += "## GDPR Storage Limitation Requirements (Art. 5(1)(e))\n\n"
    result += "Personal data must be:\n"
    result += "- Kept in a form that permits identification **only as long as necessary**\n"
    result += "- Longer storage allowed **only** for archiving in public interest, scientific/historical research, or statistical purposes (with Art. 89(1) safeguards)\n"
    result += "- Subject to appropriate technical and organisational measures\n"

    return append_disclaimer(result)


async def get_retention_guidance_impl(data_category: str, data_loader) -> str:
    """Get GDPR-aligned retention guidance for a specific data category."""
    await data_loader.load_data()
    cat_lower = data_category.lower().strip()

    entry = RETENTION_GUIDANCE.get(cat_lower)
    if not entry:
        # Fuzzy match
        for key, val in RETENTION_GUIDANCE.items():
            if cat_lower in key or key in cat_lower:
                entry = val
                break

    if not entry:
        available = ", ".join(f"'{k}'" for k in RETENTION_GUIDANCE)
        return append_disclaimer(
            f"No specific guidance for '{data_category}'. Available categories: {available}"
        )

    result = f"# Retention Guidance: {entry['category']}\n\n"
    result += f"**GDPR Articles:** {entry['gdpr_articles']}\n\n"
    result += f"**Typical Retention:** {entry['typical_retention']}\n\n"

    result += "## Legal Bases\n\n"
    for lb in entry["legal_bases"]:
        result += f"- {lb}\n"

    result += "\n## Azure Implementation\n\n"
    for ag in entry["azure_guidance"]:
        result += f"- {ag}\n"

    result += f"\n## Deletion Notes\n\n{entry['deletion_notes']}\n"

    return append_disclaimer(result)


async def check_deletion_requirements_impl(system_context: str, data_loader) -> str:
    """Check what deletion/anonymization capabilities a system must support."""
    await data_loader.load_data()

    result = "# GDPR Deletion & Anonymization Requirements\n\n"
    result += f"**System context:** {system_context}\n\n"

    result += """## Mandatory Deletion Capabilities

### 1. Right to Erasure (Art. 17)
Your system **must** be able to:
- Identify all personal data related to a specific data subject across all stores
- Delete personal data from live/operational databases
- Delete or anonymize personal data in analytics and BI systems
- Handle data in backups (crypto-shredding or deletion on restore)
- Propagate deletion to downstream recipients/processors (Art. 17(2))
- Log the deletion action for accountability (without retaining the deleted data)

### 2. Automated Retention Expiry (Art. 5(1)(e))
Your system **should** support:
- Time-to-live (TTL) or lifecycle policies on data stores
- Automated flagging of data past its retention period
- Scheduled anonymization/aggregation jobs for expired data
- Different retention periods for different data categories

### 3. Data Portability Export + Delete (Art. 20 + Art. 17)
When a data subject exercises portability followed by erasure:
- Export data in structured, machine-readable format
- Then erase all copies from all systems

## Azure Implementation Patterns

### Crypto-Shredding
- Store personal data encrypted with a per-data-subject key in Azure Key Vault
- To "delete": purge the key → data becomes unreadable
- Particularly useful for backup data that cannot be easily modified

### Soft-Delete + Purge
- Azure SQL: implement soft-delete column with scheduled hard-delete job
- Azure Cosmos DB: use TTL or change-feed-based cleanup
- Azure Blob Storage: lifecycle management rules for auto-deletion

### Cross-Store Deletion Orchestration
- Azure Logic Apps or Durable Functions to coordinate deletion across multiple stores
- Azure Event Grid to notify downstream systems of deletion events
- Track deletion status in a central audit log (Application Insights / Log Analytics)

### Backup Considerations
- Azure Backup: configure retention policies aligned with GDPR retention periods
- Document backup restoration + re-deletion procedures
- Consider geo-redundancy implications for data residency
"""

    return append_disclaimer(result)
