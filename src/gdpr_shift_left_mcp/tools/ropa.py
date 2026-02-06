"""
GDPR Shift-Left MCP Server — ROPA Tools (Art. 30)

Records of Processing Activities generation, validation, and guidance.
"""
import json
import logging
from typing import Any

from ..disclaimer import append_disclaimer

logger = logging.getLogger(__name__)

# Art. 30(1) — mandatory fields for controllers
CONTROLLER_FIELDS = [
    "Name and contact details of the controller (and joint controller / representative / DPO)",
    "Purposes of the processing",
    "Categories of data subjects",
    "Categories of personal data",
    "Categories of recipients (including third-country recipients or international organisations)",
    "Transfers to third countries and safeguards (Art. 49(1) derogations, if applicable)",
    "Envisaged time limits for erasure (retention periods)",
    "General description of technical and organisational security measures (Art. 32(1))",
]

# Art. 30(2) — mandatory fields for processors
PROCESSOR_FIELDS = [
    "Name and contact details of the processor(s) and each controller on whose behalf the processor acts (and representative / DPO)",
    "Categories of processing carried out on behalf of each controller",
    "Transfers to third countries and safeguards",
    "General description of technical and organisational security measures (Art. 32(1))",
]


async def generate_ropa_template_impl(organization_context: str, data_loader) -> str:
    """Generate a ROPA template per Art. 30."""
    await data_loader.load_data()

    result = """# Records of Processing Activities (ROPA)
## Per GDPR Article 30

**Organization:** _[Organization name]_
**Context:** {context}
**Date created:** _[Date]_
**Last updated:** _[Date]_

---

## Processing Activity Register (Controller — Art. 30(1))

| # | Field | Value |
|---|-------|-------|
| 1 | **Controller name & contact** | _[Name, address, contact details]_ |
| 2 | **Joint controller(s)** | _[If applicable]_ |
| 3 | **Representative (Art. 27)** | _[If controller is outside EU]_ |
| 4 | **DPO contact details** | _[Name, email, phone]_ |
| 5 | **Processing activity name** | _[Descriptive name]_ |
| 6 | **Purpose(s) of processing** | _[Specific, explicit, legitimate purpose(s)]_ |
| 7 | **Legal basis (Art. 6)** | _[consent / contract / legal obligation / vital interest / public task / legitimate interest]_ |
| 8 | **Categories of data subjects** | _[e.g., customers, employees, website visitors]_ |
| 9 | **Categories of personal data** | _[e.g., name, email, IP, payment data]_ |
| 10 | **Special category data (Art. 9)?** | _[Yes/No — if yes, specify Art. 9(2) basis]_ |
| 11 | **Recipients / categories of recipients** | _[Internal teams, processors, third parties]_ |
| 12 | **Third-country transfers?** | _[Yes/No — if yes, specify country + safeguard (SCC/BCR/adequacy)]_ |
| 13 | **Retention period** | _[Specify period or criteria for determining period]_ |
| 14 | **Technical measures (Art. 32)** | _[Encryption, access controls, pseudonymisation, etc.]_ |
| 15 | **Organisational measures (Art. 32)** | _[Policies, training, DPIAs, audits, etc.]_ |

---

## Azure-Specific Implementation Notes

### Maintaining ROPA in Azure
- Use **Microsoft Purview Compliance Manager** to track processing activities
- Tag Azure resources with `processing-purpose`, `data-category`, `retention-period`
- Use **Azure Resource Graph** queries to auto-discover data stores and their configurations
- Store ROPA documents in **SharePoint** or **Azure Blob Storage** with versioning enabled

### Automating ROPA Updates
- **Azure Policy** — enforce tagging standards on all data resources
- **Azure Monitor** — alert when new data stores are created without ROPA tags
- **Azure DevOps** — include ROPA review step in deployment pipelines

### Example Azure Resource Tags for ROPA
```json
{{
  "gdpr-processing-purpose": "customer-support",
  "gdpr-data-category": "contact-information",
  "gdpr-legal-basis": "contract",
  "gdpr-retention-days": "730",
  "gdpr-data-subjects": "customers",
  "gdpr-ropa-entry-id": "ROPA-CS-001"
}}
```
""".format(context=organization_context)

    return append_disclaimer(result)


async def validate_ropa_impl(ropa_content: str, data_loader) -> str:
    """Validate a ROPA document against Art. 30 mandatory fields."""
    await data_loader.load_data()
    content_lower = ropa_content.lower()

    result = "# ROPA Validation Results\n\n"

    # Check controller fields
    result += "## Controller Fields (Art. 30(1))\n\n"
    missing = []
    present = []
    FIELD_KEYWORDS = {
        "Name and contact details": ["controller", "name", "contact"],
        "Purposes of processing": ["purpose"],
        "Categories of data subjects": ["data subject", "categories"],
        "Categories of personal data": ["personal data", "categories"],
        "Recipients": ["recipient"],
        "Third-country transfers": ["transfer", "third country", "safeguard"],
        "Retention periods": ["retention", "erasure", "deletion"],
        "Security measures (Art. 32)": ["security", "encryption", "technical measure", "organisational measure"],
    }

    for field, keywords in FIELD_KEYWORDS.items():
        if any(kw in content_lower for kw in keywords):
            present.append(field)
            result += f"- ✅ **{field}** — found\n"
        else:
            missing.append(field)
            result += f"- ❌ **{field}** — MISSING\n"

    result += f"\n**Score: {len(present)}/{len(FIELD_KEYWORDS)} mandatory fields present**\n\n"

    if missing:
        result += "## Required Actions\n\n"
        for m in missing:
            result += f"- Add documentation for: **{m}**\n"

    if not missing:
        result += "✅ **All mandatory Art. 30(1) fields are present.**\n"

    return append_disclaimer(result)


async def get_ropa_requirements_impl(role: str, data_loader) -> str:
    """Get mandatory ROPA fields for a given organizational role."""
    await data_loader.load_data()
    role_lower = role.lower().strip()

    if role_lower == "controller":
        fields = CONTROLLER_FIELDS
        article = "Art. 30(1)"
    elif role_lower == "processor":
        fields = PROCESSOR_FIELDS
        article = "Art. 30(2)"
    else:
        return append_disclaimer(
            f"Unknown role '{role}'. Please specify 'controller' or 'processor'."
        )

    result = f"# ROPA Mandatory Fields — {role.title()} ({article})\n\n"
    for i, field in enumerate(fields, 1):
        result += f"{i}. {field}\n"
    result += (
        "\n**Note:** The ROPA obligation applies to organizations with 250+ employees, "
        "or where processing is not occasional, involves special categories (Art. 9), "
        "criminal data (Art. 10), or is likely to result in a risk to data subjects' "
        "rights and freedoms. In practice, most organizations should maintain a ROPA.\n"
    )
    return append_disclaimer(result)
