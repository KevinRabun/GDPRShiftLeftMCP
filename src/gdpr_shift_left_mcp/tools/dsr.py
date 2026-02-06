"""
GDPR Shift-Left MCP Server — Data Subject Rights Tools (Arts. 12–23)

Guidance, workflows, and timeline info for handling DSR requests.
"""
import json
import logging
from typing import Any

from ..disclaimer import append_disclaimer

logger = logging.getLogger(__name__)

DSR_TYPES = {
    "access": {
        "title": "Right of Access (Art. 15)",
        "article": "15",
        "description": (
            "The data subject has the right to obtain confirmation as to whether personal data "
            "concerning them is being processed, and access to that data plus supplementary information."
        ),
        "obligations": [
            "Confirm whether personal data is being processed",
            "Provide a copy of the personal data undergoing processing",
            "Inform of: purposes, categories, recipients, retention period, rights, source, automated decisions",
            "First copy must be free of charge; additional copies may incur a reasonable fee",
            "If request is made electronically, provide data in commonly used electronic form",
        ],
        "azure_notes": [
            "Use Azure Cognitive Search or Azure SQL queries to locate data subject records",
            "Azure Purview can catalogue data subject data across Azure data stores",
            "Microsoft Entra ID provides user data export capabilities",
            "Azure Data Factory can orchestrate cross-store data extraction",
        ],
    },
    "rectification": {
        "title": "Right to Rectification (Art. 16)",
        "article": "16",
        "description": (
            "The data subject has the right to obtain rectification of inaccurate personal data "
            "and, considering the purposes of processing, to have incomplete data completed."
        ),
        "obligations": [
            "Rectify inaccurate personal data without undue delay",
            "Allow completion of incomplete personal data (including via supplementary statement)",
            "Notify each recipient to whom data was disclosed (Art. 19), unless impossible or disproportionate effort",
        ],
        "azure_notes": [
            "Implement update APIs that propagate changes across all data stores",
            "Use Azure Event Grid to trigger cascading updates across services",
            "Log all rectification actions in Azure Monitor for audit trail",
        ],
    },
    "erasure": {
        "title": "Right to Erasure / Right to be Forgotten (Art. 17)",
        "article": "17",
        "description": (
            "The data subject has the right to obtain erasure of personal data where one of "
            "several grounds applies (consent withdrawn, data no longer necessary, etc.)."
        ),
        "obligations": [
            "Erase personal data without undue delay when grounds apply",
            "If data made public, take reasonable steps to inform other controllers (Art. 17(2))",
            "Grounds include: data no longer necessary, consent withdrawn, Art. 21 objection, unlawful processing, legal obligation, child data (Art. 8(1))",
            "Exceptions: freedom of expression, legal obligation, public health, archiving/research, legal claims",
        ],
        "azure_notes": [
            "Implement soft-delete with configurable purge timelines in Azure SQL / Cosmos DB",
            "Azure Blob Storage — use lifecycle management for automated deletion",
            "Azure Key Vault — crypto-shredding pattern (delete encryption key to render data unreadable)",
            "Ensure backups also have deletion/expiry mechanisms",
            "Azure Purview data map helps locate all instances of data subject information",
        ],
    },
    "restriction": {
        "title": "Right to Restriction of Processing (Art. 18)",
        "article": "18",
        "description": (
            "The data subject has the right to obtain restriction of processing in certain circumstances "
            "(accuracy contested, processing unlawful, controller no longer needs data, etc.)."
        ),
        "obligations": [
            "Mark data as restricted (store but do not process further except with consent)",
            "Inform data subject before lifting restriction",
            "Notify recipients of restriction (Art. 19)",
        ],
        "azure_notes": [
            "Implement a 'restricted' flag/column in databases",
            "Use Azure RBAC to revoke processing access while maintaining storage",
            "Azure Policy can enforce 'restricted' state via compliance checks",
        ],
    },
    "portability": {
        "title": "Right to Data Portability (Art. 20)",
        "article": "20",
        "description": (
            "The data subject has the right to receive their personal data in a structured, commonly "
            "used and machine-readable format, and to transmit it to another controller."
        ),
        "obligations": [
            "Provide data in structured, commonly used, machine-readable format (JSON, CSV, XML)",
            "Transmit directly to another controller where technically feasible",
            "Applies when processing is based on consent or contract AND carried out by automated means",
            "Must not adversely affect the rights and freedoms of others",
        ],
        "azure_notes": [
            "Build export APIs returning JSON/CSV formatted data",
            "Azure Logic Apps can automate data export workflows",
            "Azure API Management can expose a standardised portability endpoint",
            "Use Azure Blob Storage SAS tokens for secure data delivery",
        ],
    },
    "objection": {
        "title": "Right to Object (Art. 21)",
        "article": "21",
        "description": (
            "The data subject has the right to object to processing based on legitimate interest "
            "(Art. 6(1)(e)/(f)), including profiling. Also: unconditional right to object to direct marketing."
        ),
        "obligations": [
            "Stop processing unless compelling legitimate grounds override",
            "For direct marketing: stop immediately, no exceptions",
            "Inform data subject of this right at first communication, clearly and separately",
        ],
        "azure_notes": [
            "Implement opt-out flag in user profile/consent store",
            "Azure Communication Services can integrate suppression lists",
            "Use Azure Event Grid to propagate objection events across services",
        ],
    },
    "automated_decision": {
        "title": "Rights Related to Automated Decision-Making (Art. 22)",
        "article": "22",
        "description": (
            "The data subject has the right not to be subject to a decision based solely on automated "
            "processing, including profiling, which produces legal or similarly significant effects."
        ),
        "obligations": [
            "Do not base decisions solely on automated processing if they produce legal/significant effects",
            "Exceptions: contract, EU/Member State law authorisation, explicit consent",
            "When exceptions apply: implement safeguards — right to human intervention, express point of view, contest",
            "Cannot be based on special categories (Art. 9) unless Art. 9(2)(a)/(g) + safeguards apply",
        ],
        "azure_notes": [
            "Log all automated decisions with reasoning in Azure Monitor / Application Insights",
            "Implement human-review queue via Azure Service Bus + Logic Apps",
            "Azure Machine Learning model explainability (InterpretML) for transparent decisions",
            "Store audit trail in immutable Azure Blob Storage",
        ],
    },
}


async def get_dsr_guidance_impl(request_type: str, data_loader) -> str:
    """Get guidance on handling a specific data-subject request."""
    await data_loader.load_data()
    rt = request_type.lower().strip()
    dsr = DSR_TYPES.get(rt)
    if not dsr:
        available = ", ".join(f"'{k}'" for k in DSR_TYPES)
        return append_disclaimer(
            f"Unknown DSR type '{request_type}'. Available types: {available}"
        )

    result = f"# {dsr['title']}\n\n"
    result += f"**GDPR Article:** {dsr['article']}\n\n"
    result += f"{dsr['description']}\n\n"

    result += "## Controller Obligations\n\n"
    for ob in dsr["obligations"]:
        result += f"- {ob}\n"

    result += "\n## Azure Implementation Notes\n\n"
    for note in dsr["azure_notes"]:
        result += f"- {note}\n"

    return append_disclaimer(result)


async def generate_dsr_workflow_impl(request_type: str, system_context: str, data_loader) -> str:
    """Generate a step-by-step DSR fulfilment workflow."""
    await data_loader.load_data()
    rt = request_type.lower().strip()
    dsr = DSR_TYPES.get(rt)
    if not dsr:
        available = ", ".join(f"'{k}'" for k in DSR_TYPES)
        return append_disclaimer(f"Unknown DSR type '{request_type}'. Available types: {available}")

    result = f"# DSR Workflow: {dsr['title']}\n\n"
    if system_context:
        result += f"**System context:** {system_context}\n\n"

    result += """## Step-by-Step Fulfilment Process

### Step 1: Receive & Log Request
- Log the DSR request with timestamp, data subject identity, request type
- Assign a unique tracking ID
- **Azure:** Use Azure Service Bus queue for intake; log in Application Insights

### Step 2: Verify Identity (Art. 12(6))
- Verify the identity of the data subject requesting
- Request additional information if reasonable doubt exists
- Do **not** ask for more data than necessary to verify
- **Azure:** Microsoft Entra ID Verified ID for identity verification

### Step 3: Assess Scope & Feasibility
- Determine which data stores contain the data subject's data
- Check for exemptions (Art. 17(3) for erasure, Art. 20 scope for portability, etc.)
- **Azure:** Azure Purview data map to locate all personal data instances

### Step 4: Execute the Request
"""

    if rt == "access":
        result += "- Compile all personal data related to the data subject\n"
        result += "- Include supplementary information per Art. 15(1)(a)-(h)\n"
        result += "- Format data in commonly used electronic form if requested\n"
        result += "- **Azure:** Azure Data Factory pipeline to extract and compile data\n"
    elif rt == "erasure":
        result += "- Delete personal data from all live data stores\n"
        result += "- Delete or anonymize data in analytics/BI systems\n"
        result += "- Handle backup data (mark for deletion upon restore or crypto-shred)\n"
        result += "- Notify downstream controllers if data was made public (Art. 17(2))\n"
        result += "- **Azure:** Azure Lifecycle Management + crypto-shredding via Key Vault\n"
    elif rt == "portability":
        result += "- Export personal data in structured, machine-readable format (JSON/CSV)\n"
        result += "- If requested, transmit directly to receiving controller\n"
        result += "- Only data provided **by** the data subject and processed by automated means\n"
        result += "- **Azure:** Azure Logic Apps + API Management for automated export\n"
    else:
        result += f"- Fulfil the {dsr['title']} per the obligations listed above\n"
        result += "- Document all actions taken\n"

    result += """
### Step 5: Document & Respond
- Record all actions taken and data systems affected
- Provide response to data subject within **1 calendar month** (Art. 12(3))
- If extension needed: notify data subject within 1 month with reasons (Art. 12(3))
- Maximum extension: **2 additional months** for complex/numerous requests

### Step 6: Notify Recipients (Art. 19)
- Inform each recipient to whom data was disclosed
- Unless impossible or involves disproportionate effort
- Inform data subject of those recipients if requested

### Step 7: Close & Audit
- Mark request as fulfilled in tracking system
- Retain DSR processing record for accountability (Art. 5(2))
- Schedule any follow-up actions (e.g., backup deletion cycles)
"""

    return append_disclaimer(result)


async def get_dsr_timeline_impl(request_type: str, data_loader) -> str:
    """Get GDPR-mandated response timelines for a DSR type."""
    await data_loader.load_data()

    result = f"# DSR Response Timelines — {request_type.title()}\n\n"
    result += "## Standard Timeline (Art. 12(3))\n\n"
    result += "| Phase | Deadline | Notes |\n"
    result += "|-------|----------|-------|\n"
    result += "| Acknowledge receipt | As soon as practicable | Best practice: within 3 business days |\n"
    result += "| Provide response | **1 calendar month** from receipt | Starts from date of receipt, not verification |\n"
    result += "| Extension (if complex) | **+2 months** (total 3 months max) | Must notify data subject within first month with reasons |\n"
    result += "| Manifestly unfounded/excessive | May **refuse** or charge fee | Must demonstrate why request is manifestly unfounded/excessive |\n\n"

    result += "## Key Rules\n\n"
    result += "- Response must be provided **free of charge** (Art. 12(5))\n"
    result += "- Exceptions: manifestly unfounded/excessive requests — reasonable fee OR refusal\n"
    result += "- If refusing: provide reasons + right to complain to SA + seek judicial remedy\n"
    result += "- Calendar month = same date next month (e.g., 15 Jan → 15 Feb)\n"
    result += "- If month ends on non-existent date — use last day of month\n"

    return append_disclaimer(result)
