"""
GDPR Shift-Left MCP Server — DPIA Tools (Art. 35 / 36)

Data Protection Impact Assessment guidance, templates, and necessity checks.
"""
import json
import logging
from typing import Any

from ..disclaimer import append_disclaimer

logger = logging.getLogger(__name__)

# Art. 35(3) — DPIA required in at least these cases
DPIA_REQUIRED_SCENARIOS = [
    "systematic and extensive evaluation of personal aspects (profiling)",
    "large-scale processing of special categories of data (Art. 9) or criminal data (Art. 10)",
    "systematic monitoring of a publicly accessible area on a large scale",
]

# EDPB criteria that indicate DPIA necessity (WP 248)
EDPB_CRITERIA = [
    "evaluation or scoring (including profiling and predicting)",
    "automated decision-making with legal or similar significant effect",
    "systematic monitoring",
    "sensitive data or data of a highly personal nature",
    "data processed on a large scale",
    "matching or combining datasets",
    "data concerning vulnerable data subjects (children, employees, patients)",
    "innovative use or applying new technological or organisational solutions",
    "preventing data subjects from exercising a right or using a service or contract",
]


async def assess_dpia_need_impl(processing_description: str, data_loader) -> str:
    """Assess whether a DPIA is required for a described processing activity."""
    await data_loader.load_data()
    desc_lower = processing_description.lower()

    triggered_criteria = []
    for criterion in EDPB_CRITERIA:
        # Simple keyword matching — look for overlap
        keywords = criterion.lower().split()
        if sum(1 for kw in keywords if kw in desc_lower) >= len(keywords) * 0.4:
            triggered_criteria.append(criterion)

    # Check Art. 35(3) explicit triggers
    explicit_triggers = []
    TRIGGER_KEYWORDS = {
        "profiling": "Systematic evaluation / profiling (Art. 35(3)(a))",
        "special categories": "Special category data at large scale (Art. 35(3)(b))",
        "health data": "Special category data at large scale (Art. 35(3)(b))",
        "biometric": "Special category data at large scale (Art. 35(3)(b))",
        "criminal": "Criminal data processing (Art. 35(3)(b))",
        "public area": "Systematic monitoring of public area (Art. 35(3)(c))",
        "cctv": "Systematic monitoring of public area (Art. 35(3)(c))",
        "surveillance": "Systematic monitoring of public area (Art. 35(3)(c))",
    }
    for kw, trigger in TRIGGER_KEYWORDS.items():
        if kw in desc_lower and trigger not in explicit_triggers:
            explicit_triggers.append(trigger)

    # Determine outcome
    required = len(triggered_criteria) >= 2 or len(explicit_triggers) > 0

    result = "# DPIA Necessity Assessment\n\n"
    result += f"**Processing description:** {processing_description}\n\n"
    result += f"## Result: DPIA {'REQUIRED' if required else 'RECOMMENDED (assess further)'}\n\n"

    if explicit_triggers:
        result += "### Art. 35(3) Explicit Triggers\n\n"
        for t in explicit_triggers:
            result += f"- ⚠️ {t}\n"
        result += "\n"

    if triggered_criteria:
        result += "### EDPB Criteria Matched (WP 248 rev.01)\n\n"
        for c in triggered_criteria:
            result += f"- {c}\n"
        result += f"\n*{len(triggered_criteria)} of 9 criteria matched. EDPB recommends DPIA when 2+ criteria are met.*\n\n"

    if not required:
        result += (
            "### Recommendation\n\n"
            "While a DPIA may not be strictly mandatory, it is **best practice** to "
            "conduct one for any processing that may pose risks to data subjects. "
            "Consider consulting your DPO.\n"
        )

    result += "\n### Azure Implementation Notes\n\n"
    result += "- Use **Microsoft Purview Compliance Manager** for DPIA workflow management\n"
    result += "- Apply **Azure Policy** to enforce controls identified in the DPIA\n"
    result += "- Document risk assessments in **Azure DevOps** for traceability\n"

    return append_disclaimer(result)


async def generate_dpia_template_impl(processing_description: str, data_loader) -> str:
    """Generate a DPIA template pre-filled with guidance."""
    await data_loader.load_data()

    result = """# Data Protection Impact Assessment (DPIA)
## Per GDPR Article 35

---

### 1. Systematic Description of Processing (Art. 35(7)(a))

**Activity:** {desc}

**Purpose of processing:**
_[Describe the specific, explicit, and legitimate purpose(s)]_

**Legal basis (Art. 6):**
_[e.g., consent (Art. 6(1)(a)), contract (Art. 6(1)(b)), legal obligation (Art. 6(1)(c)),
legitimate interest (Art. 6(1)(f))]_

**Categories of data subjects:**
_[e.g., customers, employees, patients, children]_

**Categories of personal data:**
_[e.g., name, email, IP address, health data, location data]_

**Recipients / processors:**
_[List all recipients and processors, including sub-processors]_

**Retention period:**
_[Specify retention period and justification]_

**International transfers:**
_[If data leaves the EEA — specify destination, safeguards (SCCs, adequacy, BCRs)]_

---

### 2. Necessity and Proportionality Assessment (Art. 35(7)(b))

| Question | Answer |
|----------|--------|
| Is the processing necessary for the stated purpose? | _[Yes/No + justification]_ |
| Could the purpose be achieved with less data? | _[Yes/No + justification]_ |
| Is the data minimised? | _[Yes/No + justification]_ |
| Are retention periods justified? | _[Yes/No + justification]_ |
| How are data subjects informed? | _[Describe]_ |
| How is consent obtained/managed? (if applicable) | _[Describe]_ |

---

### 3. Risk Assessment (Art. 35(7)(c))

| Risk | Likelihood | Severity | Overall | Mitigation |
|------|-----------|----------|---------|------------|
| Unauthorized access | _[Low/Med/High]_ | _[Low/Med/High]_ | _[Score]_ | _[Controls]_ |
| Data breach / exfiltration | _[Low/Med/High]_ | _[Low/Med/High]_ | _[Score]_ | _[Controls]_ |
| Excessive data collection | _[Low/Med/High]_ | _[Low/Med/High]_ | _[Score]_ | _[Controls]_ |
| Inaccurate data leading to harm | _[Low/Med/High]_ | _[Low/Med/High]_ | _[Score]_ | _[Controls]_ |
| Re-identification of pseudonymised data | _[Low/Med/High]_ | _[Low/Med/High]_ | _[Score]_ | _[Controls]_ |
| Cross-border transfer risk | _[Low/Med/High]_ | _[Low/Med/High]_ | _[Score]_ | _[Controls]_ |

---

### 4. Measures to Address Risks (Art. 35(7)(d))

#### Technical Measures (Azure-Specific)
- [ ] **Encryption at rest**: Azure Storage Service Encryption, Azure Disk Encryption, Azure SQL TDE
- [ ] **Encryption in transit**: TLS 1.2+ enforced, Azure Front Door / Application Gateway
- [ ] **Access control**: Microsoft Entra ID RBAC, Privileged Identity Management (PIM)
- [ ] **Key management**: Azure Key Vault with CMK (Customer-Managed Keys)
- [ ] **Network isolation**: Azure Private Link, NSGs, Azure Firewall
- [ ] **Logging & monitoring**: Azure Monitor, Log Analytics, Microsoft Sentinel
- [ ] **Data classification**: Microsoft Purview Information Protection
- [ ] **Pseudonymisation/anonymisation**: Application-layer controls, Azure Confidential Computing

#### Organizational Measures
- [ ] DPO consulted and approved
- [ ] Data processing agreements with all processors (Art. 28)
- [ ] Staff training on data handling procedures
- [ ] Incident response plan covering Art. 33/34 notification
- [ ] Regular reviews scheduled (at least annually)

---

### 5. DPO Advice (Art. 35(2))

**DPO consulted:** _[Yes/No]_
**DPO recommendation:** _[Document advice]_

---

### 6. Supervisory Authority Consultation (Art. 36)

**Prior consultation required?** _[Yes if residual risk remains high after mitigation]_
**If yes, consultation date:** _[Date]_

---

### 7. Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Data Controller | | | |
| DPO | | | |
| CISO / Security Lead | | | |
""".format(desc=processing_description)

    return append_disclaimer(result)


async def get_dpia_guidance_impl(topic: str, data_loader) -> str:
    """Get detailed DPIA guidance for a specific topic or processing type."""
    await data_loader.load_data()
    topic_lower = topic.lower().strip()

    GUIDANCE = {
        "profiling": {
            "title": "Profiling & Automated Decision-Making",
            "articles": "Art. 22, Art. 35(3)(a), Recitals 71-72",
            "guidance": (
                "Profiling means any form of automated processing to evaluate personal aspects. "
                "A DPIA is mandatory when profiling produces legal or similarly significant effects.\n\n"
                "**Key requirements:**\n"
                "- Right to human intervention (Art. 22(3))\n"
                "- Suitable safeguards including right to contest\n"
                "- Explicit consent or contract necessity\n"
                "- Cannot be based solely on special-category data without Art. 9(2) basis\n\n"
                "**Azure implementation:**\n"
                "- Log all automated decisions via Azure Monitor\n"
                "- Implement human-review workflow in Azure Logic Apps\n"
                "- Store audit trails in immutable Azure Blob Storage\n"
            ),
        },
        "large-scale monitoring": {
            "title": "Large-Scale Systematic Monitoring",
            "articles": "Art. 35(3)(c), Recital 91",
            "guidance": (
                "Processing that involves systematic monitoring of data subjects on a large scale "
                "(e.g., CCTV networks, employee monitoring, location tracking) requires a DPIA.\n\n"
                "**Key requirements:**\n"
                "- Clearly defined purpose and proportionality\n"
                "- Data minimisation — collect only what's necessary\n"
                "- Defined retention periods\n"
                "- Transparent notice to data subjects\n\n"
                "**Azure implementation:**\n"
                "- Use Azure IoT Hub with data lifecycle management\n"
                "- Apply Azure Purview sensitivity labels\n"
                "- Set automated retention/deletion policies\n"
            ),
        },
        "special categories": {
            "title": "Special Categories of Data (Art. 9)",
            "articles": "Art. 9, Art. 35(3)(b), Recitals 51-56",
            "guidance": (
                "Processing special categories (health, biometric, genetic, racial/ethnic, "
                "political, religious, trade union, sexual orientation) on a large scale requires a DPIA.\n\n"
                "**Key requirements:**\n"
                "- Must have Art. 9(2) legal basis (explicit consent, employment law, vital interests, etc.)\n"
                "- Enhanced technical measures (encryption, pseudonymisation)\n"
                "- Strict access controls\n"
                "- Consider appointing a DPO if not already required\n\n"
                "**Azure implementation:**\n"
                "- Azure Confidential Computing for sensitive workloads\n"
                "- Customer-Managed Keys in Azure Key Vault\n"
                "- Azure Private Link for all data stores\n"
                "- Microsoft Purview for data classification\n"
            ),
        },
        "children": {
            "title": "Processing Children's Data",
            "articles": "Art. 8, Recital 38",
            "guidance": (
                "When offering information society services directly to children, special rules apply.\n\n"
                "**Key requirements:**\n"
                "- Consent of holder of parental responsibility for children under 16 (or lower age set by Member State, minimum 13)\n"
                "- Age verification mechanisms\n"
                "- Clear, child-friendly privacy notices\n"
                "- Enhanced data minimisation\n\n"
                "**Azure implementation:**\n"
                "- Implement age-gate in Azure AD B2C user flows\n"
                "- Store parental consent records in compliant storage\n"
                "- Apply strict retention and deletion policies\n"
            ),
        },
    }

    entry = GUIDANCE.get(topic_lower)
    if not entry:
        available = ", ".join(f"'{k}'" for k in GUIDANCE)
        return append_disclaimer(
            f"No specific guidance found for '{topic}'. Available topics: {available}. "
            "You can also use `assess_dpia_need` for a general assessment."
        )

    result = f"# DPIA Guidance: {entry['title']}\n\n"
    result += f"**Relevant provisions:** {entry['articles']}\n\n"
    result += entry["guidance"]
    return append_disclaimer(result)
