"""
GDPR Shift-Left MCP Server — Controller/Processor Role Classifier

Helps developers and technical PMs determine whether their service/system
acts as a data controller, processor, joint controller, or sub-processor
under GDPR Article 4(7) and 4(8).

Key references:
  - Article 4(7): Definition of Controller
  - Article 4(8): Definition of Processor
  - Article 26: Joint Controllers
  - Article 28: Processor obligations and DPA requirements
  - EDPB Guidelines 07/2020 on controller and processor concepts
"""
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from ..disclaimer import append_disclaimer

logger = logging.getLogger(__name__)

# ─── Controller Indicators ──────────────────────────────────────────────────

CONTROLLER_INDICATORS = [
    {
        "id": "CTRL-001",
        "indicator": "Determines purposes of processing",
        "description": "You decide WHY personal data is processed (the business objective)",
        "weight": 3,
        "keywords": ["purpose", "objective", "goal", "reason for processing", "business need"],
    },
    {
        "id": "CTRL-002",
        "indicator": "Decides what data to collect",
        "description": "You determine WHICH personal data categories to collect or process",
        "weight": 3,
        "keywords": ["collect", "gather", "obtain", "request data", "data fields"],
    },
    {
        "id": "CTRL-003",
        "indicator": "Direct relationship with data subjects",
        "description": "You interact directly with individuals whose data is processed",
        "weight": 2,
        "keywords": ["user", "customer", "subscriber", "member", "account holder", "end user"],
    },
    {
        "id": "CTRL-004",
        "indicator": "Collects consent from data subjects",
        "description": "You obtain consent directly from individuals for data processing",
        "weight": 2,
        "keywords": ["consent", "opt-in", "permission", "agree", "accept terms", "privacy policy"],
    },
    {
        "id": "CTRL-005",
        "indicator": "Determines retention periods",
        "description": "You decide HOW LONG personal data is retained",
        "weight": 2,
        "keywords": ["retention", "delete after", "keep for", "storage period", "data lifecycle"],
    },
    {
        "id": "CTRL-006",
        "indicator": "Decides on data recipients",
        "description": "You determine WHO receives or accesses the personal data",
        "weight": 2,
        "keywords": ["share with", "disclose to", "transfer to", "third party", "recipient"],
    },
    {
        "id": "CTRL-007",
        "indicator": "Uses data for own business purposes",
        "description": "You use personal data to benefit your own organization",
        "weight": 3,
        "keywords": ["analytics", "improve service", "marketing", "business intelligence", "our purposes"],
    },
    {
        "id": "CTRL-008",
        "indicator": "Determines security measures independently",
        "description": "You decide security controls without external instruction",
        "weight": 1,
        "keywords": ["security policy", "access control", "encryption choice", "security standards"],
    },
]

# ─── Processor Indicators ───────────────────────────────────────────────────

PROCESSOR_INDICATORS = [
    {
        "id": "PROC-001",
        "indicator": "Processes on behalf of another entity",
        "description": "You process personal data for/on behalf of a client or customer organization",
        "weight": 3,
        "keywords": ["on behalf of", "for client", "customer data", "client's data", "service provider"],
    },
    {
        "id": "PROC-002",
        "indicator": "Follows documented instructions",
        "description": "You act only on documented instructions from the controller",
        "weight": 3,
        "keywords": ["instruction", "as directed", "per agreement", "contract terms", "as specified"],
    },
    {
        "id": "PROC-003",
        "indicator": "Cannot use data for own purposes",
        "description": "You are prohibited from using client data for your own business purposes",
        "weight": 3,
        "keywords": ["only for", "exclusively", "not for our", "restricted use", "limited to"],
    },
    {
        "id": "PROC-004",
        "indicator": "No direct data subject relationship",
        "description": "You do not interact directly with the individuals whose data you process",
        "weight": 2,
        "keywords": ["no direct contact", "through client", "client's users", "b2b", "enterprise"],
    },
    {
        "id": "PROC-005",
        "indicator": "Returns or deletes data on contract end",
        "description": "You return or delete all personal data when the service agreement ends",
        "weight": 2,
        "keywords": ["return data", "delete on termination", "contract end", "service termination"],
    },
    {
        "id": "PROC-006",
        "indicator": "Assists controller with DSR fulfillment",
        "description": "You help the controller respond to data subject requests",
        "weight": 1,
        "keywords": ["assist with", "support dsr", "help controller", "enable compliance"],
    },
    {
        "id": "PROC-007",
        "indicator": "Subject to Data Processing Agreement",
        "description": "You have a DPA/contract specifying processing terms per Article 28",
        "weight": 2,
        "keywords": ["dpa", "data processing agreement", "processor agreement", "article 28"],
    },
    {
        "id": "PROC-008",
        "indicator": "Multi-tenant data isolation",
        "description": "You maintain strict separation between different clients' data",
        "weight": 1,
        "keywords": ["multi-tenant", "tenant isolation", "client separation", "data segregation"],
    },
]

# ─── Joint Controller Indicators ────────────────────────────────────────────

JOINT_CONTROLLER_INDICATORS = [
    {
        "id": "JOINT-001",
        "indicator": "Shared purpose determination",
        "description": "Multiple parties jointly decide the purposes of processing",
        "weight": 3,
        "keywords": ["jointly determine", "shared purpose", "common objectives", "together decide"],
    },
    {
        "id": "JOINT-002",
        "indicator": "Common platform or service",
        "description": "Multiple parties operate a shared platform processing personal data",
        "weight": 2,
        "keywords": ["shared platform", "joint service", "partnership", "collaboration"],
    },
    {
        "id": "JOINT-003",
        "indicator": "Shared data for common benefit",
        "description": "Multiple parties share and use data for mutual benefit",
        "weight": 2,
        "keywords": ["data sharing", "mutual benefit", "shared database", "common use"],
    },
]

# ─── Code Pattern Indicators ────────────────────────────────────────────────

CODE_CONTROLLER_PATTERNS = [
    {
        "id": "CODE-CTRL-001",
        "pattern": r"(signup|register|create.?account|registration)",
        "description": "User registration/signup flows",
        "weight": 2,
    },
    {
        "id": "CODE-CTRL-002",
        "pattern": r"(consent|gdpr.?consent|cookie.?consent|opt.?in|accept.?policy)",
        "description": "Consent collection mechanisms",
        "weight": 3,
    },
    {
        "id": "CODE-CTRL-003",
        "pattern": r"(privacy.?policy|terms.?of.?service|legal.?basis)",
        "description": "Legal basis/policy presentation",
        "weight": 2,
    },
    {
        "id": "CODE-CTRL-004",
        "pattern": r"(analytics|tracking|user.?behavior|telemetry)",
        "description": "Analytics/tracking for own purposes",
        "weight": 2,
    },
    {
        "id": "CODE-CTRL-005",
        "pattern": r"(marketing.?email|newsletter|promotional|advertising)",
        "description": "Direct marketing to users",
        "weight": 2,
    },
    {
        "id": "CODE-CTRL-006",
        "pattern": r"(user.?profile|preferences|settings|account.?data)",
        "description": "User profile management",
        "weight": 1,
    },
]

CODE_PROCESSOR_PATTERNS = [
    {
        "id": "CODE-PROC-001",
        "pattern": r"(webhook|callback|event.?handler|inbound.?request)",
        "description": "Receiving data via webhooks from clients",
        "weight": 2,
    },
    {
        "id": "CODE-PROC-002",
        "pattern": r"(tenant.?id|organization.?id|client.?id|customer.?id)",
        "description": "Multi-tenant data isolation",
        "weight": 2,
    },
    {
        "id": "CODE-PROC-003",
        "pattern": r"(api.?key|client.?secret|bearer.?token|oauth.?client)",
        "description": "Client authentication for API access",
        "weight": 1,
    },
    {
        "id": "CODE-PROC-004",
        "pattern": r"(forward|relay|pass.?through|proxy)",
        "description": "Data forwarding/relay patterns",
        "weight": 1,
    },
    {
        "id": "CODE-PROC-005",
        "pattern": r"(client.?config|customer.?settings|tenant.?config)",
        "description": "Client-specific configuration",
        "weight": 1,
    },
    {
        "id": "CODE-PROC-006",
        "pattern": r"(sdk|client.?library|integration|embed)",
        "description": "SDK/integration for client apps",
        "weight": 1,
    },
]

# ─── Role-Specific Obligations ──────────────────────────────────────────────

CONTROLLER_OBLIGATIONS = {
    "core_articles": ["24", "25", "26", "27", "30(1)", "32", "33", "34", "35", "36"],
    "obligations": [
        {
            "article": "Art. 5(2)",
            "title": "Accountability",
            "description": "Demonstrate compliance with GDPR principles",
        },
        {
            "article": "Art. 6",
            "title": "Lawful basis",
            "description": "Establish and document lawful basis for each processing activity",
        },
        {
            "article": "Art. 12-14",
            "title": "Transparency",
            "description": "Provide privacy notices to data subjects",
        },
        {
            "article": "Art. 15-22",
            "title": "Data subject rights",
            "description": "Facilitate access, rectification, erasure, portability, and objection rights",
        },
        {
            "article": "Art. 24",
            "title": "Responsibility",
            "description": "Implement appropriate technical and organizational measures",
        },
        {
            "article": "Art. 25",
            "title": "Privacy by design/default",
            "description": "Embed data protection into systems and processes from the start",
        },
        {
            "article": "Art. 28",
            "title": "Processor management",
            "description": "Use only processors with sufficient guarantees; have DPAs in place",
        },
        {
            "article": "Art. 30(1)",
            "title": "ROPA",
            "description": "Maintain records of processing activities",
        },
        {
            "article": "Art. 32",
            "title": "Security",
            "description": "Implement appropriate security measures",
        },
        {
            "article": "Art. 33-34",
            "title": "Breach notification",
            "description": "Notify supervisory authority within 72 hours; notify data subjects if high risk",
        },
        {
            "article": "Art. 35",
            "title": "DPIA",
            "description": "Conduct DPIAs for high-risk processing",
        },
        {
            "article": "Art. 37",
            "title": "DPO",
            "description": "Appoint DPO if required (public authority, large-scale monitoring, special categories)",
        },
    ],
}

PROCESSOR_OBLIGATIONS = {
    "core_articles": ["28", "29", "30(2)", "32", "33(2)"],
    "obligations": [
        {
            "article": "Art. 28(3)(a)",
            "title": "Documented instructions",
            "description": "Process only on documented instructions from the controller",
        },
        {
            "article": "Art. 28(3)(b)",
            "title": "Confidentiality",
            "description": "Ensure authorized personnel are under confidentiality obligations",
        },
        {
            "article": "Art. 28(3)(c)",
            "title": "Security measures",
            "description": "Implement appropriate security measures per Article 32",
        },
        {
            "article": "Art. 28(3)(d)",
            "title": "Sub-processor management",
            "description": "Engage sub-processors only with controller authorization",
        },
        {
            "article": "Art. 28(3)(e)",
            "title": "DSR assistance",
            "description": "Assist controller in responding to data subject rights requests",
        },
        {
            "article": "Art. 28(3)(f)",
            "title": "Compliance assistance",
            "description": "Assist controller with security, breach notification, and DPIAs",
        },
        {
            "article": "Art. 28(3)(g)",
            "title": "Data return/deletion",
            "description": "Delete or return all personal data at end of service",
        },
        {
            "article": "Art. 28(3)(h)",
            "title": "Audit support",
            "description": "Make available information to demonstrate compliance; allow audits",
        },
        {
            "article": "Art. 30(2)",
            "title": "ROPA (processor)",
            "description": "Maintain records of processing categories carried out on behalf of controllers",
        },
        {
            "article": "Art. 33(2)",
            "title": "Breach notification",
            "description": "Notify controller without undue delay upon becoming aware of a breach",
        },
    ],
}

# ─── Common Scenarios ───────────────────────────────────────────────────────

COMMON_SCENARIOS = [
    {
        "scenario": "SaaS platform storing customer data",
        "typical_role": "processor",
        "explanation": "If you provide software-as-a-service where clients upload/manage their own data, you typically act as a processor.",
        "exceptions": "You become a controller if you use client data for your own analytics, marketing, or product improvement without explicit contract terms.",
    },
    {
        "scenario": "Cloud infrastructure provider (IaaS/PaaS)",
        "typical_role": "processor",
        "explanation": "Infrastructure providers process data on behalf of their customers who control what data is stored.",
        "exceptions": "You may be a controller for your own operational data (logs, support tickets).",
    },
    {
        "scenario": "API service processing client requests",
        "typical_role": "processor",
        "explanation": "An API that processes data sent by clients acts as processor for that client data.",
        "exceptions": "Controller if you aggregate data across clients for your own purposes.",
    },
    {
        "scenario": "Marketing automation platform",
        "typical_role": "processor",
        "explanation": "When clients use your platform to send campaigns to their contacts, you're a processor.",
        "exceptions": "Joint controller if you also use contact data for your own marketing or targeting.",
    },
    {
        "scenario": "E-commerce website (direct sales)",
        "typical_role": "controller",
        "explanation": "You determine what customer data to collect and how to use it for your sales operations.",
        "exceptions": "N/A - you have a direct relationship with customers.",
    },
    {
        "scenario": "HR/payroll software",
        "typical_role": "processor",
        "explanation": "You process employee data on behalf of employer clients.",
        "exceptions": "Controller for your own employee data.",
    },
    {
        "scenario": "Social media platform",
        "typical_role": "controller",
        "explanation": "You determine purposes (engagement, advertising) and means of processing user data.",
        "exceptions": "May be joint controller with advertisers for certain processing.",
    },
    {
        "scenario": "Payment processor (merchant acquirer)",
        "typical_role": "mixed",
        "explanation": "Processor for transaction processing on behalf of merchants.",
        "exceptions": "Controller for fraud prevention and regulatory compliance activities.",
    },
    {
        "scenario": "Data analytics service",
        "typical_role": "depends",
        "explanation": "Processor if analyzing client's data per their instructions.",
        "exceptions": "Controller if you determine what insights to derive and how to use them.",
    },
    {
        "scenario": "Embedded SDK/widget in client apps",
        "typical_role": "processor",
        "explanation": "Processing data from client's users on behalf of the client.",
        "exceptions": "Joint controller if you also collect data for your own purposes (telemetry).",
    },
]

# ─── Assessment Questions ───────────────────────────────────────────────────

ASSESSMENT_QUESTIONS = [
    {
        "id": "q1_purpose",
        "question": "Who decides WHY the personal data is processed (the business purpose)?",
        "options": [
            {"value": "us", "label": "We decide the purposes", "scores": {"controller": 3}},
            {"value": "client", "label": "Our client/customer decides", "scores": {"processor": 3}},
            {"value": "both", "label": "We decide jointly with another party", "scores": {"joint_controller": 3}},
        ],
    },
    {
        "id": "q2_data_decision",
        "question": "Who decides WHAT personal data to collect or process?",
        "options": [
            {"value": "us", "label": "We determine the data categories", "scores": {"controller": 3}},
            {"value": "client", "label": "Client specifies what data we process", "scores": {"processor": 3}},
            {"value": "both", "label": "Joint decision", "scores": {"joint_controller": 2}},
        ],
    },
    {
        "id": "q3_data_subject_relationship",
        "question": "Who has the direct relationship with data subjects (individuals)?",
        "options": [
            {"value": "us", "label": "We interact directly with users/customers", "scores": {"controller": 2}},
            {"value": "client", "label": "Our client interacts with their users", "scores": {"processor": 2}},
            {"value": "both", "label": "Both parties interact with users", "scores": {"joint_controller": 2}},
        ],
    },
    {
        "id": "q4_consent",
        "question": "Who collects consent from data subjects (if applicable)?",
        "options": [
            {"value": "us", "label": "We collect consent directly", "scores": {"controller": 2}},
            {"value": "client", "label": "Our client obtains consent", "scores": {"processor": 2}},
            {"value": "na", "label": "Consent is not the legal basis", "scores": {}},
        ],
    },
    {
        "id": "q5_own_use",
        "question": "Do you use the personal data for YOUR OWN business purposes?",
        "options": [
            {"value": "yes", "label": "Yes, for analytics, marketing, or product improvement", "scores": {"controller": 3}},
            {"value": "no", "label": "No, only for purposes specified by client", "scores": {"processor": 3}},
            {"value": "limited", "label": "Only for service delivery/troubleshooting", "scores": {"processor": 1}},
        ],
    },
    {
        "id": "q6_instructions",
        "question": "Do you act on documented instructions from another party?",
        "options": [
            {"value": "no", "label": "No, we process data independently", "scores": {"controller": 2}},
            {"value": "yes", "label": "Yes, per client's documented instructions", "scores": {"processor": 3}},
            {"value": "partial", "label": "Partially - some discretion allowed", "scores": {"processor": 1}},
        ],
    },
    {
        "id": "q7_retention",
        "question": "Who determines how long personal data is retained?",
        "options": [
            {"value": "us", "label": "We set retention periods", "scores": {"controller": 2}},
            {"value": "client", "label": "Client/contract determines retention", "scores": {"processor": 2}},
            {"value": "law", "label": "Determined by legal requirements", "scores": {}},
        ],
    },
    {
        "id": "q8_dpa",
        "question": "Do you have a Data Processing Agreement (DPA) with another party for this processing?",
        "options": [
            {"value": "yes_we_sign", "label": "Yes, we sign client DPAs as processor", "scores": {"processor": 2}},
            {"value": "yes_they_sign", "label": "Yes, our vendors sign our DPA", "scores": {"controller": 1}},
            {"value": "no", "label": "No DPA required/in place", "scores": {}},
        ],
    },
]


# ─── Implementation ─────────────────────────────────────────────────────────


def _calculate_text_scores(text: str) -> Tuple[Dict[str, float], Dict[str, List]]:
    """Analyze text for controller/processor indicators and return scores."""
    text_lower = text.lower()
    scores: Dict[str, float] = {"controller": 0.0, "processor": 0.0, "joint_controller": 0.0}
    matched_indicators: Dict[str, List] = {"controller": [], "processor": [], "joint_controller": []}

    # Check controller indicators
    for indicator in CONTROLLER_INDICATORS:
        for kw in indicator["keywords"]:
            if kw in text_lower:
                scores["controller"] += indicator["weight"]
                matched_indicators["controller"].append(indicator)
                break

    # Check processor indicators
    for indicator in PROCESSOR_INDICATORS:
        for kw in indicator["keywords"]:
            if kw in text_lower:
                scores["processor"] += indicator["weight"]
                matched_indicators["processor"].append(indicator)
                break

    # Check joint controller indicators
    for indicator in JOINT_CONTROLLER_INDICATORS:
        for kw in indicator["keywords"]:
            if kw in text_lower:
                scores["joint_controller"] += indicator["weight"]
                matched_indicators["joint_controller"].append(indicator)
                break

    return scores, matched_indicators


def _calculate_code_scores(code: str) -> Tuple[Dict[str, float], Dict[str, List]]:
    """Analyze code for controller/processor patterns and return scores."""
    code_lower = code.lower()
    scores: Dict[str, float] = {"controller": 0.0, "processor": 0.0}
    matched_patterns: Dict[str, List] = {"controller": [], "processor": []}

    # Check controller patterns
    for pattern in CODE_CONTROLLER_PATTERNS:
        if re.search(pattern["pattern"], code_lower, re.IGNORECASE):
            scores["controller"] += pattern["weight"]
            matched_patterns["controller"].append(pattern)

    # Check processor patterns
    for pattern in CODE_PROCESSOR_PATTERNS:
        if re.search(pattern["pattern"], code_lower, re.IGNORECASE):
            scores["processor"] += pattern["weight"]
            matched_patterns["processor"].append(pattern)

    return scores, matched_patterns


def _determine_role(scores: Dict[str, float]) -> str:
    """Determine the likely role based on scores."""
    controller_score = scores.get("controller", 0)
    processor_score = scores.get("processor", 0)
    joint_score = scores.get("joint_controller", 0)

    # Check for joint controller first
    if joint_score > 3:
        return "joint_controller"

    # Check for mixed role
    if controller_score > 5 and processor_score > 5:
        ratio = min(controller_score, processor_score) / max(controller_score, processor_score)
        if ratio > 0.6:
            return "mixed"

    # Determine primary role
    if controller_score > processor_score:
        return "controller"
    elif processor_score > controller_score:
        return "processor"
    else:
        return "undetermined"


async def assess_controller_processor_role_impl(
    service_description: str, data_loader
) -> str:
    """Assess whether a service acts as controller, processor, or both."""
    await data_loader.load_data()

    scores, matched = _calculate_text_scores(service_description)
    role = _determine_role(scores)

    result = "# Controller/Processor Role Assessment\n\n"
    result += "## Service Description Analysis\n\n"

    # Show determined role
    role_display = {
        "controller": "📋 **DATA CONTROLLER**",
        "processor": "⚙️ **DATA PROCESSOR**",
        "joint_controller": "🤝 **JOINT CONTROLLER**",
        "mixed": "🔄 **MIXED ROLE** (Controller for some processing, Processor for other)",
        "undetermined": "❓ **UNDETERMINED** — More information needed",
    }
    result += f"### Likely Role: {role_display.get(role, role)}\n\n"

    # Show score breakdown
    result += "### Score Analysis\n\n"
    result += f"| Role | Score |\n|------|-------|\n"
    result += f"| Controller | {scores['controller']:.1f} |\n"
    result += f"| Processor | {scores['processor']:.1f} |\n"
    result += f"| Joint Controller | {scores['joint_controller']:.1f} |\n\n"

    # Show matched indicators
    if matched["controller"]:
        result += "### Controller Indicators Found\n\n"
        for ind in matched["controller"][:5]:
            result += f"- **{ind['indicator']}**: {ind['description']}\n"
        result += "\n"

    if matched["processor"]:
        result += "### Processor Indicators Found\n\n"
        for ind in matched["processor"][:5]:
            result += f"- **{ind['indicator']}**: {ind['description']}\n"
        result += "\n"

    if matched["joint_controller"]:
        result += "### Joint Controller Indicators Found\n\n"
        for ind in matched["joint_controller"]:
            result += f"- **{ind['indicator']}**: {ind['description']}\n"
        result += "\n"

    # GDPR definitions
    result += "---\n\n## GDPR Definitions\n\n"
    result += "**Controller (Art. 4(7)):** The natural or legal person, public authority, agency or other body "
    result += "which, alone or jointly with others, **determines the purposes and means** of the processing of personal data.\n\n"
    result += "**Processor (Art. 4(8)):** A natural or legal person, public authority, agency or other body "
    result += "which **processes personal data on behalf of the controller**.\n\n"

    # Key question reminder
    result += "---\n\n## Key Determining Questions\n\n"
    result += "1. **WHY** is personal data processed? → Whoever decides the purpose is a controller\n"
    result += "2. **WHAT** data is collected? → Whoever decides is likely a controller\n"
    result += "3. **WHO** has the relationship with data subjects? → Direct relationship suggests controller\n"
    result += "4. **Do you act on instructions** from another party? → Instructions suggest processor\n\n"

    # Recommendations
    result += "---\n\n## Recommendations\n\n"
    if role == "controller":
        result += "As a **controller**, you have primary responsibility for GDPR compliance:\n"
        result += "- Establish and document lawful basis for processing\n"
        result += "- Provide privacy notices to data subjects\n"
        result += "- Implement data subject rights processes\n"
        result += "- Conduct DPIAs for high-risk processing\n"
        result += "- Have DPAs with any processors you use\n"
    elif role == "processor":
        result += "As a **processor**, you must:\n"
        result += "- Process data only on documented controller instructions\n"
        result += "- Have a Data Processing Agreement (Art. 28) with each controller\n"
        result += "- Assist controllers with DSR fulfillment\n"
        result += "- Notify controllers of breaches without undue delay\n"
        result += "- Maintain records of processing activities (Art. 30(2))\n"
    elif role == "mixed":
        result += "With a **mixed role**, you have different obligations for different processing:\n"
        result += "- Clearly document which processing you control vs. process on behalf of others\n"
        result += "- Apply controller obligations where you determine purposes\n"
        result += "- Have DPAs for processing done on behalf of clients\n"
        result += "- Consider separate ROPA entries for controller vs. processor activities\n"

    result += "\n*Use `get_role_obligations` for detailed obligations per role.*\n"

    return append_disclaimer(result)


async def get_role_obligations_impl(
    role: str, include_azure: bool, data_loader
) -> str:
    """Get GDPR obligations specific to a role."""
    await data_loader.load_data()
    role_lower = role.lower().strip().replace(" ", "_")

    result = f"# GDPR Obligations: {role.title().replace('_', ' ')}\n\n"

    if role_lower in ("controller", "data_controller"):
        obligations = CONTROLLER_OBLIGATIONS
        result += "## Controller Obligations\n\n"
        result += "As the party that **determines the purposes and means** of processing, "
        result += "controllers bear primary accountability under GDPR.\n\n"
        result += f"**Key Articles:** {', '.join(obligations['core_articles'])}\n\n"

    elif role_lower in ("processor", "data_processor"):
        obligations = PROCESSOR_OBLIGATIONS
        result += "## Processor Obligations\n\n"
        result += "As the party that **processes personal data on behalf of the controller**, "
        result += "processors have specific contractual and regulatory obligations.\n\n"
        result += f"**Key Articles:** {', '.join(obligations['core_articles'])}\n\n"

    elif role_lower in ("joint_controller", "joint"):
        result += "## Joint Controller Obligations (Art. 26)\n\n"
        result += "When two or more controllers **jointly determine purposes and means**, they must:\n\n"
        result += "1. **Transparent arrangement** — Document respective responsibilities\n"
        result += "2. **Essence available to data subjects** — Data subjects can contact any joint controller\n"
        result += "3. **Designate contact point** — Optional single point of contact for data subjects\n"
        result += "4. **Each controller independently liable** — Data subjects can exercise rights against any party\n\n"
        result += "Each joint controller must also meet their individual controller obligations.\n\n"
        obligations = CONTROLLER_OBLIGATIONS

    elif role_lower in ("sub_processor", "sub-processor", "subprocessor"):
        result += "## Sub-Processor Obligations\n\n"
        result += "A sub-processor engaged by a processor must:\n\n"
        result += "1. **Same obligations** — Bound by same data protection obligations as the main processor\n"
        result += "2. **Authorization** — Engaged only with controller's prior authorization\n"
        result += "3. **Contract** — Have contract with processor imposing same obligations\n"
        result += "4. **Liability** — Initial processor remains liable for sub-processor's performance\n\n"
        obligations = PROCESSOR_OBLIGATIONS

    else:
        return append_disclaimer(
            f"Unknown role: '{role}'. Supported roles: controller, processor, joint_controller, sub_processor"
        )

    # List obligations
    result += "### Detailed Obligations\n\n"
    result += "| Article | Requirement | Description |\n"
    result += "|---------|-------------|-------------|\n"
    for obl in obligations["obligations"]:
        result += f"| {obl['article']} | {obl['title']} | {obl['description']} |\n"

    # Azure implementation guidance
    if include_azure:
        result += "\n---\n\n## Azure Implementation Guidance\n\n"

        if role_lower in ("controller", "data_controller", "joint_controller", "joint"):
            result += """### For Controllers on Azure

**Accountability & Documentation**
- Use **Microsoft Purview Compliance Manager** for compliance tracking
- Maintain ROPA in **SharePoint** with versioning enabled
- Use **Azure Policy** to enforce data protection standards

**Data Subject Rights**
- Implement DSR workflows using **Azure Logic Apps**
- Use **Microsoft Purview Data Map** to locate personal data
- Enable **Azure Cognitive Search** for data discovery

**Security (Art. 32)**
- Enable **Microsoft Defender for Cloud** for threat protection
- Use **Azure Key Vault** for encryption key management
- Implement **Azure DDoS Protection** and **WAF**

**Breach Notification**
- Configure **Azure Monitor** alerts for security incidents
- Use **Microsoft Sentinel** for SIEM and breach detection
- Document incident response in **Azure DevOps** or ServiceNow

**DPIA Support**
- Use **Azure compliance documentation** for risk assessments
- Leverage **Microsoft Purview** for data classification
"""
        else:
            result += """### For Processors on Azure

**Documented Instructions**
- Store processing instructions in **Azure DevOps** or **Confluence**
- Use **Azure Policy** to enforce client-specific configurations
- Tag resources with `data-controller`, `dpa-reference`, `processing-purpose`

**Multi-Tenant Isolation**
- Use **Azure Resource Groups** per client for logical isolation
- Implement **Azure Virtual Networks** with client-specific subnets
- Use **Azure AD B2B** for client admin access

**DSR Assistance**
- Expose DSR APIs for controller integration
- Use **Azure API Management** to manage controller access
- Implement data export in portable formats (JSON/CSV)

**Breach Notification to Controllers**
- Use **Azure Event Grid** to notify controllers of incidents
- Configure **Azure Service Health** alerts
- Implement webhook notifications for security events

**Audit Support (Art. 28(3)(h))**
- Enable **Azure Activity Logs** and **Diagnostic Settings**
- Use **Azure Monitor Workbooks** for compliance reporting
- Generate audit reports via **Microsoft Defender for Cloud**
"""

    return append_disclaimer(result)


async def analyze_code_for_role_indicators_impl(
    code: str, language: str, data_loader
) -> str:
    """Analyze source code for controller vs processor role indicators."""
    await data_loader.load_data()

    scores, matched = _calculate_code_scores(code)
    text_scores, text_matched = _calculate_text_scores(code)

    # Combine scores
    combined_scores = {
        "controller": scores["controller"] + text_scores["controller"] * 0.5,
        "processor": scores["processor"] + text_scores["processor"] * 0.5,
        "joint_controller": text_scores.get("joint_controller", 0),
    }
    role = _determine_role(combined_scores)

    result = f"# Code Analysis: Role Indicators ({language})\n\n"

    # Overall assessment
    role_display = {
        "controller": "📋 **Controller patterns detected**",
        "processor": "⚙️ **Processor patterns detected**",
        "mixed": "🔄 **Mixed role patterns detected**",
        "undetermined": "❓ **Insufficient indicators**",
    }
    result += f"## Assessment: {role_display.get(role, role)}\n\n"

    # Score breakdown
    result += "### Pattern Scores\n\n"
    result += f"| Role | Code Patterns | Text Keywords | Combined |\n"
    result += f"|------|---------------|---------------|----------|\n"
    result += f"| Controller | {scores['controller']:.1f} | {text_scores['controller']:.1f} | {combined_scores['controller']:.1f} |\n"
    result += f"| Processor | {scores['processor']:.1f} | {text_scores['processor']:.1f} | {combined_scores['processor']:.1f} |\n\n"

    # Detected patterns
    if matched["controller"]:
        result += "### Controller Code Patterns Detected\n\n"
        for pat in matched["controller"]:
            result += f"- **{pat['id']}**: {pat['description']} (weight: {pat['weight']})\n"
        result += "\n"

    if matched["processor"]:
        result += "### Processor Code Patterns Detected\n\n"
        for pat in matched["processor"]:
            result += f"- **{pat['id']}**: {pat['description']} (weight: {pat['weight']})\n"
        result += "\n"

    # Interpretation guidance
    result += "---\n\n## Interpretation Guide\n\n"
    result += "### Controller Patterns Indicate:\n"
    result += "- Direct user registration/authentication\n"
    result += "- Consent collection UI or APIs\n"
    result += "- Analytics/tracking for your own purposes\n"
    result += "- Marketing/newsletter functionality\n"
    result += "- User preference/profile management\n\n"

    result += "### Processor Patterns Indicate:\n"
    result += "- Multi-tenant architecture with client isolation\n"
    result += "- Webhook/callback receivers for client data\n"
    result += "- Client authentication mechanisms\n"
    result += "- Data forwarding/relay logic\n"
    result += "- SDK/embedding for client applications\n\n"

    # Recommendations
    result += "---\n\n## Recommendations\n\n"
    if role == "controller":
        result += "Your code shows **controller characteristics**. Ensure you:\n"
        result += "- Have lawful basis for each processing activity\n"
        result += "- Provide clear privacy notices at data collection points\n"
        result += "- Implement consent management if relying on consent\n"
        result += "- Build DSR fulfillment capabilities\n"
    elif role == "processor":
        result += "Your code shows **processor characteristics**. Ensure you:\n"
        result += "- Process data only per controller instructions\n"
        result += "- Maintain strict tenant data isolation\n"
        result += "- Provide data export APIs for controller DSR fulfillment\n"
        result += "- Have breach notification mechanisms to alert controllers\n"
    elif role == "mixed":
        result += "Your code shows **mixed role characteristics**. Consider:\n"
        result += "- Documenting clearly which processing is controller vs. processor\n"
        result += "- Segregating controller and processor functionality if possible\n"
        result += "- Having appropriate contracts for each relationship type\n"

    result += "\n*Note: Code analysis provides indicators only. Final role determination requires "
    result += "understanding business context and contractual relationships.*\n"

    return append_disclaimer(result)


async def generate_dpa_checklist_impl(context: str, data_loader) -> str:
    """Generate an Article 28 Data Processing Agreement checklist."""
    await data_loader.load_data()

    result = """# Data Processing Agreement (DPA) Checklist
## Per GDPR Article 28

**Context:** {context}

---

## Mandatory DPA Clauses (Art. 28(3))

A contract between controller and processor **MUST** include:

### ☐ Subject Matter, Duration, Nature, Purpose

| Item | Requirement | Status |
|------|-------------|--------|
| Subject matter | Describe what data processing is covered | ☐ |
| Duration | Specify contract/processing duration | ☐ |
| Nature of processing | Describe operations performed (storage, analysis, etc.) | ☐ |
| Purpose | State the specific purpose(s) of processing | ☐ |
| Type of personal data | List categories of data processed | ☐ |
| Categories of data subjects | Specify whose data is processed | ☐ |

### ☐ Processor Obligations

| Art. 28(3) | Obligation | Status |
|------------|------------|--------|
| (a) | Process only on **documented instructions** from controller | ☐ |
| (a) | Inform controller if an instruction infringes GDPR | ☐ |
| (b) | Ensure authorized personnel are under **confidentiality** | ☐ |
| (c) | Implement **security measures** per Article 32 | ☐ |
| (d) | Engage **sub-processors** only with controller authorization | ☐ |
| (d) | Impose same data protection obligations on sub-processors | ☐ |
| (e) | **Assist controller** with DSR fulfillment | ☐ |
| (f) | Assist with **security, breach notification, DPIAs** | ☐ |
| (g) | **Delete or return** all personal data at end of services | ☐ |
| (h) | Make available information to **demonstrate compliance** | ☐ |
| (h) | Allow and contribute to **audits/inspections** | ☐ |

### ☐ Sub-Processor Management

| Requirement | Status |
|-------------|--------|
| **Prior authorization** for engaging sub-processors | ☐ |
| Option: General written authorization with notification of changes | ☐ |
| Option: Specific authorization for each sub-processor | ☐ |
| **Right to object** to new/replacement sub-processors | ☐ |
| Sub-processor contract with **same obligations** | ☐ |
| **List of current sub-processors** provided to controller | ☐ |

### ☐ International Transfers

| Requirement | Status |
|-------------|--------|
| Transfer mechanism if processing outside EEA | ☐ |
| SCCs (Standard Contractual Clauses) if applicable | ☐ |
| Supplementary measures (encryption, etc.) if required | ☐ |

---

## Recommended Additional Clauses

### ☐ Breach Notification Details
- Notification timeframe (e.g., "without undue delay", "within 24 hours")
- Information to be provided in breach notification
- Cooperation requirements during incident response

### ☐ Audit Rights Specifics
- Frequency of audits permitted
- Notice period required
- Cost allocation for audits
- Use of third-party auditors / certifications

### ☐ Data Return/Deletion
- Format for data return (CSV, JSON, database export)
- Timeframe for deletion after contract end
- Certification of deletion

### ☐ Liability and Indemnification
- Liability caps (if permitted)
- Indemnification for GDPR violations
- Insurance requirements

---

## Azure-Specific Considerations

When using Azure services, review:

- **Microsoft Online Services DPA**: [https://aka.ms/DPA](https://aka.ms/DPA)
- **Data Processing Addendum** included in Enterprise Agreements
- **Azure compliance certifications**: ISO 27001, SOC 2, etc.
- **Data residency commitments**: EU Data Boundary

For your own DPA with clients:
- Reference Azure's security measures in your DPA
- List Azure as approved sub-processor
- Include Azure certifications as evidence of Art. 32 compliance

---

## DPA Validation Checklist

Before signing, verify:

☐ All Art. 28(3) mandatory clauses are present
☐ Subject matter and data types are accurately described
☐ Sub-processor list is complete and current
☐ Transfer mechanisms are appropriate for data locations
☐ Audit rights are practical and enforceable
☐ Data return/deletion procedures are clear
☐ Breach notification timelines are reasonable

""".format(context=context)

    return append_disclaimer(result)


async def get_role_scenarios_impl(scenario_type: str, data_loader) -> str:
    """Get common controller/processor scenarios and role determinations."""
    await data_loader.load_data()

    result = "# Controller/Processor Role Scenarios\n\n"
    result += "Common scenarios and typical role determinations based on EDPB guidance.\n\n"

    # Filter scenarios if type specified
    scenarios = COMMON_SCENARIOS
    if scenario_type and scenario_type.lower() != "all":
        kw = scenario_type.lower()
        scenarios = [s for s in scenarios if kw in s["scenario"].lower() or kw in s["explanation"].lower()]

    if not scenarios:
        result += f"No scenarios match '{scenario_type}'. Showing all scenarios.\n\n"
        scenarios = COMMON_SCENARIOS

    result += "| Scenario | Typical Role | Explanation | Exceptions |\n"
    result += "|----------|--------------|-------------|------------|\n"
    for s in scenarios:
        result += f"| {s['scenario']} | **{s['typical_role'].upper()}** | {s['explanation']} | {s['exceptions']} |\n"

    result += "\n---\n\n## Key Principles for Role Determination\n\n"
    result += "1. **Focus on 'determines purposes and means'** — The entity that decides WHY and HOW is the controller\n"
    result += "2. **'On behalf of' indicates processor** — Processing for another's purposes, not your own\n"
    result += "3. **One entity can have both roles** — Controller for some processing, processor for other\n"
    result += "4. **Substance over form** — Actual practice matters more than contract labels\n"
    result += "5. **Special attention to 'mixed' scenarios** — SaaS, analytics, platforms often have dual roles\n\n"

    result += "---\n\n## Warning Signs of Misclassification\n\n"
    result += "### Processor claiming to be Controller:\n"
    result += "- Has no direct relationship with data subjects\n"
    result += "- Acts entirely on client instructions\n"
    result += "- Cannot determine retention or use independently\n\n"

    result += "### Controller claiming to be Processor:\n"
    result += "- Uses data for own analytics/marketing\n"
    result += "- Determines what data to collect\n"
    result += "- Makes independent decisions about processing\n"
    result += "- Has terms of service (not just DPA) with data subjects\n"

    return append_disclaimer(result)
