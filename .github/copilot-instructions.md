# **Purpose**

These instructions guide GitHub Copilot (and similar AI tools) when contributing to the **GDPRShiftLeftMCP** open‑source project.  
This project provides a GDPR‑aware “shift‑left” compliance automation MCP server.  
Copilot must always prioritize **correctness, accuracy, automated test coverage, functional validation, security, and data protection** over speed.

***

## **1. Project Priorities**

### **1.1 Correctness & Accuracy**

*   All generated code must be correct, deterministic, and align with GDPR requirements.
*   No speculative interpretations of GDPR are allowed.
*   Ambiguous requirements must trigger a request for clarification.

### **1.2 Security by Default**

*   Follow industry best practices including least privilege, secure defaults, and input validation.
*   Never emit code that logs or stores personal data.
*   Ensure GDPR principles (minimization, confidentiality, purpose limitation, etc.) are respected.

### **1.3 Comprehensive Automated Testing**

*   Every new feature must include automated unit, integration, or behavior‑driven tests.
*   All code-paths, including edge cases and failure scenarios, must be tested.
*   Tests must run deterministically across environments.
*   Copilot must suggest test cases when writing or modifying code.

***

## **2. Code Quality Standards**

### **2.1 Clarity & Maintainability**

*   Prefer clear and explicit solutions over clever optimizations.
*   Document all core modules and public interfaces with docstrings and explanations.

### **2.2 Dependency Management**

*   Prefer stable, audited, actively maintained libraries.
*   Avoid unnecessary or experimental dependencies.

***

## **3. GDPR‑Specific Requirements**

### **3.1 No Personal Data in Examples**

Use placeholders only.

### **3.2 No Logging of Personal or Sensitive Data**

All logging must follow GDPR privacy‑by‑design principles.

### **3.3 Faithful Implementation of GDPR Concepts**

GDPR logic (DSRs, DPIAs, Article 30 ROPA, etc.) must be implemented precisely based on documented requirements.

***

## **4. Repository Workflow Requirements**

### **4.1 Branching Policy (Git Flow)**

Copilot must enforce that all work is done on branches:

*   `feature/<name>` for new features
*   `bugfix/<name>` for fixes
*   `release/<version>` for release staging
*   `hotfix/<name>` for production fixes

Direct commits to `main` are prohibited.

### **4.2 Pull Request Requirements**

Every PR must:

*   Be created from a branch following Git Flow.
*   Include a clear description of changes.
*   Update or add tests.
*   Pass all automated tests.
*   Undergo review before merging.

### **4.3 Continuous Integration Requirements**

CI must:

*   Run all automated tests.
*   Run linting and security scanning.
*   Reject PRs with any failing tests or regressions.

***

## **5. MCP Server Requirements**

### **5.1 API Predictability**

*   Maintain versioned schemas.
*   Avoid breaking changes unless explicitly documented.

### **5.2 Deterministic & Safe Processing**

*   No nondeterministic ordering unless specifically required.
*   Errors must be structured and safe to expose but never include sensitive data.

### **5.3 Observability**

*   Diagnostics and health checks must exclude personal data.

***

## **6. Judge-Based Functional Evaluation (New Requirement)**

To ensure consistent and reliable MCP server behavior, **judges must be implemented and run automatically on every pull request**.

### **6.1 Judge Requirements**

*   Judges must evaluate MCP functionality **end‑to‑end**, covering:
    *   Tool registration
    *   Tool invocation
    *   Error and edge-case handling
    *   Compliance logic correctness
    *   Expected vs. actual output consistency
*   Judges must be deterministic and reproducible.

### **6.2 Judge Execution Within CI**

*   Judges must run automatically during PR validation.
*   A PR **cannot be merged** unless:
    *   All judges pass
    *   All automated tests pass
    *   No regressions or warnings occur

### **6.3 Copilot’s Behavior Related to Judges**

Copilot must:

*   Generate or update judges when new MCP tools or workflows are added.
*   Ensure judges cover changes introduced by every PR.
*   Automatically suggest judge updates when modifying existing MCP functionality.
*   Never generate code that bypasses or disables judges.

### **6.4 Judge Coverage Expectations**

Judges must validate:

*   Core MCP server endpoints
*   Schema validation
*   GDPR‑specific compliance logic
*   Error handling under malformed or adversarial inputs
*   Input/output behavior for each tool
*   Backward compatibility when relevant

***

## **7. Additional Copilot Behaviors**

Copilot must:

*   Recommend tests and judges before writing complex code.
*   Suggest security hardening where appropriate.
*   Reject unsafe or ambiguous patterns.
*   Avoid generating any content that violates GDPR compliance expectations.

***

# **End of copilot-instructions.md**

***
