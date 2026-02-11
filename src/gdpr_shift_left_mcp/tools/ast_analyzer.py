"""
GDPR Shift-Left MCP Server — AST-Based Code Analyzer

Provides deep code analysis using Abstract Syntax Trees (AST) for:
- Python: Built-in `ast` module
- JavaScript/TypeScript: Token-based analysis with comment/string filtering

AST analysis improves accuracy over regex by:
- Filtering out comments and string literals (reducing false positives)
- Tracking variable assignments and data flow
- Identifying function definitions and call sites
- Verifying semantic intent of GDPR-related code
"""
import ast
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..disclaimer import append_disclaimer

logger = logging.getLogger(__name__)


# ─── Risk Patterns Data Loading ─────────────────────────────────────────────

def _load_risk_patterns() -> Dict[str, Any]:
    """Load risk patterns from the centralized JSON data file."""
    data_file = Path(__file__).parent.parent / "data" / "risk_patterns.json"
    try:
        with open(data_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Risk patterns file not found: {data_file}")
        return {"pii_indicators": {}, "cross_border_providers": {}}
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse risk patterns JSON: {e}")
        return {"pii_indicators": {}, "cross_border_providers": {}}


def _build_language_risk_lookup(
    providers: Dict[str, Any], language: str
) -> Dict[str, Tuple[str, str, str, str]]:
    """Build a risk lookup dictionary for a specific language.
    
    When multiple providers use the same package name (e.g., 'openai' is used
    by OpenAI, DeepSeek, Perplexity via their OpenAI-compatible APIs), the
    first provider in the data file wins.
    
    Returns:
        Dict mapping package name to (provider_name, headquarters, risk_level, justification)
    """
    lookup = {}
    for _provider_key, provider_data in providers.items():
        name = provider_data.get("name", "Unknown")
        hq = provider_data.get("headquarters", "Unknown")
        risk = provider_data.get("risk_level", "MEDIUM")
        justification = provider_data.get("risk_justification", "")
        packages = provider_data.get("packages", {}).get(language, [])
        for pkg in packages:
            if pkg and pkg not in lookup:  # Skip empty strings and don't overwrite
                lookup[pkg] = (name, hq, risk, justification)
    return lookup


# Load risk patterns data at module initialization
_RISK_PATTERNS = _load_risk_patterns()

# Build PII indicators from loaded data
PII_INDICATORS = _RISK_PATTERNS.get("pii_indicators", {})

# Pre-build language-specific cross-border risk lookups
_PROVIDERS = _RISK_PATTERNS.get("cross_border_providers", {})
PYTHON_CROSS_BORDER = _build_language_risk_lookup(_PROVIDERS, "python")
JAVASCRIPT_CROSS_BORDER = _build_language_risk_lookup(_PROVIDERS, "javascript")
JAVA_CROSS_BORDER = _build_language_risk_lookup(_PROVIDERS, "java")
CSHARP_CROSS_BORDER = _build_language_risk_lookup(_PROVIDERS, "csharp")
GO_CROSS_BORDER = _build_language_risk_lookup(_PROVIDERS, "go")

# Legacy alias for backward compatibility
CROSS_BORDER_IMPORTS = PYTHON_CROSS_BORDER


# ─── Data Classes ───────────────────────────────────────────────────────────


@dataclass
class ASTFinding:
    """Represents a finding from AST analysis."""
    id: str
    category: str
    severity: str
    article: str
    title: str
    description: str
    location: Optional[Dict[str, Any]] = None
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    recommendation: str = ""


@dataclass
class DataFlowNode:
    """Represents a node in data flow analysis."""
    name: str
    node_type: str  # variable, function, parameter, return
    line: int
    col: int
    sources: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    is_pii: bool = False
    is_encrypted: bool = False


@dataclass
class FunctionInfo:
    """Information about a function definition."""
    name: str
    line: int
    parameters: List[str]
    decorators: List[str]
    calls: List[str]
    returns_data: bool
    docstring: Optional[str]


# Flatten PII indicators for quick lookup
ALL_PII_TERMS: Set[str] = set()
for category in PII_INDICATORS.values():
    ALL_PII_TERMS.update(category)


# ─── DSR Function Patterns ──────────────────────────────────────────────────

DSR_FUNCTION_PATTERNS = {
    "access": {
        "article": "Art. 15",
        "patterns": [
            r"^(get|fetch|retrieve|export|download)_?(user|personal|my|subject)_?(data|info|profile)?$",
            r"^(subject_access|sar|dsr)_?(request|handler)?$",
            r"^export_personal_data$",
            r"^handle_access_request$",
        ],
        "required_operations": ["read", "return", "serialize"],
    },
    "erasure": {
        "article": "Art. 17",
        "patterns": [
            r"^(delete|erase|remove|purge)_?(user|personal|account|subject)_?(data)?$",
            r"^right_to_forget$",
            r"^handle_erasure_request$",
            r"^anonymize_user$",
        ],
        "required_operations": ["delete", "remove", "anonymize"],
    },
    "rectification": {
        "article": "Art. 16",
        "patterns": [
            r"^(update|correct|rectify|modify|edit)_?(user|personal|profile)_?(data|info)?$",
            r"^handle_rectification_request$",
        ],
        "required_operations": ["update", "save", "modify"],
    },
    "portability": {
        "article": "Art. 20",
        "patterns": [
            r"^(export|download)_?(data)?_?(json|xml|csv|portable)?$",
            r"^get_portable_data$",
            r"^handle_portability_request$",
        ],
        "required_operations": ["serialize", "json", "export"],
    },
    "restriction": {
        "article": "Art. 18",
        "patterns": [
            r"^(restrict|pause|suspend|freeze)_?(processing|account|user)?$",
            r"^handle_restriction_request$",
        ],
        "required_operations": ["flag", "suspend", "disable"],
    },
    "objection": {
        "article": "Art. 21",
        "patterns": [
            r"^(opt_out|unsubscribe|object|withdraw)_?(consent|marketing|processing)?$",
            r"^handle_objection_request$",
            r"^update_preferences$",
        ],
        "required_operations": ["update", "disable", "remove"],
    },
}


# ─── Python AST Analyzer ────────────────────────────────────────────────────


class PythonASTAnalyzer(ast.NodeVisitor):
    """Analyzes Python code using the AST module."""

    def __init__(self, code: str):
        self.code = code
        self.tree: Optional[ast.AST] = None
        self.functions: Dict[str, FunctionInfo] = {}
        self.imports: List[Dict[str, Any]] = []
        self.variables: Dict[str, DataFlowNode] = {}
        self.pii_variables: Set[str] = set()
        self.findings: List[ASTFinding] = []
        self.current_function: Optional[str] = None
        self.call_graph: Dict[str, List[str]] = {}
        self.data_flows: List[Dict[str, Any]] = []

    def parse(self) -> bool:
        """Parse the Python code into an AST."""
        try:
            self.tree = ast.parse(self.code)
            return True
        except SyntaxError as e:
            self.findings.append(ASTFinding(
                id="AST-PARSE-001",
                category="syntax",
                severity="ERROR",
                article="N/A",
                title="Syntax Error",
                description=f"Failed to parse Python code: {e}",
                location={"line": e.lineno, "col": e.offset},
                confidence="HIGH",
            ))
            return False

    def analyze(self) -> Dict[str, Any]:
        """Run full AST analysis."""
        if not self.tree:
            if not self.parse():
                return self._build_result()

        # At this point self.tree is guaranteed to be non-None
        assert self.tree is not None
        self.visit(self.tree)
        self._analyze_data_flows()
        self._check_dsr_implementations()
        self._check_cross_border_transfers()
        self._check_pii_handling()

        return self._build_result()

    def visit_Import(self, node: ast.Import) -> None:
        """Track import statements."""
        for alias in node.names:
            module_name = alias.name
            self.imports.append({
                "module": module_name,
                "alias": alias.asname,
                "line": node.lineno,
                "type": "import",
            })
            self._check_import_risk(module_name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from...import statements."""
        module_name = node.module or ""
        for alias in node.names:
            self.imports.append({
                "module": module_name,
                "name": alias.name,
                "alias": alias.asname,
                "line": node.lineno,
                "type": "from_import",
            })
        self._check_import_risk(module_name, node.lineno)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze function definitions."""
        decorators = [self._get_decorator_name(d) for d in node.decorator_list]
        params = [arg.arg for arg in node.args.args]

        # Get docstring
        docstring = ast.get_docstring(node)

        # Track calls within function
        call_finder = CallFinder()
        call_finder.visit(node)

        self.functions[node.name] = FunctionInfo(
            name=node.name,
            line=node.lineno,
            parameters=params,
            decorators=decorators,
            calls=call_finder.calls,
            returns_data=self._function_returns_data(node),
            docstring=docstring,
        )

        # Track PII in parameters
        for param in params:
            if self._is_pii_name(param):
                self.pii_variables.add(param)
                self.findings.append(ASTFinding(
                    id="AST-PII-001",
                    category="pii_handling",
                    severity="MEDIUM",
                    article="Art. 5, 25",
                    title="PII in function parameter",
                    description=f"Function '{node.name}' has parameter '{param}' that may contain PII",
                    location={"line": node.lineno, "function": node.name},
                    confidence="MEDIUM",
                    recommendation="Ensure PII is minimized and processed only as necessary",
                ))

        # Visit function body
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Analyze async function definitions (same as sync)."""
        # Convert to FunctionDef-like handling
        decorators = [self._get_decorator_name(d) for d in node.decorator_list]
        params = [arg.arg for arg in node.args.args]
        docstring = ast.get_docstring(node)

        call_finder = CallFinder()
        call_finder.visit(node)

        self.functions[node.name] = FunctionInfo(
            name=node.name,
            line=node.lineno,
            parameters=params,
            decorators=decorators,
            calls=call_finder.calls,
            returns_data=self._function_returns_data(node),
            docstring=docstring,
        )

        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                is_pii = self._is_pii_name(var_name) or self._value_contains_pii(node.value)

                self.variables[var_name] = DataFlowNode(
                    name=var_name,
                    node_type="variable",
                    line=node.lineno,
                    col=target.col_offset,
                    is_pii=is_pii,
                )

                if is_pii:
                    self.pii_variables.add(var_name)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for data flow and logging."""
        func_name = self._get_call_name(node)

        # Check for logging PII
        if func_name in ("print", "logging.info", "logging.debug", "logging.warning",
                         "logging.error", "logger.info", "logger.debug", "logger.warning",
                         "logger.error", "log", "console.log"):
            self._check_logging_pii(node, func_name)

        # Track data flow through function calls
        if self.current_function:
            if self.current_function not in self.call_graph:
                self.call_graph[self.current_function] = []
            self.call_graph[self.current_function].append(func_name)

        self.generic_visit(node)

    def _check_import_risk(self, module_name: str, line: int) -> None:
        """Check if import is a cross-border transfer risk."""
        if not module_name:
            return

        # Check full module name and progressively shorter prefixes
        # e.g., for "google.cloud.storage" check: "google.cloud.storage", "google.cloud", "google"
        parts = module_name.split(".")
        for i in range(len(parts), 0, -1):
            module_check = ".".join(parts[:i])
            if module_check in CROSS_BORDER_IMPORTS:
                provider, region, risk, justification = CROSS_BORDER_IMPORTS[module_check]
                desc = f"Import of '{module_name}' may transfer data to {region}"
                if justification:
                    desc += f". Risk rationale: {justification}"
                self.findings.append(ASTFinding(
                    id="AST-XBORDER-001",
                    category="cross_border",
                    severity=risk,
                    article="Art. 44-49",
                    title=f"Cross-border transfer risk: {provider}",
                    description=desc,
                    location={"line": line, "module": module_name},
                    confidence="HIGH",
                    recommendation="Ensure adequate safeguards (SCCs, adequacy decision) are in place",
                ))
                return  # Found a match, don't continue checking

    def _check_logging_pii(self, node: ast.Call, func_name: str) -> None:
        """Check if logging statements contain PII."""
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.pii_variables:
                self.findings.append(ASTFinding(
                    id="AST-LOG-001",
                    category="pii_logging",
                    severity="HIGH",
                    article="Art. 5(1)(f), Art. 32",
                    title="PII logged directly",
                    description=f"Variable '{arg.id}' containing PII passed to {func_name}",
                    location={"line": node.lineno, "function": self.current_function},
                    confidence="HIGH",
                    recommendation="Mask or exclude PII from logs",
                ))
            elif isinstance(arg, ast.JoinedStr):  # f-string
                for value in arg.values:
                    if isinstance(value, ast.FormattedValue):
                        if isinstance(value.value, ast.Name) and value.value.id in self.pii_variables:
                            self.findings.append(ASTFinding(
                                id="AST-LOG-002",
                                category="pii_logging",
                                severity="HIGH",
                                article="Art. 5(1)(f), Art. 32",
                                title="PII in f-string log",
                                description=f"PII variable '{value.value.id}' interpolated in log statement",
                                location={"line": node.lineno, "function": self.current_function},
                                confidence="HIGH",
                                recommendation="Mask PII before logging",
                            ))

    def _check_dsr_implementations(self) -> None:
        """Check for DSR function implementations."""
        for func_name, func_info in self.functions.items():
            for dsr_type, config in DSR_FUNCTION_PATTERNS.items():
                for pattern in config["patterns"]:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        # Verify function has required operations
                        has_operations = any(
                            op in " ".join(func_info.calls).lower()
                            for op in config["required_operations"]
                        )

                        self.findings.append(ASTFinding(
                            id=f"AST-DSR-{dsr_type.upper()}",
                            category="dsr_capability",
                            severity="INFO",
                            article=config["article"],
                            title=f"DSR capability detected: {dsr_type}",
                            description=f"Function '{func_name}' implements {dsr_type} capability",
                            location={"line": func_info.line, "function": func_name},
                            confidence="HIGH" if has_operations else "MEDIUM",
                            recommendation="Ensure complete implementation per GDPR requirements",
                        ))
                        break

    def _check_cross_border_transfers(self) -> None:
        """Analyze cross-border data transfers."""
        # Already handled in visit_Import, add call-based detection
        for func_name, func_info in self.functions.items():
            for call in func_info.calls:
                call_lower = call.lower()
                if any(api in call_lower for api in ["openai", "anthropic", "aws", "gcp", "azure"]):
                    # Check if PII flows to this call
                    pii_in_scope = any(
                        param in self.pii_variables
                        for param in func_info.parameters
                    )
                    if pii_in_scope:
                        self.findings.append(ASTFinding(
                            id="AST-XBORDER-002",
                            category="cross_border",
                            severity="HIGH",
                            article="Art. 44-49",
                            title="PII may flow to external API",
                            description=f"Function '{func_name}' may send PII to external service via '{call}'",
                            location={"line": func_info.line, "function": func_name},
                            confidence="MEDIUM",
                            recommendation="Verify data processing agreement and transfer safeguards",
                        ))

    def _check_pii_handling(self) -> None:
        """Check for proper PII handling patterns."""
        # Check for encryption before storage/transmission
        for var_name in self.pii_variables:
            if var_name in self.variables:
                var_info = self.variables[var_name]
                # Check if variable is used in any function that stores/transmits
                for func_name, func_info in self.functions.items():
                    if var_name in func_info.parameters:
                        dangerous_calls = [c for c in func_info.calls if any(
                            op in c.lower() for op in ["save", "store", "write", "send", "post", "put"]
                        )]
                        encrypt_calls = [c for c in func_info.calls if any(
                            op in c.lower() for op in ["encrypt", "hash", "mask", "anonymize"]
                        )]
                        if dangerous_calls and not encrypt_calls:
                            self.findings.append(ASTFinding(
                                id="AST-PII-002",
                                category="pii_handling",
                                severity="HIGH",
                                article="Art. 32",
                                title="PII stored/transmitted without encryption",
                                description=f"PII variable '{var_name}' in '{func_name}' may be stored/sent without encryption",
                                location={"line": func_info.line, "function": func_name},
                                confidence="MEDIUM",
                                recommendation="Encrypt PII before storage or transmission",
                            ))

    def _analyze_data_flows(self) -> None:
        """Analyze data flow paths for PII."""
        for var_name in self.pii_variables:
            flow = {
                "variable": var_name,
                "sources": [],
                "transformations": [],
                "sinks": [],
            }

            # Find where variable is used
            for func_name, func_info in self.functions.items():
                if var_name in func_info.parameters:
                    flow["sources"].append({"type": "parameter", "function": func_name})
                if any(var_name in call for call in func_info.calls):
                    flow["sinks"].append({"type": "call", "function": func_name})

            if flow["sources"] or flow["sinks"]:
                self.data_flows.append(flow)

    def _is_pii_name(self, name: str) -> bool:
        """Check if a name suggests PII content."""
        name_lower = name.lower().replace("_", "")
        return any(term.replace("_", "") in name_lower for term in ALL_PII_TERMS)

    def _value_contains_pii(self, node: ast.AST) -> bool:
        """Check if an AST value node references PII."""
        if isinstance(node, ast.Name):
            return node.id in self.pii_variables
        elif isinstance(node, ast.Call):
            return any(self._value_contains_pii(arg) for arg in node.args)
        elif isinstance(node, ast.Dict):
            return any(self._value_contains_pii(v) for v in node.values if v)
        return False

    def _function_returns_data(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> bool:
        """Check if function returns data (has return with value)."""
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value is not None:
                return True
        return False

    def _get_decorator_name(self, node: ast.AST) -> str:
        """Get decorator name as string."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_decorator_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return self._get_decorator_name(node.func)
        return ""

    def _get_call_name(self, node: ast.Call) -> str:
        """Get function call name as string."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        return ""

    def _build_result(self) -> Dict[str, Any]:
        """Build the analysis result."""
        return {
            "language": "python",
            "parse_success": self.tree is not None,
            "functions_analyzed": len(self.functions),
            "imports_found": len(self.imports),
            "pii_variables_detected": len(self.pii_variables),
            "data_flows": self.data_flows,
            "findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "severity": f.severity,
                    "article": f.article,
                    "title": f.title,
                    "description": f.description,
                    "location": f.location,
                    "confidence": f.confidence,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "functions": {
                name: {
                    "line": info.line,
                    "parameters": info.parameters,
                    "decorators": info.decorators,
                    "calls": info.calls,
                    "returns_data": info.returns_data,
                }
                for name, info in self.functions.items()
            },
            "imports": self.imports,
            "call_graph": self.call_graph,
        }


class CallFinder(ast.NodeVisitor):
    """Helper to find all function calls in a node."""

    def __init__(self):
        self.calls: List[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            self.calls.append(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                self.calls.append(f"{node.func.value.id}.{node.func.attr}")
            else:
                self.calls.append(node.func.attr)
        self.generic_visit(node)


# ─── JavaScript/TypeScript Analyzer ─────────────────────────────────────────


class JavaScriptAnalyzer:
    """
    Analyzes JavaScript/TypeScript code using token-based analysis.

    Since tree-sitter requires native bindings, this uses a simpler approach:
    1. Strip comments and string literals
    2. Apply regex patterns to clean code
    3. Track imports and function definitions
    """

    # Patterns to strip comments
    COMMENT_PATTERNS = [
        (r"//.*$", re.MULTILINE),  # Single-line comments
        (r"/\*[\s\S]*?\*/", 0),     # Multi-line comments
    ]

    # Patterns to identify strings (to mask them)
    STRING_PATTERNS = [
        r'"(?:[^"\\]|\\.)*"',
        r"'(?:[^'\\]|\\.)*'",
        r"`(?:[^`\\]|\\.)*`",
    ]

    def __init__(self, code: str, is_typescript: bool = False):
        self.code = code
        self.is_typescript = is_typescript
        self.clean_code = ""
        self.findings: List[ASTFinding] = []
        self.imports: List[Dict[str, Any]] = []
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.pii_variables: Set[str] = set()

    def _strip_comments(self) -> str:
        """Remove comments from code."""
        result = self.code
        for pattern, flags in self.COMMENT_PATTERNS:
            result = re.sub(pattern, "", result, flags=flags)
        return result

    def _mask_strings(self, code: str) -> str:
        """Replace string literals with placeholders."""
        for pattern in self.STRING_PATTERNS:
            code = re.sub(pattern, '""', code)
        return code

    def _extract_imports(self) -> None:
        """Extract import statements."""
        # ES6 imports: import x from 'y'
        es6_pattern = r"import\s+(?:{[^}]+}|\*\s+as\s+\w+|\w+)\s+from\s+['\"]([^'\"]+)['\"]"
        for match in re.finditer(es6_pattern, self.clean_code):
            module = match.group(1)
            self.imports.append({
                "module": module,
                "type": "es6_import",
                "line": self.code[:match.start()].count("\n") + 1,
            })
            self._check_import_risk(module, self.code[:match.start()].count("\n") + 1)

        # CommonJS: require('x')
        require_pattern = r"require\(['\"]([^'\"]+)['\"]\)"
        for match in re.finditer(require_pattern, self.clean_code):
            module = match.group(1)
            self.imports.append({
                "module": module,
                "type": "require",
                "line": self.code[:match.start()].count("\n") + 1,
            })
            self._check_import_risk(module, self.code[:match.start()].count("\n") + 1)

    def _check_import_risk(self, module: str, line: int) -> None:
        """Check if import is a cross-border transfer risk."""
        for risk_module, (provider, region, risk, justification) in JAVASCRIPT_CROSS_BORDER.items():
            if risk_module in module:
                desc = f"Import of '{module}' may transfer data to {region}"
                if justification:
                    desc += f". Risk rationale: {justification}"
                self.findings.append(ASTFinding(
                    id="AST-JS-XBORDER-001",
                    category="cross_border",
                    severity=risk,
                    article="Art. 44-49",
                    title=f"Cross-border transfer risk: {provider}",
                    description=desc,
                    location={"line": line, "module": module},
                    confidence="HIGH",
                    recommendation="Ensure adequate safeguards (SCCs, adequacy decision) are in place",
                ))
                break

    def _extract_functions(self) -> None:
        """Extract function definitions."""
        # Standard functions: function name(
        func_pattern = r"(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)"
        for match in re.finditer(func_pattern, self.clean_code):
            name = match.group(1)
            params = [p.strip().split(":")[0].strip() for p in match.group(2).split(",") if p.strip()]
            line = self.code[:match.start()].count("\n") + 1
            self.functions[name] = {
                "name": name,
                "line": line,
                "parameters": params,
                "type": "function",
            }
            self._check_pii_params(name, params, line)

        # Arrow functions: const name = (params) =>
        arrow_pattern = r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"
        for match in re.finditer(arrow_pattern, self.clean_code):
            name = match.group(1)
            params = [p.strip().split(":")[0].strip() for p in match.group(2).split(",") if p.strip()]
            line = self.code[:match.start()].count("\n") + 1
            self.functions[name] = {
                "name": name,
                "line": line,
                "parameters": params,
                "type": "arrow",
            }
            self._check_pii_params(name, params, line)

        # Method definitions in classes: async methodName(
        method_pattern = r"(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*{"
        for match in re.finditer(method_pattern, self.clean_code):
            name = match.group(1)
            if name not in ("if", "while", "for", "switch", "catch", "function"):
                params = [p.strip().split(":")[0].strip() for p in match.group(2).split(",") if p.strip()]
                line = self.code[:match.start()].count("\n") + 1
                if name not in self.functions:
                    self.functions[name] = {
                        "name": name,
                        "line": line,
                        "parameters": params,
                        "type": "method",
                    }
                    self._check_pii_params(name, params, line)

    def _check_pii_params(self, func_name: str, params: List[str], line: int) -> None:
        """Check function parameters for PII indicators."""
        for param in params:
            param_clean = param.lower().replace("_", "").replace("-", "")
            if any(term.replace("_", "") in param_clean for term in ALL_PII_TERMS):
                self.pii_variables.add(param)
                self.findings.append(ASTFinding(
                    id="AST-JS-PII-001",
                    category="pii_handling",
                    severity="MEDIUM",
                    article="Art. 5, 25",
                    title="PII in function parameter",
                    description=f"Function '{func_name}' has parameter '{param}' that may contain PII",
                    location={"line": line, "function": func_name},
                    confidence="MEDIUM",
                    recommendation="Ensure PII is minimized and processed only as necessary",
                ))

    def _check_logging(self) -> None:
        """Check for console.log with PII."""
        log_pattern = r"console\.(log|info|warn|error|debug)\s*\(([^)]+)\)"
        for match in re.finditer(log_pattern, self.clean_code):
            args = match.group(2)
            line = self.code[:match.start()].count("\n") + 1
            for pii_var in self.pii_variables:
                if pii_var in args:
                    self.findings.append(ASTFinding(
                        id="AST-JS-LOG-001",
                        category="pii_logging",
                        severity="HIGH",
                        article="Art. 5(1)(f), Art. 32",
                        title="PII logged to console",
                        description=f"Variable '{pii_var}' containing PII passed to console.{match.group(1)}",
                        location={"line": line},
                        confidence="HIGH",
                        recommendation="Mask or exclude PII from logs",
                    ))

    def _check_dsr_functions(self) -> None:
        """Check for DSR implementation patterns."""
        js_dsr_patterns = {
            "access": [r"^(get|fetch|export|download)(User|Personal|My)(Data|Info|Profile)?$"],
            "erasure": [r"^(delete|erase|remove)(User|Personal|Account)(Data)?$", r"^anonymize"],
            "rectification": [r"^(update|correct|edit)(User|Personal|Profile)(Data)?$"],
            "portability": [r"^export(Data|To)(Json|Csv|Xml)?$"],
            "objection": [r"^(optOut|unsubscribe|withdrawConsent)"],
        }

        for func_name in self.functions:
            for dsr_type, patterns in js_dsr_patterns.items():
                for pattern in patterns:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        article = DSR_FUNCTION_PATTERNS.get(dsr_type, {}).get("article", "Art. 15-22")
                        self.findings.append(ASTFinding(
                            id=f"AST-JS-DSR-{dsr_type.upper()}",
                            category="dsr_capability",
                            severity="INFO",
                            article=article,
                            title=f"DSR capability detected: {dsr_type}",
                            description=f"Function '{func_name}' implements {dsr_type} capability",
                            location={"line": self.functions[func_name]["line"], "function": func_name},
                            confidence="MEDIUM",
                            recommendation="Ensure complete implementation per GDPR requirements",
                        ))
                        break

    def analyze(self) -> Dict[str, Any]:
        """Run full analysis."""
        # Prepare clean code - strip comments first
        code_no_comments = self._strip_comments()

        # Extract imports BEFORE masking strings (import paths are in strings)
        self.clean_code = code_no_comments
        self._extract_imports()

        # Now mask strings for remaining analysis
        self.clean_code = self._mask_strings(code_no_comments)

        # Extract structures
        self._extract_imports()
        self._extract_functions()

        # Run checks
        self._check_logging()
        self._check_dsr_functions()

        return {
            "language": "typescript" if self.is_typescript else "javascript",
            "parse_success": True,
            "functions_analyzed": len(self.functions),
            "imports_found": len(self.imports),
            "pii_variables_detected": len(self.pii_variables),
            "findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "severity": f.severity,
                    "article": f.article,
                    "title": f.title,
                    "description": f.description,
                    "location": f.location,
                    "confidence": f.confidence,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "functions": self.functions,
            "imports": self.imports,
        }


# ─── Java Analyzer ──────────────────────────────────────────────────────────


class JavaAnalyzer:
    """
    Analyzes Java code using token-based analysis.
    
    Detects:
    - Import statements for cross-border transfer risks
    - Method definitions with PII parameters
    - Logging statements with PII
    - DSR implementation patterns
    """

    # Patterns to strip comments
    COMMENT_PATTERNS = [
        (r"//.*$", re.MULTILINE),  # Single-line comments
        (r"/\*[\s\S]*?\*/", 0),     # Multi-line comments
    ]

    # Patterns to identify strings (to mask them)
    STRING_PATTERNS = [
        r'"(?:[^"\\]|\\.)*"',
        r"'(?:[^'\\]|\\.)*'",
    ]

    def __init__(self, code: str):
        self.code = code
        self.clean_code = ""
        self.findings: List[ASTFinding] = []
        self.imports: List[Dict[str, Any]] = []
        self.methods: Dict[str, Dict[str, Any]] = {}
        self.pii_variables: Set[str] = set()

    def _strip_comments(self) -> str:
        """Remove comments from code."""
        result = self.code
        for pattern, flags in self.COMMENT_PATTERNS:
            result = re.sub(pattern, "", result, flags=flags)
        return result

    def _mask_strings(self, code: str) -> str:
        """Replace string literals with placeholders."""
        for pattern in self.STRING_PATTERNS:
            code = re.sub(pattern, '""', code)
        return code

    def _extract_imports(self) -> None:
        """Extract Java import statements."""
        # Java imports: import com.example.package;
        import_pattern = r"import\s+(static\s+)?([a-zA-Z0-9_.]+)(?:\.\*)?;"
        for match in re.finditer(import_pattern, self.clean_code):
            module = match.group(2)
            self.imports.append({
                "module": module,
                "static": match.group(1) is not None,
                "type": "import",
                "line": self.code[:match.start()].count("\n") + 1,
            })
            self._check_import_risk(module, self.code[:match.start()].count("\n") + 1)

    def _check_import_risk(self, module: str, line: int) -> None:
        """Check if import is a cross-border transfer risk."""
        for risk_module, (provider, region, risk, justification) in JAVA_CROSS_BORDER.items():
            if module.startswith(risk_module):
                desc = f"Import of '{module}' may transfer data to {region}"
                if justification:
                    desc += f". Risk rationale: {justification}"
                self.findings.append(ASTFinding(
                    id="AST-JAVA-XBORDER-001",
                    category="cross_border",
                    severity=risk,
                    article="Art. 44-49",
                    title=f"Cross-border transfer risk: {provider}",
                    description=desc,
                    location={"line": line, "module": module},
                    confidence="HIGH",
                    recommendation="Ensure adequate safeguards (SCCs, adequacy decision) are in place",
                ))
                break

    def _extract_methods(self) -> None:
        """Extract method definitions."""
        # Java methods: public void methodName(Type param, ...)
        method_pattern = r"(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{"
        for match in re.finditer(method_pattern, self.clean_code):
            name = match.group(1)
            params_str = match.group(2)
            line = self.code[:match.start()].count("\n") + 1
            
            # Parse parameters (Type name, Type name, ...)
            params = []
            if params_str.strip():
                for param in params_str.split(","):
                    parts = param.strip().split()
                    if len(parts) >= 2:
                        param_name = parts[-1]  # Last part is the parameter name
                        params.append(param_name)
            
            self.methods[name] = {
                "name": name,
                "line": line,
                "parameters": params,
                "type": "method",
            }
            self._check_pii_params(name, params, line)

    def _check_pii_params(self, method_name: str, params: List[str], line: int) -> None:
        """Check method parameters for PII indicators."""
        for param in params:
            param_clean = param.lower().replace("_", "")
            if any(term.replace("_", "") in param_clean for term in ALL_PII_TERMS):
                self.pii_variables.add(param)
                self.findings.append(ASTFinding(
                    id="AST-JAVA-PII-001",
                    category="pii_handling",
                    severity="MEDIUM",
                    article="Art. 5, 25",
                    title="PII in method parameter",
                    description=f"Method '{method_name}' has parameter '{param}' that may contain PII",
                    location={"line": line, "method": method_name},
                    confidence="MEDIUM",
                    recommendation="Ensure PII is minimized and processed only as necessary",
                ))

    def _check_logging(self) -> None:
        """Check for logging with PII."""
        # Java logging patterns
        log_patterns = [
            r"(?:logger|log|LOG)\.(info|debug|warn|error|trace)\s*\(([^)]+)\)",
            r"System\.(out|err)\.println?\s*\(([^)]+)\)",
        ]
        for log_pattern in log_patterns:
            for match in re.finditer(log_pattern, self.clean_code):
                args = match.group(2) if (match.lastindex or 0) >= 2 else match.group(1)
                line = self.code[:match.start()].count("\n") + 1
                for pii_var in self.pii_variables:
                    if pii_var in args:
                        self.findings.append(ASTFinding(
                            id="AST-JAVA-LOG-001",
                            category="pii_logging",
                            severity="HIGH",
                            article="Art. 5(1)(f), Art. 32",
                            title="PII logged",
                            description=f"Variable '{pii_var}' containing PII passed to logging statement",
                            location={"line": line},
                            confidence="HIGH",
                            recommendation="Mask or exclude PII from logs",
                        ))

    def _check_dsr_methods(self) -> None:
        """Check for DSR implementation patterns."""
        java_dsr_patterns = {
            "access": [r"^(get|fetch|export|retrieve)(User|Personal|Subject)(Data|Info)?$"],
            "erasure": [r"^(delete|erase|remove|purge)(User|Personal|Account)(Data)?$", r"^anonymize"],
            "rectification": [r"^(update|correct|modify)(User|Personal|Profile)(Data)?$"],
            "portability": [r"^export(Data|To)(Json|Csv|Xml)?$"],
            "objection": [r"^(optOut|unsubscribe|withdrawConsent)"],
        }

        for method_name in self.methods:
            for dsr_type, patterns in java_dsr_patterns.items():
                for pattern in patterns:
                    if re.match(pattern, method_name, re.IGNORECASE):
                        article = DSR_FUNCTION_PATTERNS.get(dsr_type, {}).get("article", "Art. 15-22")
                        self.findings.append(ASTFinding(
                            id=f"AST-JAVA-DSR-{dsr_type.upper()}",
                            category="dsr_capability",
                            severity="INFO",
                            article=article,
                            title=f"DSR capability detected: {dsr_type}",
                            description=f"Method '{method_name}' implements {dsr_type} capability",
                            location={"line": self.methods[method_name]["line"], "method": method_name},
                            confidence="MEDIUM",
                            recommendation="Ensure complete implementation per GDPR requirements",
                        ))
                        break

    def analyze(self) -> Dict[str, Any]:
        """Run full analysis."""
        code_no_comments = self._strip_comments()
        # Mask strings BEFORE extracting imports to avoid false positives
        self.clean_code = self._mask_strings(code_no_comments)
        self._extract_imports()
        self._extract_methods()
        self._check_logging()
        self._check_dsr_methods()

        return {
            "language": "java",
            "parse_success": True,
            "functions_analyzed": len(self.methods),
            "imports_found": len(self.imports),
            "pii_variables_detected": len(self.pii_variables),
            "findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "severity": f.severity,
                    "article": f.article,
                    "title": f.title,
                    "description": f.description,
                    "location": f.location,
                    "confidence": f.confidence,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "functions": self.methods,
            "imports": self.imports,
        }


# ─── C# Analyzer ────────────────────────────────────────────────────────────


class CSharpAnalyzer:
    """
    Analyzes C# code using token-based analysis.
    
    Detects:
    - Using directives for cross-border transfer risks
    - Method definitions with PII parameters
    - Logging statements with PII
    - DSR implementation patterns
    """

    COMMENT_PATTERNS = [
        (r"//.*$", re.MULTILINE),
        (r"/\*[\s\S]*?\*/", 0),
    ]

    STRING_PATTERNS = [
        r'"(?:[^"\\]|\\.)*"',
        r"@\"(?:[^\"]|\"\")*\"",  # Verbatim strings
        r"\$\"(?:[^\"\\]|\\.)*\"",  # Interpolated strings
    ]

    def __init__(self, code: str):
        self.code = code
        self.clean_code = ""
        self.findings: List[ASTFinding] = []
        self.imports: List[Dict[str, Any]] = []
        self.methods: Dict[str, Dict[str, Any]] = {}
        self.pii_variables: Set[str] = set()

    def _strip_comments(self) -> str:
        """Remove comments from code."""
        result = self.code
        for pattern, flags in self.COMMENT_PATTERNS:
            result = re.sub(pattern, "", result, flags=flags)
        return result

    def _mask_strings(self, code: str) -> str:
        """Replace string literals with placeholders."""
        for pattern in self.STRING_PATTERNS:
            code = re.sub(pattern, '""', code)
        return code

    def _extract_imports(self) -> None:
        """Extract C# using directives."""
        # using statements: using Namespace.SubNamespace;
        using_pattern = r"using\s+(static\s+)?([a-zA-Z0-9_.]+);"
        for match in re.finditer(using_pattern, self.clean_code):
            namespace = match.group(2)
            self.imports.append({
                "module": namespace,
                "static": match.group(1) is not None,
                "type": "using",
                "line": self.code[:match.start()].count("\n") + 1,
            })
            self._check_import_risk(namespace, self.code[:match.start()].count("\n") + 1)

    def _check_import_risk(self, namespace: str, line: int) -> None:
        """Check if using directive is a cross-border transfer risk."""
        for risk_ns, (provider, region, risk, justification) in CSHARP_CROSS_BORDER.items():
            if namespace.startswith(risk_ns):
                desc = f"Using directive '{namespace}' may transfer data to {region}"
                if justification:
                    desc += f". Risk rationale: {justification}"
                self.findings.append(ASTFinding(
                    id="AST-CSHARP-XBORDER-001",
                    category="cross_border",
                    severity=risk,
                    article="Art. 44-49",
                    title=f"Cross-border transfer risk: {provider}",
                    description=desc,
                    location={"line": line, "namespace": namespace},
                    confidence="HIGH",
                    recommendation="Ensure adequate safeguards (SCCs, adequacy decision) are in place",
                ))
                break

    def _extract_methods(self) -> None:
        """Extract method definitions."""
        # C# methods: public async Task<T> MethodName(Type param, ...)
        method_pattern = r"(?:public|private|protected|internal)?\s*(?:static\s+)?(?:async\s+)?(?:virtual\s+)?(?:override\s+)?(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(([^)]*)\)\s*\{"
        for match in re.finditer(method_pattern, self.clean_code):
            name = match.group(1)
            params_str = match.group(2)
            line = self.code[:match.start()].count("\n") + 1
            
            # Parse parameters
            params = []
            if params_str.strip():
                for param in params_str.split(","):
                    parts = param.strip().split()
                    if len(parts) >= 2:
                        param_name = parts[-1]
                        params.append(param_name)
            
            self.methods[name] = {
                "name": name,
                "line": line,
                "parameters": params,
                "type": "method",
            }
            self._check_pii_params(name, params, line)

    def _check_pii_params(self, method_name: str, params: List[str], line: int) -> None:
        """Check method parameters for PII indicators."""
        for param in params:
            param_clean = param.lower().replace("_", "")
            if any(term.replace("_", "") in param_clean for term in ALL_PII_TERMS):
                self.pii_variables.add(param)
                self.findings.append(ASTFinding(
                    id="AST-CSHARP-PII-001",
                    category="pii_handling",
                    severity="MEDIUM",
                    article="Art. 5, 25",
                    title="PII in method parameter",
                    description=f"Method '{method_name}' has parameter '{param}' that may contain PII",
                    location={"line": line, "method": method_name},
                    confidence="MEDIUM",
                    recommendation="Ensure PII is minimized and processed only as necessary",
                ))

    def _check_logging(self) -> None:
        """Check for logging with PII."""
        log_patterns = [
            r"(?:_logger|logger|Logger|Log)\.(LogInformation|LogDebug|LogWarning|LogError|Information|Debug|Warning|Error)\s*\(([^)]+)\)",
            r"Console\.Write(?:Line)?\s*\(([^)]+)\)",
            r"Debug\.Write(?:Line)?\s*\(([^)]+)\)",
        ]
        for log_pattern in log_patterns:
            for match in re.finditer(log_pattern, self.clean_code):
                args = match.group(2) if (match.lastindex or 0) >= 2 else match.group(1)
                line = self.code[:match.start()].count("\n") + 1
                for pii_var in self.pii_variables:
                    if pii_var in args:
                        self.findings.append(ASTFinding(
                            id="AST-CSHARP-LOG-001",
                            category="pii_logging",
                            severity="HIGH",
                            article="Art. 5(1)(f), Art. 32",
                            title="PII logged",
                            description=f"Variable '{pii_var}' containing PII passed to logging statement",
                            location={"line": line},
                            confidence="HIGH",
                            recommendation="Mask or exclude PII from logs",
                        ))

    def _check_dsr_methods(self) -> None:
        """Check for DSR implementation patterns."""
        csharp_dsr_patterns = {
            "access": [r"^(Get|Fetch|Export|Retrieve)(User|Personal|Subject)(Data|Info)?(?:Async)?$"],
            "erasure": [r"^(Delete|Erase|Remove|Purge)(User|Personal|Account)(Data)?(?:Async)?$", r"^Anonymize"],
            "rectification": [r"^(Update|Correct|Modify)(User|Personal|Profile)(Data)?(?:Async)?$"],
            "portability": [r"^Export(Data|To)(Json|Csv|Xml)?(?:Async)?$"],
            "objection": [r"^(OptOut|Unsubscribe|WithdrawConsent)(?:Async)?$"],
        }

        for method_name in self.methods:
            for dsr_type, patterns in csharp_dsr_patterns.items():
                for pattern in patterns:
                    if re.match(pattern, method_name, re.IGNORECASE):
                        article = DSR_FUNCTION_PATTERNS.get(dsr_type, {}).get("article", "Art. 15-22")
                        self.findings.append(ASTFinding(
                            id=f"AST-CSHARP-DSR-{dsr_type.upper()}",
                            category="dsr_capability",
                            severity="INFO",
                            article=article,
                            title=f"DSR capability detected: {dsr_type}",
                            description=f"Method '{method_name}' implements {dsr_type} capability",
                            location={"line": self.methods[method_name]["line"], "method": method_name},
                            confidence="MEDIUM",
                            recommendation="Ensure complete implementation per GDPR requirements",
                        ))
                        break

    def analyze(self) -> Dict[str, Any]:
        """Run full analysis."""
        code_no_comments = self._strip_comments()
        # Mask strings BEFORE extracting imports to avoid false positives
        self.clean_code = self._mask_strings(code_no_comments)
        self._extract_imports()
        self._extract_methods()
        self._check_logging()
        self._check_dsr_methods()

        return {
            "language": "csharp",
            "parse_success": True,
            "functions_analyzed": len(self.methods),
            "imports_found": len(self.imports),
            "pii_variables_detected": len(self.pii_variables),
            "findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "severity": f.severity,
                    "article": f.article,
                    "title": f.title,
                    "description": f.description,
                    "location": f.location,
                    "confidence": f.confidence,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "functions": self.methods,
            "imports": self.imports,
        }


# ─── Go Analyzer ────────────────────────────────────────────────────────────


class GoAnalyzer:
    """
    Analyzes Go code using token-based analysis.
    
    Detects:
    - Import statements for cross-border transfer risks
    - Function definitions with PII parameters
    - Logging statements with PII
    - DSR implementation patterns
    """

    COMMENT_PATTERNS = [
        (r"//.*$", re.MULTILINE),
        (r"/\*[\s\S]*?\*/", 0),
    ]

    STRING_PATTERNS = [
        r'"(?:[^"\\]|\\.)*"',
        r'`[^`]*`',  # Raw strings
    ]

    def __init__(self, code: str):
        self.code = code
        self.clean_code = ""
        self.findings: List[ASTFinding] = []
        self.imports: List[Dict[str, Any]] = []
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.pii_variables: Set[str] = set()

    def _strip_comments(self) -> str:
        """Remove comments from code."""
        result = self.code
        for pattern, flags in self.COMMENT_PATTERNS:
            result = re.sub(pattern, "", result, flags=flags)
        return result

    def _mask_strings(self, code: str) -> str:
        """Replace string literals with placeholders."""
        for pattern in self.STRING_PATTERNS:
            code = re.sub(pattern, '""', code)
        return code

    def _extract_imports(self) -> None:
        """Extract Go import statements."""
        # Single import: import "package" (must be at line start, optionally with whitespace)
        single_pattern = r'^\s*import\s+"([^"]+)"'
        for match in re.finditer(single_pattern, self.clean_code, re.MULTILINE):
            pkg = match.group(1)
            self.imports.append({
                "module": pkg,
                "type": "import",
                "line": self.code[:match.start()].count("\n") + 1,
            })
            self._check_import_risk(pkg, self.code[:match.start()].count("\n") + 1)

        # Block import: import ( "pkg1" "pkg2" ) (must be at line start)
        block_pattern = r'^\s*import\s*\(\s*((?:[^)]+))\s*\)'
        for match in re.finditer(block_pattern, self.clean_code, re.MULTILINE | re.DOTALL):
            imports_block = match.group(1)
            line_base = self.code[:match.start()].count("\n") + 1
            for pkg_match in re.finditer(r'"([^"]+)"', imports_block):
                pkg = pkg_match.group(1)
                self.imports.append({
                    "module": pkg,
                    "type": "import",
                    "line": line_base,
                })
                self._check_import_risk(pkg, line_base)

    def _check_import_risk(self, pkg: str, line: int) -> None:
        """Check if import is a cross-border transfer risk."""
        for risk_pkg, (provider, region, risk, justification) in GO_CROSS_BORDER.items():
            if pkg.startswith(risk_pkg) or risk_pkg in pkg:
                desc = f"Import of '{pkg}' may transfer data to {region}"
                if justification:
                    desc += f". Risk rationale: {justification}"
                self.findings.append(ASTFinding(
                    id="AST-GO-XBORDER-001",
                    category="cross_border",
                    severity=risk,
                    article="Art. 44-49",
                    title=f"Cross-border transfer risk: {provider}",
                    description=desc,
                    location={"line": line, "package": pkg},
                    confidence="HIGH",
                    recommendation="Ensure adequate safeguards (SCCs, adequacy decision) are in place",
                ))
                break

    def _extract_functions(self) -> None:
        """Extract function definitions."""
        # Go functions: func funcName(param type, ...) returnType {
        func_pattern = r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(func_pattern, self.clean_code):
            name = match.group(1)
            params_str = match.group(2)
            line = self.code[:match.start()].count("\n") + 1
            
            # Parse parameters (name type, name type, ...)
            params = []
            if params_str.strip():
                for param in params_str.split(","):
                    parts = param.strip().split()
                    if parts:
                        param_name = parts[0]  # First part is parameter name in Go
                        params.append(param_name)
            
            self.functions[name] = {
                "name": name,
                "line": line,
                "parameters": params,
                "type": "function",
            }
            self._check_pii_params(name, params, line)

    def _check_pii_params(self, func_name: str, params: List[str], line: int) -> None:
        """Check function parameters for PII indicators."""
        for param in params:
            param_clean = param.lower().replace("_", "")
            if any(term.replace("_", "") in param_clean for term in ALL_PII_TERMS):
                self.pii_variables.add(param)
                self.findings.append(ASTFinding(
                    id="AST-GO-PII-001",
                    category="pii_handling",
                    severity="MEDIUM",
                    article="Art. 5, 25",
                    title="PII in function parameter",
                    description=f"Function '{func_name}' has parameter '{param}' that may contain PII",
                    location={"line": line, "function": func_name},
                    confidence="MEDIUM",
                    recommendation="Ensure PII is minimized and processed only as necessary",
                ))

    def _check_logging(self) -> None:
        """Check for logging with PII."""
        log_patterns = [
            r'(?:log|logger)\.(Print|Printf|Println|Info|Debug|Warn|Error|Fatal)\w*\s*\(([^)]+)\)',
            r'fmt\.(Print|Printf|Println)\s*\(([^)]+)\)',
        ]
        for log_pattern in log_patterns:
            for match in re.finditer(log_pattern, self.clean_code):
                args = match.group(2)
                line = self.code[:match.start()].count("\n") + 1
                for pii_var in self.pii_variables:
                    if pii_var in args:
                        self.findings.append(ASTFinding(
                            id="AST-GO-LOG-001",
                            category="pii_logging",
                            severity="HIGH",
                            article="Art. 5(1)(f), Art. 32",
                            title="PII logged",
                            description=f"Variable '{pii_var}' containing PII passed to logging statement",
                            location={"line": line},
                            confidence="HIGH",
                            recommendation="Mask or exclude PII from logs",
                        ))

    def _check_dsr_functions(self) -> None:
        """Check for DSR implementation patterns."""
        go_dsr_patterns = {
            "access": [r"^(Get|Fetch|Export|Retrieve)(User|Personal|Subject)(Data|Info)?$"],
            "erasure": [r"^(Delete|Erase|Remove|Purge)(User|Personal|Account)(Data)?$", r"^Anonymize"],
            "rectification": [r"^(Update|Correct|Modify)(User|Personal|Profile)(Data)?$"],
            "portability": [r"^Export(Data|To)(JSON|CSV|XML)?$"],
            "objection": [r"^(OptOut|Unsubscribe|WithdrawConsent)$"],
        }

        for func_name in self.functions:
            for dsr_type, patterns in go_dsr_patterns.items():
                for pattern in patterns:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        article = DSR_FUNCTION_PATTERNS.get(dsr_type, {}).get("article", "Art. 15-22")
                        self.findings.append(ASTFinding(
                            id=f"AST-GO-DSR-{dsr_type.upper()}",
                            category="dsr_capability",
                            severity="INFO",
                            article=article,
                            title=f"DSR capability detected: {dsr_type}",
                            description=f"Function '{func_name}' implements {dsr_type} capability",
                            location={"line": self.functions[func_name]["line"], "function": func_name},
                            confidence="MEDIUM",
                            recommendation="Ensure complete implementation per GDPR requirements",
                        ))
                        break

    def analyze(self) -> Dict[str, Any]:
        """Run full analysis."""
        code_no_comments = self._strip_comments()
        # For Go, extract imports BEFORE masking strings since import paths are in quotes
        self.clean_code = code_no_comments
        self._extract_imports()
        # Mask strings for remaining analysis
        self.clean_code = self._mask_strings(code_no_comments)
        self._extract_functions()
        self._check_logging()
        self._check_dsr_functions()

        return {
            "language": "go",
            "parse_success": True,
            "functions_analyzed": len(self.functions),
            "imports_found": len(self.imports),
            "pii_variables_detected": len(self.pii_variables),
            "findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "severity": f.severity,
                    "article": f.article,
                    "title": f.title,
                    "description": f.description,
                    "location": f.location,
                    "confidence": f.confidence,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "functions": self.functions,
            "imports": self.imports,
        }


# ─── Main Analysis Functions ────────────────────────────────────────────────


def detect_language(code: str, file_path: Optional[str] = None) -> str:
    """Detect the programming language of the code."""
    if file_path:
        ext = file_path.lower().split(".")[-1] if "." in file_path else ""
        ext_map = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "tsx": "typescript",
            "jsx": "javascript",
            "mjs": "javascript",
            "cjs": "javascript",
            "java": "java",
            "cs": "csharp",
            "go": "go",
        }
        if ext in ext_map:
            return ext_map[ext]

    # Heuristic detection
    python_indicators = ["import ", "from ", "def ", "class ", "async def", "    :", "elif "]
    js_indicators = ["const ", "let ", "var ", "function ", "=> {", "require(", "import "]
    ts_indicators = [": string", ": number", ": boolean", "interface ", "<T>", ": Promise<"]
    java_indicators = ["public class", "private ", "public static void main", "System.out", "extends ", "implements "]
    csharp_indicators = ["using System", "namespace ", "public class", "private ", "Console.Write", "async Task"]
    go_indicators = ["package ", "func ", "import (", "fmt.", "go func", "chan ", ":= "]

    python_score = sum(1 for ind in python_indicators if ind in code)
    js_score = sum(1 for ind in js_indicators if ind in code)
    ts_score = sum(1 for ind in ts_indicators if ind in code)
    java_score = sum(1 for ind in java_indicators if ind in code)
    csharp_score = sum(1 for ind in csharp_indicators if ind in code)
    go_score = sum(1 for ind in go_indicators if ind in code)

    # Return highest scoring language
    scores = [
        ("go", go_score),
        ("java", java_score),
        ("csharp", csharp_score),
        ("typescript", ts_score if ts_score > 0 and js_score > 0 else 0),
        ("python", python_score),
        ("javascript", js_score),
    ]
    scores.sort(key=lambda x: x[1], reverse=True)

    if scores[0][1] > 0:
        return scores[0][0]
    return "unknown"


async def analyze_code_ast_impl(
    code: str,
    file_path: Optional[str],
    language: Optional[str],
    deep_analysis: bool,
    data_loader,
) -> str:
    """
    Analyze code using AST for GDPR compliance.

    Args:
        code: Source code to analyze
        file_path: Optional file path for language detection
        language: Override language detection (python, javascript, typescript)
        deep_analysis: Enable deep data flow analysis
        data_loader: Data loader instance

    Returns:
        JSON analysis result with findings
    """
    await data_loader.load_data()

    # Detect language
    lang = language or detect_language(code, file_path)

    if lang == "python":
        py_analyzer = PythonASTAnalyzer(code)
        result = py_analyzer.analyze()
    elif lang in ("javascript", "typescript"):
        js_analyzer = JavaScriptAnalyzer(code, is_typescript=(lang == "typescript"))
        result = js_analyzer.analyze()
    elif lang == "java":
        java_analyzer = JavaAnalyzer(code)
        result = java_analyzer.analyze()
    elif lang == "csharp":
        csharp_analyzer = CSharpAnalyzer(code)
        result = csharp_analyzer.analyze()
    elif lang == "go":
        go_analyzer = GoAnalyzer(code)
        result = go_analyzer.analyze()
    else:
        result = {
            "language": lang,
            "parse_success": False,
            "error": f"Language '{lang}' is not supported for AST analysis. Supported: python, javascript, typescript, java, csharp, go",
            "findings": [],
        }

    # Build summary
    findings = result.get("findings", [])
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "ERROR": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in severity_counts:
            severity_counts[sev] += 1

    result["summary"] = {
        "total_findings": len(findings),
        "by_severity": severity_counts,
        "categories": list(set(f.get("category", "") for f in findings)),
    }

    output = {
        "analysis_type": "AST",
        "language": result.get("language"),
        "parse_success": result.get("parse_success", False),
        "summary": result.get("summary", {}),
        "findings": findings,
        "metadata": {
            "functions_analyzed": result.get("functions_analyzed", 0),
            "imports_found": result.get("imports_found", 0),
            "pii_variables_detected": result.get("pii_variables_detected", 0),
        },
    }

    # Include error message if present
    if "error" in result:
        output["error"] = result["error"]

    if deep_analysis:
        output["functions"] = result.get("functions", {})
        output["imports"] = result.get("imports", [])
        output["call_graph"] = result.get("call_graph", {})
        output["data_flows"] = result.get("data_flows", [])

    return append_disclaimer(json.dumps(output, indent=2))


async def get_ast_capabilities_impl(data_loader) -> str:
    """Return information about AST analysis capabilities."""
    await data_loader.load_data()

    capabilities = {
        "supported_languages": {
            "python": {
                "parser": "Built-in ast module",
                "features": [
                    "Full AST parsing",
                    "Function/class extraction",
                    "Import tracking",
                    "Call graph analysis",
                    "Data flow tracking",
                    "PII variable detection",
                    "Logging analysis",
                ],
            },
            "javascript": {
                "parser": "Token-based with comment stripping",
                "features": [
                    "ES6 and CommonJS import detection",
                    "Function extraction (standard, arrow, methods)",
                    "PII parameter detection",
                    "Console logging analysis",
                    "DSR pattern matching",
                ],
            },
            "typescript": {
                "parser": "Token-based with comment stripping",
                "features": [
                    "All JavaScript features",
                    "Type annotation awareness",
                ],
            },
            "java": {
                "parser": "Token-based with comment stripping",
                "features": [
                    "Import statement detection",
                    "Method extraction with parameters",
                    "PII parameter detection",
                    "Logger and System.out logging analysis",
                    "DSR pattern matching",
                ],
            },
            "csharp": {
                "parser": "Token-based with comment stripping",
                "features": [
                    "Using directive detection",
                    "Method extraction with parameters",
                    "PII parameter detection",
                    "ILogger and Console logging analysis",
                    "DSR pattern matching",
                    "Async method support",
                ],
            },
            "go": {
                "parser": "Token-based with comment stripping",
                "features": [
                    "Import statement detection (single and block)",
                    "Function extraction with parameters",
                    "PII parameter detection",
                    "log and fmt package analysis",
                    "DSR pattern matching",
                ],
            },
        },
        "analysis_categories": {
            "cross_border": "Detects imports/calls to services that may transfer data outside EEA (Art. 44-49)",
            "pii_handling": "Identifies variables and parameters containing personal data (Art. 5, 25)",
            "pii_logging": "Flags logging statements that may expose PII (Art. 5(1)(f), 32)",
            "dsr_capability": "Detects implementation of data subject rights (Art. 15-22)",
            "syntax": "Reports code parsing errors",
        },
        "severity_levels": ["HIGH", "MEDIUM", "LOW", "INFO", "ERROR"],
        "confidence_levels": ["HIGH", "MEDIUM", "LOW"],
        "pii_categories_detected": list(PII_INDICATORS.keys()),
        "cross_border_providers_detected": list(_PROVIDERS.keys()),
    }

    return append_disclaimer(json.dumps(capabilities, indent=2))
