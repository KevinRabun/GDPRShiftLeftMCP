"""
Unit tests for the AST-based code analyzer.

Tests cover:
- Python AST analysis
- JavaScript/TypeScript analysis
- PII detection
- Cross-border transfer detection
- DSR capability detection
- Data flow analysis
- Edge cases and error handling
"""
import json
import re
import pytest
from gdpr_shift_left_mcp.tools.ast_analyzer import (
    PythonASTAnalyzer,
    JavaScriptAnalyzer,
    JavaAnalyzer,
    CSharpAnalyzer,
    GoAnalyzer,
    detect_language,
    analyze_code_ast_impl,
    get_ast_capabilities_impl,
    ALL_PII_TERMS,
    DSR_FUNCTION_PATTERNS,
    CROSS_BORDER_IMPORTS,
    PII_INDICATORS,
)


def extract_json_from_response(response: str) -> dict:
    """Extract JSON data from response with disclaimer."""
    # Find the JSON portion (ends before the citation footer)
    json_end = response.find("\n\n*Source:")
    if json_end == -1:
        json_end = response.find("\n\n---")
    if json_end == -1:
        json_str = response
    else:
        json_str = response[:json_end].strip()
    return json.loads(json_str)


# ─── Mock Data Loader ───────────────────────────────────────────────────────


class MockDataLoader:
    """Mock data loader for testing."""
    async def load_data(self):
        pass


@pytest.fixture
def data_loader():
    return MockDataLoader()


# ─── Python AST Analyzer Tests ──────────────────────────────────────────────


class TestPythonASTAnalyzer:
    """Tests for Python AST analysis."""

    def test_parse_valid_python(self):
        """Test parsing valid Python code."""
        code = """
def hello():
    print("Hello, World!")
"""
        analyzer = PythonASTAnalyzer(code)
        assert analyzer.parse() is True
        assert analyzer.tree is not None

    def test_parse_invalid_python(self):
        """Test parsing invalid Python code."""
        code = "def broken("
        analyzer = PythonASTAnalyzer(code)
        assert analyzer.parse() is False
        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].id == "AST-PARSE-001"

    def test_detect_pii_parameter(self):
        """Test PII detection in function parameters."""
        code = """
def process_user(email_address: str, phone_number: str):
    return email_address
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        assert result["pii_variables_detected"] == 2
        pii_findings = [f for f in result["findings"] if f["category"] == "pii_handling"]
        assert len(pii_findings) == 2

    def test_detect_pii_variable_assignment(self):
        """Test PII detection in variable assignments."""
        code = """
user_email = get_email()
password = get_secret()
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        assert "user_email" in analyzer.pii_variables or "password" in analyzer.pii_variables

    def test_detect_cross_border_import(self):
        """Test cross-border transfer detection via imports."""
        code = """
import openai
from anthropic import Anthropic

client = openai.Client()
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        xborder_findings = [f for f in result["findings"] if f["category"] == "cross_border"]
        assert len(xborder_findings) >= 2
        providers = [f["title"] for f in xborder_findings]
        assert any("OpenAI" in p for p in providers)
        assert any("Anthropic" in p for p in providers)

    def test_detect_dsr_access_function(self):
        """Test DSR access capability detection."""
        code = """
def export_user_data(user_id: str):
    data = db.get_user(user_id)
    return json.dumps(data)
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        dsr_findings = [f for f in result["findings"] if f["category"] == "dsr_capability"]
        assert len(dsr_findings) >= 1
        assert any("access" in f["id"].lower() for f in dsr_findings)

    def test_detect_dsr_erasure_function(self):
        """Test DSR erasure capability detection."""
        code = """
def delete_user_data(user_id: str):
    db.delete(user_id)
    return {"status": "deleted"}
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        dsr_findings = [f for f in result["findings"] if f["category"] == "dsr_capability"]
        assert len(dsr_findings) >= 1

    def test_detect_pii_logging(self):
        """Test PII logging detection."""
        code = """
def process_user(email: str):
    print(f"Processing user: {email}")
    return email
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        log_findings = [f for f in result["findings"] if f["category"] == "pii_logging"]
        assert len(log_findings) >= 1

    def test_function_extraction(self):
        """Test function extraction."""
        code = """
def func_one():
    pass

async def func_two(param):
    return param

class MyClass:
    def method_one(self):
        pass
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        assert "func_one" in result["functions"]
        assert "func_two" in result["functions"]

    def test_import_tracking(self):
        """Test import tracking."""
        code = """
import os
import json
from typing import List, Dict
from mymodule import helper
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        assert result["imports_found"] >= 4

    def test_call_graph(self):
        """Test call graph generation."""
        code = """
def outer():
    inner()
    helper.process()

def inner():
    print("inner")
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        assert "outer" in result["call_graph"]
        assert "inner" in result["call_graph"]["outer"]

    def test_async_function_analysis(self):
        """Test async function analysis."""
        code = """
async def fetch_user_data(user_id: str):
    data = await db.get(user_id)
    return data
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        assert "fetch_user_data" in result["functions"]
        assert result["functions"]["fetch_user_data"]["returns_data"] is True

    def test_decorator_extraction(self):
        """Test decorator extraction."""
        code = """
@app.route("/users")
@login_required
def get_users():
    return users
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        func_info = result["functions"]["get_users"]
        assert "app.route" in func_info["decorators"]
        assert "login_required" in func_info["decorators"]


class TestPythonDataFlow:
    """Tests for Python data flow analysis."""

    def test_pii_data_flow_tracking(self):
        """Test that PII variables are tracked through data flow."""
        code = """
def process(email: str):
    user_data = {"email": email}
    save(user_data)
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        assert result["pii_variables_detected"] >= 1
        assert "data_flows" in result

    def test_pii_without_encryption_warning(self):
        """Test warning when PII is stored without encryption."""
        code = """
def save_user(email: str):
    db.save(email)
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()

        # Should flag PII stored without encryption
        pii_findings = [f for f in result["findings"]
                       if f["category"] == "pii_handling" and "encrypt" in f.get("recommendation", "").lower()]
        # This is expected behavior - the analyzer should recommend encryption


# ─── JavaScript Analyzer Tests ──────────────────────────────────────────────


class TestJavaScriptAnalyzer:
    """Tests for JavaScript/TypeScript analysis."""

    def test_es6_import_detection(self):
        """Test ES6 import detection."""
        code = """
import openai from 'openai';
import { Client } from '@anthropic-ai/sdk';
import stripe from 'stripe';
"""
        analyzer = JavaScriptAnalyzer(code)
        result = analyzer.analyze()

        assert result["imports_found"] >= 3
        xborder = [f for f in result["findings"] if f["category"] == "cross_border"]
        assert len(xborder) >= 2

    def test_require_import_detection(self):
        """Test CommonJS require detection."""
        code = """
const openai = require('openai');
const aws = require('aws-sdk');
const stripe = require('stripe');
"""
        analyzer = JavaScriptAnalyzer(code)
        result = analyzer.analyze()

        assert result["imports_found"] >= 3

    def test_function_extraction(self):
        """Test standard function extraction."""
        code = """
function processUser(email, phoneNumber) {
    return { email, phoneNumber };
}

async function fetchData(userId) {
    return await db.get(userId);
}
"""
        analyzer = JavaScriptAnalyzer(code)
        result = analyzer.analyze()

        assert "processUser" in result["functions"]
        assert "fetchData" in result["functions"]

    def test_arrow_function_extraction(self):
        """Test arrow function extraction."""
        code = """
const getUser = (userId) => {
    return db.get(userId);
};

const processEmail = async (email) => {
    return email.toLowerCase();
};
"""
        analyzer = JavaScriptAnalyzer(code)
        result = analyzer.analyze()

        assert "getUser" in result["functions"]
        assert "processEmail" in result["functions"]

    def test_pii_parameter_detection(self):
        """Test PII detection in function parameters."""
        code = """
function processUser(firstName, lastName, emailAddress) {
    return { firstName, lastName, emailAddress };
}
"""
        analyzer = JavaScriptAnalyzer(code)
        result = analyzer.analyze()

        pii_findings = [f for f in result["findings"] if f["category"] == "pii_handling"]
        assert len(pii_findings) >= 2

    def test_console_log_pii_detection(self):
        """Test console.log PII detection."""
        code = """
function processUser(email) {
    console.log("Processing:", email);
    return email;
}
"""
        analyzer = JavaScriptAnalyzer(code)
        result = analyzer.analyze()

        log_findings = [f for f in result["findings"] if f["category"] == "pii_logging"]
        assert len(log_findings) >= 1

    def test_dsr_function_detection(self):
        """Test DSR function pattern detection."""
        code = """
const deleteUserData = async (userId) => {
    await db.delete(userId);
};

function exportUserData(userId) {
    return db.getAll(userId);
}

const unsubscribe = (email) => {
    preferences.update(email, { subscribed: false });
};
"""
        analyzer = JavaScriptAnalyzer(code)
        result = analyzer.analyze()

        dsr_findings = [f for f in result["findings"] if f["category"] == "dsr_capability"]
        assert len(dsr_findings) >= 2

    def test_comment_stripping(self):
        """Test that comments are stripped and don't trigger false positives."""
        code = """
// This function handles email processing
/* 
 * email: the user's email address
 * This is a multi-line comment
 */
function process(data) {
    return data;
}
"""
        analyzer = JavaScriptAnalyzer(code)
        result = analyzer.analyze()

        # Should not detect PII in comments
        pii_findings = [f for f in result["findings"] if f["category"] == "pii_handling"]
        # Only real parameters should be flagged, not comments
        assert all(f["location"]["function"] == "process" for f in pii_findings if "function" in f["location"])

    def test_typescript_detection(self):
        """Test TypeScript-specific features."""
        code = """
interface User {
    email: string;
    name: string;
}

function processUser(user: User): Promise<void> {
    return db.save(user);
}
"""
        analyzer = JavaScriptAnalyzer(code, is_typescript=True)
        result = analyzer.analyze()

        assert result["language"] == "typescript"


# ─── Language Detection Tests ───────────────────────────────────────────────


class TestLanguageDetection:
    """Tests for automatic language detection."""

    def test_detect_python_by_extension(self):
        """Test Python detection by file extension."""
        assert detect_language("", "main.py") == "python"
        assert detect_language("", "test.PY") == "python"

    def test_detect_javascript_by_extension(self):
        """Test JavaScript detection by file extension."""
        assert detect_language("", "app.js") == "javascript"
        assert detect_language("", "index.mjs") == "javascript"
        assert detect_language("", "server.cjs") == "javascript"

    def test_detect_typescript_by_extension(self):
        """Test TypeScript detection by file extension."""
        assert detect_language("", "app.ts") == "typescript"
        assert detect_language("", "component.tsx") == "typescript"

    def test_detect_python_by_content(self):
        """Test Python detection by code content."""
        code = """
import os
from typing import List

def main():
    pass

class MyClass:
    pass
"""
        assert detect_language(code) == "python"

    def test_detect_javascript_by_content(self):
        """Test JavaScript detection by code content."""
        code = """
const express = require('express');
let app = express();

function handler(req, res) {
    res.send('Hello');
}
"""
        assert detect_language(code) == "javascript"

    def test_detect_typescript_by_content(self):
        """Test TypeScript detection by code content."""
        code = """
interface User {
    name: string;
    age: number;
}

const getUser = (id: string): Promise<User> => {
    return fetch(id);
};
"""
        assert detect_language(code) == "typescript"


# ─── Integration Tests ──────────────────────────────────────────────────────


class TestASTIntegration:
    """Integration tests for the AST analyzer."""

    @pytest.mark.asyncio
    async def test_analyze_code_ast_python(self, data_loader):
        """Test full Python analysis via main function."""
        code = """
import openai

def export_user_data(email: str):
    print(f"Exporting data for {email}")
    return openai.get_data(email)
"""
        result = await analyze_code_ast_impl(
            code, "test.py", None, False, data_loader
        )

        # Result should be JSON with disclaimer
        assert "disclaimer" in result.lower() or "DISCLAIMER" in result
        data = extract_json_from_response(result)

        assert data["language"] == "python"
        assert data["parse_success"] is True
        assert data["summary"]["total_findings"] >= 1

    @pytest.mark.asyncio
    async def test_analyze_code_ast_javascript(self, data_loader):
        """Test full JavaScript analysis via main function."""
        code = """
const openai = require('openai');

function deleteUserData(userId) {
    return db.delete(userId);
}
"""
        result = await analyze_code_ast_impl(
            code, "app.js", None, False, data_loader
        )

        data = extract_json_from_response(result)

        assert data["language"] == "javascript"
        assert data["parse_success"] is True

    @pytest.mark.asyncio
    async def test_analyze_code_ast_deep_analysis(self, data_loader):
        """Test deep analysis mode includes extra data."""
        code = """
def process(email: str):
    return email
"""
        result = await analyze_code_ast_impl(
            code, "test.py", None, True, data_loader
        )

        data = extract_json_from_response(result)

        assert "functions" in data
        assert "imports" in data
        assert "call_graph" in data

    @pytest.mark.asyncio
    async def test_analyze_code_ast_unsupported_language(self, data_loader):
        """Test handling of unsupported language."""
        result = await analyze_code_ast_impl(
            "some code", None, "rust", False, data_loader
        )

        data = extract_json_from_response(result)

        assert data["parse_success"] is False
        assert "not supported" in data.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_get_ast_capabilities(self, data_loader):
        """Test capabilities endpoint."""
        result = await get_ast_capabilities_impl(data_loader)

        data = extract_json_from_response(result)

        assert "supported_languages" in data
        assert "python" in data["supported_languages"]
        assert "javascript" in data["supported_languages"]
        assert "typescript" in data["supported_languages"]
        assert "analysis_categories" in data


# ─── Pattern Coverage Tests ─────────────────────────────────────────────────


class TestPatternCoverage:
    """Tests to verify pattern dictionaries are complete."""

    def test_pii_indicators_not_empty(self):
        """Test that PII indicators are defined."""
        assert len(PII_INDICATORS) > 0
        for category, terms in PII_INDICATORS.items():
            assert len(terms) > 0, f"Category {category} is empty"

    def test_all_pii_terms_populated(self):
        """Test that ALL_PII_TERMS is populated."""
        assert len(ALL_PII_TERMS) > 20

    def test_dsr_patterns_cover_all_rights(self):
        """Test that DSR patterns cover all 7 rights."""
        expected_rights = ["access", "erasure", "rectification", "portability", "restriction", "objection"]
        for right in expected_rights:
            assert right in DSR_FUNCTION_PATTERNS, f"Missing DSR pattern for {right}"
            assert len(DSR_FUNCTION_PATTERNS[right]["patterns"]) > 0

    def test_cross_border_imports_defined(self):
        """Test that cross-border import patterns are defined."""
        assert len(CROSS_BORDER_IMPORTS) > 5
        for module, info in CROSS_BORDER_IMPORTS.items():
            # Now tuples: (provider, region, risk, justification)
            assert len(info) == 4, f"Expected tuple of 4 for {module}"
            provider, region, risk, justification = info
            assert provider, f"Missing provider for {module}"
            assert region, f"Missing region for {module}"
            assert risk in ("HIGH", "MEDIUM", "LOW"), f"Invalid risk for {module}"
            assert isinstance(justification, str), f"Justification should be string for {module}"


# ─── Edge Cases Tests ───────────────────────────────────────────────────────


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_code(self):
        """Test handling of empty code."""
        analyzer = PythonASTAnalyzer("")
        result = analyzer.analyze()
        assert result["parse_success"] is True
        assert result["functions_analyzed"] == 0

    def test_whitespace_only_code(self):
        """Test handling of whitespace-only code."""
        analyzer = PythonASTAnalyzer("   \n\n   \t\t\n")
        result = analyzer.analyze()
        assert result["parse_success"] is True

    def test_unicode_in_code(self):
        """Test handling of unicode characters."""
        code = """
def grüß_gott(名前: str):
    return f"Hallo, {名前}!"
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()
        assert result["parse_success"] is True

    def test_very_long_code(self):
        """Test handling of very long code."""
        code = "\n".join([f"def func_{i}(): pass" for i in range(100)])
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()
        assert result["parse_success"] is True
        assert result["functions_analyzed"] == 100

    def test_nested_functions(self):
        """Test handling of nested functions."""
        code = """
def outer():
    def inner():
        def innermost():
            pass
        return innermost
    return inner
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()
        assert result["parse_success"] is True

    def test_class_with_methods(self):
        """Test extraction of class methods."""
        code = """
class UserService:
    def __init__(self):
        pass

    def get_user(self, user_id):
        return self.db.get(user_id)

    async def delete_user(self, user_id):
        await self.db.delete(user_id)
"""
        analyzer = PythonASTAnalyzer(code)
        result = analyzer.analyze()
        assert result["parse_success"] is True

    def test_js_minified_code(self):
        """Test handling of minified JavaScript."""
        code = "const a=()=>{};const b=require('openai');function c(d){return d;}"
        analyzer = JavaScriptAnalyzer(code)
        result = analyzer.analyze()
        # Should still detect imports
        assert result["imports_found"] >= 1

    def test_mixed_quotes_js(self):
        """Test JavaScript with mixed quote styles."""
        code = """
const a = require("openai");
const b = require('stripe');
const c = `template`;
"""
        analyzer = JavaScriptAnalyzer(code)
        result = analyzer.analyze()
        assert result["imports_found"] >= 2


# ─── Java Analyzer Tests ────────────────────────────────────────────────────


class TestJavaAnalyzer:
    """Tests for Java code analysis."""

    def test_parse_valid_java(self):
        """Test parsing valid Java code."""
        code = """
import java.util.List;

public class UserService {
    public void processUser(String email) {
        System.out.println("Processing");
    }
}
"""
        analyzer = JavaAnalyzer(code)
        result = analyzer.analyze()
        assert result["language"] == "java"
        assert result["parse_success"] is True

    def test_detect_java_imports(self):
        """Test Java import detection."""
        code = """
import com.openai.OpenAI;
import com.amazonaws.services.s3.AmazonS3;
import java.util.ArrayList;
"""
        analyzer = JavaAnalyzer(code)
        result = analyzer.analyze()
        assert result["imports_found"] == 3

    def test_detect_cross_border_java(self):
        """Test cross-border detection in Java imports."""
        code = """
import com.openai.client.OpenAIClient;
import com.stripe.Stripe;
"""
        analyzer = JavaAnalyzer(code)
        result = analyzer.analyze()
        cross_border = [f for f in result["findings"] if f["category"] == "cross_border"]
        assert len(cross_border) == 2

    def test_detect_pii_in_java_method(self):
        """Test PII detection in Java method parameters."""
        code = """
public class UserController {
    public void updateUser(String email, String phoneNumber) {
        // Update user
    }
}
"""
        analyzer = JavaAnalyzer(code)
        result = analyzer.analyze()
        assert result["pii_variables_detected"] == 2

    def test_detect_java_logging_pii(self):
        """Test detection of PII in Java logging."""
        code = """
public class UserService {
    public void processEmail(String email) {
        logger.info("Processing " + email);
    }
}
"""
        analyzer = JavaAnalyzer(code)
        result = analyzer.analyze()
        log_findings = [f for f in result["findings"] if f["category"] == "pii_logging"]
        assert len(log_findings) == 1

    def test_detect_system_out_pii(self):
        """Test detection of PII in System.out."""
        code = """
public class Debug {
    public void showEmail(String email) {
        System.out.println(email);
    }
}
"""
        analyzer = JavaAnalyzer(code)
        result = analyzer.analyze()
        log_findings = [f for f in result["findings"] if f["category"] == "pii_logging"]
        assert len(log_findings) == 1

    def test_detect_java_dsr_methods(self):
        """Test DSR method detection in Java."""
        code = """
public class UserService {
    public void deleteUserData(String userId) {
        // Delete user data
    }

    public String exportUserData(String userId) {
        return "data";
    }
}
"""
        analyzer = JavaAnalyzer(code)
        result = analyzer.analyze()
        dsr_findings = [f for f in result["findings"] if f["category"] == "dsr_capability"]
        assert len(dsr_findings) >= 1

    def test_java_comment_stripping(self):
        """Test comments are not detected as imports."""
        code = """
// import com.openai.OpenAI;
/* import com.stripe.Stripe; */
import java.util.List;
"""
        analyzer = JavaAnalyzer(code)
        result = analyzer.analyze()
        assert result["imports_found"] == 1

    def test_java_static_import(self):
        """Test static import detection."""
        code = """
import static java.lang.Math.PI;
import java.util.List;
"""
        analyzer = JavaAnalyzer(code)
        result = analyzer.analyze()
        assert result["imports_found"] == 2


# ─── C# Analyzer Tests ──────────────────────────────────────────────────────


class TestCSharpAnalyzer:
    """Tests for C# code analysis."""

    def test_parse_valid_csharp(self):
        """Test parsing valid C# code."""
        code = """
using System;

namespace MyApp {
    public class UserService {
        public void ProcessUser(string email) {
            Console.WriteLine("Processing");
        }
    }
}
"""
        analyzer = CSharpAnalyzer(code)
        result = analyzer.analyze()
        assert result["language"] == "csharp"
        assert result["parse_success"] is True

    def test_detect_csharp_using(self):
        """Test C# using directive detection."""
        code = """
using OpenAI;
using Amazon.S3;
using System.Collections.Generic;
"""
        analyzer = CSharpAnalyzer(code)
        result = analyzer.analyze()
        assert result["imports_found"] == 3

    def test_detect_cross_border_csharp(self):
        """Test cross-border detection in C# using directives."""
        code = """
using OpenAI.GPT;
using Stripe.Net;
"""
        analyzer = CSharpAnalyzer(code)
        result = analyzer.analyze()
        cross_border = [f for f in result["findings"] if f["category"] == "cross_border"]
        assert len(cross_border) == 2

    def test_detect_pii_in_csharp_method(self):
        """Test PII detection in C# method parameters."""
        code = """
public class UserController {
    public void UpdateUser(string email, string phoneNumber) {
        // Update user
    }
}
"""
        analyzer = CSharpAnalyzer(code)
        result = analyzer.analyze()
        assert result["pii_variables_detected"] == 2

    def test_detect_csharp_console_logging_pii(self):
        """Test detection of PII in C# Console logging."""
        code = """
public class UserService {
    public void ProcessEmail(string email) {
        Console.WriteLine(email);
    }
}
"""
        analyzer = CSharpAnalyzer(code)
        result = analyzer.analyze()
        log_findings = [f for f in result["findings"] if f["category"] == "pii_logging"]
        assert len(log_findings) == 1

    def test_detect_csharp_ilogger_pii(self):
        """Test detection of PII in ILogger logging."""
        code = """
public class UserService {
    public void ProcessEmail(string email) {
        _logger.LogInformation("Processing " + email);
    }
}
"""
        analyzer = CSharpAnalyzer(code)
        result = analyzer.analyze()
        log_findings = [f for f in result["findings"] if f["category"] == "pii_logging"]
        assert len(log_findings) == 1

    def test_detect_csharp_dsr_methods(self):
        """Test DSR method detection in C#."""
        code = """
public class UserService {
    public async Task DeleteUserDataAsync(string userId) {
        // Delete user data
    }

    public async Task<string> ExportDataAsync(string userId) {
        return "data";
    }
}
"""
        analyzer = CSharpAnalyzer(code)
        result = analyzer.analyze()
        dsr_findings = [f for f in result["findings"] if f["category"] == "dsr_capability"]
        assert len(dsr_findings) >= 1

    def test_csharp_comment_stripping(self):
        """Test comments are not detected as using directives."""
        code = """
// using OpenAI;
/* using Stripe; */
using System.Collections.Generic;
"""
        analyzer = CSharpAnalyzer(code)
        result = analyzer.analyze()
        assert result["imports_found"] == 1

    def test_csharp_async_method(self):
        """Test async method extraction."""
        code = """
public class Service {
    public async Task<string> GetUserAsync(string userId) {
        return await _db.GetAsync(userId);
    }
}
"""
        analyzer = CSharpAnalyzer(code)
        result = analyzer.analyze()
        assert result["functions_analyzed"] >= 1

    def test_csharp_verbatim_string(self):
        """Test handling of C# verbatim strings."""
        code = '''
using System;

public class Test {
    string path = @"C:\\Users\\Test";
    string query = @"SELECT * FROM users WHERE email = 'test'";
}
'''
        analyzer = CSharpAnalyzer(code)
        result = analyzer.analyze()
        assert result["parse_success"] is True


# ─── Go Analyzer Tests ──────────────────────────────────────────────────────


class TestGoAnalyzer:
    """Tests for Go code analysis."""

    def test_parse_valid_go(self):
        """Test parsing valid Go code."""
        code = """
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
"""
        analyzer = GoAnalyzer(code)
        result = analyzer.analyze()
        assert result["language"] == "go"
        assert result["parse_success"] is True

    def test_detect_go_imports_single(self):
        """Test Go single import detection."""
        code = '''
package main

import "fmt"
import "os"
'''
        analyzer = GoAnalyzer(code)
        result = analyzer.analyze()
        assert result["imports_found"] == 2

    def test_detect_go_imports_block(self):
        """Test Go import block detection."""
        code = '''
package main

import (
    "fmt"
    "os"
    "github.com/stripe/stripe-go/v72"
)
'''
        analyzer = GoAnalyzer(code)
        result = analyzer.analyze()
        assert result["imports_found"] == 3

    def test_detect_cross_border_go(self):
        """Test cross-border detection in Go imports."""
        code = '''
package main

import (
    "github.com/sashabaranov/go-openai"
    "github.com/stripe/stripe-go/v72"
)
'''
        analyzer = GoAnalyzer(code)
        result = analyzer.analyze()
        cross_border = [f for f in result["findings"] if f["category"] == "cross_border"]
        assert len(cross_border) == 2

    def test_detect_pii_in_go_function(self):
        """Test PII detection in Go function parameters."""
        code = """
package main

func processUser(email string, phoneNumber string) error {
    return nil
}
"""
        analyzer = GoAnalyzer(code)
        result = analyzer.analyze()
        assert result["pii_variables_detected"] == 2

    def test_detect_go_fmt_logging_pii(self):
        """Test detection of PII in fmt logging."""
        code = """
package main

import "fmt"

func processEmail(email string) {
    fmt.Println(email)
}
"""
        analyzer = GoAnalyzer(code)
        result = analyzer.analyze()
        log_findings = [f for f in result["findings"] if f["category"] == "pii_logging"]
        assert len(log_findings) == 1

    def test_detect_go_log_pii(self):
        """Test detection of PII in log package."""
        code = """
package main

import "log"

func processEmail(email string) {
    log.Printf("Received: %s", email)
}
"""
        analyzer = GoAnalyzer(code)
        result = analyzer.analyze()
        log_findings = [f for f in result["findings"] if f["category"] == "pii_logging"]
        assert len(log_findings) == 1

    def test_detect_go_dsr_functions(self):
        """Test DSR function detection in Go."""
        code = """
package main

func DeleteUserData(userId string) error {
    return nil
}

func ExportDataToJSON(userId string) ([]byte, error) {
    return nil, nil
}
"""
        analyzer = GoAnalyzer(code)
        result = analyzer.analyze()
        dsr_findings = [f for f in result["findings"] if f["category"] == "dsr_capability"]
        assert len(dsr_findings) >= 1

    def test_go_comment_stripping(self):
        """Test comments are not detected as imports."""
        code = '''
package main

// import "github.com/openai/openai-go"
/* import "github.com/stripe/stripe-go" */
import "fmt"
'''
        analyzer = GoAnalyzer(code)
        result = analyzer.analyze()
        assert result["imports_found"] == 1

    def test_go_method_receiver(self):
        """Test function with method receiver."""
        code = """
package main

type UserService struct{}

func (s *UserService) GetUser(userId string) *User {
    return nil
}
"""
        analyzer = GoAnalyzer(code)
        result = analyzer.analyze()
        assert result["functions_analyzed"] >= 1

    def test_go_raw_string(self):
        """Test handling of Go raw strings."""
        code = '''
package main

func main() {
    query := `SELECT * FROM users WHERE email = 'test'`
    path := `C:\\Users\\Test`
}
'''
        analyzer = GoAnalyzer(code)
        result = analyzer.analyze()
        assert result["parse_success"] is True


# ─── Language Detection Extended Tests ──────────────────────────────────────


class TestLanguageDetectionExtended:
    """Extended tests for language detection including new languages."""

    def test_detect_java_by_extension(self):
        """Test Java detection by file extension."""
        assert detect_language("", "UserService.java") == "java"

    def test_detect_csharp_by_extension(self):
        """Test C# detection by file extension."""
        assert detect_language("", "UserService.cs") == "csharp"

    def test_detect_go_by_extension(self):
        """Test Go detection by file extension."""
        assert detect_language("", "main.go") == "go"

    def test_detect_java_by_heuristics(self):
        """Test Java detection by code heuristics."""
        code = """
public class UserService {
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
"""
        assert detect_language(code) == "java"

    def test_detect_csharp_by_heuristics(self):
        """Test C# detection by code heuristics."""
        code = """
using System;
namespace MyApp {
    public class Program {
        public async Task RunAsync() {
            Console.WriteLine("Hello");
        }
    }
}
"""
        assert detect_language(code) == "csharp"

    def test_detect_go_by_heuristics(self):
        """Test Go detection by code heuristics."""
        code = """
package main

import (
    "fmt"
)

func main() {
    fmt.Println("Hello")
}
"""
        assert detect_language(code) == "go"


# ─── Integration Tests for New Languages ────────────────────────────────────


class TestASTIntegrationExtended:
    """Integration tests for AST analysis with new languages."""

    @pytest.mark.asyncio
    async def test_analyze_java_code(self, data_loader):
        """Test full Java analysis via API."""
        code = """
import com.openai.OpenAI;

public class UserService {
    public void processUser(String email) {
        System.out.println(email);
    }
}
"""
        result = await analyze_code_ast_impl(
            code=code,
            file_path="UserService.java",
            language=None,
            deep_analysis=False,
            data_loader=data_loader,
        )
        data = extract_json_from_response(result)
        assert data["language"] == "java"
        assert data["parse_success"] is True

    @pytest.mark.asyncio
    async def test_analyze_csharp_code(self, data_loader):
        """Test full C# analysis via API."""
        code = """
using OpenAI;

public class UserService {
    public void ProcessUser(string email) {
        Console.WriteLine(email);
    }
}
"""
        result = await analyze_code_ast_impl(
            code=code,
            file_path="UserService.cs",
            language=None,
            deep_analysis=False,
            data_loader=data_loader,
        )
        data = extract_json_from_response(result)
        assert data["language"] == "csharp"
        assert data["parse_success"] is True

    @pytest.mark.asyncio
    async def test_analyze_go_code(self, data_loader):
        """Test full Go analysis via API."""
        code = '''
package main

import (
    "fmt"
    "github.com/sashabaranov/go-openai"
)

func processUser(email string) {
    fmt.Println(email)
}
'''
        result = await analyze_code_ast_impl(
            code=code,
            file_path="main.go",
            language=None,
            deep_analysis=False,
            data_loader=data_loader,
        )
        data = extract_json_from_response(result)
        assert data["language"] == "go"
        assert data["parse_success"] is True

    @pytest.mark.asyncio
    async def test_capabilities_include_new_languages(self, data_loader):
        """Test that capabilities endpoint includes new languages."""
        result = await get_ast_capabilities_impl(data_loader)
        data = extract_json_from_response(result)
        supported = data["supported_languages"]
        assert "java" in supported
        assert "csharp" in supported
        assert "go" in supported
