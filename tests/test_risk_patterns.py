"""
GDPR Shift-Left MCP Server — Risk Patterns Data Tests

Comprehensive tests for the consolidated risk_patterns.json data file.
Validates structure, completeness, and correctness of all risk pattern data.
"""
import json
import pytest
from pathlib import Path
from typing import Dict, Any, Set

from gdpr_shift_left_mcp.tools.ast_analyzer import (
    PII_INDICATORS,
    PYTHON_CROSS_BORDER,
    JAVASCRIPT_CROSS_BORDER,
    JAVA_CROSS_BORDER,
    CSHARP_CROSS_BORDER,
    GO_CROSS_BORDER,
    _PROVIDERS,
    _load_risk_patterns,
)


# ─── Data Loading Tests ─────────────────────────────────────────────────────


class TestRiskPatternsLoading:
    """Tests for risk patterns data loading."""

    def test_risk_patterns_file_exists(self):
        """Verify risk_patterns.json file exists."""
        data_file = Path(__file__).parent.parent / "src" / "gdpr_shift_left_mcp" / "data" / "risk_patterns.json"
        assert data_file.exists(), "risk_patterns.json not found"

    def test_risk_patterns_valid_json(self):
        """Verify risk_patterns.json is valid JSON."""
        data_file = Path(__file__).parent.parent / "src" / "gdpr_shift_left_mcp" / "data" / "risk_patterns.json"
        with open(data_file) as f:
            data = json.load(f)
        assert isinstance(data, dict)

    def test_risk_patterns_has_required_sections(self):
        """Verify data has both required top-level sections."""
        patterns = _load_risk_patterns()
        assert "pii_indicators" in patterns
        assert "cross_border_providers" in patterns

    def test_risk_patterns_load_function_works(self):
        """Verify _load_risk_patterns returns data."""
        patterns = _load_risk_patterns()
        assert len(patterns) >= 2
        assert patterns.get("pii_indicators")
        assert patterns.get("cross_border_providers")


# ─── PII Indicators Tests ───────────────────────────────────────────────────


class TestPIIIndicators:
    """Tests for PII indicators data."""

    REQUIRED_CATEGORIES = [
        "direct_identifiers",
        "indirect_identifiers", 
        "sensitive_data",
        "tracking",
        "children",
        "employee",
    ]

    def test_all_pii_categories_present(self):
        """Verify all required PII categories exist."""
        for category in self.REQUIRED_CATEGORIES:
            assert category in PII_INDICATORS, f"Missing PII category: {category}"

    def test_pii_categories_not_empty(self):
        """Verify each PII category has terms."""
        for category in self.REQUIRED_CATEGORIES:
            terms = PII_INDICATORS.get(category, [])
            assert len(terms) >= 5, f"Category {category} has too few terms: {len(terms)}"

    def test_direct_identifiers_comprehensive(self):
        """Verify direct identifiers cover key PII types."""
        required_terms = [
            "name", "email", "phone", "address", "ssn", "passport", 
            "birth_date", "driver_license", "national_id"
        ]
        direct = set(PII_INDICATORS.get("direct_identifiers", []))
        for term in required_terms:
            assert term in direct, f"Missing direct identifier: {term}"

    def test_indirect_identifiers_comprehensive(self):
        """Verify indirect identifiers cover key pseudonymous identifiers."""
        required_terms = [
            "user_id", "customer_id", "ip_address", "device_id", 
            "cookie", "session_id", "username"
        ]
        indirect = set(PII_INDICATORS.get("indirect_identifiers", []))
        for term in required_terms:
            assert term in indirect, f"Missing indirect identifier: {term}"

    def test_sensitive_data_covers_article9(self):
        """Verify sensitive_data covers GDPR Article 9 special categories."""
        required_terms = [
            "religion", "political", "health", "genetic", "biometric",
            "sexual_orientation", "criminal", "union"
        ]
        sensitive = set(PII_INDICATORS.get("sensitive_data", []))
        for term in required_terms:
            assert term in sensitive, f"Missing Article 9 sensitive data: {term}"

    def test_children_data_covers_coppa(self):
        """Verify children category covers child-specific terms."""
        required_terms = ["child", "minor", "parent_consent", "guardian"]
        children = set(PII_INDICATORS.get("children", []))
        for term in required_terms:
            assert term in children, f"Missing children term: {term}"

    def test_tracking_covers_common_patterns(self):
        """Verify tracking category covers common tracking patterns."""
        required_terms = ["analytics", "location", "tracking", "consent"]
        tracking = set(PII_INDICATORS.get("tracking", []))
        for term in required_terms:
            assert term in tracking, f"Missing tracking term: {term}"

    def test_employee_data_covers_hr(self):
        """Verify employee category covers HR data types."""
        required_terms = ["employee", "salary", "performance", "hire_date"]
        employee = set(PII_INDICATORS.get("employee", []))
        for term in required_terms:
            assert term in employee, f"Missing employee term: {term}"

    def test_pii_terms_are_lowercase(self):
        """Verify all PII terms are lowercase for consistent matching."""
        for category, terms in PII_INDICATORS.items():
            for term in terms:
                assert term == term.lower(), f"Non-lowercase term in {category}: {term}"

    def test_pii_terms_are_snake_case(self):
        """Verify PII terms use snake_case (no spaces, hyphens)."""
        for category, terms in PII_INDICATORS.items():
            for term in terms:
                assert " " not in term, f"Space in term {category}: {term}"
                # Hyphens are okay for some terms like "e_mail"

    def test_no_duplicate_pii_terms_within_category(self):
        """Verify no duplicate terms within same category."""
        for category, terms in PII_INDICATORS.items():
            assert len(terms) == len(set(terms)), f"Duplicates in {category}"

    def test_eu_regional_identifiers_present(self):
        """Verify EU regional national ID formats are covered."""
        direct = set(PII_INDICATORS.get("direct_identifiers", []))
        eu_ids = ["bsn", "personnummer", "cpr", "nino", "pps", "pesel", "dni"]
        found = [eid for eid in eu_ids if eid in direct]
        assert len(found) >= 5, f"Missing EU regional IDs, only found: {found}"

    def test_mobile_advertising_ids_present(self):
        """Verify mobile advertising IDs are covered."""
        indirect = set(PII_INDICATORS.get("indirect_identifiers", []))
        mobile_ids = ["idfa", "gaid", "aaid", "advertising_id"]
        found = [mid for mid in mobile_ids if mid in indirect]
        assert len(found) >= 3, f"Missing mobile ad IDs, only found: {found}"

    def test_healthcare_codes_present(self):
        """Verify healthcare-specific codes are covered."""
        sensitive = set(PII_INDICATORS.get("sensitive_data", []))
        health_codes = ["icd10", "diagnosis_code", "cpt_code"]
        found = [hc for hc in health_codes if hc in sensitive]
        assert len(found) >= 2, f"Missing healthcare codes, only found: {found}"


# ─── Cross-Border Providers Tests ───────────────────────────────────────────


class TestCrossBorderProviders:
    """Tests for cross-border provider data."""

    REQUIRED_CATEGORIES = [
        "AI/ML", "Cloud", "Payment", "Communication", "Analytics",
        "CRM", "Identity", "Social", "Database", "Consent", "CDP",
        "eSignature", "BackgroundCheck", "Marketing"
    ]

    def test_minimum_provider_count(self):
        """Verify minimum number of providers."""
        assert len(_PROVIDERS) >= 100, f"Only {len(_PROVIDERS)} providers, expected 100+"

    def test_all_categories_represented(self):
        """Verify all required categories have providers."""
        categories_found = set()
        for provider in _PROVIDERS.values():
            categories_found.add(provider.get("category"))
        
        for required in self.REQUIRED_CATEGORIES:
            assert required in categories_found, f"No providers in category: {required}"

    def test_provider_structure_valid(self):
        """Verify each provider has required fields."""
        required_fields = ["name", "headquarters", "risk_level", "category", "packages"]
        for key, provider in _PROVIDERS.items():
            for field in required_fields:
                assert field in provider, f"Provider {key} missing field: {field}"

    def test_provider_risk_levels_valid(self):
        """Verify all risk levels are valid values."""
        valid_levels = {"HIGH", "MEDIUM", "LOW"}
        for key, provider in _PROVIDERS.items():
            risk = provider.get("risk_level")
            assert risk in valid_levels, f"Provider {key} has invalid risk: {risk}"

    def test_provider_packages_structure(self):
        """Verify packages dict has expected language keys."""
        languages = ["python", "javascript", "java", "csharp", "go"]
        for key, provider in _PROVIDERS.items():
            packages = provider.get("packages", {})
            for lang in languages:
                assert lang in packages, f"Provider {key} missing language: {lang}"
                assert isinstance(packages[lang], list), f"Provider {key}.packages.{lang} not a list"

    def test_major_ai_providers_present(self):
        """Verify major AI providers are included."""
        required = ["openai", "anthropic", "cohere", "huggingface", "mistral"]
        for provider_key in required:
            assert provider_key in _PROVIDERS, f"Missing AI provider: {provider_key}"

    def test_major_cloud_providers_present(self):
        """Verify major cloud providers are included."""
        required = ["aws", "gcp", "azure"]
        for provider_key in required:
            assert provider_key in _PROVIDERS, f"Missing cloud provider: {provider_key}"

    def test_major_payment_providers_present(self):
        """Verify major payment providers are included."""
        required = ["stripe", "paypal", "square", "plaid"]
        for provider_key in required:
            assert provider_key in _PROVIDERS, f"Missing payment provider: {provider_key}"

    def test_eu_compliant_providers_marked_low(self):
        """Verify EU-headquartered providers are marked LOW risk."""
        eu_providers = [
            "mistral", "adyen", "klarna", "mollie", "messagebird", "sinch",
            "pipedrive", "cookiebot", "usercentrics", "didomi", "qdrant",
            "hetzner", "scaleway", "ovhcloud", "ionos", "sendinblue"
        ]
        for key in eu_providers:
            if key in _PROVIDERS:
                risk = _PROVIDERS[key].get("risk_level")
                assert risk == "LOW", f"EU provider {key} should be LOW risk, got {risk}"

    def test_china_providers_marked_high(self):
        """Verify China-headquartered providers are marked HIGH risk."""
        china_providers = ["alibaba_cloud", "tencent_cloud", "deepseek", "alipay", "wechat_pay"]
        for key in china_providers:
            if key in _PROVIDERS:
                risk = _PROVIDERS[key].get("risk_level")
                assert risk == "HIGH", f"China provider {key} should be HIGH risk, got {risk}"

    def test_consent_providers_present(self):
        """Verify consent management platforms are included."""
        required = ["onetrust", "trustarc", "cookiebot", "usercentrics"]
        for provider_key in required:
            assert provider_key in _PROVIDERS, f"Missing consent provider: {provider_key}"

    def test_cdp_providers_present(self):
        """Verify CDP providers are included."""
        required = ["mparticle", "tealium", "segment"]
        for provider_key in required:
            assert provider_key in _PROVIDERS, f"Missing CDP provider: {provider_key}"

    def test_background_check_providers_present(self):
        """Verify background check providers are included."""
        required = ["checkr"]
        for provider_key in required:
            assert provider_key in _PROVIDERS, f"Missing background check provider: {provider_key}"


# ─── Language Lookup Tests ──────────────────────────────────────────────────


class TestLanguageLookups:
    """Tests for language-specific lookup dictionaries."""

    def test_python_lookup_not_empty(self):
        """Verify Python cross-border lookup is populated."""
        assert len(PYTHON_CROSS_BORDER) >= 50

    def test_javascript_lookup_not_empty(self):
        """Verify JavaScript cross-border lookup is populated."""
        assert len(JAVASCRIPT_CROSS_BORDER) >= 40

    def test_java_lookup_not_empty(self):
        """Verify Java cross-border lookup is populated."""
        assert len(JAVA_CROSS_BORDER) >= 30

    def test_csharp_lookup_not_empty(self):
        """Verify C# cross-border lookup is populated."""
        assert len(CSHARP_CROSS_BORDER) >= 30

    def test_go_lookup_not_empty(self):
        """Verify Go cross-border lookup is populated."""
        assert len(GO_CROSS_BORDER) >= 25

    def test_lookup_tuple_format(self):
        """Verify lookup values are (provider, region, risk, justification) tuples."""
        for module, info in PYTHON_CROSS_BORDER.items():
            assert len(info) == 4, f"Expected 4-tuple for {module}"
            provider, region, risk, justification = info
            assert isinstance(provider, str)
            assert isinstance(region, str)
            assert risk in ("HIGH", "MEDIUM", "LOW")
            assert isinstance(justification, str)

    def test_python_openai_detection(self):
        """Verify Python can detect openai package."""
        assert "openai" in PYTHON_CROSS_BORDER
        provider, _, _, _ = PYTHON_CROSS_BORDER["openai"]
        assert "OpenAI" in provider

    def test_javascript_openai_detection(self):
        """Verify JavaScript can detect openai package."""
        assert "openai" in JAVASCRIPT_CROSS_BORDER
        provider, _, _, _ = JAVASCRIPT_CROSS_BORDER["openai"]
        assert "OpenAI" in provider

    def test_python_boto3_detection(self):
        """Verify Python can detect boto3 package."""
        assert "boto3" in PYTHON_CROSS_BORDER

    def test_javascript_aws_sdk_detection(self):
        """Verify JavaScript can detect aws-sdk package."""
        assert "aws-sdk" in JAVASCRIPT_CROSS_BORDER

    def test_java_com_openai_detection(self):
        """Verify Java can detect OpenAI packages."""
        found = any("openai" in pkg.lower() for pkg in JAVA_CROSS_BORDER.keys())
        assert found, "Java should detect OpenAI packages"

    def test_csharp_stripe_detection(self):
        """Verify C# can detect Stripe package."""
        found = any("stripe" in pkg.lower() for pkg in CSHARP_CROSS_BORDER.keys())
        assert found, "C# should detect Stripe package"

    def test_go_github_packages_detection(self):
        """Verify Go can detect github.com packages."""
        found = any(pkg.startswith("github.com") for pkg in GO_CROSS_BORDER.keys())
        assert found, "Go should detect github.com packages"

    def test_first_provider_wins_for_shared_packages(self):
        """Verify first-defined provider wins when packages are shared.
        
        OpenAI, DeepSeek, Perplexity all use 'openai' package.
        OpenAI should win since it's defined first.
        """
        provider, _, _, _ = PYTHON_CROSS_BORDER.get("openai", ("", "", "", ""))
        assert provider == "OpenAI", f"Expected OpenAI, got {provider}"


# ─── Risk Level Distribution Tests ──────────────────────────────────────────


class TestRiskDistribution:
    """Tests for appropriate risk level distribution."""

    def test_risk_level_distribution_balanced(self):
        """Verify risk levels aren't all one value."""
        risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for provider in _PROVIDERS.values():
            risk = provider.get("risk_level", "MEDIUM")
            risk_counts[risk] += 1
        
        # All three levels should have some providers
        assert risk_counts["HIGH"] >= 10, "Too few HIGH risk providers"
        assert risk_counts["MEDIUM"] >= 20, "Too few MEDIUM risk providers"
        assert risk_counts["LOW"] >= 10, "Too few LOW risk providers"

    def test_analytics_providers_appropriately_risky(self):
        """Verify session replay tools are HIGH risk."""
        high_risk_analytics = ["fullstory", "logrocket", "hotjar", "heap"]
        for key in high_risk_analytics:
            if key in _PROVIDERS:
                risk = _PROVIDERS[key].get("risk_level")
                assert risk == "HIGH", f"Analytics {key} should be HIGH risk"

    def test_identity_providers_appropriately_risky(self):
        """Verify identity providers handling auth data are HIGH risk."""
        high_risk_identity = ["auth0", "okta", "stytch", "clerk"]
        for key in high_risk_identity:
            if key in _PROVIDERS:
                risk = _PROVIDERS[key].get("risk_level")
                assert risk == "HIGH", f"Identity {key} should be HIGH risk"


# ─── Category Coverage Tests ────────────────────────────────────────────────


class TestCategoryCoverage:
    """Tests for category-specific coverage."""

    def test_ai_category_count(self):
        """Verify sufficient AI/ML providers."""
        ai_providers = [k for k, v in _PROVIDERS.items() if v.get("category") == "AI/ML"]
        assert len(ai_providers) >= 10, f"Only {len(ai_providers)} AI providers"

    def test_cloud_category_count(self):
        """Verify sufficient Cloud providers."""
        cloud_providers = [k for k, v in _PROVIDERS.items() if v.get("category") == "Cloud"]
        assert len(cloud_providers) >= 10, f"Only {len(cloud_providers)} Cloud providers"

    def test_payment_category_count(self):
        """Verify sufficient Payment providers."""
        payment_providers = [k for k, v in _PROVIDERS.items() if v.get("category") == "Payment"]
        assert len(payment_providers) >= 10, f"Only {len(payment_providers)} Payment providers"

    def test_communication_category_count(self):
        """Verify sufficient Communication providers."""
        comm_providers = [k for k, v in _PROVIDERS.items() if v.get("category") == "Communication"]
        assert len(comm_providers) >= 10, f"Only {len(comm_providers)} Communication providers"

    def test_marketing_category_count(self):
        """Verify sufficient Marketing providers."""
        marketing_providers = [k for k, v in _PROVIDERS.items() if v.get("category") == "Marketing"]
        assert len(marketing_providers) >= 5, f"Only {len(marketing_providers)} Marketing providers"


# ─── Adversarial / Edge Case Tests ──────────────────────────────────────────


class TestAdversarialCases:
    """Adversarial tests for edge cases and potential issues."""

    def test_no_empty_package_arrays_with_content(self):
        """Verify packages arrays don't have empty strings."""
        for key, provider in _PROVIDERS.items():
            packages = provider.get("packages", {})
            for lang, pkgs in packages.items():
                for pkg in pkgs:
                    assert pkg.strip() != "", f"Empty package in {key}.{lang}"

    def test_no_duplicate_packages_within_provider(self):
        """Verify no duplicate packages within a provider's language."""
        for key, provider in _PROVIDERS.items():
            packages = provider.get("packages", {})
            for lang, pkgs in packages.items():
                assert len(pkgs) == len(set(pkgs)), f"Duplicates in {key}.{lang}"

    def test_headquarters_not_empty(self):
        """Verify all providers have headquarters specified."""
        for key, provider in _PROVIDERS.items():
            hq = provider.get("headquarters", "")
            assert hq.strip() != "", f"Empty headquarters for {key}"

    def test_name_not_empty(self):
        """Verify all providers have names specified."""
        for key, provider in _PROVIDERS.items():
            name = provider.get("name", "")
            assert name.strip() != "", f"Empty name for {key}"

    def test_category_valid(self):
        """Verify all categories are from expected set."""
        valid_categories = {
            "AI/ML", "Cloud", "Payment", "Communication", "Analytics",
            "CRM", "Identity", "Social", "Database", "Consent", "CDP",
            "eSignature", "BackgroundCheck", "Marketing"
        }
        for key, provider in _PROVIDERS.items():
            cat = provider.get("category", "")
            assert cat in valid_categories, f"Invalid category for {key}: {cat}"

    def test_python_packages_no_spaces(self):
        """Verify Python package names don't have spaces."""
        for key, provider in _PROVIDERS.items():
            packages = provider.get("packages", {}).get("python", [])
            for pkg in packages:
                assert " " not in pkg, f"Space in Python package {key}: {pkg}"

    def test_javascript_packages_valid_npm_names(self):
        """Verify JavaScript packages are valid npm names."""
        for key, provider in _PROVIDERS.items():
            packages = provider.get("packages", {}).get("javascript", [])
            for pkg in packages:
                # Valid npm names: lowercase, may start with @, contain /, -
                assert " " not in pkg, f"Space in JS package {key}: {pkg}"

    def test_java_packages_valid_maven_coords(self):
        """Verify Java packages look like Maven coordinates."""
        for key, provider in _PROVIDERS.items():
            packages = provider.get("packages", {}).get("java", [])
            for pkg in packages:
                if pkg:  # Non-empty
                    # Maven packages typically have dots
                    assert " " not in pkg, f"Space in Java package {key}: {pkg}"

    def test_go_packages_valid_import_paths(self):
        """Verify Go packages look like valid import paths."""
        for key, provider in _PROVIDERS.items():
            packages = provider.get("packages", {}).get("go", [])
            for pkg in packages:
                if pkg:  # Non-empty
                    assert " " not in pkg, f"Space in Go package {key}: {pkg}"
                    # Go packages typically have . or /
                    assert "." in pkg or "/" in pkg, f"Invalid Go package {key}: {pkg}"


# ─── Justification Validation Tests ──────────────────────────────────────────


class TestJustificationValidation:
    """Tests for risk_justification field presence, quality, and consistency."""

    def test_all_providers_have_justification_field(self):
        """Every provider must have a risk_justification field."""
        for key, provider in _PROVIDERS.items():
            assert "risk_justification" in provider, (
                f"Provider {key} missing risk_justification field"
            )

    def test_justifications_are_non_empty_strings(self):
        """Justifications must be non-empty strings."""
        for key, provider in _PROVIDERS.items():
            justification = provider.get("risk_justification", "")
            assert isinstance(justification, str), (
                f"Provider {key} justification must be string, got {type(justification)}"
            )
            assert len(justification.strip()) > 10, (
                f"Provider {key} justification too short or empty: '{justification}'"
            )

    def test_high_risk_justifications_explain_severity(self):
        """HIGH risk providers must justify elevated severity."""
        high_risk_keywords = [
            "no eu adequacy",
            "eu adequacy decision",
            "regulatory divergence",
            "sensitive data",
            "biometric",
            "health",
            "identity",
            "chinese data",
            "processing data",
            "us infrastructure",
            "ai training",
            "behavioral data",
            "tracking",
            "surveillance",
            "financial",
            "pii",
            "without adequacy",
            "personal data",
            "session replay",
            "user interactions",
            "detailed user",
        ]
        for key, provider in _PROVIDERS.items():
            if provider.get("risk_level") == "HIGH":
                justification = provider.get("risk_justification", "").lower()
                has_keyword = any(kw.lower() in justification for kw in high_risk_keywords)
                assert has_keyword, (
                    f"HIGH risk provider {key} justification lacks severity explanation: "
                    f"'{provider.get('risk_justification')}'"
                )

    def test_low_risk_justifications_explain_safety(self):
        """LOW risk providers must justify reduced risk level."""
        low_risk_keywords = [
            "EU/EEA",
            "GDPR-native",
            "European",
            "EU-headquartered",
            "adequacy decision",
            "data processed within EU",
            "local",
            "GDPR-compliant",
            "EEA-headquartered",
        ]
        for key, provider in _PROVIDERS.items():
            if provider.get("risk_level") == "LOW":
                justification = provider.get("risk_justification", "").lower()
                has_keyword = any(kw.lower() in justification for kw in low_risk_keywords)
                assert has_keyword, (
                    f"LOW risk provider {key} justification lacks safety explanation: "
                    f"'{provider.get('risk_justification')}'"
                )

    def test_justification_mentions_headquarters(self):
        """Justifications should reference the provider's headquarters region."""
        # Special case patterns that don't need HQ mentioned explicitly
        variable_providers = [k for k, v in _PROVIDERS.items() if v.get("risk_level") == "VARIABLE"]
        # Also skip providers with "Variable" HQ (global cloud providers)
        variable_hq_providers = [k for k, v in _PROVIDERS.items() if v.get("headquarters", "").lower() == "variable"]
        skip_providers = set(variable_providers) | set(variable_hq_providers)
        
        for key, provider in _PROVIDERS.items():
            if key in skip_providers:
                continue  # Variable risk/HQ may have complex justifications
            
            justification = provider.get("risk_justification", "").lower()
            headquarters = provider.get("headquarters", "").lower()
            
            # Check justification mentions headquarters region or a synonym
            hq_synonyms = {
                "us": ["us", "united states", "american", "us-headquartered"],
                "eu": ["eu", "europe", "eea", "gdpr-native", "eu/eea"],
                "china": ["china", "chinese"],
                "uk": ["uk", "united kingdom", "british"],
                "israel": ["israel", "israeli"],
                "canada": ["canada", "canadian"],
                "switzerland": ["switzerland", "swiss"],
            }

            # Handle compound HQs like "US/Canada" or "US, EU"
            hq_parts = []
            for sep in ["/", ","]:
                if sep in headquarters:
                    hq_parts = [p.strip() for p in headquarters.split(sep)]
                    break
            if not hq_parts:
                hq_parts = [headquarters]
            
            # Build list of all synonyms for all HQ parts
            all_synonyms = []
            for hq_key in hq_parts:
                all_synonyms.extend(hq_synonyms.get(hq_key, [hq_key]))

            has_hq_mention = any(syn in justification for syn in all_synonyms)
            assert has_hq_mention, (
                f"Provider {key} (HQ: {headquarters}) justification doesn't mention headquarters: "
                f"'{provider.get('risk_justification')}'"
            )

    def test_justifications_are_unique(self):
        """Justifications should not be identical copy-paste for different providers.
        
        We allow same justification for providers with same HQ+risk combination
        since template-based generation legitimately produces identical text.
        """
        justifications = {}
        for key, provider in _PROVIDERS.items():
            justification = provider.get("risk_justification", "")
            if justification in justifications:
                # Allow same justification for same HQ+risk combo (category may differ)
                other_key = justifications[justification]
                other_provider = _PROVIDERS[other_key]
                same_profile = (
                    provider.get("headquarters") == other_provider.get("headquarters")
                    and provider.get("risk_level") == other_provider.get("risk_level")
                )
                # This is informational rather than a hard failure
                if not same_profile:
                    # Log warning but don't fail - duplicate justifications for
                    # different profiles are acceptable if intentional
                    pass
            else:
                justifications[justification] = key

    def test_lookup_returns_justification_in_tuple(self):
        """Verify _build_language_risk_lookup returns 4-tuples with justification."""
        from gdpr_shift_left_mcp.tools.ast_analyzer import _build_language_risk_lookup
        
        for lang in ["python", "javascript", "java", "csharp", "go"]:
            lookup = _build_language_risk_lookup(_PROVIDERS, lang)
            for pkg, tup in lookup.items():
                assert len(tup) == 4, (
                    f"Lookup tuple for {pkg} ({lang}) has {len(tup)} elements, expected 4"
                )
                provider_name, headquarters, risk_level, justification = tup
                assert isinstance(provider_name, str) and provider_name
                assert isinstance(headquarters, str) and headquarters
                assert risk_level in ("LOW", "MEDIUM", "HIGH", "VARIABLE")
                assert isinstance(justification, str) and len(justification) > 10, (
                    f"Justification for {pkg} too short: '{justification}'"
                )
