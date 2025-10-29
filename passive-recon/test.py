#!/usr/bin/env python3
"""
Simple Test Script for Passive Reconnaissance Tool
===================================================

Performs basic validation and testing of the tool's functionality.
"""

import sys
import json
from pathlib import Path

# Test imports
def test_imports():
    """Test that all modules can be imported."""
    print("[TEST] Testing module imports...")

    try:
        from seeds.scope_builder import ScopeBuilder
        from collectors.search_engine import SearchEngineCollector
        from collectors.certificate_transparency import CTCollector
        from collectors.github_collector import GitHubCollector
        from collectors.cloud_storage import CloudStorageCollector
        from collectors.paste_sites import PasteSiteCollector
        from detectors.secret_detector import SecretDetector
        from detectors.vulnerability_detector import VulnerabilityDetector
        from detectors.admin_panel_detector import AdminPanelDetector
        from normalizers.url_normalizer import URLNormalizer
        from scorers.risk_scorer import RiskScorer
        from outputs.output_handler import OutputHandler
        from utils.cache_manager import CacheManager
        from utils.rate_limiter import RateLimiter
        from utils.validator import Validator, ValidationError

        print("  ✓ All core modules import successfully")
        return True
    except ImportError as e:
        print(f"  ✗ Import error: {e}")
        return False


def test_validator():
    """Test the validator module."""
    print("\n[TEST] Testing validator...")

    from utils.validator import Validator

    # Test valid domain
    valid, error = Validator.validate_domain("example.com")
    assert valid, f"Valid domain rejected: {error}"
    print("  ✓ Valid domain accepted")

    # Test invalid domain
    valid, error = Validator.validate_domain("invalid..domain")
    assert not valid, "Invalid domain accepted"
    print("  ✓ Invalid domain rejected")

    # Test organization name
    valid, error = Validator.validate_organization_name("Test Company")
    assert valid, f"Valid org name rejected: {error}"
    print("  ✓ Valid organization name accepted")

    return True


def test_config_files():
    """Test that configuration files exist and are valid."""
    print("\n[TEST] Testing configuration files...")

    # Check config.example.json
    config_example = Path("config.example.json")
    if not config_example.exists():
        print("  ✗ config.example.json not found")
        return False

    try:
        with open(config_example, 'r') as f:
            config = json.load(f)
        print("  ✓ config.example.json is valid JSON")
    except json.JSONDecodeError as e:
        print(f"  ✗ config.example.json is invalid: {e}")
        return False

    # Check rules files
    rules_files = [
        "rules/google_dorks.json",
        "rules/secret_patterns.json"
    ]

    for rules_file in rules_files:
        file_path = Path(rules_file)
        if not file_path.exists():
            print(f"  ✗ {rules_file} not found")
            return False

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            print(f"  ✓ {rules_file} is valid JSON")
        except json.JSONDecodeError as e:
            print(f"  ✗ {rules_file} is invalid: {e}")
            return False

    return True


def test_scope_builder():
    """Test the scope builder module."""
    print("\n[TEST] Testing scope builder...")

    from seeds.scope_builder import ScopeBuilder

    config = {
        'scope': {
            'generate_tld_variants': True,
            'max_subdomains': 100
        }
    }

    builder = ScopeBuilder(config)
    scope = builder.build_scope(["example.com"], [])

    assert len(scope['domains']) > 0, "No domains generated"
    assert "example.com" in scope['domains'], "Original domain not in scope"

    print(f"  ✓ Generated {len(scope['domains'])} domain variants")
    return True


def test_secret_detector():
    """Test the secret detector module."""
    print("\n[TEST] Testing secret detector...")

    from detectors.secret_detector import SecretDetector

    config = {
        'secret_patterns': {
            'enabled': True,
            'entropy_checking': True,
            'min_entropy': 3.5
        }
    }

    detector = SecretDetector(config)

    # Test that detector initializes correctly and has patterns loaded
    assert hasattr(detector, 'patterns'), "Patterns not loaded"
    assert len(detector.patterns) > 0, "No patterns available"

    print(f"  ✓ Secret detector initialized with {len(detector.patterns)} patterns")

    # Test with realistic AWS key pattern (higher entropy)
    test_content = "AWS_KEY=AKIAIOSFODNN7EXAMPLEKEY123"
    findings = detector.detect([{
        'url': 'https://example.com/test',
        'content': test_content,
        'snippet': test_content,
        'source': 'test'
    }])

    print(f"  ✓ Detector processed test data ({len(findings)} findings)")

    return True


def test_url_normalizer():
    """Test the URL normalizer module."""
    print("\n[TEST] Testing URL normalizer...")

    from normalizers.url_normalizer import URLNormalizer

    normalizer = URLNormalizer()

    # Test URL normalization
    url1 = "https://example.com:443/path?b=2&a=1#fragment"
    url2 = "https://example.com/path?a=1&b=2"

    norm1 = normalizer.normalize_url(url1)
    norm2 = normalizer.normalize_url(url2)

    assert norm1 == norm2, "Equivalent URLs not normalized to same form"
    print("  ✓ URL normalization working correctly")

    return True


def test_risk_scorer():
    """Test the risk scorer module."""
    print("\n[TEST] Testing risk scorer...")

    from scorers.risk_scorer import RiskScorer

    config = {}
    scorer = RiskScorer(config)

    test_finding = {
        'category': 'secret',
        'data_type': 'aws_key',
        'confidence': 0.9,
        'severity': 'critical'
    }

    score_result = scorer.calculate_risk_score(test_finding)

    assert 'score' in score_result, "Score not calculated"
    assert 'severity' in score_result, "Severity not determined"
    assert score_result['score'] > 0, "Invalid score"

    print(f"  ✓ Risk scoring working (score: {score_result['score']})")
    return True


def run_all_tests():
    """Run all tests."""
    print("="*70)
    print("RUNNING PASSIVE RECONNAISSANCE TOOL TESTS")
    print("="*70)

    tests = [
        ("Module Imports", test_imports),
        ("Validator", test_validator),
        ("Configuration Files", test_config_files),
        ("Scope Builder", test_scope_builder),
        ("Secret Detector", test_secret_detector),
        ("URL Normalizer", test_url_normalizer),
        ("Risk Scorer", test_risk_scorer)
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                print(f"\n[FAIL] {test_name} test failed")
        except Exception as e:
            failed += 1
            print(f"\n[FAIL] {test_name} test failed with exception: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "="*70)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("="*70)

    if failed == 0:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {failed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
