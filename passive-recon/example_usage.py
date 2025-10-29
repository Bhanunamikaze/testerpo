#!/usr/bin/env python3
"""
Example Usage Script
====================

Demonstrates how to use the Passive Recon Scanner programmatically.

WARNING: Only run against authorized targets.
"""

from passive_recon import PassiveReconScanner


def example_basic_scan():
    """
    Example 1: Basic domain scan
    """
    print("="*60)
    print("Example 1: Basic Domain Scan")
    print("="*60)

    scanner = PassiveReconScanner('config.json')

    # Simple domain scan
    scanner.run(['example.com'])


def example_multi_target():
    """
    Example 2: Multiple targets with organization names
    """
    print("\n" + "="*60)
    print("Example 2: Multiple Targets")
    print("="*60)

    scanner = PassiveReconScanner('config.json')

    targets = [
        'example.com',
        'example.org',
        'Example Corporation'  # Organization name
    ]

    scanner.run(targets)


def example_with_scope_file():
    """
    Example 3: Using a scope file
    """
    print("\n" + "="*60)
    print("Example 3: With Scope File")
    print("="*60)

    # Create sample scope file
    scope_content = """# Target domains
example.com
example.org

# Organizations (prefix with "org:")
org:Example Corporation
org:Example Inc

# Exclusions (prefix with "exclude:")
exclude:out-of-scope.example.com
"""

    with open('example_scope.txt', 'w') as f:
        f.write(scope_content)

    scanner = PassiveReconScanner('config.json')
    scanner.run(['example.com'], scope_file='example_scope.txt')


def example_custom_collectors():
    """
    Example 4: Using individual collectors
    """
    print("\n" + "="*60)
    print("Example 4: Individual Collectors")
    print("="*60)

    from seeds.scope_builder import ScopeBuilder
    from collectors.certificate_transparency import CTCollector
    from utils.cache_manager import CacheManager

    # Build scope
    config = {'scope': {}}
    builder = ScopeBuilder(config)
    scope = builder.build_scope(['example.com'])

    print(f"Scope generated: {len(scope['domains'])} domain variants")

    # Just run CT collector
    cache = CacheManager('cache')
    ct_collector = CTCollector({}, cache)

    subdomains = ct_collector.collect(['example.com'])
    print(f"Found {len(subdomains)} subdomains from CT logs")

    for subdomain in list(subdomains)[:10]:
        print(f"  - {subdomain}")


def example_secret_detection():
    """
    Example 5: Secret detection on sample data
    """
    print("\n" + "="*60)
    print("Example 5: Secret Detection")
    print("="*60)

    from detectors.secret_detector import SecretDetector

    # Sample findings with potential secrets
    sample_findings = [
        {
            'url': 'https://github.com/example/repo/blob/config.py',
            'title': 'Configuration File',
            'content': '''
                # AWS Configuration
                AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
                AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            '''
        },
        {
            'url': 'https://example.com/.env',
            'title': 'Environment Variables',
            'content': '''
                DB_HOST=localhost
                DB_PASSWORD=super_secret_password123
                API_KEY=sk_test_51HqZ7bKc3xQ5YpJkRzP8aU
            '''
        }
    ]

    detector = SecretDetector({})
    secrets = detector.detect(sample_findings)

    print(f"Detected {len(secrets)} potential secrets:")
    for secret in secrets:
        print(f"\n  Type: {secret['secret_type']}")
        print(f"  Severity: {secret['severity']}")
        print(f"  Confidence: {secret['confidence']:.2f}")
        print(f"  URL: {secret['url']}")


def main():
    """Run all examples."""
    print("🔍 Passive Reconnaissance - Usage Examples")
    print("="*60)
    print("⚠️  WARNING: Only run against authorized targets!")
    print("="*60 + "\n")

    # Note: These examples use placeholder data
    # In real usage, you would scan actual authorized targets

    try:
        # Example 4: Individual collectors (safe to run)
        example_custom_collectors()

        # Example 5: Secret detection (safe to run)
        example_secret_detection()

        # Commented out full scans - uncomment to run on authorized targets
        # example_basic_scan()
        # example_multi_target()
        # example_with_scope_file()

        print("\n" + "="*60)
        print("✅ Examples completed!")
        print("="*60)
        print("\nTo run full scans, edit this script and:")
        print("1. Ensure you have proper authorization")
        print("2. Create config.json from config.example.json")
        print("3. Uncomment the desired example functions")
        print("4. Replace 'example.com' with your authorized target")

    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure you have:")
        print("1. Created config.json from config.example.json")
        print("2. All required modules are properly installed")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")


if __name__ == '__main__':
    main()
