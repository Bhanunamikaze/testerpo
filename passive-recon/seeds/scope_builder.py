"""
Scope Builder Module
====================

Generates comprehensive target scope from seed domains and organization names.
Produces domain variants, subdomain patterns, and brand variations for recon.
"""

import re
from typing import List, Dict, Set
from pathlib import Path


class ScopeBuilder:
    """
    Builds and expands reconnaissance scope from initial targets.
    Generates domain variations, staging patterns, and organization aliases.
    """

    # Common staging/environment prefixes
    ENV_PREFIXES = [
        'dev', 'development', 'test', 'testing', 'qa', 'uat',
        'stage', 'staging', 'stg', 'preprod', 'pre-prod',
        'sandbox', 'sbx', 'demo', 'int', 'internal',
        'beta', 'alpha', 'canary', 'preview'
    ]

    # Common TLD variations
    COMMON_TLDS = [
        'com', 'net', 'org', 'io', 'co', 'ai', 'app', 'dev',
        'cloud', 'tech', 'info', 'biz', 'us', 'uk', 'eu'
    ]

    # Common SaaS/cloud patterns
    SAAS_PATTERNS = [
        'api', 'app', 'admin', 'portal', 'dashboard', 'console',
        'my', 'client', 'customer', 'partner', 'vendor',
        'secure', 'auth', 'login', 'sso', 'oauth',
        'cdn', 'static', 'assets', 'media', 'files', 'storage',
        'mail', 'email', 'smtp', 'webmail',
        'vpn', 'remote', 'access',
        'docs', 'wiki', 'kb', 'help', 'support',
        'git', 'gitlab', 'jenkins', 'ci', 'build'
    ]

    def __init__(self, config: Dict):
        """Initialize scope builder with configuration."""
        self.config = config
        self.scope_config = config.get('scope', {})
        self.minimal_scope = self.scope_config.get('minimal_scope', False)

    def build_scope(self, targets: List[str], scope_file: str = None) -> Dict:
        """
        Build comprehensive reconnaissance scope.

        Args:
            targets: List of root domains or organization names
            scope_file: Optional file with additional scope items

        Returns:
            Dictionary containing expanded scope items
        """
        scope = {
            'root_domains': [],
            'domains': set(),
            'organizations': set(),
            'brands': set(),
            'patterns': [],
            'exclusions': set()
        }

        # Process primary targets
        for target in targets:
            if self._is_domain(target):
                scope['root_domains'].append(target)
                scope['domains'].update(self._expand_domain(target))
            else:
                # Treat as organization/brand name
                scope['organizations'].add(target)
                scope['brands'].add(target)

        # Load additional scope from file
        if scope_file:
            additional_scope = self._load_scope_file(scope_file)
            scope['domains'].update(additional_scope.get('domains', []))
            scope['organizations'].update(additional_scope.get('organizations', []))
            scope['exclusions'].update(additional_scope.get('exclusions', []))

        # Generate brand variations
        for org in scope['organizations']:
            scope['brands'].update(self._generate_brand_variants(org))

        # Generate search patterns
        scope['patterns'] = self._generate_search_patterns(scope)

        # Convert sets to lists for JSON serialization
        scope['domains'] = list(scope['domains'])
        scope['organizations'] = list(scope['organizations'])
        scope['brands'] = list(scope['brands'])
        scope['exclusions'] = list(scope['exclusions'])

        return scope

    def _is_domain(self, target: str) -> bool:
        """Check if target looks like a domain name."""
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, target))

    def _expand_domain(self, domain: str) -> Set[str]:
        """
        Expand a single domain into multiple variants.

        Generates:
        - Original domain
        - Environment-prefixed subdomains
        - TLD variations
        - Common service subdomains
        """
        variants = {domain}

        # If minimal_scope is enabled, return only the original domain
        if self.minimal_scope:
            return variants

        # Extract base domain (without TLD)
        parts = domain.split('.')
        if len(parts) >= 2:
            base_name = parts[0]
            original_tld = '.'.join(parts[1:])

            # Environment prefixes
            for prefix in self.ENV_PREFIXES:
                variants.add(f"{prefix}.{domain}")
                variants.add(f"{prefix}-{base_name}.{original_tld}")
                variants.add(f"{base_name}-{prefix}.{original_tld}")

            # TLD variations
            if self.scope_config.get('generate_tld_variants', True):
                for tld in self.COMMON_TLDS:
                    if tld != original_tld:
                        variants.add(f"{base_name}.{tld}")

            # SaaS/service subdomains
            for service in self.SAAS_PATTERNS:
                variants.add(f"{service}.{domain}")

        return variants

    def _generate_brand_variants(self, brand: str) -> Set[str]:
        """
        Generate brand name variations.

        Returns:
        - Original brand
        - Lowercase
        - No spaces
        - Hyphenated
        - Concatenated
        """
        variants = {brand}

        # Normalize
        clean = brand.strip()
        variants.add(clean.lower())
        variants.add(clean.upper())

        # Remove spaces
        no_space = clean.replace(' ', '')
        variants.add(no_space)
        variants.add(no_space.lower())

        # Hyphenated
        hyphenated = clean.replace(' ', '-')
        variants.add(hyphenated)
        variants.add(hyphenated.lower())

        # Underscored
        underscored = clean.replace(' ', '_')
        variants.add(underscored)
        variants.add(underscored.lower())

        # Abbreviations (if multi-word)
        words = clean.split()
        if len(words) > 1:
            abbreviation = ''.join(w[0] for w in words)
            variants.add(abbreviation.upper())
            variants.add(abbreviation.lower())

        return variants

    def _load_scope_file(self, scope_file: str) -> Dict:
        """
        Load additional scope from file.

        File format (one per line):
        domain.com
        org:Organization Name
        exclude:excluded-domain.com
        """
        scope = {
            'domains': set(),
            'organizations': set(),
            'exclusions': set()
        }

        try:
            with open(scope_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    if line.startswith('org:'):
                        scope['organizations'].add(line[4:])
                    elif line.startswith('exclude:'):
                        scope['exclusions'].add(line[8:])
                    else:
                        scope['domains'].add(line)
        except FileNotFoundError:
            pass

        return scope

    def _generate_search_patterns(self, scope: Dict) -> List[Dict]:
        """
        Generate search patterns for use in dorking and queries.

        Returns list of pattern dictionaries with placeholders.
        """
        patterns = []

        # Domain-based patterns
        for domain in scope['root_domains']:
            patterns.append({
                'type': 'domain',
                'pattern': f'site:{domain}',
                'target': domain
            })

        # Brand-based patterns
        for brand in scope['brands']:
            patterns.append({
                'type': 'brand',
                'pattern': f'"{brand}"',
                'target': brand
            })

            # Brand mentions in specific sites
            for paste_site in ['pastebin.com', 'gist.github.com', 'gitlab.com']:
                patterns.append({
                    'type': 'brand_leak',
                    'pattern': f'site:{paste_site} "{brand}"',
                    'target': brand,
                    'source': paste_site
                })

        # Organization patterns
        for org in scope['organizations']:
            patterns.append({
                'type': 'organization',
                'pattern': f'"{org}"',
                'target': org
            })

        return patterns

    def is_in_scope(self, item: str, scope: Dict) -> bool:
        """
        Check if an item (domain, URL, etc.) is within scope.

        Args:
            item: Item to check (domain or URL)
            scope: Scope dictionary

        Returns:
            True if in scope, False otherwise
        """
        # Check exclusions first
        for exclusion in scope.get('exclusions', []):
            if exclusion in item:
                return False

        # Check if matches any domain
        for domain in scope.get('domains', []):
            if domain in item:
                return True

        # Check if matches any brand
        for brand in scope.get('brands', []):
            if brand.lower() in item.lower():
                return True

        return False

    def get_scope_summary(self, scope: Dict) -> str:
        """Generate human-readable scope summary."""
        lines = [
            "Reconnaissance Scope:",
            f"  Root Domains: {len(scope.get('root_domains', []))}",
            f"  Total Domain Variants: {len(scope.get('domains', []))}",
            f"  Organizations: {len(scope.get('organizations', []))}",
            f"  Brand Variants: {len(scope.get('brands', []))}",
            f"  Search Patterns: {len(scope.get('patterns', []))}",
            f"  Exclusions: {len(scope.get('exclusions', []))}"
        ]

        if scope.get('root_domains'):
            lines.append("\n  Primary Targets:")
            for domain in scope['root_domains'][:5]:
                lines.append(f"    - {domain}")

        return '\n'.join(lines)
