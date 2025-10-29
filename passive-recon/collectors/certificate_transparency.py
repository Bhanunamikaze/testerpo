"""
Certificate Transparency Collector
===================================

Queries Certificate Transparency logs to discover subdomains and certificates.
CT logs are public, append-only logs of SSL/TLS certificates.

Primary data sources:
- crt.sh (web interface to CT logs)
- Censys
- CertSpotter API
- Facebook CT API
"""

import json
import logging
import re
import time
from typing import Dict, List, Set
from urllib.parse import quote


logger = logging.getLogger(__name__)


class CTCollector:
    """
    Collects subdomains and certificate data from Certificate Transparency logs.
    This is one of the most reliable passive subdomain enumeration techniques.
    """

    def __init__(self, config: Dict, cache_manager):
        """
        Initialize CT collector.

        Args:
            config: Configuration dictionary
            cache_manager: CacheManager instance
        """
        self.config = config
        self.cache_manager = cache_manager

    def collect(self, domains: List[str]) -> Set[str]:
        """
        Collect subdomains from CT logs for given domains.

        Args:
            domains: List of root domains to query

        Returns:
            Set of discovered subdomains
        """
        all_subdomains = set()

        logger.info("Querying Certificate Transparency logs...")

        for domain in domains:
            subdomains = self._query_domain(domain)
            all_subdomains.update(subdomains)
            logger.info(f"  {domain}: Found {len(subdomains)} subdomains")

        return all_subdomains

    def _query_domain(self, domain: str) -> Set[str]:
        """
        Query CT logs for a single domain.

        Args:
            domain: Domain to query

        Returns:
            Set of subdomains
        """
        # Check cache
        cache_key = f"ct:{domain}"
        cached = self.cache_manager.get(cache_key)

        if cached:
            logger.debug(f"  Cache hit for {domain}")
            return set(cached)

        subdomains = set()

        # Try multiple CT data sources
        sources = [
            ('crt.sh', self._query_crtsh),
            ('certspotter', self._query_certspotter),
        ]

        for source_name, query_func in sources:
            try:
                results = query_func(domain)
                subdomains.update(results)
                logger.debug(f"    {source_name}: {len(results)} subdomains")
            except Exception as e:
                logger.warning(f"    {source_name} query failed: {e}")

        # Clean and validate subdomains
        cleaned = self._clean_subdomains(subdomains, domain)

        # Cache results for 24 hours
        self.cache_manager.set(cache_key, list(cleaned), ttl=86400)

        return cleaned

    def _query_crtsh(self, domain: str) -> Set[str]:
        """
        Query crt.sh for certificates.

        crt.sh provides a web interface to CT logs with JSON output.
        API: https://crt.sh/?q=%.domain.com&output=json

        Args:
            domain: Domain to query

        Returns:
            Set of subdomains
        """
        try:
            import requests

            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            data = response.json()
            subdomains = set()

            for entry in data:
                # Extract common_name and name_value
                common_name = entry.get('common_name', '')
                name_value = entry.get('name_value', '')

                if common_name:
                    subdomains.add(common_name.lower())

                # name_value can contain multiple domains separated by newlines
                if name_value:
                    for name in name_value.split('\n'):
                        subdomains.add(name.strip().lower())

            return subdomains

        except ImportError:
            logger.warning("requests library not installed, skipping crt.sh")
            return set()
        except Exception as e:
            logger.debug(f"crt.sh query error: {e}")
            return set()

    def _query_certspotter(self, domain: str) -> Set[str]:
        """
        Query CertSpotter API for certificates.

        CertSpotter: https://sslmate.com/certspotter/
        API: https://api.certspotter.com/v1/issuances?domain=example.com

        Args:
            domain: Domain to query

        Returns:
            Set of subdomains
        """
        try:
            import requests

            url = f"https://api.certspotter.com/v1/issuances"
            params = {
                'domain': domain,
                'include_subdomains': 'true',
                'expand': 'dns_names'
            }

            # Add API key if configured
            headers = {}
            api_key = self.config.get('certspotter_api_key')
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'

            response = requests.get(url, params=params, headers=headers, timeout=30)

            # CertSpotter free tier is limited, don't fail on rate limit
            if response.status_code == 429:
                logger.warning("CertSpotter rate limit hit")
                return set()

            response.raise_for_status()
            data = response.json()

            subdomains = set()
            for entry in data:
                for dns_name in entry.get('dns_names', []):
                    subdomains.add(dns_name.lower())

            return subdomains

        except ImportError:
            logger.warning("requests library not installed, skipping CertSpotter")
            return set()
        except Exception as e:
            logger.debug(f"CertSpotter query error: {e}")
            return set()

    def _clean_subdomains(self, subdomains: Set[str], root_domain: str) -> Set[str]:
        """
        Clean and validate discovered subdomains.

        Removes:
        - Wildcards
        - Invalid characters
        - Non-matching domains
        - Duplicates

        Args:
            subdomains: Raw set of subdomains
            root_domain: Root domain to validate against

        Returns:
            Cleaned set of valid subdomains
        """
        cleaned = set()

        for subdomain in subdomains:
            # Remove wildcards
            subdomain = subdomain.replace('*.', '')

            # Must end with root domain
            if not subdomain.endswith(root_domain):
                continue

            # Basic validation
            if not self._is_valid_domain(subdomain):
                continue

            cleaned.add(subdomain)

        return cleaned

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate domain name format.

        Args:
            domain: Domain to validate

        Returns:
            True if valid, False otherwise
        """
        # Basic domain regex
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

        if not re.match(pattern, domain):
            return False

        # Check length
        if len(domain) > 253:
            return False

        # Check label lengths
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63 or len(label) == 0:
                return False

        return True

    def extract_certificate_details(self, domain: str) -> List[Dict]:
        """
        Extract detailed certificate information for a domain.

        Returns certificate metadata including:
        - Issuer
        - Valid from/to dates
        - SANs (Subject Alternative Names)
        - Organization details

        Args:
            domain: Domain to query

        Returns:
            List of certificate details
        """
        try:
            import requests

            url = f"https://crt.sh/?q={domain}&output=json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            data = response.json()
            certificates = []

            seen_fingerprints = set()

            for entry in data:
                # Deduplicate by certificate ID
                cert_id = entry.get('id')
                if cert_id in seen_fingerprints:
                    continue

                seen_fingerprints.add(cert_id)

                cert_info = {
                    'id': cert_id,
                    'issuer_name': entry.get('issuer_name'),
                    'common_name': entry.get('common_name'),
                    'name_value': entry.get('name_value'),
                    'not_before': entry.get('not_before'),
                    'not_after': entry.get('not_after'),
                    'entry_timestamp': entry.get('entry_timestamp')
                }

                certificates.append(cert_info)

            return certificates

        except Exception as e:
            logger.error(f"Certificate details extraction failed: {e}")
            return []

    def find_expired_certificates(self, domain: str) -> List[Dict]:
        """
        Find expired certificates for a domain.
        May indicate forgotten subdomains or infrastructure.

        Args:
            domain: Domain to query

        Returns:
            List of expired certificate details
        """
        try:
            from datetime import datetime

            all_certs = self.extract_certificate_details(domain)
            expired_certs = []

            for cert in all_certs:
                not_after = cert.get('not_after')
                if not_after:
                    try:
                        expiry_date = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                        if expiry_date < datetime.now(expiry_date.tzinfo):
                            expired_certs.append(cert)
                    except ValueError:
                        continue

            return expired_certs

        except Exception as e:
            logger.error(f"Expired certificate search failed: {e}")
            return []
