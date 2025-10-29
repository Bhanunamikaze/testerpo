"""
URL Normalizer
==============

Normalizes URLs and deduplicates findings.
"""

import hashlib
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Set


class URLNormalizer:
    """
    Normalizes URLs and deduplicates findings based on content similarity.
    """

    # Tracking parameters to remove
    TRACKING_PARAMS = {
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
        'fbclid', 'gclid', 'msclkid',
        'ref', 'source', 'campaign',
        '_ga', '_gid'
    }

    def normalize_url(self, url: str) -> str:
        """
        Normalize a URL by:
        - Converting to lowercase
        - Removing tracking parameters
        - Sorting query parameters
        - Removing default ports
        - Removing fragment

        Args:
            url: URL to normalize

        Returns:
            Normalized URL
        """
        try:
            parsed = urlparse(url)

            # Lowercase scheme and netloc
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()

            # Remove default ports
            if netloc.endswith(':80') and scheme == 'http':
                netloc = netloc[:-3]
            elif netloc.endswith(':443') and scheme == 'https':
                netloc = netloc[:-4]

            # Parse and filter query parameters
            query_params = parse_qs(parsed.query)
            filtered_params = {
                k: v for k, v in query_params.items()
                if k not in self.TRACKING_PARAMS
            }

            # Sort parameters for consistency
            sorted_query = urlencode(sorted(filtered_params.items()), doseq=True)

            # Reconstruct URL without fragment
            normalized = urlunparse((
                scheme,
                netloc,
                parsed.path,
                parsed.params,
                sorted_query,
                ''  # Remove fragment
            ))

            return normalized

        except Exception:
            # If parsing fails, return original
            return url

    def deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Deduplicate findings based on normalized URLs and content hashes.

        Args:
            findings: List of findings

        Returns:
            Deduplicated list
        """
        seen_keys = set()
        unique_findings = []

        for finding in findings:
            # Generate deduplication key
            dedup_key = self._generate_dedup_key(finding)

            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                unique_findings.append(finding)

        return unique_findings

    def _generate_dedup_key(self, finding: Dict) -> str:
        """
        Generate unique key for deduplication.

        Args:
            finding: Finding dictionary

        Returns:
            Deduplication key
        """
        # Use URL if available
        url = finding.get('url', '')
        if url:
            normalized_url = self.normalize_url(url)
        else:
            normalized_url = ''

        # Create content hash
        content_fields = ['title', 'snippet', 'description', 'content']
        content_parts = []

        for field in content_fields:
            if field in finding and finding[field]:
                content_parts.append(str(finding[field]))

        content = ''.join(content_parts)
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        # Combine URL and content hash
        return f"{normalized_url}:{content_hash}"

    def extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ''

    def is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain."""
        return self.extract_domain(url1) == self.extract_domain(url2)
