"""
Paste Sites Collector
======================

Searches paste sites and public snippet services for data leaks:
- Pastebin
- GitHub Gists
- Paste.ee
- Dpaste
- Hastebin
- Ghostbin
- Ideone
- Codepad
"""

import logging
from typing import Dict, List


logger = logging.getLogger(__name__)


class PasteSiteCollector:
    """
    Searches paste sites for organization mentions and potential leaks.
    Uses search engines and site-specific APIs where available.
    """

    PASTE_SITES = [
        'pastebin.com',
        'gist.github.com',
        'paste.ee',
        'dpaste.com',
        'hastebin.com',
        'ghostbin.com',
        'ideone.com',
        'codepad.org',
        'jsbin.com',
        'jsfiddle.net',
        'codepen.io',
        'repl.it'
    ]

    def __init__(self, config: Dict, rate_limiter, cache_manager):
        """
        Initialize paste site collector.

        Args:
            config: Configuration dictionary
            rate_limiter: RateLimiter instance
            cache_manager: CacheManager instance
        """
        self.config = config
        self.rate_limiter = rate_limiter
        self.cache_manager = cache_manager

    def collect(self, scope: Dict) -> List[Dict]:
        """
        Search paste sites for organization mentions.

        Args:
            scope: Scope dictionary

        Returns:
            List of paste findings
        """
        findings = []

        # Search for brands on paste sites
        for brand in list(scope.get('brands', []))[:5]:  # Limit to top 5
            findings.extend(self._search_pastes(brand))

        # Search for domains
        for domain in scope.get('root_domains', []):
            findings.extend(self._search_pastes(domain))

        logger.info(f"Paste Sites: Found {len(findings)} potential leaks")
        return findings

    def _search_pastes(self, query: str) -> List[Dict]:
        """
        Search paste sites for a query.

        Note: Most paste sites don't have public search APIs.
        This typically requires:
        1. Using search engines (Google dorks)
        2. Third-party services (Pastebin alerts, etc.)
        3. Manual scraping (use with caution)

        Args:
            query: Search term

        Returns:
            List of findings
        """
        cache_key = f"paste:{query}"
        cached = self.cache_manager.get(cache_key)
        if cached:
            return cached

        findings = []

        # Try Pastebin scraping API if configured
        pastebin_key = self.config.get('pastebin_api_key')
        if pastebin_key:
            findings.extend(self._search_pastebin(query, pastebin_key))

        # For other sites, would typically use Google dorks:
        # site:pastebin.com "query"
        # site:gist.github.com "query"
        # etc.

        # This is typically better done through the search engine collector
        # with appropriate dorks already configured

        self.cache_manager.set(cache_key, findings, ttl=7200)
        return findings

    def _search_pastebin(self, query: str, api_key: str) -> List[Dict]:
        """
        Search Pastebin using API.

        Note: Pastebin scraping API requires PRO account.
        https://pastebin.com/doc_scraping_api

        Args:
            query: Search term
            api_key: Pastebin API key

        Returns:
            List of matching pastes
        """
        try:
            import requests

            # Pastebin scraping API
            url = "https://scrape.pastebin.com/api_scraping.php"
            params = {
                'limit': 100
            }

            self.rate_limiter.wait_if_needed('pastebin')

            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()

            pastes = response.json()
            findings = []

            # Filter pastes that mention the query
            for paste in pastes:
                content = paste.get('scrape_raw_text', '') or ''
                title = paste.get('title', '') or ''

                if query.lower() in content.lower() or query.lower() in title.lower():
                    findings.append({
                        'type': 'paste',
                        'site': 'pastebin',
                        'key': paste.get('key'),
                        'url': f"https://pastebin.com/{paste.get('key')}",
                        'title': title,
                        'user': paste.get('user'),
                        'date': paste.get('date'),
                        'size': paste.get('size'),
                        'query': query,
                        'category': 'paste_leak',
                        'source': 'pastebin',
                        'severity': 'medium',
                        'description': f'Pastebin mention of {query}'
                    })

            return findings

        except ImportError:
            logger.warning("requests library not installed")
            return []
        except Exception as e:
            logger.warning(f"Pastebin search failed: {e}")
            return []

    def get_paste_content(self, paste_url: str) -> str:
        """
        Fetch content of a specific paste.

        Args:
            paste_url: URL to paste

        Returns:
            Paste content
        """
        try:
            import requests

            # Add rate limiting
            self.rate_limiter.wait_if_needed('paste_fetch')

            response = requests.get(paste_url, timeout=10)
            response.raise_for_status()

            return response.text

        except Exception as e:
            logger.warning(f"Failed to fetch paste {paste_url}: {e}")
            return ""

    def monitor_recent_pastes(self, keywords: List[str], duration_minutes: int = 60) -> List[Dict]:
        """
        Monitor recent pastes for keywords.

        This would be used for continuous monitoring rather than one-time scans.

        Args:
            keywords: List of keywords to monitor
            duration_minutes: How long to monitor

        Returns:
            List of matching pastes
        """
        # Placeholder for monitoring functionality
        # Would continuously poll paste sites and alert on keyword matches
        logger.info("Continuous paste monitoring not implemented")
        return []
