"""
GitHub and Code Repository Collector
=====================================

Searches GitHub, GitLab, and other code forges for:
- Public repositories
- Gists and snippets
- Code containing secrets
- Organization members and their repos
- Issues and pull requests
"""

import json
import logging
import time
from typing import Dict, List


logger = logging.getLogger(__name__)


class GitHubCollector:
    """
    Collects information from GitHub and other code repositories.
    Uses GitHub API and search to find sensitive data leaks.
    """

    def __init__(self, config: Dict, rate_limiter, cache_manager):
        """
        Initialize GitHub collector.

        Args:
            config: Configuration with API tokens
            rate_limiter: RateLimiter instance
            cache_manager: CacheManager instance
        """
        self.config = config
        self.rate_limiter = rate_limiter
        self.cache_manager = cache_manager
        self.api_token = config.get('api_token')

    def collect(self, scope: Dict) -> List[Dict]:
        """
        Collect findings from GitHub.

        Args:
            scope: Scope dictionary

        Returns:
            List of findings
        """
        findings = []

        # Search repositories
        for org in scope.get('organizations', []):
            findings.extend(self._search_org_repos(org))

        # Search code for domains and brands
        for domain in scope.get('root_domains', []):
            findings.extend(self._search_code(domain))

        for brand in list(scope.get('brands', []))[:5]:  # Limit to top 5 brands
            findings.extend(self._search_code(brand))

        # Search gists
        for brand in list(scope.get('brands', []))[:5]:
            findings.extend(self._search_gists(brand))

        logger.info(f"GitHub: Found {len(findings)} items")
        return findings

    def _search_org_repos(self, org_name: str) -> List[Dict]:
        """Search for organization repositories."""
        cache_key = f"github:org:{org_name}"
        cached = self.cache_manager.get(cache_key)
        if cached:
            return cached

        results = []

        try:
            import requests

            # GitHub API: List org repos
            url = f"https://api.github.com/orgs/{org_name}/repos"
            headers = self._get_headers()

            self.rate_limiter.wait_if_needed('github')
            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code == 404:
                logger.debug(f"Organization not found: {org_name}")
                return []

            response.raise_for_status()
            repos = response.json()

            for repo in repos:
                results.append({
                    'type': 'github_repository',
                    'url': repo.get('html_url'),
                    'name': repo.get('full_name'),
                    'description': repo.get('description', ''),
                    'is_fork': repo.get('fork', False),
                    'is_private': repo.get('private', False),
                    'language': repo.get('language'),
                    'stars': repo.get('stargazers_count', 0),
                    'updated_at': repo.get('updated_at'),
                    'category': 'code_repository',
                    'source': 'github',
                    'severity': 'medium'
                })

        except ImportError:
            logger.warning("requests library not installed")
            return []
        except Exception as e:
            logger.warning(f"GitHub org search failed for {org_name}: {e}")
            return []

        self.cache_manager.set(cache_key, results, ttl=7200)
        return results

    def _search_code(self, query: str) -> List[Dict]:
        """
        Search GitHub code for a query.

        Args:
            query: Search term

        Returns:
            List of code search results
        """
        cache_key = f"github:code:{query}"
        cached = self.cache_manager.get(cache_key)
        if cached:
            return cached

        results = []

        try:
            import requests

            # GitHub Code Search API
            url = "https://api.github.com/search/code"
            headers = self._get_headers()
            params = {
                'q': query,
                'per_page': 30
            }

            self.rate_limiter.wait_if_needed('github')
            response = requests.get(url, headers=headers, params=params, timeout=15)

            if response.status_code == 403:
                logger.warning("GitHub API rate limit hit or authentication required")
                return []

            response.raise_for_status()
            data = response.json()

            for item in data.get('items', []):
                results.append({
                    'type': 'github_code',
                    'url': item.get('html_url'),
                    'path': item.get('path'),
                    'repository': item.get('repository', {}).get('full_name'),
                    'repository_url': item.get('repository', {}).get('html_url'),
                    'query': query,
                    'category': 'code_leak',
                    'source': 'github',
                    'severity': 'high'
                })

        except ImportError:
            return []
        except Exception as e:
            logger.warning(f"GitHub code search failed for '{query}': {e}")
            return []

        self.cache_manager.set(cache_key, results, ttl=3600)
        return results

    def _search_gists(self, query: str) -> List[Dict]:
        """Search public gists."""
        # Note: GitHub doesn't have a gist search API
        # Would need to use web scraping or Google dork: site:gist.github.com query
        # Placeholder for now
        return []

    def _get_headers(self) -> Dict:
        """Get API request headers with authentication if available."""
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Passive-Recon-Scanner/1.0'
        }

        if self.api_token:
            headers['Authorization'] = f'token {self.api_token}'

        return headers

    def search_commits(self, repo_full_name: str, search_term: str) -> List[Dict]:
        """
        Search commit messages and diffs for sensitive data.

        Args:
            repo_full_name: Repository full name (org/repo)
            search_term: Term to search for

        Returns:
            List of matching commits
        """
        try:
            import requests

            url = f"https://api.github.com/search/commits"
            headers = self._get_headers()
            headers['Accept'] = 'application/vnd.github.cloak-preview+json'

            params = {
                'q': f'repo:{repo_full_name} {search_term}',
                'per_page': 30
            }

            self.rate_limiter.wait_if_needed('github')
            response = requests.get(url, headers=headers, params=params, timeout=15)
            response.raise_for_status()

            data = response.json()
            commits = []

            for item in data.get('items', []):
                commits.append({
                    'sha': item.get('sha'),
                    'message': item.get('commit', {}).get('message'),
                    'author': item.get('commit', {}).get('author', {}).get('name'),
                    'date': item.get('commit', {}).get('author', {}).get('date'),
                    'url': item.get('html_url')
                })

            return commits

        except Exception as e:
            logger.warning(f"Commit search failed: {e}")
            return []
