"""
Browser-Based Search Engine Collector
======================================

Uses Playwright to execute Google dorks with concurrent browser sessions.
Eliminates API key requirements and enables high-throughput dorking.

Features:
- Multiple browser sessions (configurable)
- 10-15 tabs per browser for parallel queries
- Stealth techniques to avoid detection
- Result parsing from HTML
- CAPTCHA detection and handling
"""

import asyncio
import json
import logging
import random
import time
from typing import Dict, List, Optional
from pathlib import Path
from urllib.parse import quote_plus

from utils.browser_pool import BrowserPool


logger = logging.getLogger(__name__)


class BrowserSearchEngineCollector:
    """
    Executes search engine dorks using Playwright browsers.
    Supports concurrent execution across multiple tabs and browsers.
    """

    def __init__(self, config: Dict, rate_limiter, cache_manager):
        """
        Initialize browser-based collector.

        Args:
            config: Configuration dictionary
            rate_limiter: RateLimiter instance (used for delay calculation)
            cache_manager: CacheManager instance
        """
        self.config = config
        self.rate_limiter = rate_limiter
        self.cache_manager = cache_manager
        self.dorks = self._load_dorks()

        # Browser configuration
        self.browser_config = {
            'browser_count': config.get('browser_count', 3),
            'tabs_per_browser': config.get('tabs_per_browser', 12),
            'headless': config.get('headless', True),
            'max_results_per_query': config.get('max_results_per_query', 20),
            'delay_range': config.get('delay_range', [2, 5]),  # Random delay between queries
        }

        self.stats = {
            'queries_executed': 0,
            'results_found': 0,
            'captchas_encountered': 0,
            'errors': 0,
        }

    def _load_dorks(self) -> Dict:
        """Load Google dorks from rules file."""
        dorks_file = Path(__file__).parent.parent / 'rules' / 'google_dorks.json'

        try:
            with open(dorks_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Could not load dorks: {e}")
            return {'categories': {}}

    async def collect(self, scope: Dict) -> List[Dict]:
        """
        Execute search engine queries using browsers.

        Args:
            scope: Scope dictionary with domains, brands, etc.

        Returns:
            List of findings from search engines
        """
        logger.info("Starting browser-based search engine collection...")
        logger.info(f"Configuration: {self.browser_config['browser_count']} browsers × {self.browser_config['tabs_per_browser']} tabs = {self.browser_config['browser_count'] * self.browser_config['tabs_per_browser']} concurrent operations")

        # Generate all queries
        all_queries = self._generate_all_queries(scope)
        logger.info(f"Generated {len(all_queries)} search queries")

        # Execute queries concurrently
        findings = await self._execute_queries_concurrent(all_queries)

        logger.info(f"Browser collection complete: {len(findings)} results")
        logger.info(f"Stats: {self.stats}")

        return findings

    def _generate_all_queries(self, scope: Dict) -> List[Dict]:
        """
        Generate all search queries from dorks and scope.

        Args:
            scope: Scope dictionary

        Returns:
            List of query dictionaries
        """
        queries = []

        for category_name, category_data in self.dorks.get('categories', {}).items():
            for dork in category_data.get('dorks', []):
                # Generate queries from this dork
                dork_queries = self._generate_queries_from_dork(dork, scope, category_name, category_data)
                queries.extend(dork_queries)

        return queries

    def _generate_queries_from_dork(self, dork: Dict, scope: Dict, category: str, category_data: Dict) -> List[Dict]:
        """Generate concrete queries from a dork template."""
        queries = []
        template = dork['query']

        # Replace {domain} placeholder
        if '{domain}' in template:
            for domain in scope.get('root_domains', []):
                query_string = template.replace('{domain}', domain)
                queries.append({
                    'query': query_string,
                    'category': category,
                    'severity': category_data.get('severity', 'medium'),
                    'description': dork.get('description'),
                    'keywords': dork.get('keywords', []),
                    'target': domain
                })

        # Replace {brand} placeholder
        elif '{brand}' in template:
            for brand in scope.get('brands', []):
                query_string = template.replace('{brand}', brand)
                queries.append({
                    'query': query_string,
                    'category': category,
                    'severity': category_data.get('severity', 'medium'),
                    'description': dork.get('description'),
                    'keywords': dork.get('keywords', []),
                    'target': brand
                })

        # No placeholders - apply to top targets
        else:
            for target in scope.get('root_domains', [])[:3]:
                query_string = f"{template} {target}"
                queries.append({
                    'query': query_string,
                    'category': category,
                    'severity': category_data.get('severity', 'medium'),
                    'description': dork.get('description'),
                    'keywords': dork.get('keywords', []),
                    'target': target
                })

        return queries

    async def _execute_queries_concurrent(self, queries: List[Dict]) -> List[Dict]:
        """
        Execute queries concurrently using browser pool.

        Args:
            queries: List of query dictionaries

        Returns:
            List of findings
        """
        all_findings = []

        # Initialize browser pool
        async with BrowserPool(self.browser_config) as pool:
            # Create tasks for all queries
            tasks = []
            for query_info in queries:
                # Check cache first
                cache_key = f"browser_search:{query_info['query']}"
                cached = self.cache_manager.get(cache_key)

                # Only use cache if it has actual results (skip empty results)
                if cached is not None and len(cached) > 0:
                    logger.debug(f"Cache hit: {query_info['query'][:50]}...")
                    all_findings.extend(cached)
                    continue

                # Create task
                tasks.append({
                    'query_info': query_info,
                    'cache_key': cache_key,
                    'callback': self._execute_single_query
                })

            # Execute tasks in parallel with progress tracking
            batch_size = self.browser_config['browser_count'] * self.browser_config['tabs_per_browser']
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                logger.info(f"Executing batch {i // batch_size + 1}/{(len(tasks) + batch_size - 1) // batch_size} ({len(batch)} queries)...")

                batch_results = await pool.execute_concurrent_tasks(batch)

                # Process results
                for result in batch_results:
                    if result and 'findings' in result:
                        findings = result['findings']
                        all_findings.extend(findings)

                        # Cache results
                        self.cache_manager.set(result['cache_key'], findings, ttl=3600)

                # Random delay between batches
                if i + batch_size < len(tasks):
                    delay = random.uniform(*self.browser_config['delay_range'])
                    logger.debug(f"Batch delay: {delay:.1f}s")
                    await asyncio.sleep(delay)

        return all_findings

    async def _execute_single_query(self, page, task: Dict) -> Dict:
        """
        Execute a single search query in a browser page.

        Args:
            page: Playwright page instance
            task: Task dictionary with query info

        Returns:
            Dictionary with findings
        """
        query_info = task['query_info']
        query = query_info['query']

        try:
            # Random delay before query
            await asyncio.sleep(random.uniform(0.5, 2.0))

            # Execute search
            findings = await self._search_google(page, query_info)

            self.stats['queries_executed'] += 1
            self.stats['results_found'] += len(findings)

            logger.debug(f"Query '{query[:50]}...' returned {len(findings)} results")

            return {
                'cache_key': task['cache_key'],
                'findings': findings
            }

        except Exception as e:
            logger.error(f"Query failed '{query[:50]}...': {e}")
            self.stats['errors'] += 1
            return {
                'cache_key': task['cache_key'],
                'findings': []
            }

    async def _search_google(self, page, query_info: Dict) -> List[Dict]:
        """
        Perform Google search and parse results.

        Args:
            page: Playwright page instance
            query_info: Query information

        Returns:
            List of search results
        """
        query = query_info['query']
        encoded_query = quote_plus(query)

        # Google search URL
        url = f"https://www.google.com/search?q={encoded_query}&num={self.browser_config['max_results_per_query']}"

        try:
            # Navigate to search page
            response = await page.goto(url, wait_until='domcontentloaded', timeout=30000)

            # Check for CAPTCHA
            if await self._detect_captcha(page):
                self.stats['captchas_encountered'] += 1
                logger.warning(f"CAPTCHA detected for query: {query[:50]}...")
                await asyncio.sleep(random.uniform(10, 20))  # Long delay after CAPTCHA
                return []

            # Wait for results to load
            try:
                await page.wait_for_selector('div#search', timeout=5000)
            except:
                # Results might already be loaded
                pass

            # Parse results
            results = await self._parse_google_results(page, query_info)

            return results

        except Exception as e:
            logger.error(f"Google search error: {e}")
            return []

    async def _parse_google_results(self, page, query_info: Dict) -> List[Dict]:
        """
        Parse Google search results from page.

        Args:
            page: Playwright page instance
            query_info: Query information

        Returns:
            List of parsed results
        """
        results = []

        try:
            # Get all search result containers
            result_elements = await page.query_selector_all('div.g')

            for element in result_elements[:self.browser_config['max_results_per_query']]:
                try:
                    # Extract link
                    link_elem = await element.query_selector('a')
                    if not link_elem:
                        continue

                    url = await link_elem.get_attribute('href')
                    if not url or not url.startswith('http'):
                        continue

                    # Extract title
                    title_elem = await element.query_selector('h3')
                    title = await title_elem.inner_text() if title_elem else 'No title'

                    # Extract snippet
                    snippet_elem = await element.query_selector('div[data-sncf]')
                    if not snippet_elem:
                        snippet_elem = await element.query_selector('div.VwiC3b')
                    snippet = await snippet_elem.inner_text() if snippet_elem else ''

                    # Create finding
                    finding = {
                        'url': url,
                        'title': title,
                        'snippet': snippet,
                        'query': query_info['query'],
                        'category': query_info['category'],
                        'severity': query_info['severity'],
                        'description': query_info['description'],
                        'keywords': query_info['keywords'],
                        'source': 'google_browser',
                        'timestamp': time.time()
                    }

                    results.append(finding)

                except Exception as e:
                    logger.debug(f"Error parsing result element: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error parsing Google results: {e}")

        return results

    async def _detect_captcha(self, page) -> bool:
        """
        Detect if page shows a CAPTCHA.

        Args:
            page: Playwright page instance

        Returns:
            True if CAPTCHA detected
        """
        try:
            # Check for common CAPTCHA indicators
            captcha_indicators = [
                'recaptcha',
                'captcha',
                'g-recaptcha',
                'unusual traffic',
                'automated requests'
            ]

            page_content = await page.content()
            page_text = page_content.lower()

            for indicator in captcha_indicators:
                if indicator in page_text:
                    return True

            return False

        except:
            return False

    async def _search_bing(self, page, query_info: Dict) -> List[Dict]:
        """
        Perform Bing search (alternative to Google).

        Args:
            page: Playwright page instance
            query_info: Query information

        Returns:
            List of search results
        """
        query = query_info['query']
        encoded_query = quote_plus(query)

        url = f"https://www.bing.com/search?q={encoded_query}&count={self.browser_config['max_results_per_query']}"

        try:
            await page.goto(url, wait_until='domcontentloaded', timeout=30000)

            # Wait for results
            try:
                await page.wait_for_selector('li.b_algo', timeout=5000)
            except:
                pass

            # Parse Bing results
            results = []
            result_elements = await page.query_selector_all('li.b_algo')

            for element in result_elements[:self.browser_config['max_results_per_query']]:
                try:
                    # Extract link
                    link_elem = await element.query_selector('a')
                    if not link_elem:
                        continue

                    url = await link_elem.get_attribute('href')
                    if not url or not url.startswith('http'):
                        continue

                    # Extract title
                    title_elem = await element.query_selector('h2')
                    title = await title_elem.inner_text() if title_elem else 'No title'

                    # Extract snippet
                    snippet_elem = await element.query_selector('p')
                    snippet = await snippet_elem.inner_text() if snippet_elem else ''

                    # Create finding
                    finding = {
                        'url': url,
                        'title': title,
                        'snippet': snippet,
                        'query': query_info['query'],
                        'category': query_info['category'],
                        'severity': query_info['severity'],
                        'description': query_info['description'],
                        'keywords': query_info['keywords'],
                        'source': 'bing_browser',
                        'timestamp': time.time()
                    }

                    results.append(finding)

                except Exception as e:
                    logger.debug(f"Error parsing Bing result: {e}")
                    continue

            return results

        except Exception as e:
            logger.error(f"Bing search error: {e}")
            return []

    def get_stats(self) -> Dict:
        """Get collection statistics."""
        return self.stats


# Synchronous wrapper for backward compatibility
class BrowserSearchEngineCollectorSync:
    """Synchronous wrapper for browser-based search collector."""

    def __init__(self, config: Dict, rate_limiter, cache_manager):
        self.collector = BrowserSearchEngineCollector(config, rate_limiter, cache_manager)

    def collect(self, scope: Dict) -> List[Dict]:
        """
        Synchronous collect method.

        Args:
            scope: Scope dictionary

        Returns:
            List of findings
        """
        # Run async collection in event loop
        return asyncio.run(self.collector.collect(scope))

    def get_stats(self) -> Dict:
        """Get statistics."""
        return self.collector.get_stats()
