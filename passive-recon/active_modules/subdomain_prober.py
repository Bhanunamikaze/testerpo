"""
Subdomain Prober - Active DNS and HTTP Liveness Checking

Performs active checks on discovered subdomains to determine:
- DNS resolution (A, AAAA, CNAME records)
- HTTP/HTTPS accessibility
- Response codes and redirects
- Server headers
"""

import socket
import logging
import requests
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class SubdomainProber:
    """
    Actively probes discovered subdomains to check liveness and gather metadata.

    ⚠️  REQUIRES AUTHORIZATION - This performs active DNS and HTTP requests
    """

    def __init__(self, config: Dict):
        """
        Initialize the subdomain prober.

        Args:
            config: Configuration dictionary with probe settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

        self.timeout = config.get('timeout', 5)
        self.follow_redirects = config.get('follow_redirects', True)
        self.check_dns = config.get('check_dns', True)
        self.check_http = config.get('check_http', True)
        self.check_https = config.get('check_https', True)
        self.max_workers = config.get('threads', 10)
        self.user_agent = config.get('user_agent', 'Mozilla/5.0 (Security Scanner)')

    def probe_subdomains(self, subdomains: Set[str]) -> List[Dict]:
        """
        Probe a list of subdomains for liveness and metadata.

        Args:
            subdomains: Set of subdomain strings to probe

        Returns:
            List of dictionaries containing probe results
        """
        if not subdomains:
            self.logger.info("No subdomains to probe")
            return []

        self.logger.info(f"Probing {len(subdomains)} subdomains for liveness...")

        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(self._probe_single, subdomain): subdomain
                for subdomain in subdomains
            }

            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self.logger.debug(f"Error probing {subdomain}: {e}")

        live_count = sum(1 for r in results if r.get('is_live', False))
        self.logger.info(f"Found {live_count} live subdomains out of {len(subdomains)}")

        return results

    def _probe_single(self, subdomain: str) -> Optional[Dict]:
        """
        Probe a single subdomain.

        Args:
            subdomain: Subdomain to probe

        Returns:
            Dictionary with probe results or None if all checks failed
        """
        result = {
            'subdomain': subdomain,
            'is_live': False,
            'dns_records': {},
            'http_status': None,
            'https_status': None,
            'http_redirect': None,
            'https_redirect': None,
            'server': None,
            'title': None,
            'technologies': []
        }

        # DNS Resolution Check
        if self.check_dns:
            dns_records = self._check_dns(subdomain)
            result['dns_records'] = dns_records

            if dns_records:
                result['is_live'] = True

        # HTTP Check
        if self.check_http and result['is_live']:
            http_result = self._check_http(subdomain, scheme='http')
            if http_result:
                result['http_status'] = http_result['status_code']
                result['http_redirect'] = http_result.get('redirect')
                result['server'] = http_result.get('server')
                result['title'] = http_result.get('title')

        # HTTPS Check
        if self.check_https and result['is_live']:
            https_result = self._check_http(subdomain, scheme='https')
            if https_result:
                result['https_status'] = https_result['status_code']
                result['https_redirect'] = https_result.get('redirect')
                if not result['server']:
                    result['server'] = https_result.get('server')
                if not result['title']:
                    result['title'] = https_result.get('title')

        # Only return if subdomain is actually live
        if result['is_live']:
            return result

        return None

    def _check_dns(self, subdomain: str) -> Dict:
        """
        Check DNS resolution for a subdomain.

        Args:
            subdomain: Subdomain to resolve

        Returns:
            Dictionary with DNS records (A, AAAA, CNAME)
        """
        records = {}

        try:
            # Get IPv4 addresses (A records)
            try:
                ipv4 = socket.getaddrinfo(subdomain, None, socket.AF_INET)
                records['A'] = list(set([addr[4][0] for addr in ipv4]))
            except socket.gaierror:
                pass

            # Get IPv6 addresses (AAAA records)
            try:
                ipv6 = socket.getaddrinfo(subdomain, None, socket.AF_INET6)
                records['AAAA'] = list(set([addr[4][0] for addr in ipv6]))
            except socket.gaierror:
                pass

            # Get canonical name (CNAME)
            try:
                cname = socket.getfqdn(subdomain)
                if cname != subdomain:
                    records['CNAME'] = cname
            except:
                pass

        except Exception as e:
            self.logger.debug(f"DNS resolution failed for {subdomain}: {e}")

        return records

    def _check_http(self, subdomain: str, scheme: str = 'http') -> Optional[Dict]:
        """
        Check HTTP/HTTPS accessibility of a subdomain.

        Args:
            subdomain: Subdomain to check
            scheme: 'http' or 'https'

        Returns:
            Dictionary with HTTP response details or None if unreachable
        """
        url = f"{scheme}://{subdomain}"

        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=False,  # Don't verify SSL for scanning
                headers={'User-Agent': self.user_agent}
            )

            result = {
                'status_code': response.status_code,
                'server': response.headers.get('Server'),
                'content_type': response.headers.get('Content-Type'),
                'content_length': len(response.content)
            }

            # Check for redirects
            if response.history:
                result['redirect'] = response.url

            # Extract title from HTML
            if 'text/html' in result.get('content_type', ''):
                title = self._extract_title(response.text)
                if title:
                    result['title'] = title

            return result

        except requests.exceptions.SSLError:
            self.logger.debug(f"SSL error for {url}")
            return None
        except requests.exceptions.ConnectionError:
            self.logger.debug(f"Connection error for {url}")
            return None
        except requests.exceptions.Timeout:
            self.logger.debug(f"Timeout for {url}")
            return None
        except Exception as e:
            self.logger.debug(f"HTTP check failed for {url}: {e}")
            return None

    def _extract_title(self, html: str) -> Optional[str]:
        """
        Extract page title from HTML.

        Args:
            html: HTML content

        Returns:
            Page title or None
        """
        try:
            import re
            match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                # Clean up whitespace
                title = re.sub(r'\s+', ' ', title)
                return title[:200]  # Limit length
        except Exception as e:
            self.logger.debug(f"Error extracting title: {e}")

        return None

    def format_results(self, probe_results: List[Dict]) -> str:
        """
        Format probe results for display.

        Args:
            probe_results: List of probe result dictionaries

        Returns:
            Formatted string for logging/display
        """
        if not probe_results:
            return "No live subdomains found"

        output = []
        output.append(f"\n{'='*70}")
        output.append(f"LIVE SUBDOMAIN PROBE RESULTS ({len(probe_results)} live)")
        output.append(f"{'='*70}\n")

        for result in probe_results:
            output.append(f"Subdomain: {result['subdomain']}")

            # DNS records
            if result['dns_records']:
                dns = result['dns_records']
                if 'A' in dns:
                    output.append(f"  IPv4: {', '.join(dns['A'])}")
                if 'AAAA' in dns:
                    output.append(f"  IPv6: {', '.join(dns['AAAA'])}")
                if 'CNAME' in dns:
                    output.append(f"  CNAME: {dns['CNAME']}")

            # HTTP status
            if result['http_status']:
                output.append(f"  HTTP: {result['http_status']}")
                if result['http_redirect']:
                    output.append(f"    → Redirects to: {result['http_redirect']}")

            # HTTPS status
            if result['https_status']:
                output.append(f"  HTTPS: {result['https_status']}")
                if result['https_redirect']:
                    output.append(f"    → Redirects to: {result['https_redirect']}")

            # Server header
            if result['server']:
                output.append(f"  Server: {result['server']}")

            # Page title
            if result['title']:
                output.append(f"  Title: {result['title']}")

            output.append("")  # Blank line between results

        return "\n".join(output)
