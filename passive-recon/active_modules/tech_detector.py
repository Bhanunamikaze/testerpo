"""
Technology Detector - CMS, WAF, and Framework Detection

Detects web technologies from HTTP responses:
- Content Management Systems (WordPress, Jira, etc.)
- Web Application Firewalls
- JavaScript Frameworks
- Analytics platforms
"""

import re
import logging
import requests
from typing import Dict, List, Set, Optional
from urllib.parse import urljoin


class TechnologyDetector:
    """
    Detects web technologies from HTTP responses and page content.
    """

    # CMS Detection patterns
    CMS_PATTERNS = {
        'WordPress': [
            r'/wp-content/',
            r'/wp-includes/',
            r'wp-json',
            r'<meta name="generator" content="WordPress'
        ],
        'Jira': [
            r'/jira/',
            r'<meta name="application-name" content="JIRA"',
            r'Atlassian Jira',
        ],
        'Confluence': [
            r'/confluence/',
            r'<meta name="confluence-',
            r'Atlassian Confluence',
        ],
        'Drupal': [
            r'/sites/default/',
            r'Drupal.settings',
            r'<meta name="generator" content="Drupal'
        ],
        'SharePoint': [
            r'/_layouts/',
            r'MicrosoftSharePointTeamServices',
            r'SharePoint',
        ],
        'MediaWiki': [
            r'/index.php?title=',
            r'MediaWiki',
            r'<meta name="generator" content="MediaWiki'
        ],
        'GitLab': [
            r'gitlab',
            r'/assets/gitlab',
            r'<meta content="GitLab"'
        ],
        'Jenkins': [
            r'/static/[^/]+/jenkins',
            r'Jenkins',
            r'X-Jenkins'
        ],
    }

    # WAF Detection (from headers)
    WAF_HEADERS = {
        'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
        'Akamai': ['akamai', 'x-akamai'],
        'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
        'Sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
        'Incapsula': ['x-cdn', 'x-iinfo'],
        'F5 BIG-IP': ['bigipserver', 'f5'],
        'Barracuda': ['barra_counter_session'],
        'ModSecurity': ['mod_security', 'NOYB'],
    }

    # Framework Detection
    FRAMEWORK_PATTERNS = {
        'React': [r'react', r'_react', r'data-react'],
        'Angular': [r'ng-', r'angular', r'data-ng-'],
        'Vue.js': [r'vue', r'v-', r'data-v-'],
        'jQuery': [r'jquery'],
        'Bootstrap': [r'bootstrap'],
        'Django': [r'csrfmiddlewaretoken'],
        'Laravel': [r'laravel_session'],
        'Ruby on Rails': [r'csrf-param', r'csrf-token'],
        'ASP.NET': [r'__VIEWSTATE', r'__EVENTVALIDATION'],
        'Express.js': [r'x-powered-by.*express'],
    }

    # Analytics Detection
    ANALYTICS_PATTERNS = {
        'Google Analytics': [r'google-analytics\.com', r'gtag', r'ga\.js'],
        'Google Tag Manager': [r'googletagmanager\.com', r'gtm\.js'],
        'Facebook Pixel': [r'facebook\.com/tr', r'fbq\('],
        'Hotjar': [r'hotjar\.com'],
        'Mixpanel': [r'mixpanel\.com'],
        'Segment': [r'segment\.(com|io)'],
    }

    def __init__(self, config: Dict = None):
        """
        Initialize the technology detector.

        Args:
            config: Configuration dictionary (optional)
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.timeout = self.config.get('timeout', 10)
        self.user_agent = self.config.get('user_agent', 'Mozilla/5.0 (Security Scanner)')

    def detect_technologies(self, subdomain_results: List[Dict]) -> List[Dict]:
        """
        Detect technologies for live subdomains.

        Args:
            subdomain_results: List of subdomain probe results

        Returns:
            Enhanced results with technology detection
        """
        if not subdomain_results:
            return []

        self.logger.info(f"Detecting web technologies for {len(subdomain_results)} hosts...")

        enhanced_results = []

        for subdomain_info in subdomain_results:
            subdomain = subdomain_info['subdomain']

            # Only check if HTTP/HTTPS is accessible
            if not (subdomain_info.get('http_status') or subdomain_info.get('https_status')):
                continue

            # Prefer HTTPS if available
            if subdomain_info.get('https_status'):
                url = f"https://{subdomain}"
            else:
                url = f"http://{subdomain}"

            technologies = self._detect_from_url(url)

            if technologies:
                enhanced_info = subdomain_info.copy()
                enhanced_info['technologies'] = technologies
                enhanced_results.append(enhanced_info)

        self.logger.info(f"Technology detection complete for {len(enhanced_results)} hosts")

        return enhanced_results

    def _detect_from_url(self, url: str) -> Dict[str, List[str]]:
        """
        Detect technologies from a URL.

        Args:
            url: URL to analyze

        Returns:
            Dictionary with detected technologies by category
        """
        technologies = {
            'cms': [],
            'waf': [],
            'frameworks': [],
            'analytics': [],
            'server': [],
            'other': []
        }

        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                headers={'User-Agent': self.user_agent},
                allow_redirects=True
            )

            # Analyze headers
            self._detect_from_headers(response.headers, technologies)

            # Analyze HTML content
            if response.text:
                self._detect_from_html(response.text, technologies)

        except Exception as e:
            self.logger.debug(f"Error detecting technologies for {url}: {e}")

        return technologies

    def _detect_from_headers(self, headers: Dict, technologies: Dict):
        """
        Detect technologies from HTTP headers.

        Args:
            headers: HTTP response headers
            technologies: Dictionary to populate with detections
        """
        # Server header
        server = headers.get('Server', '')
        if server:
            technologies['server'].append(server)

        # X-Powered-By header
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            technologies['other'].append(f"Powered by: {powered_by}")

        # WAF Detection
        for waf_name, header_indicators in self.WAF_HEADERS.items():
            for indicator in header_indicators:
                for header_name, header_value in headers.items():
                    if indicator.lower() in header_name.lower() or \
                       indicator.lower() in str(header_value).lower():
                        if waf_name not in technologies['waf']:
                            technologies['waf'].append(waf_name)
                        break

        # Framework detection from headers
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for header_name, header_value in headers.items():
                for pattern in patterns:
                    if re.search(pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                        if framework not in technologies['frameworks']:
                            technologies['frameworks'].append(framework)

    def _detect_from_html(self, html: str, technologies: Dict):
        """
        Detect technologies from HTML content.

        Args:
            html: HTML content
            technologies: Dictionary to populate with detections
        """
        html_lower = html.lower()

        # CMS Detection
        for cms_name, patterns in self.CMS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    if cms_name not in technologies['cms']:
                        technologies['cms'].append(cms_name)
                    break

        # Framework Detection
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            if framework in technologies['frameworks']:
                continue  # Already detected from headers

            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    if framework not in technologies['frameworks']:
                        technologies['frameworks'].append(framework)
                    break

        # Analytics Detection
        for analytics_name, patterns in self.ANALYTICS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    if analytics_name not in technologies['analytics']:
                        technologies['analytics'].append(analytics_name)
                    break

    def format_results(self, tech_results: List[Dict]) -> str:
        """
        Format technology detection results for display.

        Args:
            tech_results: List of results with technology detections

        Returns:
            Formatted string for logging/display
        """
        if not tech_results:
            return "No technologies detected"

        output = []
        output.append(f"\n{'='*70}")
        output.append(f"TECHNOLOGY DETECTION RESULTS ({len(tech_results)} hosts)")
        output.append(f"{'='*70}\n")

        for result in tech_results:
            output.append(f"Host: {result['subdomain']}")

            technologies = result.get('technologies', {})

            if technologies.get('server'):
                output.append(f"  Server: {', '.join(technologies['server'])}")

            if technologies.get('cms'):
                output.append(f"  CMS: {', '.join(technologies['cms'])}")

            if technologies.get('waf'):
                output.append(f"  WAF: {', '.join(technologies['waf'])}")

            if technologies.get('frameworks'):
                output.append(f"  Frameworks: {', '.join(technologies['frameworks'])}")

            if technologies.get('analytics'):
                output.append(f"  Analytics: {', '.join(technologies['analytics'])}")

            if technologies.get('other'):
                output.append(f"  Other: {', '.join(technologies['other'])}")

            output.append("")

        return "\n".join(output)
