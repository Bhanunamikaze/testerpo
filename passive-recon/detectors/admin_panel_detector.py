"""
Admin Panel Detector
====================

Detects exposed administrative interfaces:
- Web admin panels
- DevOps dashboards
- Database management tools
- Monitoring interfaces
- CI/CD systems
"""

import re
import logging
from typing import Dict, List


logger = logging.getLogger(__name__)


class AdminPanelDetector:
    """
    Detects administrative panels and dashboards in discovered assets.
    """

    ADMIN_INDICATORS = {
        'generic_admin': {
            'url_patterns': [r'/admin', r'/administrator', r'/manage', r'/dashboard', r'/panel'],
            'title_patterns': [r'admin', r'dashboard', r'control panel', r'management'],
            'severity': 'medium'
        },
        'cms_admin': {
            'url_patterns': [r'/wp-admin', r'/wp-login', r'/administrator', r'/user/login'],
            'title_patterns': [r'wordpress', r'joomla', r'drupal', r'log in'],
            'severity': 'medium'
        },
        'database_tools': {
            'url_patterns': [r'/phpmyadmin', r'/adminer', r'/myadmin', r'/pma'],
            'title_patterns': [r'phpmyadmin', r'adminer', r'database', r'mysql'],
            'severity': 'high'
        },
        'devops_dashboards': {
            'url_patterns': [r'/jenkins', r'/grafana', r'/kibana', r'/sonarqube'],
            'title_patterns': [
                r'jenkins', r'grafana', r'kibana', r'sonarqube',
                r'prometheus', r'elasticsearch'
            ],
            'severity': 'high'
        },
        'kubernetes': {
            'url_patterns': [r'/kubernetes', r'/k8s', r'/rancher', r'/argocd'],
            'title_patterns': [r'kubernetes', r'k8s dashboard', r'rancher', r'argo cd'],
            'severity': 'high'
        },
        'monitoring': {
            'url_patterns': [r'/nagios', r'/zabbix', r'/cacti', r'/observium'],
            'title_patterns': [r'nagios', r'zabbix', r'monitoring'],
            'severity': 'medium'
        },
        'repository_management': {
            'url_patterns': [r'/artifactory', r'/nexus', r'/harbor', r'/registry'],
            'title_patterns': [r'artifactory', r'nexus', r'harbor', r'docker registry'],
            'severity': 'high'
        },
        'ci_cd': {
            'url_patterns': [r'/jenkins', r'/travis', r'/circleci', r'/gitlab-ci', r'/actions'],
            'title_patterns': [r'jenkins', r'ci/cd', r'pipeline', r'build'],
            'severity': 'high'
        },
        'webmail': {
            'url_patterns': [r'/webmail', r'/roundcube', r'/squirrelmail', r'/mail'],
            'title_patterns': [r'webmail', r'roundcube', r'mail login'],
            'severity': 'low'
        },
        'vpn_remote': {
            'url_patterns': [r'/vpn', r'/remote', r'/citrix', r'/pulse'],
            'title_patterns': [r'vpn', r'remote access', r'citrix', r'pulse secure'],
            'severity': 'medium'
        }
    }

    def __init__(self, config: Dict):
        """Initialize admin panel detector."""
        self.config = config

    def detect(self, findings: List[Dict]) -> List[Dict]:
        """
        Detect administrative panels in findings.

        Args:
            findings: List of findings to scan

        Returns:
            List of detected admin panels
        """
        admin_findings = []

        for finding in findings:
            url = finding.get('url', '')
            title = finding.get('title', '')
            content = finding.get('content', '') or finding.get('snippet', '')

            # Check each admin panel type
            for panel_type, indicators in self.ADMIN_INDICATORS.items():
                if self._matches_admin_panel(url, title, content, indicators):
                    admin_finding = {
                        **finding,
                        'type': 'admin_panel',
                        'category': 'admin_interface',
                        'panel_type': panel_type,
                        'severity': indicators['severity'],
                        'description': f'Exposed {panel_type.replace("_", " ")} interface',
                        'confidence': self._calculate_confidence(url, title, indicators)
                    }
                    admin_findings.append(admin_finding)

        logger.info(f"Detected {len(admin_findings)} admin panels")
        return admin_findings

    def _matches_admin_panel(self, url: str, title: str, content: str, indicators: Dict) -> bool:
        """
        Check if URL/title/content matches admin panel indicators.

        Args:
            url: URL to check
            title: Page title
            content: Page content
            indicators: Dictionary of patterns

        Returns:
            True if matches
        """
        # Check URL patterns
        for pattern in indicators.get('url_patterns', []):
            if re.search(pattern, url, re.IGNORECASE):
                return True

        # Check title patterns
        for pattern in indicators.get('title_patterns', []):
            if re.search(pattern, title, re.IGNORECASE):
                return True

        # Check content for strong indicators
        for pattern in indicators.get('title_patterns', []):
            if re.search(pattern, content[:500], re.IGNORECASE):  # Check first 500 chars
                return True

        return False

    def _calculate_confidence(self, url: str, title: str, indicators: Dict) -> float:
        """Calculate confidence score for admin panel detection."""
        confidence = 0.5

        # URL match is strong signal
        for pattern in indicators.get('url_patterns', []):
            if re.search(pattern, url, re.IGNORECASE):
                confidence += 0.3
                break

        # Title match adds confidence
        for pattern in indicators.get('title_patterns', []):
            if re.search(pattern, title, re.IGNORECASE):
                confidence += 0.2
                break

        return min(1.0, confidence)
