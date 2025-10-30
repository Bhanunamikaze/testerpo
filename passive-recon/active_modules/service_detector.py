"""
Service Detector - Service Version Detection

Analyzes open ports and banners to identify specific services and versions.
"""

import re
import logging
from typing import Dict, List, Optional


class ServiceDetector:
    """
    Detects services and versions from port scan results and banners.
    """

    # Common service patterns
    SERVICE_PATTERNS = {
        'ssh': [
            (r'SSH-([\d\.]+)-OpenSSH_([\d\.]+[^\s]*)', 'OpenSSH'),
            (r'SSH-([\d\.]+)', 'SSH'),
        ],
        'apache': [
            (r'Apache/([\d\.]+)', 'Apache HTTP Server'),
            (r'Apache', 'Apache HTTP Server'),
        ],
        'nginx': [
            (r'nginx/([\d\.]+)', 'nginx'),
            (r'nginx', 'nginx'),
        ],
        'iis': [
            (r'Microsoft-IIS/([\d\.]+)', 'Microsoft IIS'),
            (r'Microsoft-IIS', 'Microsoft IIS'),
        ],
        'mysql': [
            (r'([\d\.]+)-MariaDB', 'MariaDB'),
            (r'([\d\.]+)-MySQL', 'MySQL'),
        ],
        'postgresql': [
            (r'PostgreSQL ([\d\.]+)', 'PostgreSQL'),
        ],
        'redis': [
            (r'Redis', 'Redis'),
        ],
        'mongodb': [
            (r'MongoDB', 'MongoDB'),
        ],
        'elasticsearch': [
            (r'Elasticsearch', 'Elasticsearch'),
        ],
        'ftp': [
            (r'vsftpd ([\d\.]+)', 'vsftpd'),
            (r'ProFTPD ([\d\.]+)', 'ProFTPD'),
            (r'FileZilla Server', 'FileZilla'),
        ],
        'smtp': [
            (r'Postfix', 'Postfix'),
            (r'Exim ([\d\.]+)', 'Exim'),
            (r'Sendmail', 'Sendmail'),
        ]
    }

    def __init__(self, config: Dict = None):
        """
        Initialize the service detector.

        Args:
            config: Configuration dictionary (optional)
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

    def detect_services(self, port_scan_results: List[Dict]) -> List[Dict]:
        """
        Detect services from port scan results.

        Args:
            port_scan_results: List of port scan result dictionaries

        Returns:
            Enhanced results with service detection
        """
        if not port_scan_results:
            return []

        self.logger.info("Detecting services from port scan results...")

        enhanced_results = []

        for host_result in port_scan_results:
            enhanced_host = host_result.copy()
            enhanced_ports = []

            for port_info in host_result.get('open_ports', []):
                enhanced_port = port_info.copy()

                # Detect service from banner
                if port_info.get('banner'):
                    detection = self._analyze_banner(
                        port_info['banner'],
                        port_info['port']
                    )
                    if detection:
                        enhanced_port['detected_service'] = detection['service']
                        enhanced_port['version'] = detection.get('version')
                        enhanced_port['product'] = detection.get('product')

                enhanced_ports.append(enhanced_port)

            enhanced_host['open_ports'] = enhanced_ports
            enhanced_results.append(enhanced_host)

        return enhanced_results

    def _analyze_banner(self, banner: str, port: int) -> Optional[Dict]:
        """
        Analyze a banner to detect service and version.

        Args:
            banner: Banner string from port
            port: Port number

        Returns:
            Dictionary with service detection results or None
        """
        # Try to match against known patterns
        for service_type, patterns in self.SERVICE_PATTERNS.items():
            for pattern, product_name in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    result = {
                        'service': service_type,
                        'product': product_name
                    }

                    # Extract version if captured
                    if match.groups():
                        result['version'] = match.group(1)

                    return result

        # Generic detection based on common keywords
        banner_lower = banner.lower()

        if 'http' in banner_lower:
            return {'service': 'http', 'product': 'HTTP Server'}
        elif 'ftp' in banner_lower:
            return {'service': 'ftp', 'product': 'FTP Server'}
        elif 'ssh' in banner_lower:
            return {'service': 'ssh', 'product': 'SSH Server'}
        elif 'smtp' in banner_lower or 'mail' in banner_lower:
            return {'service': 'smtp', 'product': 'Mail Server'}
        elif 'mysql' in banner_lower:
            return {'service': 'mysql', 'product': 'MySQL'}
        elif 'postgres' in banner_lower:
            return {'service': 'postgresql', 'product': 'PostgreSQL'}

        return None

    def format_results(self, detection_results: List[Dict]) -> str:
        """
        Format service detection results for display.

        Args:
            detection_results: List of enhanced scan results

        Returns:
            Formatted string for logging/display
        """
        if not detection_results:
            return "No services detected"

        output = []
        output.append(f"\n{'='*70}")
        output.append("SERVICE DETECTION RESULTS")
        output.append(f"{'='*70}\n")

        for host_result in detection_results:
            output.append(f"Host: {host_result['subdomain']} ({host_result['ip']})")
            output.append("")

            for port_info in host_result.get('open_ports', []):
                port_line = f"  Port {port_info['port']}/tcp"

                if port_info.get('detected_service'):
                    product = port_info.get('product', port_info['detected_service'])
                    version = port_info.get('version', '')

                    if version:
                        port_line += f"  {product} {version}"
                    else:
                        port_line += f"  {product}"
                else:
                    port_line += f"  {port_info.get('service', 'unknown')}"

                output.append(port_line)

            output.append("")

        return "\n".join(output)
