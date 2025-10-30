"""
Active Reconnaissance Modules

⚠️  WARNING: ACTIVE SCANNING REQUIRES EXPLICIT AUTHORIZATION ⚠️

These modules perform ACTIVE reconnaissance which directly interacts with
target infrastructure. This includes:
- DNS lookups
- HTTP/HTTPS requests
- Port scanning
- Service enumeration
- Banner grabbing

LEGAL REQUIREMENTS:
- Written authorization from asset owner is MANDATORY
- Unauthorized scanning is illegal in most jurisdictions
- Violation may result in criminal charges
- Always obtain explicit permission before using these modules

Use --active-scan flag to enable (disabled by default)
"""

from .subdomain_prober import SubdomainProber
from .port_scanner import PortScanner
from .service_detector import ServiceDetector
from .tech_detector import TechnologyDetector
from .ssl_analyzer import SSLAnalyzer

__all__ = [
    'SubdomainProber',
    'PortScanner',
    'ServiceDetector',
    'TechnologyDetector',
    'SSLAnalyzer'
]
