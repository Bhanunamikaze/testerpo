"""Detection modules for secrets, vulnerabilities, and admin panels."""

from .secret_detector import SecretDetector
from .vulnerability_detector import VulnerabilityDetector
from .admin_panel_detector import AdminPanelDetector

__all__ = ['SecretDetector', 'VulnerabilityDetector', 'AdminPanelDetector']
