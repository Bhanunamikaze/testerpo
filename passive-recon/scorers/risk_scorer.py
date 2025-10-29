"""
Risk Scorer
===========

Calculates risk scores for findings based on:
- Data sensitivity
- Exposure level
- Exploitability
- Impact potential
"""

from typing import Dict


class RiskScorer:
    """
    Calculates risk scores and severity levels for findings.
    Uses multiple factors to produce accurate risk assessments.
    """

    # Base severity scores
    SEVERITY_SCORES = {
        'critical': 10.0,
        'high': 7.5,
        'medium': 5.0,
        'low': 2.5,
        'info': 1.0
    }

    # Category impact multipliers
    CATEGORY_MULTIPLIERS = {
        'credential_leak': 1.5,
        'secret_detected': 1.5,
        'code_leak': 1.3,
        'cloud_storage': 1.4,
        'admin_interface': 1.2,
        'vulnerability': 1.3,
        'paste_leak': 1.2,
        'directory_listing': 1.1,
        'info_disclosure': 1.0
    }

    def __init__(self, config: Dict):
        """Initialize risk scorer."""
        self.config = config

    def calculate_risk_score(self, finding: Dict) -> Dict:
        """
        Calculate comprehensive risk score for a finding.

        Args:
            finding: Finding dictionary

        Returns:
            Dictionary with score, severity, and factors
        """
        # Start with base severity
        base_severity = finding.get('severity', 'medium')
        base_score = self.SEVERITY_SCORES.get(base_severity, 5.0)

        # Apply category multiplier
        category = finding.get('category', 'info_disclosure')
        category_multiplier = self.CATEGORY_MULTIPLIERS.get(category, 1.0)

        # Confidence factor
        confidence = finding.get('confidence', 0.5)
        confidence_multiplier = 0.5 + (confidence * 0.5)  # Range: 0.5 to 1.0

        # Calculate final score
        score = base_score * category_multiplier * confidence_multiplier

        # Determine severity from score
        if score >= 9.0:
            severity = 'critical'
        elif score >= 7.0:
            severity = 'high'
        elif score >= 4.0:
            severity = 'medium'
        elif score >= 2.0:
            severity = 'low'
        else:
            severity = 'info'

        return {
            'score': round(score, 2),
            'severity': severity,
            'confidence': confidence,
            'factors': {
                'base_severity': base_severity,
                'base_score': base_score,
                'category': category,
                'category_multiplier': category_multiplier,
                'confidence_multiplier': confidence_multiplier
            }
        }

    def prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Sort findings by risk score (highest first).

        Args:
            findings: List of findings

        Returns:
            Sorted list
        """
        return sorted(
            findings,
            key=lambda f: f.get('risk_score', 0),
            reverse=True
        )
