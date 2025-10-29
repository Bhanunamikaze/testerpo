"""
Secret Detector
===============

Detects secrets, credentials, and API keys in discovered content using:
- Regex patterns for known secret formats
- Entropy analysis for high-entropy strings
- Context-based scoring
- Vendor-specific patterns
"""

import json
import re
import math
import logging
from typing import Dict, List, Optional
from pathlib import Path
from collections import Counter


logger = logging.getLogger(__name__)


class SecretDetector:
    """
    Detects secrets and credentials using pattern matching and entropy analysis.
    Implements false positive reduction through context and entropy checks.
    """

    def __init__(self, config: Dict):
        """
        Initialize secret detector.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> Dict:
        """Load secret patterns from rules file."""
        patterns_file = Path(__file__).parent.parent / 'rules' / 'secret_patterns.json'

        try:
            with open(patterns_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Secret patterns file not found: {patterns_file}")
            return {'patterns': {}}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in patterns file: {e}")
            return {'patterns': {}}

    def detect(self, findings: List[Dict]) -> List[Dict]:
        """
        Scan findings for secrets and credentials.

        Args:
            findings: List of findings to scan

        Returns:
            List of detected secrets
        """
        secret_findings = []

        for finding in findings:
            # Extract content to scan
            content = self._extract_scannable_content(finding)

            if not content:
                continue

            # Scan content with all patterns
            secrets = self._scan_content(content, finding)

            # Add to findings if secrets detected
            if secrets:
                for secret in secrets:
                    secret_finding = {
                        **finding,  # Copy original finding
                        'type': 'secret_detected',
                        'category': 'credential_leak',
                        'secret_type': secret['type'],
                        'secret_description': secret['description'],
                        'pattern_matched': secret['pattern_name'],
                        'severity': secret['severity'],
                        'confidence': secret['confidence'],
                        'context': secret.get('context', ''),
                        'evidence_snippet': secret.get('snippet', '')[:200],  # Limit snippet
                    }
                    secret_findings.append(secret_finding)

        logger.info(f"Detected {len(secret_findings)} potential secrets")
        return secret_findings

    def _extract_scannable_content(self, finding: Dict) -> str:
        """Extract content from finding for scanning."""
        content_fields = ['content', 'snippet', 'description', 'title']
        content_parts = []

        for field in content_fields:
            if field in finding and finding[field]:
                content_parts.append(str(finding[field]))

        return ' '.join(content_parts)

    def _scan_content(self, content: str, finding: Dict) -> List[Dict]:
        """
        Scan content for secrets using all patterns.

        Args:
            content: Content to scan
            finding: Original finding (for context)

        Returns:
            List of detected secrets
        """
        detected_secrets = []

        for pattern_name, pattern_config in self.patterns.get('patterns', {}).items():
            regex = pattern_config.get('regex')
            if not regex:
                continue

            try:
                # Compile regex
                if pattern_config.get('multiline', False):
                    matches = re.finditer(regex, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                else:
                    matches = re.finditer(regex, content, re.IGNORECASE)

                for match in matches:
                    matched_text = match.group(0)

                    # Apply filters
                    if self._is_false_positive(matched_text, pattern_config):
                        continue

                    # Calculate confidence
                    confidence = self._calculate_confidence(
                        matched_text,
                        content,
                        pattern_config
                    )

                    # Extract context
                    context = self._extract_context(content, match.start(), match.end())

                    detected_secrets.append({
                        'type': pattern_name,
                        'description': pattern_config.get('description'),
                        'pattern_name': pattern_name,
                        'severity': pattern_config.get('severity', 'medium'),
                        'confidence': confidence,
                        'snippet': matched_text,
                        'context': context
                    })

            except re.error as e:
                logger.warning(f"Invalid regex for pattern {pattern_name}: {e}")
                continue

        return detected_secrets

    def _is_false_positive(self, matched_text: str, pattern_config: Dict) -> bool:
        """
        Check if match is likely a false positive.

        Args:
            matched_text: The matched string
            pattern_config: Pattern configuration

        Returns:
            True if likely false positive
        """
        # Check against false positive filters
        fp_filters = self.patterns.get('false_positive_filters', {})

        # Check for excessive repeated characters
        max_repeated = fp_filters.get('max_repeated_chars', 4)
        for char in set(matched_text):
            if matched_text.count(char) > len(matched_text) * 0.5:
                return True
            if char * (max_repeated + 1) in matched_text:
                return True

        # Check exclude patterns
        for exclude_pattern in fp_filters.get('exclude_patterns', []):
            if re.search(exclude_pattern, matched_text, re.IGNORECASE):
                return True

        # Check common test values
        matched_lower = matched_text.lower()
        for test_value in fp_filters.get('common_test_values', []):
            if test_value in matched_lower:
                return True

        # Check entropy if threshold specified
        entropy_threshold = pattern_config.get('entropy_threshold')
        if entropy_threshold:
            entropy = self._calculate_entropy(matched_text)
            if entropy < entropy_threshold:
                return True

        return False

    def _calculate_confidence(self, matched_text: str, full_content: str, pattern_config: Dict) -> float:
        """
        Calculate confidence score for a match.

        Factors:
        - Entropy of the matched string
        - Presence of context keywords
        - Pattern specificity
        - Location in content

        Args:
            matched_text: Matched string
            full_content: Full content being scanned
            pattern_config: Pattern configuration

        Returns:
            Confidence score (0.0 to 1.0)
        """
        confidence = 0.5  # Base confidence

        # Entropy boost
        entropy = self._calculate_entropy(matched_text)
        if entropy > 4.5:
            confidence += 0.2
        elif entropy > 4.0:
            confidence += 0.1

        # Context keywords boost
        context_keywords = pattern_config.get('context_keywords', [])
        if context_keywords:
            content_lower = full_content.lower()
            matched_keywords = sum(1 for kw in context_keywords if kw.lower() in content_lower)
            if matched_keywords > 0:
                confidence += 0.1 * min(matched_keywords, 3)

        # Format verification boost
        if pattern_config.get('verification', {}).get('prefix_mandatory'):
            confidence += 0.1

        # Normalize to 0-1 range
        return min(1.0, max(0.0, confidence))

    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Higher entropy indicates more randomness (typical of secrets).

        Args:
            text: String to calculate entropy for

        Returns:
            Entropy value
        """
        if not text:
            return 0.0

        # Count character frequencies
        counter = Counter(text)
        length = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _extract_context(self, content: str, start: int, end: int, window: int = 50) -> str:
        """
        Extract context around a match.

        Args:
            content: Full content
            start: Match start position
            end: Match end position
            window: Characters to include before/after

        Returns:
            Context string
        """
        context_start = max(0, start - window)
        context_end = min(len(content), end + window)

        context = content[context_start:context_end]

        # Add ellipsis if truncated
        if context_start > 0:
            context = '...' + context
        if context_end < len(content):
            context = context + '...'

        # Redact the actual secret in context
        secret = content[start:end]
        redacted = secret[:4] + '*' * (len(secret) - 8) + secret[-4:] if len(secret) > 8 else '***'
        context = context.replace(secret, redacted)

        return context

    def verify_secret(self, secret_type: str, secret_value: str) -> Dict:
        """
        Verify if a detected secret is valid/active.

        WARNING: This makes active checks and may trigger alerts!
        Only use with explicit authorization.

        Args:
            secret_type: Type of secret
            secret_value: Secret value to verify

        Returns:
            Verification result
        """
        # Placeholder - implement with extreme caution
        # Verification would involve making API calls with the secret
        # This is ACTIVE testing and may violate authorization scope

        return {
            'verified': False,
            'method': 'not_implemented',
            'warning': 'Active verification not implemented for safety'
        }

    def get_pattern_summary(self) -> Dict:
        """Get summary of loaded patterns."""
        total = len(self.patterns.get('patterns', {}))

        by_severity = {}
        for pattern_config in self.patterns.get('patterns', {}).values():
            severity = pattern_config.get('severity', 'unknown')
            by_severity[severity] = by_severity.get(severity, 0) + 1

        return {
            'total_patterns': total,
            'by_severity': by_severity
        }
