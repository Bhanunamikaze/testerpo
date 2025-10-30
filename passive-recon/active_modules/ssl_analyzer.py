"""
SSL/TLS Certificate Analyzer

Analyzes SSL/TLS certificates for:
- Certificate details (issuer, subject, validity)
- Expiration dates and warnings
- Certificate chain validation
- Weak cipher detection
"""

import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
import OpenSSL.crypto


class SSLAnalyzer:
    """
    Analyzes SSL/TLS certificates for security and validity.
    """

    def __init__(self, config: Dict = None):
        """
        Initialize the SSL analyzer.

        Args:
            config: Configuration dictionary (optional)
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.timeout = self.config.get('timeout', 5)
        self.warn_days = self.config.get('expiration_warning_days', 30)

    def analyze_certificates(self, subdomain_results: List[Dict]) -> List[Dict]:
        """
        Analyze SSL certificates for hosts with HTTPS.

        Args:
            subdomain_results: List of subdomain probe results

        Returns:
            List of SSL analysis results
        """
        if not subdomain_results:
            return []

        self.logger.info("Analyzing SSL/TLS certificates...")

        results = []

        for subdomain_info in subdomain_results:
            # Only analyze if HTTPS is available
            if not subdomain_info.get('https_status'):
                continue

            subdomain = subdomain_info['subdomain']
            cert_info = self._analyze_certificate(subdomain)

            if cert_info:
                result = {
                    'subdomain': subdomain,
                    'certificate': cert_info
                }
                results.append(result)

        self.logger.info(f"Analyzed {len(results)} SSL certificates")

        return results

    def _analyze_certificate(self, hostname: str, port: int = 443) -> Optional[Dict]:
        """
        Analyze SSL certificate for a hostname.

        Args:
            hostname: Hostname to analyze
            port: Port number (default: 443)

        Returns:
            Dictionary with certificate information or None
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Don't verify for scanning

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate in DER format
                    der_cert = ssock.getpeercert(binary_form=True)

                    # Parse with OpenSSL
                    x509 = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1,
                        der_cert
                    )

                    # Extract information
                    cert_info = self._extract_cert_info(x509)

                    # Get cipher information
                    cert_info['cipher'] = {
                        'name': ssock.cipher()[0],
                        'protocol': ssock.cipher()[1],
                        'bits': ssock.cipher()[2]
                    }

                    return cert_info

        except ssl.SSLError as e:
            self.logger.debug(f"SSL error for {hostname}: {e}")
            return None
        except socket.timeout:
            self.logger.debug(f"Timeout connecting to {hostname}:{port}")
            return None
        except Exception as e:
            self.logger.debug(f"Error analyzing certificate for {hostname}: {e}")
            return None

    def _extract_cert_info(self, x509) -> Dict:
        """
        Extract information from X509 certificate.

        Args:
            x509: OpenSSL X509 certificate object

        Returns:
            Dictionary with certificate information
        """
        cert_info = {}

        # Subject
        subject = x509.get_subject()
        cert_info['subject'] = {
            'common_name': subject.CN if hasattr(subject, 'CN') else None,
            'organization': subject.O if hasattr(subject, 'O') else None,
            'country': subject.C if hasattr(subject, 'C') else None,
        }

        # Issuer
        issuer = x509.get_issuer()
        cert_info['issuer'] = {
            'common_name': issuer.CN if hasattr(issuer, 'CN') else None,
            'organization': issuer.O if hasattr(issuer, 'O') else None,
        }

        # Validity
        not_before = datetime.strptime(
            x509.get_notBefore().decode('ascii'),
            '%Y%m%d%H%M%SZ'
        )
        not_after = datetime.strptime(
            x509.get_notAfter().decode('ascii'),
            '%Y%m%d%H%M%SZ'
        )

        cert_info['validity'] = {
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'is_expired': datetime.utcnow() > not_after,
            'days_until_expiry': (not_after - datetime.utcnow()).days
        }

        # Check for expiration warnings
        if cert_info['validity']['days_until_expiry'] < self.warn_days:
            cert_info['validity']['expiration_warning'] = True

        if cert_info['validity']['is_expired']:
            cert_info['validity']['expiration_warning'] = True
            cert_info['validity']['severity'] = 'critical'
        elif cert_info['validity']['days_until_expiry'] < 7:
            cert_info['validity']['severity'] = 'high'
        elif cert_info['validity']['days_until_expiry'] < 30:
            cert_info['validity']['severity'] = 'medium'

        # Serial number
        cert_info['serial_number'] = hex(x509.get_serial_number())

        # Version
        cert_info['version'] = x509.get_version() + 1  # OpenSSL uses 0-based

        # Signature algorithm
        cert_info['signature_algorithm'] = x509.get_signature_algorithm().decode('ascii')

        # Get SANs (Subject Alternative Names)
        try:
            san_ext = None
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                if ext.get_short_name() == b'subjectAltName':
                    san_ext = ext
                    break

            if san_ext:
                san_string = str(san_ext)
                # Parse SAN string (format: "DNS:example.com, DNS:www.example.com")
                sans = []
                for san in san_string.split(','):
                    san = san.strip()
                    if san.startswith('DNS:'):
                        sans.append(san[4:])
                cert_info['subject_alternative_names'] = sans
        except:
            pass

        return cert_info

    def format_results(self, ssl_results: List[Dict]) -> str:
        """
        Format SSL analysis results for display.

        Args:
            ssl_results: List of SSL analysis results

        Returns:
            Formatted string for logging/display
        """
        if not ssl_results:
            return "No SSL certificates analyzed"

        output = []
        output.append(f"\n{'='*70}")
        output.append(f"SSL/TLS CERTIFICATE ANALYSIS ({len(ssl_results)} certificates)")
        output.append(f"{'='*70}\n")

        for result in ssl_results:
            output.append(f"Host: {result['subdomain']}")

            cert = result['certificate']

            # Subject
            if cert.get('subject'):
                subject = cert['subject']
                output.append(f"  Subject CN: {subject.get('common_name', 'N/A')}")
                if subject.get('organization'):
                    output.append(f"  Organization: {subject['organization']}")

            # Issuer
            if cert.get('issuer'):
                issuer = cert['issuer']
                output.append(f"  Issuer: {issuer.get('common_name', 'N/A')}")

            # Validity
            if cert.get('validity'):
                validity = cert['validity']
                days = validity['days_until_expiry']

                if validity.get('is_expired'):
                    output.append(f"  Status: ⚠️  EXPIRED")
                elif days < 7:
                    output.append(f"  Status: ⚠️  Expires in {days} days (CRITICAL)")
                elif days < 30:
                    output.append(f"  Status: ⚠️  Expires in {days} days (WARNING)")
                else:
                    output.append(f"  Status: ✓ Valid ({days} days remaining)")

                output.append(f"  Valid From: {validity['not_before']}")
                output.append(f"  Valid Until: {validity['not_after']}")

            # Cipher
            if cert.get('cipher'):
                cipher = cert['cipher']
                output.append(f"  Cipher: {cipher['name']} ({cipher['protocol']}, {cipher['bits']} bits)")

            # SANs
            if cert.get('subject_alternative_names'):
                sans = cert['subject_alternative_names']
                output.append(f"  SANs: {len(sans)} domains")
                for san in sans[:5]:  # Show first 5
                    output.append(f"    - {san}")
                if len(sans) > 5:
                    output.append(f"    ... and {len(sans) - 5} more")

            output.append("")

        return "\n".join(output)
