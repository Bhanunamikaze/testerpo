#!/usr/bin/env python3
"""
Passive Reconnaissance Script for External Pentesting
======================================================

AUTHORIZATION REQUIRED: Only use on targets with explicit written authorization.

This script performs passive reconnaissance without actively touching target infrastructure.
It discovers publicly exposed assets, credentials, secrets, and vulnerabilities through:
- Certificate Transparency logs
- Search engine dorking
- Code repository enumeration
- Cloud storage discovery
- Third-party SaaS footprint analysis

Author: Pentest Team
Version: 1.0.0
"""

import argparse
import json
import logging
import sys
import signal
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Local imports
from seeds.scope_builder import ScopeBuilder
from collectors.search_engine import SearchEngineCollector
from collectors.certificate_transparency import CTCollector
from collectors.github_collector import GitHubCollector
from collectors.cloud_storage import CloudStorageCollector
from collectors.paste_sites import PasteSiteCollector
from detectors.secret_detector import SecretDetector
from detectors.vulnerability_detector import VulnerabilityDetector
from detectors.admin_panel_detector import AdminPanelDetector
from normalizers.url_normalizer import URLNormalizer
from scorers.risk_scorer import RiskScorer
from outputs.output_handler import OutputHandler
from utils.cache_manager import CacheManager
from utils.rate_limiter import RateLimiter
from utils.validator import Validator, ValidationError

# Try to import browser-based collector (optional)
try:
    from collectors.browser_search_engine import BrowserSearchEngineCollectorSync
    BROWSER_COLLECTOR_AVAILABLE = True
except ImportError:
    BROWSER_COLLECTOR_AVAILABLE = False

# Try to import active reconnaissance modules (optional - requires explicit --active-scan flag)
try:
    from active_modules.subdomain_prober import SubdomainProber
    from active_modules.port_scanner import PortScanner
    from active_modules.service_detector import ServiceDetector
    from active_modules.tech_detector import TechnologyDetector
    from active_modules.ssl_analyzer import SSLAnalyzer
    ACTIVE_MODULES_AVAILABLE = True
except ImportError:
    ACTIVE_MODULES_AVAILABLE = False


class PassiveReconScanner:
    """
    Main orchestrator for passive reconnaissance operations.
    Coordinates all collectors, detectors, and output handlers.
    """

    def __init__(self, config_path: str):
        """Initialize scanner with configuration."""
        self.config = self._load_config(config_path)
        self.setup_logging()
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.scope_builder = ScopeBuilder(self.config)
        self.normalizer = URLNormalizer()
        self.scorer = RiskScorer(self.config)
        self.cache_manager = CacheManager(self.config.get('cache_dir', 'cache'))
        self.rate_limiter = RateLimiter(self.config.get('rate_limits', {}))

        # Initialize collectors
        self.collectors = self._init_collectors()

        # Initialize detectors
        self.detectors = self._init_detectors()

        # Initialize output handler
        self.output_handler = OutputHandler(self.config.get('output', {}))

        # Storage for findings
        self.findings = []
        self.assets = set()

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[!] Configuration file not found: {config_path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[!] Invalid JSON in configuration file: {e}")
            sys.exit(1)

    def setup_logging(self):
        """Configure logging for the scanner."""
        log_level = self.config.get('log_level', 'INFO')
        log_file = self.config.get('log_file', 'passive_recon.log')

        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def _init_collectors(self) -> Dict:
        """Initialize all data collectors."""
        # Choose search engine collector based on configuration
        use_browser = self.config.get('search_engines', {}).get('use_browser', False)

        if use_browser and BROWSER_COLLECTOR_AVAILABLE:
            self.logger.info("Using browser-based search engine collector (Playwright)")
            search_collector = BrowserSearchEngineCollectorSync(
                self.config.get('search_engines', {}),
                self.rate_limiter,
                self.cache_manager
            )
        else:
            if use_browser and not BROWSER_COLLECTOR_AVAILABLE:
                self.logger.warning("Browser collector requested but not available. Install: pip install playwright && playwright install chromium")
            self.logger.info("Using API-based search engine collector")
            search_collector = SearchEngineCollector(
                self.config.get('search_engines', {}),
                self.rate_limiter,
                self.cache_manager
            )

        return {
            'search_engine': search_collector,
            'certificate_transparency': CTCollector(
                self.config.get('ct_logs', {}),
                self.cache_manager
            ),
            'github': GitHubCollector(
                self.config.get('github', {}),
                self.rate_limiter,
                self.cache_manager
            ),
            'cloud_storage': CloudStorageCollector(
                self.config.get('cloud', {}),
                self.cache_manager
            ),
            'paste_sites': PasteSiteCollector(
                self.config.get('paste_sites', {}),
                self.rate_limiter,
                self.cache_manager
            )
        }

    def _init_detectors(self) -> Dict:
        """Initialize all detection modules."""
        return {
            'secrets': SecretDetector(self.config.get('secret_patterns', {})),
            'vulnerabilities': VulnerabilityDetector(self.config.get('vuln_indicators', {})),
            'admin_panels': AdminPanelDetector(self.config.get('admin_patterns', {}))
        }

    def _init_active_modules(self) -> Dict:
        """
        Initialize active reconnaissance modules.

        ⚠️  These modules perform ACTIVE scanning and require explicit authorization!
        """
        if not ACTIVE_MODULES_AVAILABLE:
            self.logger.warning("Active modules not available - install dependencies")
            return {}

        active_config = self.config.get('active_recon', {})

        return {
            'subdomain_prober': SubdomainProber(active_config.get('subdomain_probing', {})),
            'port_scanner': PortScanner(active_config.get('port_scanning', {})),
            'service_detector': ServiceDetector(active_config.get('service_detection', {})),
            'tech_detector': TechnologyDetector(active_config.get('tech_detection', {})),
            'ssl_analyzer': SSLAnalyzer(active_config.get('ssl_analysis', {}))
        }

    def run(self, targets: List[str], scope_file: Optional[str] = None, active_scan: bool = False):
        """
        Execute the complete passive reconnaissance workflow.

        Args:
            targets: List of root domains or organization names
            scope_file: Optional file containing additional scope definitions
            active_scan: Enable active reconnaissance (requires authorization!)
        """
        # Store scan metadata for output generation
        self.scan_start_time = datetime.utcnow()
        self.scan_targets = targets
        self.scan_type = 'passive+active' if active_scan else 'passive'

        self.logger.info("="*60)
        self.logger.info("Starting Passive Reconnaissance Scan")
        self.logger.info("="*60)
        self.logger.info(f"Targets: {', '.join(targets)}")
        self.logger.info(f"Timestamp: {self.scan_start_time.isoformat()}Z")

        # Phase 1: Scope Seeding
        self.logger.info("\n[Phase 1] Building reconnaissance scope...")
        scope = self.scope_builder.build_scope(targets, scope_file)
        self.logger.info(f"  Generated {len(scope['domains'])} domain variants")
        self.logger.info(f"  Loaded {len(scope.get('organizations', []))} organization names")

        # Phase 2: Asset Discovery
        self.logger.info("\n[Phase 2] Discovering assets...")
        self._discover_assets(scope)

        # Phase 2.5: Active Reconnaissance (OPTIONAL - requires explicit flag)
        if active_scan:
            self.logger.info("\n[Phase 2.5] ⚠️  ACTIVE RECONNAISSANCE ENABLED ⚠️")
            self.logger.warning("="*60)
            self.logger.warning("PERFORMING ACTIVE SCANNING - ENSURE YOU HAVE AUTHORIZATION!")
            self.logger.warning("="*60)
            self._active_reconnaissance()
        else:
            self.logger.info("\n[Phase 2.5] Active reconnaissance: DISABLED (use --active-scan to enable)")

        # Phase 3: Content and Indicator Extraction
        self.logger.info("\n[Phase 3] Extracting indicators from discovered assets...")
        self._extract_indicators()

        # Phase 4: Detection
        self.logger.info("\n[Phase 4] Running detection modules...")
        self._run_detectors()

        # Phase 5: Risk Scoring and Deduplication
        self.logger.info("\n[Phase 5] Scoring and deduplicating findings...")
        self._score_and_deduplicate()

        # Phase 6: Output Generation
        self.logger.info("\n[Phase 6] Generating output reports...")
        self._generate_outputs()

        # Summary
        self._print_summary()

    def _discover_assets(self, scope: Dict):
        """
        Phase 2: Discover assets across all data sources.
        """
        # Certificate Transparency
        self.logger.info("  [2.1] Querying Certificate Transparency logs...")
        ct_assets = self.collectors['certificate_transparency'].collect(scope['domains'])
        self.assets.update(ct_assets)
        self.logger.info(f"    Found {len(ct_assets)} subdomains from CT logs")

        # Search Engine Dorking
        self.logger.info("  [2.2] Executing Google dorks...")
        search_results = self.collectors['search_engine'].collect(scope)
        self.assets.update([r['url'] for r in search_results])
        self.findings.extend(search_results)
        self.logger.info(f"    Found {len(search_results)} results from search engines")

        # GitHub and Code Repositories
        self.logger.info("  [2.3] Enumerating code repositories...")
        github_results = self.collectors['github'].collect(scope)
        self.findings.extend(github_results)
        self.logger.info(f"    Found {len(github_results)} repositories and gists")

        # Cloud Storage Discovery
        self.logger.info("  [2.4] Discovering cloud storage endpoints...")
        cloud_results = self.collectors['cloud_storage'].collect(scope)
        self.findings.extend(cloud_results)
        self.logger.info(f"    Found {len(cloud_results)} potential cloud storage buckets")

        # Paste Sites
        self.logger.info("  [2.5] Searching paste sites...")
        paste_results = self.collectors['paste_sites'].collect(scope)
        self.findings.extend(paste_results)
        self.logger.info(f"    Found {len(paste_results)} paste site references")

    def _active_reconnaissance(self):
        """
        Phase 2.5: Active Reconnaissance - REQUIRES AUTHORIZATION!

        Performs active scanning on discovered assets:
        - Subdomain liveness probing (DNS + HTTP/HTTPS)
        - Port scanning (TCP)
        - Service detection and banner grabbing
        - Web technology detection (CMS, WAF, frameworks)
        - SSL/TLS certificate analysis
        """
        # Initialize active modules
        active_modules = self._init_active_modules()

        if not active_modules:
            self.logger.error("Active modules not available - cannot perform active scanning")
            return

        # Extract discovered subdomains from CT logs
        subdomains_to_probe = set()

        # Get subdomains from assets
        for asset in self.assets:
            # Assets from CT logs are typically subdomains
            if not asset.startswith('http'):
                subdomains_to_probe.add(asset)

        if not subdomains_to_probe:
            self.logger.warning("No subdomains discovered to perform active reconnaissance")
            return

        self.logger.info(f"  Performing active reconnaissance on {len(subdomains_to_probe)} discovered subdomains...")

        # Step 1: Probe subdomains for liveness
        self.logger.info("\n  [2.5.1] Probing subdomains for liveness (DNS + HTTP/HTTPS)...")
        live_subdomains = active_modules['subdomain_prober'].probe_subdomains(subdomains_to_probe)
        self.logger.info(f"    ✓ Found {len(live_subdomains)} live subdomains")

        if not live_subdomains:
            self.logger.info("    No live subdomains found - skipping further active recon")
            return

        # Add liveness results to findings
        for subdomain_result in live_subdomains:
            self.findings.append({
                'category': 'active_recon',
                'type': 'live_subdomain',
                'subdomain': subdomain_result['subdomain'],
                'data': subdomain_result,
                'source': 'active_recon',
                'severity': 'info'
            })

        # Step 2: Port scanning on live hosts
        self.logger.info("\n  [2.5.2] Scanning ports on live hosts...")
        port_scan_results = active_modules['port_scanner'].scan_hosts(live_subdomains)
        self.logger.info(f"    ✓ Found {len(port_scan_results)} hosts with open ports")

        # Add port scan results to findings
        for port_result in port_scan_results:
            self.findings.append({
                'category': 'active_recon',
                'type': 'open_ports',
                'subdomain': port_result['subdomain'],
                'data': port_result,
                'source': 'active_recon',
                'severity': 'medium' if port_result['total_open'] > 0 else 'info'
            })

        # Step 3: Service detection on open ports
        if port_scan_results:
            self.logger.info("\n  [2.5.3] Detecting services on open ports...")
            service_results = active_modules['service_detector'].detect_services(port_scan_results)

            for service_result in service_results:
                self.findings.append({
                    'category': 'active_recon',
                    'type': 'service_detection',
                    'subdomain': service_result['subdomain'],
                    'data': service_result,
                    'source': 'active_recon',
                    'severity': 'info'
                })

        # Step 4: Web technology detection
        self.logger.info("\n  [2.5.4] Detecting web technologies...")
        tech_results = active_modules['tech_detector'].detect_technologies(live_subdomains)
        self.logger.info(f"    ✓ Detected technologies on {len(tech_results)} hosts")

        for tech_result in tech_results:
            # Check for concerning technologies
            severity = 'info'
            technologies = tech_result.get('technologies', {})

            # Increase severity if admin panels or development frameworks detected
            if any('admin' in str(t).lower() for t in technologies.get('cms', [])):
                severity = 'medium'

            self.findings.append({
                'category': 'active_recon',
                'type': 'technology_detection',
                'subdomain': tech_result['subdomain'],
                'data': tech_result,
                'source': 'active_recon',
                'severity': severity
            })

        # Step 5: SSL/TLS analysis
        self.logger.info("\n  [2.5.5] Analyzing SSL/TLS certificates...")
        ssl_results = active_modules['ssl_analyzer'].analyze_certificates(live_subdomains)
        self.logger.info(f"    ✓ Analyzed {len(ssl_results)} SSL certificates")

        for ssl_result in ssl_results:
            cert = ssl_result.get('certificate', {})
            validity = cert.get('validity', {})

            # Determine severity based on certificate status
            severity = 'info'
            if validity.get('is_expired'):
                severity = 'high'
            elif validity.get('expiration_warning'):
                severity = 'medium'

            self.findings.append({
                'category': 'active_recon',
                'type': 'ssl_certificate',
                'subdomain': ssl_result['subdomain'],
                'data': ssl_result,
                'source': 'active_recon',
                'severity': severity
            })

        self.logger.info("\n  Active reconnaissance complete!")
        self.logger.info(f"  Total active findings: {len([f for f in self.findings if f.get('source') == 'active_recon'])}")

    def _extract_indicators(self):
        """
        Phase 3: Extract weak-signal indicators from discovered content.
        """
        indicator_count = 0
        for finding in self.findings:
            indicators = self._classify_and_extract(finding)
            finding['indicators'] = indicators
            indicator_count += len(indicators)

        self.logger.info(f"  Extracted {indicator_count} indicators from {len(self.findings)} findings")

    def _classify_and_extract(self, finding: Dict) -> List[str]:
        """Classify finding and extract relevant indicators."""
        indicators = []
        content = finding.get('content', '') + ' ' + finding.get('title', '')

        # File type indicators
        if any(ext in finding.get('url', '') for ext in ['.env', '.git', '.bak', '.old', '.sql']):
            indicators.append('sensitive_file_extension')

        # Content indicators
        sensitive_keywords = [
            'api_key', 'secret', 'password', 'token', 'credentials',
            'private', 'backup', 'dump', 'BEGIN PRIVATE KEY', 'ssh-rsa'
        ]

        for keyword in sensitive_keywords:
            if keyword.lower() in content.lower():
                indicators.append(f'keyword_{keyword}')

        # URL patterns
        if 'index of /' in content.lower():
            indicators.append('directory_listing')

        return indicators

    def _run_detectors(self):
        """
        Phase 4: Run all detection modules on findings.
        """
        # Secret detection
        self.logger.info("  [4.1] Scanning for secrets and credentials...")
        secret_findings = self.detectors['secrets'].detect(self.findings)
        self.logger.info(f"    Detected {len(secret_findings)} potential secrets")

        # Vulnerability indicators
        self.logger.info("  [4.2] Identifying vulnerability indicators...")
        vuln_findings = self.detectors['vulnerabilities'].detect(self.findings)
        self.logger.info(f"    Identified {len(vuln_findings)} vulnerability indicators")

        # Admin panel detection
        self.logger.info("  [4.3] Detecting exposed admin panels...")
        admin_findings = self.detectors['admin_panels'].detect(self.findings)
        self.logger.info(f"    Found {len(admin_findings)} potential admin panels")

        # Merge detector results back into findings
        all_detections = secret_findings + vuln_findings + admin_findings
        for detection in all_detections:
            detection['detection_timestamp'] = datetime.utcnow().isoformat()
            self.findings.append(detection)

    def _score_and_deduplicate(self):
        """
        Phase 5: Score findings by risk and deduplicate.
        """
        # Score each finding
        for finding in self.findings:
            score = self.scorer.calculate_risk_score(finding)
            finding['risk_score'] = score['score']
            finding['severity'] = score['severity']
            finding['confidence'] = score['confidence']

        # Deduplicate
        initial_count = len(self.findings)
        self.findings = self.normalizer.deduplicate_findings(self.findings)
        deduped_count = initial_count - len(self.findings)

        self.logger.info(f"  Removed {deduped_count} duplicate findings")
        self.logger.info(f"  Total unique findings: {len(self.findings)}")

    def _generate_outputs(self):
        """
        Phase 6: Generate output files in various formats.
        """
        output_dir = self.config.get('output', {}).get('directory', 'results')

        # Build scan metadata for enhanced reporting
        scan_metadata = {
            'scan_start': self.scan_start_time.isoformat() + 'Z' if hasattr(self, 'scan_start_time') else datetime.utcnow().isoformat() + 'Z',
            'scan_end': datetime.utcnow().isoformat() + 'Z',
            'targets': self.scan_targets if hasattr(self, 'scan_targets') else [],
            'scan_type': self.scan_type if hasattr(self, 'scan_type') else 'passive',
            'tool_version': '2.0.0',
            'total_findings': len(self.findings)
        }

        # Generate all configured output formats (JSON, CSV, HTML, TXT)
        self.output_handler.write_all_formats(self.findings, output_dir, scan_metadata)

        # Log generated files
        formats = self.config.get('output', {}).get('formats', ['json', 'csv', 'html', 'txt'])
        if 'json' in formats:
            self.logger.info(f"  JSON report: {output_dir}/findings.json")
        if 'csv' in formats:
            self.logger.info(f"  CSV report: {output_dir}/findings.csv")
        if 'html' in formats:
            self.logger.info(f"  HTML report: {output_dir}/report.html")
        if 'txt' in formats:
            self.logger.info(f"  TXT report: {output_dir}/findings.txt")

        # High-severity findings (separate JSON file)
        critical_findings = [f for f in self.findings if f.get('severity') in ['high', 'critical']]
        if critical_findings:
            self.output_handler.write_json(critical_findings, output_dir, scan_metadata, filename='critical_findings.json')
            self.logger.info(f"  Critical findings: {output_dir}/critical_findings.json ({len(critical_findings)} findings)")

    def _print_summary(self):
        """Print executive summary of findings."""
        self.logger.info("\n" + "="*60)
        self.logger.info("SCAN SUMMARY")
        self.logger.info("="*60)

        # Count by severity
        severity_counts = {}
        for finding in self.findings:
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Count by category
        category_counts = {}
        for finding in self.findings:
            category = finding.get('category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1

        self.logger.info(f"\nTotal Findings: {len(self.findings)}")
        self.logger.info(f"Total Assets Discovered: {len(self.assets)}")

        self.logger.info("\nFindings by Severity:")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                self.logger.info(f"  {severity.upper()}: {count}")

        self.logger.info("\nTop Categories:")
        sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for category, count in sorted_categories:
            self.logger.info(f"  {category}: {count}")

        # High-impact findings
        critical = [f for f in self.findings if f.get('severity') in ['critical', 'high']]
        if critical:
            self.logger.info(f"\n⚠ {len(critical)} HIGH-PRIORITY findings require immediate attention!")

        self.logger.info("\n" + "="*60)


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    print("\n\n[!] Scan interrupted by user (Ctrl+C)")
    print("[!] Cleaning up and exiting...")
    print("[!] Partial results may be available in the output directory")
    sys.exit(130)


def main():
    """Main entry point for the script."""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(
        description='Passive Reconnaissance Tool for External Pentesting',
        epilog='Example: python passive_recon.py -c config.json -t example.com company-name',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-c', '--config',
        required=True,
        help='Path to configuration file (JSON)'
    )

    parser.add_argument(
        '-t', '--targets',
        nargs='+',
        required=True,
        help='Target domains or organization names'
    )

    parser.add_argument(
        '-s', '--scope-file',
        help='Optional file containing additional scope (one domain per line)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    parser.add_argument(
        '--skip-validation',
        action='store_true',
        help='Skip input validation (not recommended)'
    )

    parser.add_argument(
        '--active-scan',
        action='store_true',
        help='⚠️  Enable active reconnaissance (DNS/HTTP probing, port scanning, etc.) - REQUIRES AUTHORIZATION!'
    )

    args = parser.parse_args()

    # Show warning if active scanning is enabled
    if args.active_scan:
        print("\n" + "="*70)
        print("⚠️  WARNING: ACTIVE RECONNAISSANCE ENABLED ⚠️")
        print("="*70)
        print("Active scanning will directly interact with target infrastructure:")
        print("  - DNS lookups")
        print("  - HTTP/HTTPS requests")
        print("  - TCP port scanning")
        print("  - Service enumeration")
        print("  - Banner grabbing")
        print()
        print("LEGAL REQUIREMENT:")
        print("  You MUST have explicit written authorization from the asset owner")
        print("  before proceeding with active scanning.")
        print()
        print("Unauthorized scanning is illegal in most jurisdictions and may result")
        print("in criminal charges.")
        print("="*70)

        # Require confirmation
        try:
            confirmation = input("\nType 'I HAVE AUTHORIZATION' to continue: ")
            if confirmation != "I HAVE AUTHORIZATION":
                print("\n[!] Authorization not confirmed. Exiting...")
                sys.exit(1)
        except (KeyboardInterrupt, EOFError):
            print("\n\n[!] Scan cancelled")
            sys.exit(1)

        print("\n[+] Authorization confirmed. Proceeding with active scanning...\n")

    # Validate inputs unless explicitly skipped
    if not args.skip_validation:
        print("[*] Validating inputs...")

        config_path = Path(args.config)
        scope_path = Path(args.scope_file) if args.scope_file else None

        is_valid, results = Validator.validate_all(
            args.targets,
            config_path,
            scope_path
        )

        # Print any warnings
        if results['warnings']:
            print("\n[!] Warnings:")
            for warning in results['warnings']:
                print(f"    - {warning}")

        # Print errors and exit if validation failed
        if not is_valid:
            print("\n[!] Validation failed with the following errors:")
            for error in results['errors']:
                print(f"    - {error}")
            print("\n[!] Use --skip-validation to bypass (not recommended)")
            sys.exit(1)

        print("[+] Validation passed\n")

    # Initialize and run scanner
    try:
        scanner = PassiveReconScanner(args.config)
        scanner.run(args.targets, args.scope_file, active_scan=args.active_scan)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except ValidationError as e:
        print(f"\n[!] Validation error: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"\n[!] File not found: {e}")
        sys.exit(1)
    except PermissionError as e:
        print(f"\n[!] Permission denied: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"\n[!] Invalid JSON in configuration: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        logging.exception("Fatal error during scan:")
        sys.exit(1)


if __name__ == '__main__':
    main()
