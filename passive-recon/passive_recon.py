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

    def run(self, targets: List[str], scope_file: Optional[str] = None):
        """
        Execute the complete passive reconnaissance workflow.

        Args:
            targets: List of root domains or organization names
            scope_file: Optional file containing additional scope definitions
        """
        self.logger.info("="*60)
        self.logger.info("Starting Passive Reconnaissance Scan")
        self.logger.info("="*60)
        self.logger.info(f"Targets: {', '.join(targets)}")
        self.logger.info(f"Timestamp: {datetime.utcnow().isoformat()}Z")

        # Phase 1: Scope Seeding
        self.logger.info("\n[Phase 1] Building reconnaissance scope...")
        scope = self.scope_builder.build_scope(targets, scope_file)
        self.logger.info(f"  Generated {len(scope['domains'])} domain variants")
        self.logger.info(f"  Loaded {len(scope.get('organizations', []))} organization names")

        # Phase 2: Asset Discovery
        self.logger.info("\n[Phase 2] Discovering assets...")
        self._discover_assets(scope)

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

        # JSON output
        self.output_handler.write_json(self.findings, output_dir)
        self.logger.info(f"  JSON report: {output_dir}/findings.json")

        # CSV output
        self.output_handler.write_csv(self.findings, output_dir)
        self.logger.info(f"  CSV report: {output_dir}/findings.csv")

        # HTML report
        self.output_handler.write_html(self.findings, output_dir, self.config)
        self.logger.info(f"  HTML report: {output_dir}/report.html")

        # High-severity findings
        critical_findings = [f for f in self.findings if f.get('severity') in ['high', 'critical']]
        if critical_findings:
            self.output_handler.write_json(critical_findings, output_dir, filename='critical_findings.json')
            self.logger.info(f"  Critical findings: {output_dir}/critical_findings.json")

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

    args = parser.parse_args()

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
        scanner.run(args.targets, args.scope_file)
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
