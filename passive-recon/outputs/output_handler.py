"""
Output Handler
==============

Generates comprehensive output reports in multiple formats:
- JSON (machine-readable, complete data)
- CSV (spreadsheet-friendly, flattened data)
- HTML (visual report with charts and tables)
- TXT (human-readable, easy to review)
"""

import json
import csv
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from collections import Counter


logger = logging.getLogger(__name__)


class OutputHandler:
    """
    Handles output generation in multiple formats.
    Creates structured, easy-to-understand reports with evidence and statistics.
    """

    def __init__(self, config: Dict):
        """Initialize output handler."""
        self.config = config

    def write_all_formats(self, findings: List[Dict], output_dir: str, scan_metadata: Dict = None):
        """
        Write findings to all configured formats.

        Args:
            findings: List of findings
            output_dir: Output directory
            scan_metadata: Metadata about the scan
        """
        formats = self.config.get('formats', ['json', 'csv', 'html', 'txt'])

        if 'json' in formats:
            self.write_json(findings, output_dir, scan_metadata)

        if 'csv' in formats:
            self.write_csv(findings, output_dir)

        if 'html' in formats:
            self.write_html(findings, output_dir, scan_metadata)

        if 'txt' in formats:
            self.write_txt(findings, output_dir, scan_metadata)

    def write_json(self, findings: List[Dict], output_dir: str, scan_metadata: Dict = None, filename: str = 'findings.json'):
        """
        Write findings to JSON file with comprehensive metadata.

        Args:
            findings: List of findings
            output_dir: Output directory
            scan_metadata: Metadata about the scan
            filename: Output filename
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        output_path = Path(output_dir) / filename

        # Calculate statistics
        stats = self._calculate_statistics(findings)

        output_data = {
            'metadata': {
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'tool_version': '1.0.0',
                'scan_type': scan_metadata.get('scan_type', 'passive') if scan_metadata else 'passive',
                'targets': scan_metadata.get('targets', []) if scan_metadata else [],
                'total_findings': len(findings),
                'statistics': stats
            },
            'findings': findings,
            'summary': {
                'by_severity': stats['by_severity'],
                'by_category': stats['by_category'],
                'by_source': stats['by_source']
            }
        }

        try:
            with open(output_path, 'w') as f:
                json.dump(output_data, f, indent=2, default=str)
            logger.info(f"✓ JSON output written to: {output_path}")
        except IOError as e:
            logger.error(f"✗ Failed to write JSON output: {e}")

    def write_csv(self, findings: List[Dict], output_dir: str, filename: str = 'findings.csv'):
        """
        Write findings to CSV file with comprehensive columns.

        Args:
            findings: List of findings
            output_dir: Output directory
            filename: Output filename
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        output_path = Path(output_dir) / filename

        if not findings:
            logger.warning("No findings to write to CSV")
            return

        # Define comprehensive CSV columns
        columns = [
            'severity', 'risk_score', 'confidence', 'category', 'type',
            'subdomain', 'url', 'title', 'description',
            'source', 'data_type', 'timestamp', 'evidence'
        ]

        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
                writer.writeheader()

                for finding in findings:
                    # Flatten finding for CSV
                    row = {}
                    for col in columns:
                        value = finding.get(col, '')

                        # Handle nested data
                        if col == 'evidence' and 'data' in finding:
                            value = str(finding['data'])[:200]  # Truncate for CSV
                        elif col == 'subdomain' and 'data' in finding:
                            data = finding.get('data', {})
                            value = data.get('subdomain', finding.get('subdomain', ''))

                        row[col] = value

                    writer.writerow(row)

            logger.info(f"✓ CSV output written to: {output_path}")

        except IOError as e:
            logger.error(f"✗ Failed to write CSV output: {e}")

    def write_txt(self, findings: List[Dict], output_dir: str, scan_metadata: Dict = None, filename: str = 'findings.txt'):
        """
        Write findings to human-readable text file.

        Args:
            findings: List of findings
            output_dir: Output directory
            scan_metadata: Metadata about the scan
            filename: Output filename
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        output_path = Path(output_dir) / filename

        # Calculate statistics
        stats = self._calculate_statistics(findings)

        lines = []
        lines.append("=" * 80)
        lines.append("PASSIVE RECONNAISSANCE REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Tool Version: 1.0.0")

        if scan_metadata:
            lines.append(f"Targets: {', '.join(scan_metadata.get('targets', []))}")
            lines.append(f"Scan Type: {scan_metadata.get('scan_type', 'passive').upper()}")

        lines.append("")
        lines.append("=" * 80)
        lines.append("EXECUTIVE SUMMARY")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Total Findings: {len(findings)}")
        lines.append("")

        # Severity breakdown
        lines.append("Findings by Severity:")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = stats['by_severity'].get(severity, 0)
            if count > 0:
                indicator = "🔴" if severity == 'critical' else "🟠" if severity == 'high' else "🟡" if severity == 'medium' else "🔵" if severity == 'low' else "⚪"
                lines.append(f"  {indicator} {severity.upper():10s}: {count:4d} findings")

        lines.append("")

        # Category breakdown
        lines.append("Findings by Category:")
        for category, count in sorted(stats['by_category'].items(), key=lambda x: x[1], reverse=True)[:10]:
            lines.append(f"  • {category:20s}: {count:4d} findings")

        lines.append("")

        # Source breakdown
        lines.append("Findings by Source:")
        for source, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  • {source:20s}: {count:4d} findings")

        lines.append("")
        lines.append("=" * 80)
        lines.append("DETAILED FINDINGS")
        lines.append("=" * 80)

        # Group findings by severity
        by_severity = self._group_by_severity(findings)

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_findings = by_severity[severity]
            if not severity_findings:
                continue

            lines.append("")
            lines.append(f"\n{severity.upper()} SEVERITY - {len(severity_findings)} Findings")
            lines.append("-" * 80)

            for i, finding in enumerate(severity_findings, 1):
                lines.append("")
                lines.append(f"[{severity.upper()}-{i:03d}] {finding.get('title', 'Untitled Finding')}")
                lines.append("")

                # Basic info
                lines.append(f"  Category:    {finding.get('category', 'unknown')}")
                lines.append(f"  Type:        {finding.get('type', 'unknown')}")
                lines.append(f"  Severity:    {severity.upper()}")
                lines.append(f"  Risk Score:  {finding.get('risk_score', 'N/A')}")
                lines.append(f"  Confidence:  {finding.get('confidence', 0) * 100:.0f}%")
                lines.append(f"  Source:      {finding.get('source', 'unknown')}")

                # URL/Location
                if finding.get('url'):
                    lines.append(f"  URL:         {finding['url']}")
                if finding.get('subdomain'):
                    lines.append(f"  Subdomain:   {finding['subdomain']}")

                # Description
                description = (finding.get('description') or
                             finding.get('vuln_description') or
                             finding.get('secret_description') or
                             'No description available')
                lines.append(f"  Description: {description}")

                # Evidence/Data (for active recon findings)
                if finding.get('data'):
                    data = finding['data']

                    # Handle different data types
                    if finding.get('type') == 'live_subdomain':
                        if data.get('dns_records'):
                            dns = data['dns_records']
                            if dns.get('A'):
                                lines.append(f"  IP Address:  {', '.join(dns['A'])}")
                        if data.get('http_status'):
                            lines.append(f"  HTTP:        {data['http_status']}")
                        if data.get('https_status'):
                            lines.append(f"  HTTPS:       {data['https_status']}")
                        if data.get('server'):
                            lines.append(f"  Server:      {data['server']}")
                        if data.get('title'):
                            lines.append(f"  Title:       {data['title'][:60]}")

                    elif finding.get('type') == 'open_ports':
                        open_ports = data.get('open_ports', [])
                        if open_ports:
                            lines.append(f"  Open Ports:  {len(open_ports)} found")
                            for port_info in open_ports[:5]:  # Show first 5
                                port_line = f"    - {port_info['port']}/tcp  {port_info.get('service', 'unknown')}"
                                if port_info.get('banner'):
                                    port_line += f"  ({port_info['banner'][:40]})"
                                lines.append(port_line)
                            if len(open_ports) > 5:
                                lines.append(f"    ... and {len(open_ports) - 5} more")

                    elif finding.get('type') == 'technology_detection':
                        technologies = data.get('technologies', {})
                        if technologies.get('cms'):
                            lines.append(f"  CMS:         {', '.join(technologies['cms'])}")
                        if technologies.get('waf'):
                            lines.append(f"  WAF:         {', '.join(technologies['waf'])}")
                        if technologies.get('frameworks'):
                            lines.append(f"  Frameworks:  {', '.join(technologies['frameworks'][:3])}")
                        if technologies.get('server'):
                            lines.append(f"  Server:      {', '.join(technologies['server'])}")

                    elif finding.get('type') == 'ssl_certificate':
                        cert = data.get('certificate', {})
                        if cert.get('issuer'):
                            lines.append(f"  Issuer:      {cert['issuer'].get('common_name', 'N/A')}")
                        if cert.get('validity'):
                            validity = cert['validity']
                            days = validity.get('days_until_expiry', 'N/A')
                            status = "EXPIRED" if validity.get('is_expired') else f"{days} days remaining"
                            lines.append(f"  Valid Until: {validity.get('not_after', 'N/A')}")
                            lines.append(f"  Status:      {status}")

                lines.append("-" * 80)

        # Footer
        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append("⚠️  This report contains sensitive security information.")
        lines.append("Handle with care and store securely.")
        lines.append("")

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            logger.info(f"✓ TXT output written to: {output_path}")
        except IOError as e:
            logger.error(f"✗ Failed to write TXT output: {e}")

    def write_html(self, findings: List[Dict], output_dir: str, scan_metadata: Dict = None):
        """
        Generate enhanced HTML report with charts and detailed information.

        Args:
            findings: List of findings
            output_dir: Output directory
            scan_metadata: Metadata about the scan
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        output_path = Path(output_dir) / 'report.html'

        # Calculate statistics
        stats = self._calculate_statistics(findings)

        # Group findings
        by_severity = self._group_by_severity(findings)

        # Generate HTML
        html = self._generate_enhanced_html(findings, by_severity, stats, scan_metadata or {})

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            logger.info(f"✓ HTML report written to: {output_path}")
        except IOError as e:
            logger.error(f"✗ Failed to write HTML report: {e}")

    def _calculate_statistics(self, findings: List[Dict]) -> Dict:
        """Calculate comprehensive statistics from findings."""
        stats = {
            'total': len(findings),
            'by_severity': Counter(),
            'by_category': Counter(),
            'by_source': Counter(),
            'by_type': Counter()
        }

        for finding in findings:
            stats['by_severity'][finding.get('severity', 'info')] += 1
            stats['by_category'][finding.get('category', 'unknown')] += 1
            stats['by_source'][finding.get('source', 'unknown')] += 1
            stats['by_type'][finding.get('type', 'unknown')] += 1

        # Convert Counters to regular dicts
        stats['by_severity'] = dict(stats['by_severity'])
        stats['by_category'] = dict(stats['by_category'])
        stats['by_source'] = dict(stats['by_source'])
        stats['by_type'] = dict(stats['by_type'])

        return stats

    def _group_by_severity(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by severity level."""
        by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }

        for finding in findings:
            severity = finding.get('severity', 'info')
            by_severity[severity].append(finding)

        return by_severity

    def _generate_enhanced_html(self, findings: List[Dict], by_severity: Dict, stats: Dict, scan_metadata: Dict) -> str:
        """Generate enhanced HTML report with better visualization."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        # Generate severity chart data
        severity_data = ','.join([str(stats['by_severity'].get(s, 0)) for s in ['critical', 'high', 'medium', 'low', 'info']])

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passive Reconnaissance Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}

        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}

        .header .meta {{
            opacity: 0.9;
            font-size: 0.95em;
        }}

        .content {{
            padding: 40px;
        }}

        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .stat-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
        }}

        .stat-card.critical {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; }}
        .stat-card.high {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; }}
        .stat-card.medium {{ background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%); }}
        .stat-card.low {{ background: linear-gradient(135deg, #a1c4fd 0%, #c2e9fb 100%); }}
        .stat-card.info {{ background: linear-gradient(135deg, #d299c2 0%, #fef9d7 100%); }}
        .stat-card.total {{ background: linear-gradient(135deg, #30cfd0 0%, #330867 100%); color: white; }}

        .stat-card h3 {{
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
            opacity: 0.9;
        }}

        .stat-card .number {{
            font-size: 3em;
            font-weight: bold;
            line-height: 1;
        }}

        .charts {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin: 40px 0;
        }}

        .chart-container {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .chart-container h3 {{
            margin-bottom: 20px;
            color: #333;
            font-size: 1.2em;
        }}

        .section {{
            margin: 40px 0;
        }}

        .section-header {{
            background: linear-gradient(to right, #667eea, #764ba2);
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .section-header h2 {{
            font-size: 1.5em;
        }}

        .badge {{
            background: rgba(255,255,255,0.3);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }}

        .finding {{
            background: white;
            border: 1px solid #e0e0e0;
            border-left: 5px solid #ccc;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            transition: box-shadow 0.2s;
        }}

        .finding:hover {{
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }}

        .finding.critical {{ border-left-color: #f5576c; background: #fff5f7; }}
        .finding.high {{ border-left-color: #fa709a; background: #fff8f9; }}
        .finding.medium {{ border-left-color: #fcb69f; background: #fffaf8; }}
        .finding.low {{ border-left-color: #a1c4fd; background: #f8fbff; }}
        .finding.info {{ border-left-color: #d299c2; background: #faf8fc; }}

        .finding-title {{
            font-size: 1.2em;
            font-weight: 600;
            color: #333;
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .severity-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .severity-badge.critical {{ background: #f5576c; color: white; }}
        .severity-badge.high {{ background: #fa709a; color: white; }}
        .severity-badge.medium {{ background: #fcb69f; color: #333; }}
        .severity-badge.low {{ background: #a1c4fd; color: #333; }}
        .severity-badge.info {{ background: #d299c2; color: white; }}

        .finding-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            margin: 15px 0;
            font-size: 0.9em;
        }}

        .meta-item {{
            display: flex;
            flex-direction: column;
        }}

        .meta-label {{
            font-weight: 600;
            color: #666;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 3px;
        }}

        .meta-value {{
            color: #333;
            word-break: break-word;
        }}

        .finding-description {{
            color: #555;
            line-height: 1.6;
            margin: 15px 0;
        }}

        .finding-url {{
            color: #667eea;
            word-break: break-all;
            text-decoration: none;
        }}

        .finding-url:hover {{
            text-decoration: underline;
        }}

        .finding-data {{
            background: #f0f4f8;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }}

        .footer {{
            background: #2d3748;
            color: white;
            padding: 30px;
            text-align: center;
            margin-top: 40px;
        }}

        .footer p {{
            margin: 5px 0;
            opacity: 0.8;
        }}

        .no-findings {{
            text-align: center;
            padding: 60px 20px;
            color: #999;
        }}

        .no-findings-icon {{
            font-size: 4em;
            margin-bottom: 20px;
        }}

        @media print {{
            body {{ background: white; padding: 0; }}
            .container {{ box-shadow: none; }}
            .finding {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Security Reconnaissance Report</h1>
            <div class="meta">
                <p><strong>Generated:</strong> {timestamp}</p>
                <p><strong>Scan Type:</strong> {scan_metadata.get('scan_type', 'Passive').upper()}</p>
                {f"<p><strong>Targets:</strong> {', '.join(scan_metadata.get('targets', []))}</p>" if scan_metadata.get('targets') else ""}
            </div>
        </div>

        <div class="content">
            <!-- Dashboard -->
            <div class="dashboard">
                <div class="stat-card total">
                    <h3>Total Findings</h3>
                    <div class="number">{len(findings)}</div>
                </div>
"""

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = stats['by_severity'].get(severity, 0)
            html += f"""
                <div class="stat-card {severity}">
                    <h3>{severity}</h3>
                    <div class="number">{count}</div>
                </div>
"""

        html += """
            </div>

            <!-- Charts -->
            <div class="charts">
                <div class="chart-container">
                    <h3>Findings by Severity</h3>
                    <canvas id="severityChart"></canvas>
                </div>
                <div class="chart-container">
                    <h3>Findings by Category</h3>
                    <canvas id="categoryChart"></canvas>
                </div>
            </div>

            <!-- Findings -->
"""

        # Add findings by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_findings = by_severity[severity]
            if not severity_findings:
                continue

            html += f"""
            <div class="section">
                <div class="section-header">
                    <h2>{severity.upper()} Severity</h2>
                    <span class="badge">{len(severity_findings)} findings</span>
                </div>
"""

            for i, finding in enumerate(severity_findings, 1):
                title = finding.get('title', 'Untitled Finding')
                url = finding.get('url', '')
                subdomain = finding.get('subdomain', '')
                description = (finding.get('description') or
                             finding.get('vuln_description') or
                             finding.get('secret_description') or
                             'No description available')

                html += f"""
                <div class="finding {severity}">
                    <div class="finding-title">
                        <span>{self._escape_html(title)}</span>
                        <span class="severity-badge {severity}">{severity}</span>
                    </div>

                    <div class="finding-meta">
                        <div class="meta-item">
                            <span class="meta-label">Category</span>
                            <span class="meta-value">{finding.get('category', 'unknown')}</span>
                        </div>
                        <div class="meta-item">
                            <span class="meta-label">Type</span>
                            <span class="meta-value">{finding.get('type', 'unknown')}</span>
                        </div>
                        <div class="meta-item">
                            <span class="meta-label">Risk Score</span>
                            <span class="meta-value">{finding.get('risk_score', 'N/A')}</span>
                        </div>
                        <div class="meta-item">
                            <span class="meta-label">Confidence</span>
                            <span class="meta-value">{finding.get('confidence', 0) * 100:.0f}%</span>
                        </div>
                        <div class="meta-item">
                            <span class="meta-label">Source</span>
                            <span class="meta-value">{finding.get('source', 'unknown')}</span>
                        </div>
"""

                if subdomain:
                    html += f"""
                        <div class="meta-item">
                            <span class="meta-label">Subdomain</span>
                            <span class="meta-value">{self._escape_html(subdomain)}</span>
                        </div>
"""

                html += """
                    </div>

                    <div class="finding-description">
                        {self._escape_html(description)}
                    </div>
"""

                if url:
                    html += f"""
                    <p><strong>URL:</strong> <a href="{self._escape_html(url)}" class="finding-url" target="_blank">{self._escape_html(url)}</a></p>
"""

                # Add detailed data for active recon findings
                if finding.get('data'):
                    html += self._format_finding_data_html(finding)

                html += """
                </div>
"""

            html += """
            </div>
"""

        # No findings message
        if not findings:
            html += """
            <div class="no-findings">
                <div class="no-findings-icon">🎉</div>
                <h2>No Findings</h2>
                <p>No security issues were discovered during this scan.</p>
            </div>
"""

        # Footer and Scripts
        category_labels = list(stats['by_category'].keys())
        category_data = list(stats['by_category'].values())

        html += f"""
        </div>

        <div class="footer">
            <p><strong>Passive Reconnaissance Scanner v1.0.0</strong></p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
            <p>© 2025 Security Assessment Team</p>
        </div>
    </div>

    <script>
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [{severity_data}],
                    backgroundColor: [
                        '#f5576c',
                        '#fa709a',
                        '#fcb69f',
                        '#a1c4fd',
                        '#d299c2'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});

        // Category Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps(category_labels[:10])},
                datasets: [{{
                    label: 'Findings',
                    data: {json.dumps(category_data[:10])},
                    backgroundColor: 'rgba(102, 126, 234, 0.8)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            stepSize: 1
                        }}
                    }}
                }},
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""

        return html

    def _format_finding_data_html(self, finding: Dict) -> str:
        """Format finding data for HTML display."""
        data = finding.get('data', {})
        finding_type = finding.get('type', '')
        html = '<div class="finding-data">'

        if finding_type == 'live_subdomain':
            if data.get('dns_records'):
                dns = data['dns_records']
                html += '<strong>DNS Records:</strong><br>'
                if dns.get('A'):
                    html += f"  A: {', '.join(dns['A'])}<br>"
                if dns.get('AAAA'):
                    html += f"  AAAA: {', '.join(dns['AAAA'])}<br>"
                if dns.get('CNAME'):
                    html += f"  CNAME: {dns['CNAME']}<br>"

            if data.get('http_status'):
                html += f"<strong>HTTP:</strong> {data['http_status']}<br>"
            if data.get('https_status'):
                html += f"<strong>HTTPS:</strong> {data['https_status']}<br>"
            if data.get('server'):
                html += f"<strong>Server:</strong> {self._escape_html(data['server'])}<br>"
            if data.get('title'):
                html += f"<strong>Title:</strong> {self._escape_html(data['title'])}<br>"

        elif finding_type == 'open_ports':
            open_ports = data.get('open_ports', [])
            if open_ports:
                html += f'<strong>Open Ports ({len(open_ports)}):</strong><br>'
                for port_info in open_ports:
                    html += f"  Port {port_info['port']}/tcp - {port_info.get('service', 'unknown')}"
                    if port_info.get('banner'):
                        html += f" ({self._escape_html(port_info['banner'][:50])})"
                    html += '<br>'

        elif finding_type == 'technology_detection':
            technologies = data.get('technologies', {})
            if technologies.get('cms'):
                html += f"<strong>CMS:</strong> {', '.join(technologies['cms'])}<br>"
            if technologies.get('waf'):
                html += f"<strong>WAF:</strong> {', '.join(technologies['waf'])}<br>"
            if technologies.get('frameworks'):
                html += f"<strong>Frameworks:</strong> {', '.join(technologies['frameworks'])}<br>"
            if technologies.get('server'):
                html += f"<strong>Server:</strong> {', '.join(technologies['server'])}<br>"

        elif finding_type == 'ssl_certificate':
            cert = data.get('certificate', {})
            if cert.get('issuer'):
                html += f"<strong>Issuer:</strong> {cert['issuer'].get('common_name', 'N/A')}<br>"
            if cert.get('validity'):
                validity = cert['validity']
                html += f"<strong>Valid Until:</strong> {validity.get('not_after', 'N/A')}<br>"
                days = validity.get('days_until_expiry', 'N/A')
                status = "⚠️ EXPIRED" if validity.get('is_expired') else f"✓ {days} days remaining"
                html += f"<strong>Status:</strong> {status}<br>"
            if cert.get('cipher'):
                cipher = cert['cipher']
                html += f"<strong>Cipher:</strong> {cipher['name']} ({cipher['bits']} bits)<br>"

        html += '</div>'
        return html

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ''
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;'))
