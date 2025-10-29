"""
Output Handler
==============

Generates output reports in multiple formats:
- JSON (machine-readable)
- CSV (spreadsheet-friendly)
- HTML (human-readable)
"""

import json
import csv
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List


logger = logging.getLogger(__name__)


class OutputHandler:
    """
    Handles output generation in multiple formats.
    Creates structured reports with evidence and remediation guidance.
    """

    def __init__(self, config: Dict):
        """Initialize output handler."""
        self.config = config

    def write_json(self, findings: List[Dict], output_dir: str, filename: str = 'findings.json'):
        """
        Write findings to JSON file.

        Args:
            findings: List of findings
            output_dir: Output directory
            filename: Output filename
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        output_path = Path(output_dir) / filename

        output_data = {
            'metadata': {
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'total_findings': len(findings),
                'version': '1.0.0'
            },
            'findings': findings
        }

        try:
            with open(output_path, 'w') as f:
                json.dump(output_data, f, indent=2, default=str)
            logger.info(f"JSON output written to: {output_path}")
        except IOError as e:
            logger.error(f"Failed to write JSON output: {e}")

    def write_csv(self, findings: List[Dict], output_dir: str, filename: str = 'findings.csv'):
        """
        Write findings to CSV file.

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

        # Define CSV columns
        columns = [
            'severity', 'category', 'type', 'url', 'title',
            'description', 'risk_score', 'confidence', 'source',
            'timestamp'
        ]

        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
                writer.writeheader()

                for finding in findings:
                    # Flatten finding for CSV
                    row = {col: finding.get(col, '') for col in columns}
                    writer.writerow(row)

            logger.info(f"CSV output written to: {output_path}")

        except IOError as e:
            logger.error(f"Failed to write CSV output: {e}")

    def write_html(self, findings: List[Dict], output_dir: str, config: Dict = None):
        """
        Generate HTML report.

        Args:
            findings: List of findings
            output_dir: Output directory
            config: Configuration dictionary
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        output_path = Path(output_dir) / 'report.html'

        # Group findings by severity
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

        # Generate HTML
        html = self._generate_html_report(by_severity, config or {})

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            logger.info(f"HTML report written to: {output_path}")
        except IOError as e:
            logger.error(f"Failed to write HTML report: {e}")

    def _generate_html_report(self, findings_by_severity: Dict, config: Dict) -> str:
        """Generate HTML report content."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Passive Reconnaissance Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #0066cc;
            padding-bottom: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-card {{
            padding: 20px;
            border-radius: 5px;
            text-align: center;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            text-transform: uppercase;
        }}
        .summary-card .count {{
            font-size: 32px;
            font-weight: bold;
        }}
        .critical {{ background: #ffebee; color: #c62828; }}
        .high {{ background: #fff3e0; color: #e65100; }}
        .medium {{ background: #fff9c4; color: #f57f17; }}
        .low {{ background: #e1f5fe; color: #01579b; }}
        .info {{ background: #f3e5f5; color: #4a148c; }}
        .finding {{
            margin: 15px 0;
            padding: 15px;
            border-left: 4px solid #ccc;
            background: #fafafa;
        }}
        .finding.critical {{ border-left-color: #c62828; }}
        .finding.high {{ border-left-color: #e65100; }}
        .finding.medium {{ border-left-color: #f57f17; }}
        .finding.low {{ border-left-color: #01579b; }}
        .finding.info {{ border-left-color: #4a148c; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .finding-title {{
            font-weight: bold;
            font-size: 16px;
        }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .finding-details {{
            margin: 10px 0;
            font-size: 14px;
        }}
        .finding-url {{
            color: #0066cc;
            word-break: break-all;
        }}
        .section {{
            margin: 30px 0;
        }}
        .section h2 {{
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 8px;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            text-align: center;
            color: #999;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Passive Reconnaissance Report</h1>
        <p><strong>Generated:</strong> {timestamp}</p>

        <div class="summary">
"""

        # Add summary cards
        total = sum(len(findings) for findings in findings_by_severity.values())
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = len(findings_by_severity[severity])
            html += f"""
            <div class="summary-card {severity}">
                <h3>{severity}</h3>
                <div class="count">{count}</div>
            </div>
"""

        html += f"""
        </div>

        <div class="summary-card" style="background: #e8f5e9; color: #2e7d32; margin: 20px 0;">
            <h3>Total Findings</h3>
            <div class="count">{total}</div>
        </div>
"""

        # Add findings by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings = findings_by_severity[severity]
            if not findings:
                continue

            html += f"""
        <div class="section">
            <h2>{severity.upper()} Severity ({len(findings)} findings)</h2>
"""

            for finding in findings:
                title = finding.get('title', 'Untitled Finding')
                url = finding.get('url', 'N/A')
                description = finding.get('description', '') or finding.get('vuln_description', '') or finding.get('secret_description', '')
                category = finding.get('category', 'unknown')
                confidence = finding.get('confidence', 0) * 100

                html += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">{self._escape_html(title[:100])}</div>
                    <span class="severity-badge {severity}">{severity}</span>
                </div>
                <div class="finding-details">
                    <p><strong>Category:</strong> {category}</p>
                    <p><strong>URL:</strong> <a href="{url}" class="finding-url" target="_blank">{self._escape_html(url[:100])}</a></p>
                    <p><strong>Description:</strong> {self._escape_html(description)}</p>
                    <p><strong>Confidence:</strong> {confidence:.0f}%</p>
                </div>
            </div>
"""

            html += """
        </div>
"""

        # Footer
        html += f"""
        <div class="footer">
            <p>Generated by Passive Reconnaissance Scanner v1.0.0</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
"""

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
