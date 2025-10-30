#!/usr/bin/env python3
"""
Test script for output handler - validates all 4 output formats
"""

import os
import sys
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from outputs.output_handler import OutputHandler

# Sample findings with different severities and types
sample_findings = [
    {
        "type": "exposed_secret",
        "category": "secrets",
        "severity": "critical",
        "risk_score": 9.5,
        "confidence": 0.95,
        "title": "AWS Access Key Exposed",
        "description": "Found AWS access key in public GitHub repository",
        "url": "https://github.com/example/repo/blob/main/config.py",
        "source": "github",
        "data_type": "code",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "evidence": "AKIAIOSFODNN7EXAMPLE",
        "data": {
            "secret_type": "aws_access_key",
            "file_path": "config.py",
            "line_number": 42
        }
    },
    {
        "type": "subdomain",
        "category": "subdomains",
        "severity": "info",
        "risk_score": 2.0,
        "confidence": 1.0,
        "title": "Subdomain Discovered",
        "description": "New subdomain found via Certificate Transparency",
        "subdomain": "api.example.com",
        "source": "certificate_transparency",
        "data_type": "subdomain",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "data": {
            "issuer": "Let's Encrypt",
            "valid_from": "2025-01-01",
            "valid_until": "2025-12-31"
        }
    },
    {
        "type": "admin_panel",
        "category": "admin_panels",
        "severity": "high",
        "risk_score": 7.5,
        "confidence": 0.85,
        "title": "Admin Panel Detected",
        "description": "Potential admin panel found in search results",
        "url": "https://example.com/admin/login",
        "source": "google_dorks",
        "data_type": "url",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "evidence": "<title>Admin Login - Example Corp</title>",
        "data": {
            "panel_type": "custom",
            "requires_auth": True
        }
    },
    {
        "type": "vulnerability_indicator",
        "category": "vulnerabilities",
        "severity": "medium",
        "risk_score": 5.5,
        "confidence": 0.70,
        "title": "Debug Mode Enabled",
        "description": "Application appears to have debug mode enabled",
        "url": "https://staging.example.com/error",
        "source": "google_dorks",
        "data_type": "url",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "evidence": "DEBUG = True in settings.py",
        "data": {
            "framework": "Django",
            "error_type": "stack_trace"
        }
    },
    {
        "type": "cloud_storage",
        "category": "cloud_storage",
        "severity": "low",
        "risk_score": 3.0,
        "confidence": 0.60,
        "title": "Public S3 Bucket",
        "description": "Potentially accessible S3 bucket found",
        "url": "https://example-backups.s3.amazonaws.com",
        "source": "cloud_storage",
        "data_type": "url",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "data": {
            "bucket_name": "example-backups",
            "region": "us-east-1",
            "accessible": True
        }
    },
    # Active recon findings
    {
        "type": "live_subdomain",
        "category": "active_recon",
        "severity": "info",
        "risk_score": 2.0,
        "confidence": 1.0,
        "title": "Live Subdomain Confirmed",
        "description": "Subdomain is live and responding",
        "subdomain": "app.example.com",
        "source": "active_recon",
        "data_type": "subdomain",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "data": {
            "dns_records": {
                "A": ["93.184.216.34"],
                "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]
            },
            "http_status": 200,
            "https_status": 200,
            "server": "nginx/1.21.0",
            "title": "Example App - Dashboard"
        }
    },
    {
        "type": "open_ports",
        "category": "active_recon",
        "severity": "medium",
        "risk_score": 5.0,
        "confidence": 1.0,
        "title": "Open Ports Detected",
        "description": "Multiple open ports found on target",
        "subdomain": "app.example.com",
        "source": "active_recon",
        "data_type": "port_scan",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "data": {
            "ip": "93.184.216.34",
            "open_ports": [
                {"port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_8.2p1"},
                {"port": 80, "service": "HTTP", "banner": "nginx/1.21.0"},
                {"port": 443, "service": "HTTPS", "banner": "nginx/1.21.0"},
                {"port": 3306, "service": "MySQL", "banner": "5.7.33-MySQL"}
            ],
            "scan_type": "common",
            "total_scanned": 26
        }
    },
    {
        "type": "technology_detection",
        "category": "active_recon",
        "severity": "info",
        "risk_score": 2.5,
        "confidence": 0.90,
        "title": "Web Technologies Detected",
        "description": "Identified web technologies in use",
        "subdomain": "app.example.com",
        "source": "active_recon",
        "data_type": "tech_stack",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "data": {
            "technologies": {
                "cms": ["WordPress"],
                "waf": ["Cloudflare"],
                "frameworks": ["React", "Express.js"],
                "analytics": ["Google Analytics", "Hotjar"],
                "server": ["nginx/1.21.0"]
            }
        }
    },
    {
        "type": "ssl_certificate",
        "category": "active_recon",
        "severity": "low",
        "risk_score": 3.0,
        "confidence": 1.0,
        "title": "SSL Certificate Analysis",
        "description": "SSL certificate details and validation",
        "subdomain": "app.example.com",
        "source": "active_recon",
        "data_type": "certificate",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "data": {
            "certificate": {
                "subject": {
                    "common_name": "*.example.com",
                    "organization": "Example Corp"
                },
                "issuer": {
                    "common_name": "Let's Encrypt Authority X3",
                    "organization": "Let's Encrypt"
                },
                "validity": {
                    "not_before": "2025-01-01T00:00:00",
                    "not_after": "2025-12-31T23:59:59",
                    "is_expired": False,
                    "days_until_expiry": 245
                },
                "cipher": {
                    "name": "TLS_AES_256_GCM_SHA384",
                    "protocol": "TLSv1.3",
                    "bits": 256
                },
                "subject_alternative_names": [
                    "example.com",
                    "*.example.com",
                    "www.example.com"
                ]
            }
        }
    }
]

# Scan metadata
scan_metadata = {
    "scan_start": "2025-10-30T05:00:00Z",
    "scan_end": datetime.utcnow().isoformat() + 'Z',
    "targets": ["example.com"],
    "scan_type": "passive+active",
    "tool_version": "2.0.0",
    "total_findings": len(sample_findings)
}

# Test configuration
test_config = {
    "formats": ["json", "csv", "html", "txt"],
    "include_evidence": True,
    "redact_secrets": False,
    "max_snippet_length": 200
}

def main():
    print("Testing Output Handler...")
    print(f"Sample findings: {len(sample_findings)}")
    print(f"Output directory: test_results")
    print()

    # Create output handler
    output_handler = OutputHandler(test_config)

    # Generate all output formats
    output_handler.write_all_formats(sample_findings, "test_results", scan_metadata)

    print("\n" + "="*60)
    print("OUTPUT GENERATION COMPLETE")
    print("="*60)
    print("\nGenerated files:")

    output_dir = "test_results"
    for fmt in test_config['formats']:
        if fmt == 'json':
            filepath = os.path.join(output_dir, 'findings.json')
        elif fmt == 'csv':
            filepath = os.path.join(output_dir, 'findings.csv')
        elif fmt == 'html':
            filepath = os.path.join(output_dir, 'report.html')
        elif fmt == 'txt':
            filepath = os.path.join(output_dir, 'findings.txt')

        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            print(f"  ✓ {filepath} ({size:,} bytes)")
        else:
            print(f"  ✗ {filepath} (NOT FOUND)")

    print("\nTo view the HTML report:")
    print(f"  Open: {output_dir}/report.html in your browser")
    print("\nTo view the TXT report:")
    print(f"  cat {output_dir}/findings.txt")

if __name__ == "__main__":
    main()
