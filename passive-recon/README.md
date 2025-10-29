# 🔍 Passive Reconnaissance Script

A comprehensive, field-tested passive reconnaissance toolkit for external penetration testing. This script discovers publicly exposed assets, credentials, secrets, and vulnerabilities **without actively touching target infrastructure**.

## ⚠️ AUTHORIZATION REQUIRED

**ONLY use this tool on targets with explicit written authorization.** Unauthorized testing is illegal and unethical. This tool is designed for:

- Authorized external penetration tests
- Red team engagements with proper authorization
- Security assessments with client consent
- Bug bounty programs within defined scope
- Educational purposes in controlled environments

## 🎯 Features

### Data Sources
- **Certificate Transparency Logs**: Subdomain discovery via crt.sh, CertSpotter
- **Search Engines**: 🚀 **NEW: Browser-based dorking** with Playwright
  - **No API keys required** - Free unlimited dorking
  - **High concurrency** - 3 browsers × 12 tabs = 36 concurrent queries
  - **Stealth features** - Anti-detection techniques built-in
  - **Alternative**: API-based (Google Custom Search, Bing API)
  - **200+ predefined dorks** across 13 categories
- **Code Repositories**: GitHub, GitLab, Bitbucket enumeration
- **Cloud Storage**: AWS S3, Google Cloud Storage, Azure Blob discovery
- **Paste Sites**: Pastebin, GitHub Gists, and more
- **Third-party SaaS**: Public Jira, Confluence, Trello, Notion pages

### Detection Capabilities
- **Secret Detection**: 80+ patterns for API keys, tokens, credentials
  - AWS keys, Azure secrets, GCP credentials
  - GitHub tokens, GitLab PATs
  - Stripe, Twilio, SendGrid keys
  - Database connection strings
  - SSH private keys, JWT tokens
- **Vulnerability Indicators**: Debug modes, exposed configs, error messages
- **Admin Panels**: DevOps dashboards, database tools, CMS admin pages
- **Information Disclosure**: Stack traces, framework leakage, backup files

### Intelligent Analysis
- **Entropy Analysis**: Identifies high-entropy strings (likely secrets)
- **Context Scoring**: Reduces false positives via keyword proximity
- **Risk Calculation**: Multi-factor risk scoring (severity × category × confidence)
- **Deduplication**: Smart deduping across sources and normalized URLs

### Output Formats
- **JSON**: Machine-readable, full finding details
- **CSV**: Spreadsheet-friendly, easy filtering
- **HTML**: Beautiful visual reports with severity highlighting

## 📦 Installation

### Requirements
- Python 3.8+
- Internet connection
- (Optional) API keys for enhanced functionality

### Setup

```bash
# Clone or extract the toolkit
cd passive-recon

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers (for browser-based dorking)
playwright install chromium

# Copy example config
cp config.example.json config.json

# Edit config with your settings
nano config.json

# Enable browser-based dorking (no API keys needed!)
# In config.json, set: "use_browser": true

# Set secure permissions
chmod 600 config.json
```

### Browser-Based vs API-Based

**Browser-Based** (Recommended - No API Keys):
- ✅ Free unlimited queries
- ✅ High speed (36+ concurrent queries)
- ✅ Better results
- ⚠️ May encounter CAPTCHAs with aggressive settings

**API-Based** (Traditional):
- ✅ No CAPTCHAs
- ✅ Stable and reliable
- ❌ Requires API keys ($5/1000 queries)
- ❌ Lower query limits

See **[BROWSER_SETUP.md](BROWSER_SETUP.md)** for detailed browser configuration.

## 🚀 Quick Start

### Basic Usage

```bash
# Simple domain scan
python passive_recon.py -c config.json -t example.com

# Multiple domains
python passive_recon.py -c config.json -t example.com example.org

# With organization name
python passive_recon.py -c config.json -t example.com "Acme Corporation"

# With scope file
python passive_recon.py -c config.json -t example.com -s scope.txt
```

### Scope File Format

Create a `scope.txt` file:

```
# Domains (one per line)
example.com
example.org

# Organizations (prefix with "org:")
org:Acme Corporation
org:ACME

# Exclusions (prefix with "exclude:")
exclude:out-of-scope.example.com
```

## 📋 Configuration

### API Keys (Optional but Recommended)

#### Google Custom Search API
1. Create project at [Google Cloud Console](https://console.cloud.google.com/)
2. Enable Custom Search API
3. Create API key
4. Create Custom Search Engine at [Programmable Search](https://programmablesearchengine.google.com/)
5. Add to config:
   ```json
   "google_api_key": "your-key",
   "google_cse_id": "your-cse-id"
   ```

#### GitHub Token
1. Generate at [GitHub Settings → Developer settings → Personal access tokens](https://github.com/settings/tokens)
2. Scopes: `public_repo`, `read:org`, `read:user`
3. Add to config:
   ```json
   "github": {
     "api_token": "ghp_..."
   }
   ```

#### Other APIs
- **Bing API**: [Azure Cognitive Services](https://azure.microsoft.com/en-us/services/cognitive-services/bing-web-search-api/)
- **CertSpotter**: [SSLMate CertSpotter](https://sslmate.com/certspotter/pricing) (free tier available)
- **Pastebin**: [Pastebin API](https://pastebin.com/doc_scraping_api) (requires PRO)

### Rate Limiting

Adjust in `config.json` based on your API quotas:

```json
"rate_limits": {
  "google": {
    "requests_per_minute": 10,
    "min_delay": 2.0
  },
  "github": {
    "requests_per_hour": 60
  }
}
```

## 📊 Output

Results are saved to `results/` directory:

```
results/
├── findings.json          # Full machine-readable findings
├── findings.csv           # Spreadsheet-friendly format
├── report.html            # Visual HTML report
└── critical_findings.json # High/critical severity only
```

### Understanding Results

Each finding includes:
- **URL**: Location of the finding
- **Title/Description**: What was found
- **Category**: Type (credential_leak, admin_interface, etc.)
- **Severity**: critical, high, medium, low, info
- **Confidence**: 0.0-1.0 score
- **Risk Score**: Composite risk assessment
- **Evidence**: Redacted snippet (secrets masked)
- **Context**: Surrounding text

### Severity Levels

| Severity | Score | Examples |
|----------|-------|----------|
| Critical | 9.0+ | Exposed credentials, AWS keys, private keys |
| High | 7.0-8.9 | Admin panels, backup files, cloud buckets |
| Medium | 4.0-6.9 | Directory listings, framework disclosure |
| Low | 2.0-3.9 | Webmail, low-impact info disclosure |
| Info | <2.0 | General reconnaissance findings |

## 🎓 Google Dorks Reference

### Credentials & Secrets
```
site:example.com ext:env
site:example.com "api_key" OR "secret_key"
site:example.com "BEGIN RSA PRIVATE KEY"
site:example.com "AWS_ACCESS_KEY_ID"
```

### Configuration Files
```
site:example.com ext:sql
site:example.com ext:bak OR ext:old
site:example.com filetype:json "firebase"
site:example.com "composer.json" OR "package.json"
```

### Admin Panels
```
site:example.com inurl:/admin
site:example.com "jenkins" OR "grafana" OR "kibana"
site:example.com "phpmyadmin"
```

### Cloud Storage
```
site:s3.amazonaws.com "company-name"
site:storage.googleapis.com "company-name"
site:blob.core.windows.net "company-name"
```

### Code Repositories
```
site:github.com "company-name" "token"
site:gist.github.com "company-name"
site:example.com ".git" OR "/.git/config"
```

### Paste Sites
```
site:pastebin.com "company-name"
site:paste.ee "company-name"
```

### Third-party SaaS
```
site:trello.com "company-name"
site:atlassian.net "company-name" AND inurl:/wiki
site:docs.google.com "company-name" "published to the web"
```

200+ additional dorks are configured in `rules/google_dorks.json`.

## 🔧 Advanced Usage

### Custom Dorks

Add to `rules/google_dorks.json`:

```json
{
  "categories": {
    "custom_category": {
      "severity": "high",
      "dorks": [
        {
          "query": "site:{domain} custom query",
          "description": "What this finds",
          "keywords": ["keyword1", "keyword2"]
        }
      ]
    }
  }
}
```

### Custom Secret Patterns

Add to `rules/secret_patterns.json`:

```json
{
  "patterns": {
    "custom_api_key": {
      "regex": "custom-[0-9a-zA-Z]{32}",
      "description": "Custom service API key",
      "severity": "high",
      "entropy_threshold": 4.0
    }
  }
}
```

### Continuous Monitoring

Run periodically via cron:

```bash
# Add to crontab
0 2 * * * cd /path/to/passive-recon && python passive_recon.py -c config.json -t example.com >> scan.log 2>&1
```

Compare results over time:

```bash
# Generate diff report
diff results/findings-2024-01-01.json results/findings-2024-01-15.json
```

## 🛠️ Troubleshooting

### Rate Limiting / CAPTCHAs

If you encounter rate limiting:
1. Increase delays in `config.json`
2. Use API keys instead of scraping
3. Reduce `max_results_per_query`
4. Add exponential backoff

### No Results Found

Common causes:
- Target has minimal online footprint
- Search engines haven't indexed target yet
- Need API keys for better coverage
- Scope too narrow

Solutions:
- Add more scope variants (subdomains, brands)
- Wait for CT log propagation (can take days for new certs)
- Use multiple search engines
- Enable more data sources

### Memory Usage

For large scans:
- Enable caching: Reduces redundant API calls
- Process domains individually
- Limit `max_subdomains` in config
- Use streaming output

## 📚 Module Structure

```
passive-recon/
├── passive_recon.py          # Main orchestrator
├── config.example.json        # Sample configuration
├── seeds/
│   └── scope_builder.py       # Target scope expansion
├── collectors/
│   ├── search_engine.py       # Google/Bing dorking
│   ├── certificate_transparency.py  # CT log queries
│   ├── github_collector.py    # Code repository enum
│   ├── cloud_storage.py       # Bucket discovery
│   └── paste_sites.py         # Paste monitoring
├── detectors/
│   ├── secret_detector.py     # Credential detection
│   ├── vulnerability_detector.py  # Vuln indicators
│   └── admin_panel_detector.py    # Admin interface detection
├── normalizers/
│   └── url_normalizer.py      # URL normalization & dedup
├── scorers/
│   └── risk_scorer.py         # Risk calculation
├── outputs/
│   └── output_handler.py      # Multi-format reports
├── utils/
│   ├── cache_manager.py       # Result caching
│   └── rate_limiter.py        # Smart rate limiting
└── rules/
    ├── google_dorks.json      # 200+ Google dorks
    └── secret_patterns.json   # 80+ secret patterns
```

## 🔒 Security Best Practices

### For Pentesters

1. **Authorization**: Always get written authorization before scanning
2. **Scope**: Stay within defined scope boundaries
3. **Disclosure**: Follow responsible disclosure for findings
4. **Evidence**: Preserve minimal evidence, encrypt at rest
5. **Credentials**: Never attempt to use discovered credentials without explicit permission

### For Tool Operation

1. **API Keys**: Store in environment variables, not in config
2. **Results**: Encrypt sensitive findings immediately
3. **Transmission**: Use encrypted channels for report delivery
4. **Retention**: Follow client data retention policies
5. **Cleanup**: Securely delete findings after engagement

### Configuration Security

```bash
# Secure config file
chmod 600 config.json

# Use environment variables for secrets
export GITHUB_TOKEN="ghp_..."
export GOOGLE_API_KEY="AIza..."

# Reference in code (not implemented by default)
api_token = os.environ.get('GITHUB_TOKEN')
```

## 🤝 Contributing

This is a specialized tool for authorized security testing. Contributions welcome:

- New data source collectors
- Additional secret patterns
- Improved detection logic
- Bug fixes and optimizations
- Documentation improvements

## 📜 License

This tool is provided for educational and authorized security testing purposes only.

## ⚖️ Legal Disclaimer

The authors and contributors:
- Assume no liability for misuse of this tool
- Do not condone unauthorized access or testing
- Recommend following all applicable laws and regulations
- Advise obtaining proper authorization before use

**Unauthorized access to computer systems is illegal.**

## 📞 Support

For issues, questions, or suggestions:
- Review documentation thoroughly
- Check configuration matches examples
- Verify API keys and permissions
- Review log files for detailed errors

## 🎯 Roadmap

Planned features:
- [ ] Wayback Machine integration
- [ ] Shodan/Censys passive lookups
- [ ] WHOIS/ASN enumeration
- [ ] Email harvesting (OSINT)
- [ ] Social media footprint analysis
- [ ] Mobile app analysis (APK/IPA inspection)
- [ ] Continuous monitoring dashboard
- [ ] Integration with security platforms (SIEM, ticketing)
- [ ] Machine learning for false positive reduction
- [ ] Automated secret verification (with caution)

## 🙏 Acknowledgments

Built on proven reconnaissance techniques from:
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- NIST Cybersecurity Framework
- Bug bounty community best practices

Uses public data sources:
- Certificate Transparency (Google, Sectigo, DigiCert)
- Search engines (Google, Bing)
- Code repositories (GitHub, GitLab)
- Community-sourced dork databases

## 📈 Performance Tips

- **Caching**: Enable aggressive caching for repeat scans
- **Parallel execution**: Run domain scans in parallel (future feature)
- **Selective modules**: Disable unused collectors to speed up scans
- **Result filtering**: Use `min_confidence` to reduce noise
- **Incremental scans**: Save state and resume interrupted scans

## 🎓 Learning Resources

- [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)
- [Certificate Transparency Explained](https://certificate.transparency.dev/)
- [OWASP Passive Reconnaissance](https://owasp.org/www-community/Passive_reconnaissance)
- [Bug Bounty Reconnaissance](https://www.bugcrowd.com/blog/recon-techniques/)

---

**Remember**: With great power comes great responsibility. Always test ethically and legally. 🛡️
