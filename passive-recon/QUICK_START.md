# 🚀 Quick Start Guide

## 5-Minute Setup

### 1. Installation
```bash
cd passive-recon
pip install -r requirements.txt
```

### 2. Configuration
```bash
cp config.example.json config.json
# Edit config.json with your settings (API keys optional)
```

### 3. First Scan
```bash
# Basic scan (replace with authorized target)
python passive_recon.py -c config.json -t example.com

# Results in results/ directory
```

## What You Get

After the scan completes, check `results/` folder:

- **findings.json** - All findings (machine-readable)
- **findings.csv** - Spreadsheet format
- **report.html** - Visual report (open in browser)
- **critical_findings.json** - High-priority items only

## Understanding Results

### Severity Levels
- 🔴 **Critical**: Exposed credentials, private keys, AWS keys
- 🟠 **High**: Admin panels, backup files, cloud buckets
- 🟡 **Medium**: Directory listings, framework disclosure
- 🔵 **Low**: Webmail, minor info disclosure
- ⚪ **Info**: General reconnaissance data

### What to Prioritize

1. **Critical Secrets**
   - AWS/Azure/GCP credentials
   - API keys, tokens
   - Database passwords
   - Private keys

2. **High-Value Targets**
   - Public cloud buckets
   - Exposed admin panels
   - Database management tools
   - Backup files

3. **Information Disclosure**
   - Stack traces with paths
   - Debug mode enabled
   - Version information
   - Error messages

## Common Use Cases

### Scenario 1: Domain Takeover Check
```bash
python passive_recon.py -c config.json -t target.com
# Look for: Expired subdomains in CT logs
```

### Scenario 2: Credential Leak Hunt
```bash
python passive_recon.py -c config.json -t target.com "Company Name"
# Look for: GitHub repos, paste sites, cloud buckets
```

### Scenario 3: Attack Surface Mapping
```bash
python passive_recon.py -c config.json -t target.com -s scope.txt
# Look for: All discovered subdomains, admin panels, APIs
```

## No API Keys? No Problem!

The script works without API keys using:
- Certificate Transparency logs (no auth needed)
- Manual dork lists (provide to search engines manually)
- Cloud bucket enumeration (no auth needed)
- Pattern-based detection (local processing)

**With API keys, you get:**
- Automated search engine queries
- Higher rate limits
- More comprehensive coverage
- Faster scans

## Next Steps

1. **Review the HTML report** - Start with critical/high findings
2. **Validate findings** - Check if vulnerabilities are confirmed
3. **Document evidence** - Screenshots, URLs, timestamps
4. **Report to client** - Use findings.json/csv for structured reports
5. **Retest after remediation** - Compare before/after results

## Troubleshooting

### "No results found"
- Target might have minimal online footprint
- Try adding organization name: `-t domain.com "Company Name"`
- Check if domains are recently registered (CT logs take time)

### "Rate limited"
- Increase delays in config.json
- Get API keys for higher limits
- Run scan overnight with slower settings

### "Import errors"
- Install dependencies: `pip install -r requirements.txt`
- Use Python 3.8+: `python3 --version`

### "Config file not found"
- Create from example: `cp config.example.json config.json`
- Specify path: `-c /path/to/config.json`

## Pro Tips

✨ **Cache is your friend** - Second runs are much faster
✨ **Start small** - Test on one domain before bulk scanning
✨ **Read the HTML** - Most readable format for first review
✨ **Export CSV** - Great for filtering and sorting in Excel
✨ **Version control** - Save results with timestamps for comparison

## Safety Reminders

⚠️ **Authorization required** - Never scan without permission
⚠️ **Stay in scope** - Respect boundaries defined by client
⚠️ **Handle data carefully** - Results contain sensitive information
⚠️ **Don't verify secrets** - Passive only, no active testing

## Example Output

```
==============================
Passive Reconnaissance Scan
==============================
Targets: example.com
Timestamp: 2024-01-15T10:30:00Z

[Phase 1] Building scope...
  Generated 156 domain variants

[Phase 2] Discovering assets...
  [2.1] Certificate Transparency: 42 subdomains
  [2.2] Search engines: 127 results
  [2.3] GitHub: 8 repositories
  [2.4] Cloud storage: 3 buckets
  [2.5] Paste sites: 5 references

[Phase 3] Extracting indicators...

[Phase 4] Running detectors...
  [4.1] Secrets: 12 potential credentials
  [4.2] Vulnerabilities: 7 indicators
  [4.3] Admin panels: 4 interfaces

[Phase 5] Scoring and deduplicating...
  Removed 23 duplicates
  Total unique findings: 162

[Phase 6] Generating reports...
  JSON: results/findings.json
  CSV: results/findings.csv
  HTML: results/report.html
  Critical: results/critical_findings.json

==============================
SCAN SUMMARY
==============================
Total Findings: 162
Total Assets: 185

By Severity:
  CRITICAL: 3
  HIGH: 15
  MEDIUM: 67
  LOW: 45
  INFO: 32

⚠️ 18 HIGH-PRIORITY findings require immediate attention!
```

---

**Ready to scan? Remember: Authorization first! 🛡️**
