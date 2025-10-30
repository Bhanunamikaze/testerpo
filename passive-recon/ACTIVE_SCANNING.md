# Active Reconnaissance Module

⚠️  **WARNING: ACTIVE SCANNING REQUIRES EXPLICIT AUTHORIZATION** ⚠️

## Overview

The active reconnaissance module performs **active scanning** on discovered subdomains, which means directly interacting with target infrastructure. This is **DISABLED BY DEFAULT** and requires the `--active-scan` flag to enable.

### What is Active Reconnaissance?

Active reconnaissance involves **direct interaction** with target systems:
- DNS lookups
- HTTP/HTTPS requests
- TCP port scanning
- Service enumeration
- Banner grabbing
- SSL/TLS certificate retrieval

**This is different from passive reconnaissance**, which only collects publicly available information without touching the target.

---

## Legal Requirements

🚨 **UNAUTHORIZED SCANNING IS ILLEGAL** 🚨

- You **MUST** have explicit written authorization from the asset owner
- Unauthorized port scanning and service enumeration are illegal in most jurisdictions
- Violations may result in criminal charges under computer fraud and abuse laws
- Always obtain proper authorization before using `--active-scan`

---

## Modules

The active reconnaissance suite includes 5 specialized modules:

### 1. Subdomain Prober (`subdomain_prober.py`)

**Purpose:** Validate discovered subdomains for liveness

**What it does:**
- DNS resolution (A, AAAA, CNAME records)
- HTTP connectivity checks
- HTTPS connectivity checks
- Response code analysis
- Server header extraction
- Page title extraction

**Configuration:**
```json
"subdomain_probing": {
  "timeout": 5,
  "follow_redirects": true,
  "check_dns": true,
  "check_http": true,
  "check_https": true,
  "threads": 10,
  "user_agent": "Mozilla/5.0 (Security Scanner)"
}
```

### 2. Port Scanner (`port_scanner.py`)

**Purpose:** Discover open TCP ports on live hosts

**What it does:**
- TCP SYN scanning (socket-based)
- Common ports scan (fast - 26 ports)
- Top 100 ports scan (moderate)
- Custom port lists
- Banner grabbing
- Rate limiting to avoid detection

**Scan Types:**
- `common`: 26 common ports (HTTP, HTTPS, SSH, FTP, databases, etc.)
- `top100`: Top 100 most common ports
- `top1000`: Extended port list
- `full`: All ports 1-65535 (very slow!)

**Configuration:**
```json
"port_scanning": {
  "scan_type": "common",
  "timeout": 2,
  "threads": 50,
  "rate_limit": 100
}
```

### 3. Service Detector (`service_detector.py`)

**Purpose:** Identify services running on open ports

**What it does:**
- Banner analysis
- Service fingerprinting
- Version detection
- Pattern matching for common services (SSH, Apache, nginx, MySQL, etc.)

**Detected Services:**
- SSH (OpenSSH versions)
- Web servers (Apache, nginx, IIS)
- Databases (MySQL, PostgreSQL, MongoDB, Redis)
- Mail servers (Postfix, Exim, Sendmail)
- FTP servers (vsftpd, ProFTPD)

### 4. Technology Detector (`tech_detector.py`)

**Purpose:** Identify web technologies, CMS, and frameworks

**What it does:**
- CMS detection (WordPress, Jira, Confluence, Drupal, SharePoint, etc.)
- WAF detection (Cloudflare, Akamai, AWS WAF, ModSecurity, etc.)
- Framework detection (React, Angular, Vue.js, Django, Laravel, etc.)
- Analytics detection (Google Analytics, Facebook Pixel, Hotjar, etc.)
- Header analysis for technology fingerprinting

**Detected Technologies:**
- **CMS**: WordPress, Jira, Confluence, Drupal, SharePoint, MediaWiki, GitLab, Jenkins
- **WAF**: Cloudflare, Akamai, AWS WAF, Sucuri, Incapsula, F5 BIG-IP, Barracuda
- **Frameworks**: React, Angular, Vue.js, jQuery, Bootstrap, Django, Laravel, Rails, ASP.NET
- **Analytics**: Google Analytics, Google Tag Manager, Facebook Pixel, Hotjar, Mixpanel

### 5. SSL Analyzer (`ssl_analyzer.py`)

**Purpose:** Analyze SSL/TLS certificates for security issues

**What it does:**
- Certificate details extraction
- Expiration date checking
- Certificate chain validation
- Cipher suite analysis
- Subject Alternative Names (SANs) enumeration
- Expired certificate detection

**Analysis includes:**
- Certificate subject and issuer
- Validity periods
- Days until expiration (with warnings)
- Cipher information
- Protocol version
- Subject Alternative Names
- Serial number

---

## Usage

### Enable Active Scanning

```bash
python3 passive_recon.py -c config.json -t example.com --active-scan
```

### Authorization Prompt

When you use `--active-scan`, you'll see:

```
======================================================================
⚠️  WARNING: ACTIVE RECONNAISSANCE ENABLED ⚠️
======================================================================
Active scanning will directly interact with target infrastructure:
  - DNS lookups
  - HTTP/HTTPS requests
  - TCP port scanning
  - Service enumeration
  - Banner grabbing

LEGAL REQUIREMENT:
  You MUST have explicit written authorization from the asset owner
  before proceeding with active scanning.

Unauthorized scanning is illegal in most jurisdictions and may result
in criminal charges.
======================================================================

Type 'I HAVE AUTHORIZATION' to continue:
```

You **must** type exactly `I HAVE AUTHORIZATION` to proceed.

---

## Workflow

When active scanning is enabled, it runs as **Phase 2.5** (between asset discovery and content extraction):

1. **Phase 1**: Passive scope building
2. **Phase 2**: Passive asset discovery (CT logs, dorks, etc.)
3. **Phase 2.5**: 🔴 **ACTIVE RECONNAISSANCE** 🔴
   - 2.5.1: Probe subdomains for liveness
   - 2.5.2: Scan ports on live hosts
   - 2.5.3: Detect services on open ports
   - 2.5.4: Detect web technologies
   - 2.5.5: Analyze SSL/TLS certificates
4. **Phase 3**: Content extraction
5. **Phase 4**: Detection engines
6. **Phase 5**: Risk scoring
7. **Phase 6**: Output generation

---

## Output

Active reconnaissance results are added to the findings with:

```json
{
  "category": "active_recon",
  "type": "live_subdomain|open_ports|service_detection|technology_detection|ssl_certificate",
  "subdomain": "api.example.com",
  "data": {
    // Detailed results specific to the module
  },
  "source": "active_recon",
  "severity": "info|low|medium|high|critical"
}
```

### Example: Live Subdomain Finding

```json
{
  "category": "active_recon",
  "type": "live_subdomain",
  "subdomain": "api.example.com",
  "data": {
    "is_live": true,
    "dns_records": {
      "A": ["192.168.1.100"]
    },
    "http_status": 301,
    "https_status": 200,
    "https_redirect": "https://api.example.com/v1/",
    "server": "nginx/1.18.0",
    "title": "Example API Documentation"
  },
  "source": "active_recon",
  "severity": "info"
}
```

### Example: Open Ports Finding

```json
{
  "category": "active_recon",
  "type": "open_ports",
  "subdomain": "db.example.com",
  "data": {
    "ip": "192.168.1.101",
    "open_ports": [
      {
        "port": 22,
        "service": "SSH",
        "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
      },
      {
        "port": 3306,
        "service": "MySQL",
        "banner": "5.7.33-0ubuntu0.18.04.1-log"
      }
    ],
    "total_open": 2
  },
  "source": "active_recon",
  "severity": "medium"
}
```

---

## Performance

### Timing Estimates

For a typical engagement with 50 discovered subdomains:

- **Subdomain probing**: ~2-5 minutes (10 concurrent threads)
- **Port scanning**: ~1-3 minutes per live host (common ports)
- **Service detection**: ~10-30 seconds (included in port scan)
- **Tech detection**: ~5-15 seconds per live web server
- **SSL analysis**: ~2-5 seconds per HTTPS host

**Total for 50 subdomains with 10 live:** ~10-20 minutes

### Resource Usage

- **CPU**: Moderate (multi-threaded scanning)
- **Memory**: ~100-200 MB
- **Network**: Moderate bandwidth, multiple concurrent connections
- **Disk**: Minimal (results cached in memory)

---

## Detection Avoidance

Active scanning can trigger security alerts. To minimize detection:

### 1. **Rate Limiting**

Configure slower scanning in `config.json`:

```json
"port_scanning": {
  "threads": 10,      // Reduce from 50
  "rate_limit": 20,   // Reduce from 100 ports/sec
  "timeout": 5        // Increase from 2
}
```

### 2. **Scan Type**

Use `common` instead of `top100` or `full`:

```json
"port_scanning": {
  "scan_type": "common"  // Only 26 ports instead of 100+
}
```

### 3. **Timing**

- Scan during business hours (less suspicious)
- Use lower thread counts
- Add delays between hosts

---

## Best Practices

### 1. **Authorization**

✅ **DO:**
- Get written authorization before scanning
- Document the authorized scope
- Keep authorization on file
- Verify you're scanning authorized targets only

❌ **DON'T:**
- Scan without authorization
- Exceed the authorized scope
- Scan production systems during peak hours (without approval)
- Use aggressive scan settings without approval

### 2. **Communication**

✅ **DO:**
- Notify the security team before scanning
- Provide your source IP addresses
- Schedule scans during agreed windows
- Have emergency contact information ready

❌ **DON'T:**
- Scan without notification
- Ignore incident response contacts
- Continue if asked to stop

### 3. **Responsible Scanning**

✅ **DO:**
- Use reasonable rate limits
- Start with less aggressive scans
- Monitor for service disruption
- Log all scanning activity

❌ **DON'T:**
- Use maximum threads/rates
- Scan continuously without breaks
- Ignore failed connections (may indicate blocking)

---

## Troubleshooting

### Issue: "Active modules not available"

**Solution:** Install pyOpenSSL:
```bash
pip3 install pyOpenSSL>=23.3.0
```

### Issue: Connection timeouts

**Solution:** Increase timeouts in config:
```json
"subdomain_probing": {
  "timeout": 10
}
```

### Issue: "Permission denied" errors

**Solution:** Port scanning <1024 may require root on Linux:
```bash
sudo python3 passive_recon.py -c config.json -t example.com --active-scan
```

### Issue: Too many "No route to host" errors

**Solution:** Target may be blocking your IP. Use VPN or reduce scan rate.

### Issue: No open ports found

**Solution:**
- Firewall may be blocking
- Use different scan type: `"scan_type": "top100"`
- Increase timeout

---

## Dependencies

The active reconnaissance module requires:

```
requests>=2.31.0       # HTTP/HTTPS requests
pyOpenSSL>=23.3.0      # SSL/TLS certificate analysis
```

Install with:
```bash
pip3 install -r requirements.txt
```

---

## Comparison: Passive vs Active

| Feature | Passive Recon | Active Recon (--active-scan) |
|---------|---------------|------------------------------|
| **Touches target** | ❌ No | ✅ Yes |
| **Requires authorization** | Recommended | ⚠️  **REQUIRED** |
| **Detection risk** | Very Low | Medium to High |
| **Speed** | Fast | Slower |
| **Depth** | Limited | Comprehensive |
| **Legality** | Generally legal | Requires permission |
| **Discovery** | Public data only | Live hosts, services, configs |

---

## Examples

### Passive Only (Default)

```bash
python3 passive_recon.py -c config.json -t example.com
```

Output: Google dorks, CT logs, paste sites, GitHub repos

### Passive + Active

```bash
python3 passive_recon.py -c config.json -t example.com --active-scan
```

Output: Everything above + live subdomains, open ports, services, technologies, SSL certs

---

## Summary

✅ **Use Active Scanning When:**
- You have written authorization
- You need comprehensive infrastructure mapping
- You want to identify live services and technologies
- You're conducting authorized penetration testing

❌ **Don't Use Active Scanning When:**
- You lack authorization
- You're doing reconnaissance research only
- You want to stay undetected
- You're unsure about legal implications

---

**Version:** 1.0.0
**Last Updated:** 2025-10-29
**⚠️  ALWAYS GET AUTHORIZATION BEFORE ACTIVE SCANNING ⚠️**
