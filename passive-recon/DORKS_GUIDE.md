# 🔎 Google Dorks Comprehensive Guide

## Table of Contents
1. [Sensitive Files](#sensitive-files)
2. [Credentials & API Keys](#credentials--api-keys)
3. [Admin Panels](#admin-panels)
4. [Directory Listings](#directory-listings)
5. [Cloud Storage](#cloud-storage)
6. [Code Repositories](#code-repositories)
7. [API Endpoints](#api-endpoints)
8. [Paste Sites](#paste-sites)
9. [Collaboration Platforms](#collaboration-platforms)
10. [Brand Impersonation](#brand-impersonation)

---

## Sensitive Files

### Environment Files
```
site:example.com ext:env OR filetype:env
site:example.com ".env"
site:example.com intext:"APP_KEY" OR intext:"DB_PASSWORD"
```

**What to look for:**
- `APP_KEY`, `APP_SECRET`
- `DB_PASSWORD`, `DATABASE_URL`
- `API_KEY`, `SECRET_KEY`
- Service credentials (AWS, SendGrid, etc.)

### SQL Dumps
```
site:example.com ext:sql OR filetype:sql
site:example.com "INSERT INTO" "password"
site:example.com "CREATE TABLE" "users"
site:example.com "dump" ext:sql
```

**Risk:** Database backups may contain:
- User credentials (hashed or plaintext)
- Application secrets
- Business-critical data

### Configuration Files
```
site:example.com ext:xml "backup"
site:example.com ext:config OR ext:conf
site:example.com "application.properties" OR "application.yml"
site:example.com "web.config"
site:example.com "settings.py"
```

### Backup Files
```
site:example.com ext:bak OR ext:old OR ext:backup
site:example.com ext:zip "backup"
site:example.com ext:tar.gz "backup"
site:example.com ext:7z "database"
```

---

## Credentials & API Keys

### AWS Credentials
```
site:example.com "AWS_ACCESS_KEY_ID" OR "AWS_SECRET_ACCESS_KEY"
site:example.com "AKIA[0-9A-Z]{16}"
site:github.com "example.com" "AKIA"
```

**Format:** AWS Access Keys start with `AKIA`, `ASIA`, `AIDA`, or `AROA`

### GitHub Tokens
```
site:example.com "ghp_" OR "gho_" OR "ghu_"
site:github.com "example.com" "ghp_"
site:gist.github.com "example.com" "token"
```

**Format:** GitHub PATs start with `ghp_`, OAuth tokens with `gho_`

### Google API Keys
```
site:example.com "AIza" "api_key"
site:example.com "firebase" "apiKey"
site:github.com "example.com" "AIza"
```

**Format:** Google API keys start with `AIza`

### Stripe Keys
```
site:example.com "sk_live_" OR "pk_live_"
site:example.com "sk_test_" OR "pk_test_"
site:github.com "example.com" "sk_live_"
```

**Format:**
- Secret keys: `sk_live_`, `sk_test_`
- Publishable keys: `pk_live_`, `pk_test_`

### Generic Secrets
```
site:example.com intext:"api_key" OR intext:"apikey"
site:example.com intext:"secret" "="
site:example.com "password" "=" -site:example.com/docs
site:example.com "Authorization: Bearer"
```

### Private Keys
```
site:example.com "BEGIN RSA PRIVATE KEY"
site:example.com "BEGIN OPENSSH PRIVATE KEY"
site:example.com "BEGIN PGP PRIVATE KEY"
site:example.com "ssh-rsa" ext:txt
```

---

## Admin Panels

### Generic Admin
```
site:example.com inurl:/admin
site:example.com inurl:/administrator
site:example.com inurl:/dashboard
site:example.com intitle:"Admin Login"
site:example.com intitle:"Dashboard" "Sign in"
```

### CMS Admin
```
site:example.com inurl:/wp-admin OR inurl:/wp-login
site:example.com inurl:/administrator "joomla"
site:example.com inurl:/user/login "drupal"
site:example.com "/ghost/signin"
```

### Database Management
```
site:example.com inurl:/phpmyadmin
site:example.com inurl:/adminer
site:example.com intitle:"phpMyAdmin"
site:example.com "adminer" "login"
```

### DevOps Dashboards
```
site:example.com "Jenkins" "Dashboard"
site:example.com inurl:/grafana
site:example.com inurl:/kibana
site:example.com "SonarQube" intitle:"Dashboard"
site:example.com "Kubernetes Dashboard"
```

### Monitoring Tools
```
site:example.com "Nagios" "login"
site:example.com "Zabbix" intitle:"Dashboard"
site:example.com "Prometheus" inurl:/graph
site:example.com "Elasticsearch" inurl:/_plugin/kibana
```

---

## Directory Listings

### Basic Listings
```
site:example.com intitle:"index of /"
site:example.com intitle:"index of" "parent directory"
site:example.com "Index of /" +".git" OR +".env" OR +"backup"
```

### Specific Directories
```
site:example.com intitle:"index of" "/backup"
site:example.com intitle:"index of" "/config"
site:example.com intitle:"index of" "/database"
site:example.com intitle:"index of" "/admin"
site:example.com intitle:"index of" "/.git"
```

### Sensitive Files in Listings
```
site:example.com intitle:"index of" ".env"
site:example.com intitle:"index of" ".sql"
site:example.com intitle:"index of" ".zip"
site:example.com intitle:"index of" "id_rsa"
```

---

## Cloud Storage

### AWS S3
```
site:s3.amazonaws.com "example"
site:s3.amazonaws.com "example-backup"
site:s3.amazonaws.com "example-prod"
site:example.com ".s3.amazonaws.com"
site:amazonaws.com "example" "backup"
```

**Test bucket access:** `https://bucket-name.s3.amazonaws.com/`

### Google Cloud Storage
```
site:storage.googleapis.com "example"
site:storage.googleapis.com "example-backup"
site:example.com "storage.googleapis.com"
```

**Test bucket access:** `https://storage.googleapis.com/bucket-name/`

### Azure Blob Storage
```
site:blob.core.windows.net "example"
site:example.com ".blob.core.windows.net"
site:windows.net "example"
```

**URL format:** `https://account.blob.core.windows.net/container`

### CDN URLs
```
site:example.com "cloudfront.net"
site:example.com ".azureedge.net"
site:example.com "cdn" "storage"
```

---

## Code Repositories

### GitHub
```
site:github.com "example.com" "password"
site:github.com "example.com" "api_key"
site:github.com "example.com" "token"
site:github.com "example.com" "secret"
site:github.com "example.com" filename:.env
site:github.com "example.com" filename:config.json
```

### GitLab
```
site:gitlab.com "example.com" "password"
site:gitlab.com "example.com" "secret"
```

### Bitbucket
```
site:bitbucket.org "example.com"
```

### GitHub Gists
```
site:gist.github.com "example.com"
site:gist.github.com "example.com" "password"
site:gist.github.com "example.com" "api"
```

### Exposed .git
```
site:example.com "/.git/config"
site:example.com "/.git/HEAD"
site:example.com "/.git" "index"
site:example.com inurl:/.git intitle:"index of"
```

---

## API Endpoints

### API Documentation
```
site:example.com "swagger" OR "openapi"
site:example.com inurl:/api-docs
site:example.com intitle:"API Documentation"
site:example.com "/swagger-ui.html"
site:example.com "Swagger UI"
```

### GraphQL
```
site:example.com inurl:/graphql
site:example.com "graphql" "playground"
site:example.com "graphiql"
site:example.com inurl:/graphql/v1
```

### REST APIs
```
site:example.com inurl:/api/v1
site:example.com inurl:/api/v2
site:example.com "/rest/api"
site:example.com "API" "endpoint"
```

### Internal APIs
```
site:example.com inurl:/internal/api
site:example.com inurl:/api/internal
site:example.com "internal API"
```

---

## Paste Sites

### Pastebin
```
site:pastebin.com "example.com"
site:pastebin.com "example.com" "password"
site:pastebin.com "example.com" "api"
site:pastebin.com "@example.com"
```

### Alternative Paste Sites
```
site:paste.ee "example.com"
site:dpaste.com "example.com"
site:hastebin.com "example.com"
site:ghostbin.com "example.com"
site:ideone.com "example.com"
site:codepad.org "example.com"
```

### Code Sharing
```
site:repl.it "example.com"
site:jsfiddle.net "example.com"
site:codepen.io "example.com"
site:jsbin.com "example.com"
```

---

## Collaboration Platforms

### Trello
```
site:trello.com "example" OR "example.com"
site:trello.com inurl:/example
site:trello.com "example" "api"
```

### Jira & Confluence
```
site:atlassian.net "example" inurl:/wiki
site:atlassian.net "example" inurl:/browse
site:atlassian.net "example" "password"
site:*.atlassian.net "example"
```

### Notion
```
site:notion.site "example"
site:notion.so "example"
```

### Google Docs/Drive
```
site:docs.google.com "example" "published to the web"
site:drive.google.com "example" "shared"
```

### Airtable
```
site:airtable.com "example"
site:airtable.com "example" "base"
```

### Monday.com
```
site:monday.com "example"
```

### Asana
```
site:asana.com "example"
```

---

## Brand Impersonation

### Fake Login Pages
```
intitle:"example" inurl:login -site:example.com
intitle:"example login" -site:example.com
"example" "sign in" -site:example.com -site:support.example.com
```

### Fake Support
```
"example support" inurl:help -site:example.com
"example customer service" -site:example.com
```

### Typosquatting
```
site:examp1e.com
site:exmple.com
site:example.co
site:examplecorp.com -site:example.com
```

### Phishing Pages
```
"example" inurl:verify -site:example.com
"example" inurl:secure -site:example.com
"example" inurl:account "suspended"
```

---

## Advanced Operators

### Combining Operators
```
site:example.com (ext:sql OR ext:env OR ext:bak)
site:example.com ("api_key" OR "password" OR "secret")
site:example.com inurl:admin -inurl:example.com/docs
```

### Excluding Results
```
site:example.com "password" -site:example.com/docs -site:support.example.com
site:example.com ext:sql -"example" -"test"
```

### Exact Matches
```
site:example.com "exact phrase here"
site:example.com "AWS_ACCESS_KEY_ID"
```

### Wildcards
```
site:*.example.com "password"
site:example.* "api"
```

### File Types
```
site:example.com filetype:pdf "confidential"
site:example.com filetype:xlsx "budget"
site:example.com filetype:doc "proprietary"
```

---

## Verification & Validation

After finding results:

1. **Verify authenticity**: Check if the page/file is real
2. **Check freshness**: Use cache: operator to see when indexed
3. **Test access**: Confirm the resource is still accessible
4. **Assess sensitivity**: Evaluate the risk of the exposure
5. **Document evidence**: Screenshot and save URLs
6. **Report responsibly**: Follow disclosure guidelines

### Using Cache
```
cache:example.com/path
```
Shows Google's cached version and when it was indexed.

---

## Ethical Guidelines

### DO:
✅ Get written authorization before testing
✅ Stay within defined scope
✅ Report findings responsibly
✅ Document your methodology
✅ Respect rate limits and robots.txt

### DON'T:
❌ Test without authorization
❌ Attempt to use discovered credentials
❌ Download sensitive data unnecessarily
❌ Automate queries excessively (rate limits)
❌ Share findings publicly before remediation

---

## Tools Integration

### Using with Scripts

```python
from collectors.search_engine import SearchEngineCollector

# Execute dork programmatically
collector = SearchEngineCollector(config, rate_limiter, cache)
results = collector.execute_search("site:example.com ext:env")
```

### Automation
- Use the passive_recon.py script for automated dorking
- Results are cached to avoid redundant queries
- Rate limiting prevents blocking

### Manual Testing
For quick manual tests:
1. Open Google/Bing
2. Enter dork query
3. Review first 3-5 pages of results
4. Document findings
5. Verify accessibility

---

## Quick Reference Card

| Target | Dork Pattern |
|--------|-------------|
| Config files | `site:TARGET ext:env OR ext:config` |
| AWS keys | `site:TARGET "AKIA"` |
| GitHub leaks | `site:github.com "TARGET" "password"` |
| Admin panels | `site:TARGET inurl:/admin` |
| S3 buckets | `site:s3.amazonaws.com "TARGET"` |
| Backups | `site:TARGET ext:sql OR ext:bak` |
| API docs | `site:TARGET "swagger"` |
| Paste leaks | `site:pastebin.com "TARGET"` |

---

**Remember:** Always use these techniques ethically and legally! 🛡️
