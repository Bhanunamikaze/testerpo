# How to Disable Domain Variant Generation

## Problem
The tool generates 100+ domain variants like:
- `stg.hackingdream.net`
- `dev-hackingdream.net`
- `api.hackingdream.net`
- etc.

This is **NOT brute forcing** - it's intelligent pattern generation based on real enterprise naming conventions.

## Solution: Use Minimal Scope Mode

### Option 1: Minimal Scope (Recommended)
**Only checks the exact domain(s) you provide**

Edit your `config.json`:
```json
{
  "scope": {
    "minimal_scope": true,
    "generate_tld_variants": false,
    "max_subdomains": 1000
  }
}
```

**Result:**
- Input: `hackingdream.net`
- Generated: `hackingdream.net` (1 domain only)

---

### Option 2: Disable TLD Variants Only
**Keeps environment variants but removes TLD changes**

```json
{
  "scope": {
    "minimal_scope": false,
    "generate_tld_variants": false,
    "max_subdomains": 1000
  }
}
```

**Result:**
- Checks: `dev.hackingdream.net`, `staging.hackingdream.net`, etc.
- Skips: `hackingdream.com`, `hackingdream.org`, etc.

---

### Option 3: Custom Pattern Selection
**Manually edit which patterns to use**

Edit `seeds/scope_builder.py` lines 21-44:

```python
# Remove patterns you don't want
ENV_PREFIXES = [
    'dev', 'staging', 'api'  # Only these 3
]

SAAS_PATTERNS = [
    'api', 'admin'  # Only these 2
]
```

---

## Comparison

| Mode | Domains Generated | Example |
|------|-------------------|---------|
| **Normal** | 114 | hackingdream.net, dev.hackingdream.net, api.hackingdream.net, hackingdream.com, ... |
| **Minimal Scope** | 1 | hackingdream.net |
| **No TLD Variants** | ~60 | hackingdream.net, dev.hackingdream.net, api.hackingdream.net |

---

## Why These Patterns Exist

The tool generates these variants because:

1. ✅ **Real companies use these patterns** - Finding `dev.example.com` is very common
2. ✅ **High success rate** - Staging/dev environments often leak sensitive info
3. ✅ **Passive reconnaissance** - Just checks public Certificate Transparency logs
4. ✅ **No target interaction** - Not touching your actual infrastructure
5. ✅ **Legal** - Reading public databases only

---

## Quick Test

```bash
# Test normal mode
python3 -c "
from seeds.scope_builder import ScopeBuilder
config = {'scope': {'minimal_scope': False}}
builder = ScopeBuilder(config)
scope = builder.build_scope(['example.com'])
print(f'Normal mode: {len(scope[\"domains\"])} domains')
"

# Test minimal mode
python3 -c "
from seeds.scope_builder import ScopeBuilder
config = {'scope': {'minimal_scope': True}}
builder = ScopeBuilder(config)
scope = builder.build_scope(['example.com'])
print(f'Minimal mode: {len(scope[\"domains\"])} domains')
"
```

---

## Recommendation

- **Use minimal_scope: true** if you only want to scan the exact domain provided
- **Keep default settings** if you want comprehensive reconnaissance (recommended for pentesting)

The pattern generation is a **feature, not a bug** - it finds real subdomains that exist!
