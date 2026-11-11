# ZDay Scanner

> **Deep Web Application Security Scanner** - A comprehensive, modular security scanner for web applications with zero-day detection capabilities.

## Features

### 🔍 Multi-Phase Scanning Pipeline
1. **Reconnaissance** - Endpoint discovery, crawling, technology mapping
2. **Fingerprinting** - 1000+ technology signatures across 10 categories
3. **Vulnerability Detection** - 7 injection types + deserialization, auth bypass, logic flaws, race conditions, crypto issues
4. **Reporting** - Interactive HTML dashboard, JSON, Markdown

### 🎯 Technology Fingerprinting
- **Servers**: Apache, nginx, IIS, LiteSpeed, Caddy, OpenResty
- **Languages**: PHP, Python, Node.js, Java, Go, Ruby, .NET
- **Frameworks** (25+): Django, Flask, FastAPI, Express, Spring, Laravel, Rails, Next.js, Nuxt, NestJS, etc.
- **CMS** (10+): WordPress, Drupal, Joomla, Magento, Shopify, Ghost, Wix, Squarespace, etc.
- **Cloud Providers**: AWS, GCP, Azure, Cloudflare, Vercel, Netlify, Heroku, DigitalOcean, etc.
- **WAFs** (12+): Cloudflare, AWS WAF, Akamai, Imperva, F5, Sucuri, ModSecurity, etc.
- **JavaScript Libraries**: React, Vue, Angular, jQuery, Bootstrap, Tailwind, etc.

### 💉 Zero-Day Detection
- **Injection**: SQLi, NoSQLi, XSS, Command Injection, SSTI, LDAP, XPath
- **Deserialization**: Java, Python, PHP, Node.js, .NET gadget chains
- **Auth Bypass**: SQL auth bypass, JWT none algorithm, path traversal, default creds, session fixation
- **Business Logic**: IDOR, price manipulation, quantity abuse, coupon abuse
- **Race Conditions**: Concurrent request testing on sensitive endpoints
- **Cryptography**: Weak TLS, certificate issues, weak hashes, client-side crypto flaws

### 📊 Reporting
- **HTML Dashboard**: Interactive charts, filterable tables, vulnerability modals
- **JSON**: Machine-readable for CI/CD integration
- **Markdown**: Documentation-ready for GitHub/GitLab

## Installation

```bash
# Clone and install
git clone https://github.com/hassanrazahasrat/zday_scanner
cd zday_scanner
pip install -r requirements.txt

# Optional: Install Playwright for headless fingerprinting
playwright install chromium
```

## Quick Start

```bash
# Basic scan
python main.py -u https://example.com

# Full scan with all output formats
python main.py -u https://example.com -f json html markdown -o ./reports

# Deep scan with custom settings
python main.py -u https://example.com --depth 3 --max-pages 200 --rate-limit 5

# Authenticated scan
python main.py -u https://example.com --auth-header "Authorization: Bearer token" --cookie "session=abc123"

# Behind proxy
python main.py -u https://example.com --proxy http://127.0.0.1:8080
```

## Configuration

Create `config.yaml` or use environment variables (`ZDAY_*`):

```yaml
timeout: 30
rate_limit: 10.0
max_concurrent: 10
max_pages: 100
crawl_depth: 2
enable_headless_fingerprinting: true
enable_intrusive_tests: false
```

## Project Structure

```
zday_scanner/
├── main.py                 # CLI entry point
├── config.yaml             # Configuration
├── requirements.txt        # Dependencies
├── test_imports.py         # Import verification
├── test_scanner.py         # Functional tests
├── src/
│   ├── core/               # Core models, config, scanner
│   ├── fingerprinting/     # 8 fingerprinters + aggregator
│   ├── technologies/       # DB, version detection, CVE matching
│   ├── zero_days/          # Detection engine + 6 detectors
│   ├── utils/              # HTTP client with rate limiting
│   └── reporting/          # 3 report formats
└── data/
    ├── fingerprints.json   # 1000+ signatures
    └── cves.json          # CVE database
```

## Architecture

```
Target → HTTPClient → Fingerprinters (parallel)
  ↓
Aggregator → VersionDetector → CVEMatcher
  ↓
DetectionEngine → Detectors (parallel per phase)
  ↓
Reporters → Output
```

## Exit Codes

- `0`: No critical/high vulnerabilities
- `1`: High severity vulnerabilities found
- `2`: Critical vulnerabilities found
- `130`: Interrupted by user

## Development

```bash
# Run import tests
python test_imports.py

# Run functional tests
python test_scanner.py

# Type checking
mypy src/
```

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is for **authorized security testing only**. Only scan applications you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.
