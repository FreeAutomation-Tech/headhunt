# HeadHunt

HTTP security header analyzer for penetration testers and security engineers.
Scan websites for missing security headers, get severity ratings, and fix guidance.

> **Disclaimer**: This tool is provided for **educational purposes and authorized security testing only**. You must have explicit permission to scan any target. The authors are not responsible for misuse or unauthorized scanning.

## Quick Start

```bash
pip install requests
headhunt scan https://example.com
```

## Features

- **10 security headers checked** with severity ratings (HIGH, MEDIUM, LOW, INFO)
- **Grade A-F scoring** based on header implementation
- **Fix guidance** for each missing header
- **Batch scanning** from a file of URLs
- **JSON output** for CI/CD integration
- **Follows redirects** and detects redirect chains

## Usage

```bash
# Scan a single URL
headhunt scan https://example.com

# Scan with custom timeout
headhunt scan https://example.com --timeout 30

# Scan multiple URLs from a file
headhunt scan urls.txt --file

# JSON output (for automation)
headhunt scan https://example.com --json

# Don't follow redirects
headhunt scan https://example.com --no-follow
```

## Headers Checked

| Header | Severity | Description |
|--------|----------|-------------|
| Strict-Transport-Security | HIGH | Enforces HTTPS |
| Content-Security-Policy | HIGH | Controls resource loading |
| X-Frame-Options | MEDIUM | Prevents clickjacking |
| X-Content-Type-Options | MEDIUM | Prevents MIME sniffing |
| Cache-Control | MEDIUM | Controls sensitive caching |
| Access-Control-Allow-Origin | MEDIUM | CORS policy |
| Referrer-Policy | LOW | Referrer leakage control |
| Permissions-Policy | LOW | API access restriction |
| Pragma | LOW | Legacy cache control |
| X-XSS-Protection | INFO | Deprecated header |

## Scoring

- **A**: 90-100% — Excellent security posture
- **B**: 75-89% — Good, minor improvements
- **C**: 55-74% — Fair, several headers missing
- **D**: 35-54% — Poor, many critical headers missing
- **F**: 0-34% — Failing, severe security gaps
