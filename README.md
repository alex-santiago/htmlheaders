# HTTP Security Headers Auditor

This project provides a Python script to fetch HTTP(S) response headers for a given URL, evaluate common security headers, and generate an actionable report to improve web security.

## Features
- **Fetch Headers:** Performs both `HEAD` and `GET` requests to capture final-page headers.
- **Security Checks:** Evaluates common HTTP security headers including:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - Cross-Origin policies (`COOP`, `COEP`, `CORP`)
  - Cookie security flags (`Secure`, `HttpOnly`, `SameSite`)
- **Detailed Recommendations:** Provides severity levels and clear fixes for missing/weak headers.
- **NGINX Config Examples:** Outputs ready-to-use baseline header configuration.

## Requirements
- Python 3.7+
- `requests` library (`pip install requests`)

## Usage
```bash
# Run with a specific URL
python security_headers_audit.py https://example.com

# Run without arguments (uses default test URL)
python security_headers_audit.py

# Example output
No URL provided, using default: https://seckit-langara.pantheonsite.io/student-appeal-request-digital-form-0
Final URL: https://seckit-langara.pantheonsite.io/student-appeal-request-digital-form-0
Observed Response Headers:
  ...
Findings (most severe first):
  ...
```

## Example NGINX Configuration
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Resource-Policy "same-site" always;
```

## License
MIT License
