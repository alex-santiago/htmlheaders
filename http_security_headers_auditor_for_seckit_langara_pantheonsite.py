#!/usr/bin/env python3
"""
file: tools/security_headers_audit.py
Purpose: Fetch HTTP(S) response headers for a URL, evaluate common security headers,
         and print a concise, actionable report. Adds a safe default URL so the
         script does not exit with SystemExit(1) when no argument is provided.

Run examples:
  python security_headers_audit.py                          # uses default URL
  python security_headers_audit.py https://example.com      # custom URL
  AUDIT_URL=https://example.com python security_headers_audit.py
  python security_headers_audit.py --self-test              # run unit tests only

Notes:
- Uses GET (with redirects) and tries HEAD to capture final-page headers.
- Network calls require the 'requests' package.
- Tests do not require network and do not import 'requests'.
"""
from __future__ import annotations

import argparse
import os
import sys
import textwrap
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List

# Default target avoids SystemExit when no CLI arg is provided.
DEFAULT_URL = (
    "https://seckit-langara.pantheonsite.io/student-appeal-request-digital-form-0"
)


@dataclass
class Finding:
    header: str
    present: bool
    severity: str
    message: str
    recommendation: Optional[str] = None


def _normalize_headers(h: Dict[str, str]) -> Dict[str, str]:
    return {k.lower(): v.strip() for k, v in h.items()}


def _get_requests():
    """Import requests lazily so tests can run without it installed."""
    try:
        import requests  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "This script requires the 'requests' package. Install with: pip install requests"
        ) from exc
    return requests


def fetch(url: str, head_timeout: int = 20, get_timeout: int = 30) -> Tuple[Dict[str, str], Dict[str, str], str]:
    """Return (head_headers, get_headers, final_url)."""
    requests = _get_requests()
    s = requests.Session()
    s.max_redirects = 10
    s.headers.update({"User-Agent": "SecurityHeadersAudit/1.1 (+https://example.local)"})

    # HEAD (some servers 405/empty; ignore body)
    try:
        r_head = s.head(url, allow_redirects=True, timeout=head_timeout)
        head_headers = _normalize_headers(r_head.headers)
        final_url = r_head.url
    except Exception:
        head_headers = {}
        final_url = url

    # GET
    r_get = s.get(url, allow_redirects=True, timeout=get_timeout)
    r_get.raise_for_status()
    get_headers = _normalize_headers(r_get.headers)
    final_url = r_get.url
    return head_headers, get_headers, final_url


def check_cookie_flags(headers: Dict[str, str]) -> List[Finding]:
    out: List[Finding] = []
    set_cookie = headers.get("set-cookie")
    if not set_cookie:
        return out

    # Heuristic split for multiple Set-Cookie values flattened into one header line
    parts: List[str] = []
    buf = ""
    for segment in set_cookie.split(","):
        if ("=" in segment) and (";" in segment or buf == "") and buf and not buf.strip().endswith(";"):
            buf += "," + segment
        else:
            if buf:
                parts.append(buf)
            buf = segment
    if buf:
        parts.append(buf)

    for raw in parts:
        c = raw.lower()
        name = raw.split("=", 1)[0].strip()
        sev = "medium"
        if "secure" not in c:
            out.append(Finding(
                header=f"Set-Cookie: {name}", present=False, severity=sev,
                message="Cookie missing Secure; it can be sent over HTTP.",
                recommendation="Append ; Secure to all cookies (serve exclusively over HTTPS).",
            ))
        if "httponly" not in c:
            out.append(Finding(
                header=f"Set-Cookie: {name}", present=False, severity=sev,
                message="Cookie missing HttpOnly; accessible to JS (riskier for XSS).",
                recommendation="Append ; HttpOnly to session/auth cookies.",
            ))
        if "samesite=" not in c:
            out.append(Finding(
                header=f"Set-Cookie: {name}", present=False, severity="low",
                message="Cookie missing SameSite; CSRF risk on cross-site navigations.",
                recommendation="Append ; SameSite=Lax (or Strict) unless cross-site POSTs are required.",
            ))
    return out


def evaluate(headers: Dict[str, str]) -> List[Finding]:
    f: List[Finding] = []

    # HSTS
    hsts = headers.get("strict-transport-security")
    if not hsts:
        f.append(Finding("Strict-Transport-Security", False, "high",
                        "HSTS missing; downgrade and cookie hijack risk.",
                        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"))
    elif "max-age=" not in hsts:
        f.append(Finding("Strict-Transport-Security", True, "medium",
                        "HSTS present but missing max-age.",
                        "Set at least max-age=31536000; includeSubDomains; preload if eligible."))

    # CSP
    csp = headers.get("content-security-policy")
    if not csp:
        f.append(Finding("Content-Security-Policy", False, "high",
                        "CSP missing; XSS and injection risk not mitigated in-browser.",
                        "Start with: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"))
    elif "unsafe-inline" in csp or "*" in csp:
        f.append(Finding("Content-Security-Policy", True, "medium",
                        "CSP is weak (contains unsafe-inline or wildcards).",
                        "Replace inline scripts with nonces/hashes; avoid wildcards; audit 3rd-party hosts."))

    # XFO
    xfo = headers.get("x-frame-options")
    if not xfo:
        f.append(Finding("X-Frame-Options", False, "medium",
                        "X-Frame-Options missing; clickjacking possible.",
                        "Add: X-Frame-Options: DENY (or SAMEORIGIN if embedding is required)."))

    # XCTO
    xcto = headers.get("x-content-type-options")
    if xcto != "nosniff":
        f.append(Finding("X-Content-Type-Options", False, "medium",
                        "X-Content-Type-Options missing or not 'nosniff'.",
                        "Add: X-Content-Type-Options: nosniff"))

    # Referrer-Policy
    rp = headers.get("referrer-policy")
    if not rp:
        f.append(Finding("Referrer-Policy", False, "low",
                        "Referrer-Policy missing; may leak URLs to third parties.",
                        "Add: Referrer-Policy: no-referrer-when-downgrade (or strict-origin-when-cross-origin)."))

    # Permissions-Policy
    pp = headers.get("permissions-policy")
    if not pp:
        f.append(Finding("Permissions-Policy", False, "low",
                        "Permissions-Policy missing; browser features not explicitly limited.",
                        "Add minimal set, e.g.: Permissions-Policy: geolocation=(), microphone=(), camera=()"))

    # COOP/COEP/CORP
    if not headers.get("cross-origin-opener-policy"):
        f.append(Finding("Cross-Origin-Opener-Policy", False, "low",
                        "COOP missing; weaker cross-origin isolation.",
                        "Add: Cross-Origin-Opener-Policy: same-origin"))
    if not headers.get("cross-origin-embedder-policy"):
        f.append(Finding("Cross-Origin-Embedder-Policy", False, "low",
                        "COEP missing; weaker cross-origin isolation.",
                        "Add: Cross-Origin-Embedder-Policy: require-corp (validate impact)."))
    if not headers.get("cross-origin-resource-policy"):
        f.append(Finding("Cross-Origin-Resource-Policy", False, "low",
                        "CORP missing; resources can be embedded cross-site by default.",
                        "Add: Cross-Origin-Resource-Policy: same-site (or same-origin)."))

    # Cookies
    f.extend(check_cookie_flags(headers))

    return f


def render_report(final_url: str, headers: Dict[str, str], findings: List[Finding]) -> str:
    lines: List[str] = []
    lines.append(f"Final URL: {final_url}\n")
    lines.append("Observed Response Headers:\n")
    for k in sorted(headers):
        lines.append(f"  {k}: {headers[k]}")

    def rank_key(x: Finding):
        order = {"high": 0, "medium": 1, "low": 2}
        return (order.get(x.severity, 9), x.header)

    findings.sort(key=rank_key)

    lines.append("\nFindings (most severe first):\n")
    if not findings:
        lines.append("  No obvious header issues detected. ✅")
    else:
        for fnd in findings:
            lines.append(f"- [{fnd.severity.upper()}] {fnd.header}: {fnd.message}")
            if fnd.recommendation:
                lines.append(f"  ▶ Fix: {fnd.recommendation}")

    lines.append("\nHardening reference values (copy/paste baseline):\n")
    lines.append(textwrap.dedent(
        """
        # Example NGINX (server/location block)
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Embedder-Policy "require-corp" always;
        add_header Cross-Origin-Resource-Policy "same-site" always;
        """
    ))
    return "\n".join(lines)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="HTTP Security Headers Auditor")
    p.add_argument(
        "url",
        nargs="?",
        default=os.environ.get("AUDIT_URL", DEFAULT_URL),
        help=f"Target URL (default: $AUDIT_URL or {DEFAULT_URL})",
    )
    p.add_argument("--timeout", type=int, default=30, help="GET timeout in seconds")
    p.add_argument("--head-timeout", type=int, default=20, help="HEAD timeout in seconds")
    p.add_argument("--self-test", action="store_true", help="Run unit tests and exit")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_tests()

    try:
        head_h, get_h, final_url = fetch(args.url, head_timeout=args.head_timeout, get_timeout=args.timeout)
    except RuntimeError as e:
        print(str(e))
        return 2
    except Exception as e:
        print(f"Request failed: {e}")
        return 2

    headers = {**head_h, **get_h}  # prefer GET values
    findings = evaluate(headers)
    report = render_report(final_url, headers, findings)
    print(report)
    return 0


# -----------------------------
# Tests (no network required)
# -----------------------------
import unittest


class EvaluateTests(unittest.TestCase):
    def test_missing_core_headers(self):
        findings = evaluate({})
        names = {f.header for f in findings}
        self.assertIn("Strict-Transport-Security", names)
        self.assertIn("Content-Security-Policy", names)
        self.assertIn("X-Frame-Options", names)
        self.assertIn("X-Content-Type-Options", names)
        self.assertIn("Referrer-Policy", names)

    def test_cookie_flags_missing(self):
        cookies = {"set-cookie": "sid=abc123; Path=/"}
        f = check_cookie_flags(cookies)
        texts = "\n".join(x.message for x in f)
        self.assertIn("Secure", texts)
        self.assertIn("HttpOnly", texts)
        self.assertIn("SameSite", texts)

    def test_cookie_flags_present(self):
        cookies = {"set-cookie": "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"}
        f = check_cookie_flags(cookies)
        self.assertEqual(len(f), 0)


class ArgParseTests(unittest.TestCase):
    def test_default_url_used_when_missing(self):
        ns = parse_args([])
        self.assertEqual(ns.url, os.environ.get("AUDIT_URL", DEFAULT_URL))


def run_tests() -> int:
    """Run the test suite and return appropriate exit code."""
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
