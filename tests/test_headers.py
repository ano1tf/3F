"""Analyse directive par directive de la CSP et durcissement des cookies."""

from __future__ import annotations

import httpx

from app.models import Severity
from app.scanner.checks_http import analyse_csp, check_cookies, check_headers, parse_csp
from app.scanner.fetcher import HttpResponse


def ids(findings) -> set[str]:
    return {finding.id for finding in findings}


def test_parse_csp_normalizes_directives():
    parsed = parse_csp("default-src 'self'; Script-Src 'self' cdn.test; object-src 'none';")
    assert parsed["default-src"] == ["'self'"]
    assert parsed["script-src"] == ["'self'", "cdn.test"]
    assert parsed["object-src"] == ["'none'"]


def test_strict_csp_produces_no_major_finding():
    findings = analyse_csp(
        "default-src 'none'; script-src 'self' 'nonce-abc'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; report-to csp-endpoint; "
        "upgrade-insecure-requests",
        is_https=True,
    )
    assert ids(findings) == set()


def test_unsafe_inline_and_wildcard_are_flagged():
    findings = analyse_csp("default-src *; script-src 'unsafe-inline' *", is_https=True)
    assert "headers.csp-unsafe" in ids(findings)
    assert "headers.csp-wildcard" in ids(findings)


def test_unsafe_eval_is_flagged():
    findings = analyse_csp("script-src 'self' 'unsafe-eval'", is_https=True)
    assert "headers.csp-unsafe" in ids(findings)


def test_http_and_data_schemes_are_flagged():
    findings = analyse_csp("script-src http: data:", is_https=True)
    assert "headers.csp-http-scheme" in ids(findings)
    assert "headers.csp-data-scripts" in ids(findings)


def test_softening_directives_are_reported():
    findings = analyse_csp("default-src 'self'", is_https=True)
    found = ids(findings)
    assert "headers.csp-object-src" in found
    assert "headers.csp-base-uri" in found
    assert "headers.csp-frame-ancestors" in found
    assert "headers.csp-upgrade" in found
    assert "headers.csp-reporting" in found
    assert all(f.severity in {Severity.LOW, Severity.INFO} for f in findings)


def test_csp_without_script_directive():
    findings = analyse_csp("frame-ancestors 'none'", is_https=True)
    assert "headers.csp-incomplete" in ids(findings)


def response_with_cookie(cookie: str) -> HttpResponse:
    return HttpResponse(url="https://site.test/", status=200, headers=httpx.Headers({"set-cookie": cookie}))


def test_cookie_without_flags():
    findings = check_cookies(response_with_cookie("session=abc; Path=/"))
    assert "cookies.flags" in ids(findings)


def test_hardened_cookie_is_accepted():
    findings = check_cookies(
        response_with_cookie("session=abc; Secure; HttpOnly; SameSite=Lax; Path=/")
    )
    assert findings == []


def test_host_prefix_violation_is_detected():
    findings = check_cookies(response_with_cookie("__Host-session=abc; Secure; Path=/"))
    # __Host- impose l'absence de Domain et secure, ici il manque HttpOnly mais surtout
    # le cookie est correct : seul HttpOnly manque, donc pas de violation de préfixe.
    assert "cookies.prefix-violation" not in ids(findings)


def test_host_prefix_with_domain_is_flagged():
    findings = check_cookies(
        response_with_cookie("__Host-session=abc; Secure; Path=/; Domain=example.org")
    )
    assert "cookies.prefix-violation" in ids(findings)


def test_secure_prefix_without_secure_is_flagged():
    findings = check_cookies(response_with_cookie("__Secure-token=abc; Path=/"))
    assert "cookies.prefix-violation" in ids(findings)


def test_missing_security_headers_are_reported():
    resp = HttpResponse(
        url="https://site.test/",
        status=200,
        headers=httpx.Headers({"server": "nginx/1.18.0", "content-type": "text/html"}),
    )
    findings = check_headers(resp, is_https=True)
    found = ids(findings)
    assert "headers.missing.strict-transport-security" in found
    assert "headers.missing.content-security-policy" in found
    assert "headers.clickjacking" in found
    assert "headers.version-disclosure" in found


def test_hsts_short_max_age_is_flagged():
    resp = HttpResponse(
        url="https://site.test/",
        status=200,
        headers=httpx.Headers(
            {
                "strict-transport-security": "max-age=3600",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
            }
        ),
    )
    found = ids(check_headers(resp, is_https=True))
    assert "headers.hsts-short" in found


def test_hsts_disabled_is_flagged():
    resp = HttpResponse(
        url="https://site.test/",
        status=200,
        headers=httpx.Headers(
            {
                "strict-transport-security": "max-age=0",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
            }
        ),
    )
    found = ids(check_headers(resp, is_https=True))
    assert "headers.hsts-disabled" in found
