"""Empreinte technique : WAF, CDN, CMS, frameworks, bibliothèques, analytique."""

from __future__ import annotations

from app.scanner.tech import detect


def test_cloudflare_and_wordpress():
    fingerprint = detect(
        {"cf-ray": "8a", "server": "cloudflare"},
        "<html><link href='/wp-content/x.css'><script src='/wp-includes/js/jquery-3.6.0.min.js'></script>",
        [],
    )
    assert fingerprint["waf"] == "Cloudflare"
    assert fingerprint["cdn"] == "Cloudflare"
    assert fingerprint["cms"] == "WordPress"
    assert "jQuery 3.6.0" in fingerprint["bibliotheques"]


def test_nextjs_and_analytics():
    fingerprint = detect(
        {"server": "Vercel"},
        '<script src="/_next/static/chunk.js"></script><script src="https://www.googletagmanager.com/gtm.js?id=GTM-X"></script>',
        [],
    )
    assert fingerprint["cms"] == "Next.js"
    assert "Vercel" in fingerprint["waf"]
    assert "Google Tag Manager" in fingerprint["analytique"]


def test_php_and_bootstrap_from_headers():
    fingerprint = detect(
        {"x-powered-by": "PHP/8.2.1", "cookie": "PHPSESSID=abc"},
        "<link rel='stylesheet' href='/css/bootstrap.min.css'>",
        [],
    )
    assert "PHP" in fingerprint["langage"]
    assert "Bootstrap" in fingerprint["frameworks"]


def test_nothing_detected():
    assert detect({}, "<html><body>bonjour</body></html>", []) == {}
