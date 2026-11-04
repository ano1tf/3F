"""Analyse HTML : contenu mixte, formulaires non chiffrés, fuites dans le code."""

from __future__ import annotations

import httpx

from app.scanner.checks_content import check_page, parse_page
from app.scanner.fetcher import HttpResponse

HTML = """<!doctype html>
<html><head>
<meta name="generator" content="WordPress 6.2.1">
<script src="http://cdn.example.test/app.js"></script>
<script src="https://trusted.test/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>
<link rel="stylesheet" href="http://cdn.example.test/style.css">
</head><body onload="init()">
<!-- TODO: enlever le mot de passe de debug -->
<form action="http://insecure.test/login" method="post">
  <input type="password" name="pwd">
</form>
<form action="/contact" method="post">
  <input type="text" name="message">
</form>
<a href="https://partner.test" target="_blank">partenaire</a>
<a href="https://safe.test" target="_blank" rel="noopener noreferrer">sûr</a>
</body></html>
"""


def response(html: str = HTML, url: str = "https://site.test/") -> HttpResponse:
    return HttpResponse(
        url=url,
        status=200,
        headers=httpx.Headers({"content-type": "text/html; charset=utf-8"}),
        body=html.encode("utf-8"),
    )


def test_parser_extracts_forms_and_links():
    info = parse_page(HTML)
    assert len(info.forms) == 2
    assert info.forms[0]["has_password"] is True
    assert info.generator == "WordPress 6.2.1"
    assert any("cdn.example.test" in s for s in info.scripts)
    assert len(info.scripts_with_integrity) == 1


def test_detects_mixed_content_and_insecure_password_form():
    findings, _ = check_page(response())
    ids = {f.id for f in findings}
    assert "content.mixed-content" in ids
    assert "content.insecure-password-form" in ids


def test_detects_comment_leak_generator_and_target_blank():
    findings, _ = check_page(response())
    ids = {f.id for f in findings}
    assert "content.comments-leak" in ids
    assert "content.generator-version" in ids
    assert "content.blank-noopener" in ids
    assert "content.inline-handlers" in ids


def test_sri_only_flags_external_script_without_integrity():
    findings, _ = check_page(response())
    sri = next(f for f in findings if f.id == "content.script-integrity")
    assert "cdn.example.test" in sri.evidence
    assert "trusted.test" not in sri.evidence


def test_http_page_is_not_double_reported():
    findings, _ = check_page(response(url="http://site.test/"))
    assert not any(f.id == "content.mixed-content" for f in findings)
