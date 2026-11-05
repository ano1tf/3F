"""Détection de secrets dans les scripts publics (valeurs masquées)."""

from __future__ import annotations

import asyncio

from app.models import Severity
from app.scanner.checks_secrets import (
    find_secrets,
    inline_scripts,
    jwt_findings,
    mask,
    scan_scripts,
    script_urls,
)

AWS = "AKIAZ7Q2XK4M9PLW3TRV"
GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def ids_in(text: str) -> set[str]:
    return {pattern.id for pattern, _line, _value in find_secrets(text)}


def test_detects_cloud_and_saas_keys():
    found = ids_in(
        f'const a="{AWS}"; const b="{GITHUB}"; const c="SG.{ "a"*20 }.{ "b"*20 }";'
    )
    assert "secrets.aws-access-key" in found
    assert "secrets.github-token" in found
    assert "secrets.sendgrid" in found


def test_detects_private_key_and_basic_auth():
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n"
        "const url='https://admin:SuperSecret123@interne.test/api';\n"
    )
    found = ids_in(text)
    assert "secrets.private-key" in found
    assert "secrets.basic-auth-url" in found


def test_ignores_placeholders_and_code():
    text = "const key='AKIAIOSFODNN7EXAMPLE'; password='your_password_here';"
    found = ids_in(text)
    assert "secrets.aws-access-key" not in found
    assert "secrets.generic-assignment" not in found


def test_values_are_masked():
    hits = find_secrets(f'key="{AWS}"')
    assert hits
    _pattern, _line, masked = hits[0]
    assert AWS not in masked
    assert masked.startswith("AKIAZ7")
    assert mask("court") == "co…"


def test_line_numbers_are_reported():
    hits = find_secrets(f"line1\nline2\nconst k='{AWS}';\n")
    _pattern, line, _value = hits[0]
    assert line == 3


def test_inline_scripts_extraction():
    html = "<script>let a=1;</script><script src='x.js'></script><script>let b=2;</script>"
    assert "let a=1" in inline_scripts(html)
    assert "let b=2" in inline_scripts(html)


def test_script_urls_keep_same_origin_only():
    scripts = [
        "/static/app.js",
        "https://cdn.autre.test/lib.js",
        "//cdn.autre.test/lib.js",
        "data:text/javascript;base64,AAA",
        "/static/app.js",
    ]
    urls = script_urls(scripts, "https://cible.test/")
    assert urls == ["https://cible.test/static/app.js"]


def test_scan_scripts_flags_key_and_source_map(vulnerable_server):
    async def run():
        from app.scanner.fetcher import Fetcher

        async with Fetcher(allow_private=True) as fetcher:
            return await scan_scripts(
                fetcher,
                vulnerable_server.url,
                ["/static/app.js"],
                inline_html="",
                limit=3,
            )

    findings, meta = asyncio.run(run())
    ids = {finding.id for finding in findings}
    assert "secrets.aws-access-key" in ids
    assert "secrets.source-map" in ids
    key_finding = next(f for f in findings if f.id == "secrets.aws-access-key")
    assert AWS not in key_finding.evidence
    assert key_finding.severity is Severity.CRITICAL
    assert meta["scripts_analyses"] == "1"


def test_scan_scripts_ignores_third_party(vulnerable_server):
    async def run():
        from app.scanner.fetcher import Fetcher

        async with Fetcher(allow_private=True) as fetcher:
            return await scan_scripts(
                fetcher, vulnerable_server.url, ["https://cdn.autre.test/x.js"], limit=3
            )

    findings, meta = asyncio.run(run())
    assert findings == []
    assert meta == {}


# --------------------------------------------------------------------------- #
# Nouvelles signatures (SaaS, CI, paiements, bases) et analyse des JWT
# --------------------------------------------------------------------------- #

def _jwt(header: dict, payload: dict, signature: str = "") -> str:
    import base64
    import json

    def encode(value: dict) -> str:
        raw = json.dumps(value).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{encode(header)}.{encode(payload)}.{signature}"


def test_detects_new_saas_and_ci_tokens():
    text = "\n".join(
        [
            'const anthropic="sk-ant-api03-' + "a1B2" * 12 + '";',
            'const gitlab="glpat-' + "a1B2c3D4e5F6g7H8i9J0" + '";',
            'const npm="npm_' + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" + '";',
            'const hook="https://hooks.slack.com/services/T0000000/B0000000/xYz0123456789abcdefghij";',
            'const db="postgres://admin:S3cretPassw0rd@db.interne.test:5432/app";',
        ]
    )
    found = ids_in(text)
    assert "secrets.anthropic" in found
    assert "secrets.gitlab" in found
    assert "secrets.npm" in found
    assert "secrets.slack-webhook" in found
    assert "secrets.database-url" in found


def test_anthropic_key_is_not_reported_as_openai():
    text = 'const key="sk-ant-api03-' + "Zx9" * 14 + '";'
    found = ids_in(text)
    assert "secrets.anthropic" in found
    assert "secrets.openai" not in found


def test_jwt_without_signature_is_critical():
    token = _jwt({"alg": "none", "typ": "JWT"}, {"sub": "42", "role": "admin"})
    findings = jwt_findings([("https://site.test/app.js", f'const t="{token}";')])

    assert [f.id for f in findings] == ["secrets.jwt-alg-none"]
    assert findings[0].severity is Severity.CRITICAL
    assert token not in findings[0].evidence
    assert "alg: none" in findings[0].evidence


def test_jwt_with_admin_claim_is_high():
    token = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "7", "role": "admin"}, "c2lnbmF0dXJl")
    findings = jwt_findings([("https://site.test/app.js", f'const t="{token}";')])

    assert [f.id for f in findings] == ["secrets.jwt-privileged"]
    assert findings[0].severity is Severity.HIGH
    assert token not in findings[0].evidence


def test_ordinary_jwt_does_not_raise_jwt_alerts():
    token = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "7", "role": "user"}, "c2lnbmF0dXJl")
    texts = [("https://site.test/app.js", f'const t="{token}";')]

    assert jwt_findings(texts) == []
    # Le constat générique « JWT présent » reste, lui, bien détecté.
    assert "secrets.jwt" in ids_in(texts[0][1])


def test_scan_scripts_collects_fetched_scripts(vulnerable_server):
    from app.scanner.fetcher import Fetcher

    async def run():
        collected: list[tuple[str, str]] = []
        async with Fetcher(allow_private=True) as fetcher:
            findings, _meta = await scan_scripts(
                fetcher,
                vulnerable_server.url,
                ["/static/app.js"],
                limit=3,
                collected=collected,
            )
        return findings, collected

    found, collected = asyncio.run(run())
    assert any(f.id == "secrets.aws-access-key" for f in found)
    assert collected and collected[0][0].endswith("/static/app.js")
    assert "AKIA" in collected[0][1]
