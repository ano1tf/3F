"""Contrôles approfondis : redirections ouvertes, AXFR, sous-domaines."""

from __future__ import annotations

import asyncio

import httpx

from app.scanner.checks_deep import (
    _is_reflected_redirect,
    _with_param,
    check_open_redirect,
    check_zone_transfer,
    discover_subdomains,
)
from app.scanner.fetcher import HttpResponse


class FakeFetcher:
    """Fetcher minimal : renvoie toujours la même redirection."""

    def __init__(self, status: int, location: str) -> None:
        self.status = status
        self.location = location

    async def get(self, url: str, **_kwargs) -> HttpResponse:
        headers = httpx.Headers({"location": self.location}) if self.location else httpx.Headers()
        return HttpResponse(url=url, status=self.status, headers=headers, body=b"")


def test_with_param_preserves_existing_query():
    url = _with_param("https://site.test/login?lang=fr", "next", "https://evil.test/")
    assert "lang=fr" in url
    assert "next=https%3A%2F%2Fevil.test%2F" in url


def test_reflection_detection_requires_redirect_and_probe_host():
    ok = HttpResponse(
        url="https://site.test/",
        status=302,
        headers=httpx.Headers({"location": "https://vulnlens.example/probe"}),
    )
    assert _is_reflected_redirect(ok) is True

    external = HttpResponse(
        url="https://site.test/",
        status=302,
        headers=httpx.Headers({"location": "https://ailleurs.test/"}),
    )
    assert _is_reflected_redirect(external) is False

    not_redirect = HttpResponse(
        url="https://site.test/",
        status=200,
        headers=httpx.Headers({"location": "https://vulnlens.example/probe"}),
    )
    assert _is_reflected_redirect(not_redirect) is False


def test_open_redirect_is_detected():
    fetcher = FakeFetcher(302, "https://vulnlens.example/probe")
    findings = asyncio.run(check_open_redirect(fetcher, "https://site.test/login"))
    assert len(findings) == 1
    assert findings[0].id == "web.open-redirect"
    assert findings[0].severity.value == "high"


def test_no_open_redirect_on_clean_site():
    fetcher = FakeFetcher(302, "https://site.test/compte")
    findings = asyncio.run(check_open_redirect(fetcher, "https://site.test/login"))
    assert findings == []


def test_zone_transfer_skipped_for_ip_targets():
    assert asyncio.run(check_zone_transfer("127.0.0.1")) is None
    assert asyncio.run(check_zone_transfer("192.168.1.10")) is None


def test_subdomains_skipped_for_ip_targets():
    assert asyncio.run(discover_subdomains("127.0.0.1")) == []
