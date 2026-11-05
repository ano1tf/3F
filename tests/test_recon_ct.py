"""Sous-domaines via Certificate Transparency (crt.sh)."""

from __future__ import annotations

import asyncio

from app.scanner import recon_ct
from app.scanner.fetcher import HttpResponse

PAYLOAD = """
[
  {"name_value": "www.cible.test\\n*.cible.test\\napi.cible.test"},
  {"name_value": "staging.cible.test"},
  {"name_value": "autre.test"},
  {"name_value": "Cible.test"}
]
"""


def test_parse_records_cleans_and_filters():
    names = recon_ct.parse_records(PAYLOAD, "cible.test")
    assert names == ["api.cible.test", "staging.cible.test", "www.cible.test"]
    assert "autre.test" not in names
    assert all(name.endswith(".cible.test") for name in names)


def test_parse_records_handles_garbage():
    assert recon_ct.parse_records("pas du json", "cible.test") == []
    assert recon_ct.parse_records("{}", "cible.test") == []


def test_fetch_subdomains_uses_fetcher_and_fails_soft():
    class FakeFetcher:
        def __init__(self, response):
            self.response = response
            self.calls = []

        async def get(self, url, **_kwargs):
            self.calls.append(url)
            return self.response

    good = FakeFetcher(HttpResponse(url="https://crt.sh", status=200, body=PAYLOAD.encode()))
    assert "www.cible.test" in asyncio.run(recon_ct.fetch_subdomains(good, "cible.test"))
    assert "crt.sh" in good.calls[0]

    broken = FakeFetcher(HttpResponse(url="https://crt.sh", status=503))
    assert asyncio.run(recon_ct.fetch_subdomains(broken, "cible.test")) == []


def test_fetch_skips_ip_targets():
    class Boom:
        async def get(self, *_args, **_kwargs):
            raise AssertionError("ne doit pas être appelé")

    assert asyncio.run(recon_ct.fetch_subdomains(Boom(), "127.0.0.1")) == []
