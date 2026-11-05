"""Crawler borné : extraction de liens, filtres, exploration."""

from __future__ import annotations

import asyncio

from app.scanner.crawl import _is_crawlable, _normalize, crawl, extract_links

HTML = """
<html><head><title>Accueil — Site</title></head><body>
  <a href="/about">À propos</a>
  <a href="https://cible.test/contact?x=1#form">Contact</a>
  <a href="/logout">Déconnexion</a>
  <a href="/fichier.pdf">PDF</a>
  <a href="https://autre.test/page">Externe</a>
  <a href="mailto:contact@cible.test">Mail</a>
  <a href="javascript:void(0)">JS</a>
</body></html>
"""


def test_extract_links_resolves_and_keeps_title():
    links, title = extract_links(HTML, "https://cible.test/")
    assert title.startswith("Accueil")
    assert "https://cible.test/about" in links
    assert "https://cible.test/contact?x=1#form" in links
    assert "https://autre.test/page" in links
    assert not any(link.startswith("mailto:") for link in links)
    assert not any(link.startswith("javascript:") for link in links)


def test_crawlable_filters():
    assert _is_crawlable("https://cible.test/about", "cible.test") is True
    assert _is_crawlable("https://cible.test/manuel.pdf", "cible.test") is False
    assert _is_crawlable("https://cible.test/logout", "cible.test") is False
    assert _is_crawlable("https://autre.test/x", "cible.test") is False
    assert _is_crawlable("ftp://cible.test/x", "cible.test") is False


def test_normalize_drops_fragment_and_default_port():
    assert _normalize("https://cible.test:443/a#top") == "https://cible.test/a"
    assert _normalize("https://cible.test:8443/a") == "https://cible.test:8443/a"


def test_crawl_single_page_does_not_follow(vulnerable_server):
    async def run():
        from app.scanner.fetcher import Fetcher

        async with Fetcher(allow_private=True) as fetcher:
            return await crawl(fetcher, vulnerable_server.url, max_pages=1)

    result = asyncio.run(run())
    assert len(result.pages) == 1
    assert result.pages[0].response.status == 200
    assert result.pages[0].ok is True


def test_crawl_respects_max_pages(vulnerable_server):
    async def run():
        from app.scanner.fetcher import Fetcher

        async with Fetcher(allow_private=True) as fetcher:
            return await crawl(fetcher, vulnerable_server.url, max_pages=3)

    result = asyncio.run(run())
    assert 1 <= len(result.pages) <= 3
