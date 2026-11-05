"""Crawler minimal, borné et respectueux.

Objectif : ne pas juger un site sur sa seule page d'accueil. On explore un petit
nombre de pages internes (jamais de formulaires, jamais de déconnexion), puis on
agrège les constats : « CSP absente sur 8 pages sur 9 » vaut mieux que huit
constats identiques.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from .fetcher import Fetcher, HttpResponse

SKIP_EXTENSIONS = (
    ".pdf", ".zip", ".rar", ".7z", ".gz", ".tar", ".png", ".jpg", ".jpeg", ".gif",
    ".webp", ".svg", ".ico", ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".webm", ".mp3", ".avi", ".mov", ".dmg", ".exe", ".apk", ".iso",
    ".xml", ".rss", ".json", ".csv", ".xlsx", ".docx",
)

SKIP_TOKENS = (
    "logout", "signout", "log-out", "deconnexion", "disconnect", "delete",
    "supprimer", "unsubscribe", "desinscription", "panier/remove", "cart/remove",
    "wp-login.php?action=logout",
)

MAX_DEPTH = 2


@dataclass
class CrawlPage:
    url: str
    response: HttpResponse
    title: str = ""

    @property
    def ok(self) -> bool:
        return self.response.error is None and 200 <= self.response.status < 400

    def summary(self) -> dict:
        return {
            "url": self.url,
            "status": self.response.status,
            "title": self.title,
            "ms": self.response.elapsed_ms,
            "error": self.response.error or "",
        }


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            for key, value in attrs:
                if key.lower() == "href" and value:
                    self.links.append(value)
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.title:
            self.title = data.strip()[:120]


def extract_links(html: str, base_url: str) -> tuple[list[str], str]:
    parser = _LinkParser()
    try:
        parser.feed(html[:400_000])
        parser.close()
    except Exception:  # noqa: BLE001 - HTML exotique
        pass
    resolved = []
    for href in parser.links:
        link = (href or "").strip()
        if not link or link.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        try:
            resolved.append(urljoin(base_url, link))
        except ValueError:
            continue
    return resolved, parser.title


def _normalize(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    netloc = host
    if parts.port and parts.port not in (80, 443):
        netloc = f"{host}:{parts.port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme, netloc, path, parts.query, ""))


def _is_crawlable(url: str, origin_host: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in {"http", "https"}:
        return False
    if (parts.hostname or "").lower() != origin_host:
        return False
    lowered = (parts.path or "").lower()
    if lowered.endswith(SKIP_EXTENSIONS):
        return False
    if any(token in url.lower() for token in SKIP_TOKENS):
        return False
    if len(url) > 500:
        return False
    return True


@dataclass
class CrawlResult:
    pages: list[CrawlPage] = field(default_factory=list)
    skipped: int = 0


async def crawl(
    fetcher: Fetcher,
    start_url: str,
    max_pages: int = 1,
    concurrency: int = 3,
    initial: HttpResponse | None = None,
) -> CrawlResult:
    """Explore au plus `max_pages` pages internes en largeur (profondeur 2)."""
    origin_host = (urlsplit(start_url).hostname or "").lower()

    first_response = initial or await fetcher.get(start_url)
    pages: list[CrawlPage] = []
    visited: set[str] = set()

    main_url = _normalize(first_response.url or start_url)
    visited.add(main_url)
    title = ""
    if first_response.body:
        _, title = extract_links(first_response.text, first_response.url or start_url)
    pages.append(CrawlPage(url=first_response.url or start_url, response=first_response, title=title))

    if max_pages <= 1 or first_response.error:
        return CrawlResult(pages=pages)

    queue: list[tuple[str, int]] = [
        (link, 1) for link in extract_links(first_response.text, first_response.url)[0]
    ]
    skipped = 0

    while queue and len(pages) < max_pages:
        batch: list[tuple[str, int]] = []
        while queue and len(batch) < concurrency:
            link, depth = queue.pop(0)
            normalized = _normalize(link)
            if normalized in visited or not _is_crawlable(link, origin_host):
                skipped += 1
                continue
            visited.add(normalized)
            batch.append((normalized, depth))

        if not batch:
            continue

        responses = await asyncio.gather(
            *(fetcher.get(url, max_bytes=400_000, timeout=8) for url, _ in batch)
        )

        for (url, depth), response in zip(batch, responses, strict=False):
            if response.error:
                continue
            content_type = response.header("content-type").lower()
            if content_type and "html" not in content_type:
                continue
            links, page_title = extract_links(response.text, response.url or url)
            pages.append(CrawlPage(url=response.url or url, response=response, title=page_title))
            if depth < MAX_DEPTH:
                queue.extend((link, depth + 1) for link in links)
            if len(pages) >= max_pages:
                break

    return CrawlResult(pages=pages, skipped=skipped)


def absolute_links(html: str, base_url: str) -> list[str]:
    links, _ = extract_links(html, base_url)
    return links


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def quick_title(html: str) -> str:
    match = TITLE_RE.search(html[:20000])
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""
