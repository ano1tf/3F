"""Sous-domaines passifs via les journaux de transparence des certificats (crt.sh).

Aucun balayage : on lit un registre public alimenté par les émissions de certificats.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import quote

import dns.asyncresolver
import dns.exception

from .fetcher import Fetcher

CRT_SH = "https://crt.sh/?q={query}&output=json"
MAX_SUBDOMAINS = 200


def parse_records(payload: str, domain: str) -> list[str]:
    """Extrait et nettoie les noms d'hôtes d'une réponse crt.sh."""
    try:
        records = json.loads(payload)
    except (ValueError, TypeError):
        return []
    if not isinstance(records, list):
        return []

    domain = domain.lower().strip(".")
    found: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        for name in str(record.get("name_value", "")).splitlines():
            candidate = name.strip().lower().lstrip("*.")
            if not candidate or candidate == domain:
                continue
            if not candidate.endswith(f".{domain}"):
                continue
            if any(char in candidate for char in " /@,"):
                continue
            found.add(candidate)
    return sorted(found)[:MAX_SUBDOMAINS]


async def fetch_subdomains(fetcher: Fetcher, domain: str) -> list[str]:
    """Interroge crt.sh ; renvoie [] en cas d'indisponibilité (jamais bloquant)."""
    if not domain or domain.replace(".", "").isdigit():
        return []
    url = CRT_SH.format(query=quote(f"%.{domain}"))
    response = await fetcher.get(url, max_bytes=2_000_000, timeout=8.0)
    if response.error or response.status != 200:
        return []
    return parse_records(response.text, domain)


async def resolve(names: list[str], concurrency: int = 12, limit: int = 60) -> dict[str, list[str]]:
    """Résout les noms découverts (borné) pour nourrir la détection de takeover."""
    subset = [name for name in names if name][:limit]
    if not subset:
        return {}
    semaphore = asyncio.Semaphore(concurrency)

    async def lookup(name: str) -> tuple[str, list[str]]:
        async with semaphore:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 4.0
            resolver.timeout = 3.0
            try:
                answer = await resolver.resolve(name, "A", raise_on_no_answer=False)
            except (dns.exception.DNSException, OSError):
                return name, []
            return name, [record.to_text() for record in (answer or [])]

    results = await asyncio.gather(*(lookup(name) for name in subset))
    return {name: addresses for name, addresses in results if addresses}
