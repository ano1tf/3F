"""Preuve de propriété d'un domaine.

Deux méthodes, au choix :
1. Enregistrement DNS TXT : `_vulnlens.<domaine>` = `vulnlens-verification=<token>`
2. Fichier : `https://<domaine>/.well-known/vulnlens.txt` contenant `<token>`

La preuve est stockée en base et attachée aux analyses suivantes (badge « vérifié »).
Aucun jeton n'est un secret : il ne sert qu'à démontrer le contrôle du domaine.
"""

from __future__ import annotations

import dns.asyncresolver
import dns.exception

from . import config, db
from .safety import ScanError, normalize_target, validate_target

RECORD_NAME = "_vulnlens"
TOKEN_PREFIX = "vulnlens-verification="
FILE_PATH = "/.well-known/vulnlens.txt"


async def _dns_txt(name: str) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6.0
    resolver.timeout = 4.0
    try:
        answer = await resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except (dns.exception.DNSException, OSError):
        return []
    values: list[str] = []
    for record in answer or []:
        chunks = getattr(record, "strings", None)
        values.append(
            b"".join(chunks).decode("utf-8", errors="replace")
            if chunks
            else record.to_text().strip('"')
        )
    return values


async def check_dns(host: str, token: str) -> bool:
    records = await _dns_txt(f"{RECORD_NAME}.{host}")
    expected = f"{TOKEN_PREFIX}{token}"
    return any(expected in record for record in records)


async def check_file(host: str, token: str) -> bool:
    """Vérifie `/.well-known/vulnlens.txt` (HTTPS puis HTTP en repli).

    Le téléchargement passe par le `Fetcher` gardé : les hôtes internes
    (localhost, 169.254.169.254, *.internal…) sont refusés et chaque redirection
    est revalidée. Auparavant, cette fonction forçait `allow_private=True`, ce qui
    permettait un SSRF via `POST /api/verify/<hôte interne>/check`.
    """
    from .scanner.fetcher import Fetcher

    allow_private = config.ALLOW_PRIVATE_TARGETS
    async with Fetcher(allow_private=allow_private) as fetcher:
        for scheme in ("https", "http"):
            try:
                await validate_target(f"{scheme}://{host}/", allow_private=allow_private)
            except ScanError:
                continue
            response = await fetcher.get(
                f"{scheme}://{host}{FILE_PATH}", max_bytes=4096, timeout=8
            )
            if response.error or response.status != 200:
                continue
            if token in response.text[:4096]:
                return True
    return False


def instructions(host: str, token: str) -> dict[str, str]:
    record = f"{RECORD_NAME}.{host}"
    return {
        "methode_dns": f'TXT {record} = "{TOKEN_PREFIX}{token}"',
        "methode_fichier": f"https://{host}{FILE_PATH} → contenu : {token}",
        "record_name": record,
        "record_value": f"{TOKEN_PREFIX}{token}",
        "file_url": f"https://{host}{FILE_PATH}",
    }


async def status(host: str) -> dict:
    """État de vérification + jeton + instructions, sans effet de bord réseau."""
    row = await db.ensure_token(host)
    return {
        "host": host,
        "token": row["token"],
        "verified": bool(row.get("verified_at")),
        "verified_at": row.get("verified_at"),
        "method": row.get("method"),
        "instructions": instructions(host, row["token"]),
    }


async def verify(host: str) -> dict:
    """Tente la vérification : DNS d'abord, fichier ensuite."""
    row = await db.ensure_token(host)
    token = row["token"]

    if await check_dns(host, token):
        await db.mark_verified(host, "dns")
        return {**await status(host), "detail": "Enregistrement TXT trouvé."}

    if await check_file(host, token):
        await db.mark_verified(host, "fichier")
        return {**await status(host), "detail": "Fichier .well-known trouvé."}

    return {
        **(await status(host)),
        "detail": "Aucune preuve trouvée : ni TXT, ni fichier .well-known.",
    }


async def is_verified(host: str) -> bool:
    try:
        return await db.is_verified(host)
    except Exception:  # noqa: BLE001 - la vérification ne doit jamais casser un scan
        return False


async def host_from_url(url: str) -> str:
    return (normalize_target(url).split("//", 1)[1]).split("/", 1)[0].split(":")[0]


__all__ = ["check_dns", "check_file", "instructions", "is_verified", "status", "verify", "host_from_url"]
