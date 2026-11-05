"""Garde-fous d'analyse.

Deux objectifs :
1. Empêcher l'outil de servir de proxy SSRF (interdiction des cibles internes,
   loopback, link-local, métadonnées cloud…).
2. Normaliser et valider la cible avant de lancer le moindre paquet.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from . import config


class ScanError(Exception):
    """Erreur d'analyse destinée à l'utilisateur."""

    def __init__(self, message: str, code: str = "scan_error") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "kubernetes.default",
    "kubernetes.default.svc",
}


def normalize_target(raw: str) -> str:
    """Transforme « example.com » ou « http://example.com/x » en URL propre."""
    value = (raw or "").strip()
    if not value:
        raise ScanError("Indique une adresse à analyser (ex. https://exemple.fr).", "empty_target")
    if len(value) > 2048:
        raise ScanError("Adresse trop longue.", "target_too_long")
    if "://" not in value:
        value = "https://" + value.lstrip("/")

    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"}:
        raise ScanError("Seuls les schémas http:// et https:// sont pris en charge.", "bad_scheme")
    if not parts.hostname:
        raise ScanError("Adresse invalide : nom d'hôte manquant.", "bad_host")
    if parts.username or parts.password:
        raise ScanError("Les identifiants dans l'URL ne sont pas acceptés.", "credentials_in_url")

    try:
        port = parts.port
    except ValueError as exc:
        raise ScanError("Port invalide dans l'adresse.", "bad_port") from exc
    hostname = (parts.hostname or "").lower()
    if ":" in hostname:  # IPv6 littéral
        netloc = f"[{hostname}]"
    else:
        netloc = hostname
    if port and port not in (80, 443):
        netloc = f"{netloc}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme, netloc, path, parts.query, ""))


def _is_public_ip(ip: ipaddress._BaseAddress) -> bool:
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def resolve_host(host: str, port: int) -> list[str]:
    """Résolution DNS (dans un thread pour ne pas bloquer la boucle)."""
    import asyncio

    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo, host, port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ScanError(
            f"Impossible de résoudre « {host} » : domaine introuvable ou DNS injoignable.",
            "dns_failure",
        ) from exc
    return sorted({info[4][0] for info in infos})


@dataclass
class SafeTarget:
    url: str
    host: str
    port: int
    addresses: list[str]


async def validate_target(raw: str, allow_private: bool | None = None) -> SafeTarget:
    """Valide l'URL et refuse les cibles internes (anti-SSRF)."""
    allow_private = config.ALLOW_PRIVATE_TARGETS if allow_private is None else allow_private
    url = normalize_target(raw)
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if not allow_private and not _is_public_ip(literal):
            raise ScanError(
                "Cible interne bloquée (adresse privée, loopback ou réservée). "
                "L'outil refuse de scanner le réseau local pour éviter tout détournement (SSRF).",
                "private_target",
            )
        return SafeTarget(url, host, port, [str(literal)])

    if host in BLOCKED_HOSTNAMES and not allow_private:
        raise ScanError("Cible interne bloquée (nom d'hôte réservé).", "private_target")
    if host.endswith(".local") or host.endswith(".internal") or host.endswith(".home.arpa"):
        if not allow_private:
            raise ScanError("Cible interne bloquée (domaine local).", "private_target")

    addresses = await resolve_host(host, port)
    if not addresses:
        raise ScanError("Le domaine ne renvoie aucune adresse IP.", "dns_failure")
    if not allow_private:
        for addr in addresses:
            if not _is_public_ip(ipaddress.ip_address(addr)):
                raise ScanError(
                    "Le domaine pointe vers une adresse interne : analyse refusée (anti-SSRF).",
                    "private_target",
                )
    return SafeTarget(url, host, port, addresses)
