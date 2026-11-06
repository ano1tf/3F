"""Garde-fous d'analyse.

Trois objectifs :
1. Empêcher l'outil de servir de proxy SSRF (interdiction des cibles internes,
   loopback, link-local, métadonnées cloud…) — y compris **à chaque saut de
   redirection**, pas seulement sur l'URL de départ.
2. Normaliser et valider la cible avant de lancer le moindre paquet.
3. Refuser les plages d'adresses qui ne sont pas réellement publiques
   (CGNAT 100.64/10, réseaux de test, multicast…) : certaines hébergent des
   services de métadonnées ou des services internes.
"""

from __future__ import annotations

import ipaddress
import socket
import time
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

# Suffixes qui ne peuvent pas être des sites publics.
BLOCKED_SUFFIXES = (
    ".local",
    ".localdomain",
    ".internal",
    ".home.arpa",
    ".lan",
    ".corp",
    ".intranet",
    ".onion",
)

# Plages interdites en plus des drapeaux de la bibliothèque standard.
# 100.64.0.0/10 (CGNAT) héberge par exemple les métadonnées Alibaba Cloud
# (100.100.100.200) et n'est pas marquée « privée » par ipaddress.
BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "100::/64",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


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


def _unwrap(ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
    """Ramène une IPv6 mappée (::ffff:127.0.0.1) à son IPv4 réelle."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_public_ip(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Vrai uniquement si l'adresse est routable sur l'Internet public.

    Volontairement strict : tout ce qui n'est pas public est refusé. Cela couvre
    loopback, RFC1918, link-local (169.254.169.254), CGNAT, multicast, réservé,
    documentation et IPv6 ULA.
    """
    if isinstance(ip, str):
        try:
            address = ipaddress.ip_address(ip.strip("[]"))
        except ValueError:
            return False
    else:
        address = ip

    address = _unwrap(address)
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return False
    if not address.is_global:
        return False
    for network in BLOCKED_NETWORKS:
        if network.version == address.version and address in network:
            return False
    return True


# Alias rétrocompatible (ancien nom interne).
_is_public_ip = is_public_ip


def is_blocked_host(host: str) -> bool:
    """Nom d'hôte manifestement interne (localhost, *.local, métadonnées…)."""
    lowered = (host or "").strip().lower().rstrip(".")
    if not lowered:
        return True
    if lowered in BLOCKED_HOSTNAMES:
        return True
    if lowered.endswith(BLOCKED_SUFFIXES):
        return True
    return False


# Cache de résolution très court : évite un DNS par requête HTTP tout en
# gardant une fenêtre de confiance minimale (protection anti-rebinding).
_DNS_CACHE: dict[tuple[str, int], tuple[float, tuple[str, ...]]] = {}
_DNS_TTL = 30.0
_DNS_CACHE_MAX = 256


async def resolve_host(host: str, port: int) -> list[str]:
    """Résolution DNS (dans un thread pour ne pas bloquer la boucle)."""
    import asyncio

    key = (host.lower(), int(port))
    now = time.monotonic()
    cached = _DNS_CACHE.get(key)
    if cached and now - cached[0] < _DNS_TTL:
        return list(cached[1])

    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo, host, port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ScanError(
            f"Impossible de résoudre « {host} » : domaine introuvable ou DNS injoignable.",
            "dns_failure",
        ) from exc
    addresses = sorted({info[4][0] for info in infos})
    if len(_DNS_CACHE) >= _DNS_CACHE_MAX:
        _DNS_CACHE.clear()
    _DNS_CACHE[key] = (now, tuple(addresses))
    return addresses


@dataclass
class SafeTarget:
    url: str
    host: str
    port: int
    addresses: list[str]


async def validate_target(
    raw: str,
    allow_private: bool | None = None,
    *,
    redirect: bool = False,
) -> SafeTarget:
    """Valide l'URL et refuse les cibles internes (anti-SSRF).

    `redirect=True` adapte seulement le message : la règle appliquée est
    identique, ce qui permet de bloquer un `Location: http://169.254.169.254/`
    exactement comme une cible saisie à la main.
    """
    allow_private = config.ALLOW_PRIVATE_TARGETS if allow_private is None else allow_private
    url = normalize_target(raw)
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if parts.scheme == "https" else 80)

    def _refuse(message: str) -> ScanError:
        if redirect:
            return ScanError(
                f"Redirection bloquée : {message} (protection anti-SSRF).",
                "blocked_redirect",
            )
        return ScanError(message, "private_target")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if not allow_private and not is_public_ip(literal):
            raise _refuse(
                "cible interne (adresse privée, loopback ou réservée). "
                "L'outil refuse de scanner le réseau local pour éviter tout détournement (SSRF)"
                if not redirect
                else "elle vise une adresse interne"
            )
        return SafeTarget(url, host, port, [str(literal)])

    if is_blocked_host(host) and not allow_private:
        raise _refuse(
            "Cible interne bloquée (nom d'hôte réservé)."
            if not redirect
            else "elle vise un nom d'hôte réservé"
        )

    addresses = await resolve_host(host, port)
    if not addresses:
        raise ScanError("Le domaine ne renvoie aucune adresse IP.", "dns_failure")
    if not allow_private:
        for addr in addresses:
            if not is_public_ip(addr):
                raise _refuse(
                    "Le domaine pointe vers une adresse interne : analyse refusée (anti-SSRF)."
                    if not redirect
                    else "elle pointe vers une adresse interne"
                )
    return SafeTarget(url, host, port, addresses)


async def validate_redirect_url(raw: str, allow_private: bool | None = None) -> SafeTarget:
    """Valide une URL de redirection (même règles que la cible initiale)."""
    if (urlsplit(raw).scheme or "").lower() not in {"http", "https"}:
        raise ScanError(
            "Redirection bloquée : schéma non autorisé (protection anti-SSRF).",
            "blocked_redirect",
        )
    return await validate_target(raw, allow_private, redirect=True)
