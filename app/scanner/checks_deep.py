"""Contrôles approfondis : transfert de zone DNS, redirections ouvertes, sous-domaines.

Tous restent non destructifs : une requête DNS AXFR, quelques requêtes HTTP avec
une URL de sonde neutre (`vulnlens.example`, TLD réservé), et de la résolution
DNS passive sur une liste de noms courants.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import socket
import string
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Finding, Severity
from .fetcher import Fetcher, HttpResponse

CATEGORY = "Reconnaissance approfondie"

SUBDOMAIN_WORDLIST = [
    "www", "api", "app", "admin", "portal", "vpn", "mail", "webmail", "smtp", "imap",
    "ftp", "sftp", "ssh", "git", "gitlab", "jenkins", "ci", "build", "staging", "stage",
    "dev", "test", "qa", "uat", "preprod", "demo", "beta", "old", "legacy", "backup",
    "db", "mysql", "postgres", "redis", "mongo", "cache", "cdn", "static", "assets",
    "media", "files", "docs", "wiki", "blog", "shop", "status", "monitor", "grafana",
    "kibana", "intranet", "sso", "auth", "login", "oauth", "id", "ns1", "ns2", "mx",
]

REDIRECT_PARAMS = ["next", "url", "redirect", "return", "returnUrl", "dest", "continue"]
PROBE_URL = "https://vulnlens.example/probe"
MAX_SUBDOMAINS = 8


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return []
    return sorted({info[4][0] for info in infos})


# ---------------------------------------------------------------------------
# Transfert de zone
# ---------------------------------------------------------------------------


def _attempt_axfr(host: str) -> tuple[bool, str]:
    import dns.exception
    import dns.query
    import dns.zone

    try:
        import dns.resolver

        answers = dns.resolver.resolve(host, "NS", lifetime=4)
        nameservers = [str(record.target).rstrip(".") for record in answers]
    except Exception as exc:  # noqa: BLE001
        return False, f"NS introuvables : {type(exc).__name__}"

    for nameserver in nameservers[:2]:
        try:
            addresses = _resolve(nameserver)
            if not addresses:
                continue
            zone = dns.zone.from_xfr(dns.query.xfr(addresses[0], host, lifetime=8))
            records = [str(node) for node in list(zone.nodes.keys())[:10]]
            return True, f"{len(zone.nodes)} nœuds via {nameserver} ({', '.join(records[:5])}…)"
        except dns.exception.DNSException:
            continue
        except Exception:  # noqa: BLE001
            continue
    return False, "Transfert refusé par les serveurs interrogés"


async def check_zone_transfer(host: str) -> Finding | None:
    if _is_ip(host):
        return None
    transferred, detail = await asyncio.to_thread(_attempt_axfr, host)
    if not transferred:
        return None
    return Finding(
        id="dns.zone-transfer",
        title="Transfert de zone DNS autorisé (AXFR)",
        severity=Severity.CRITICAL,
        category="DNS & e-mail",
        description="N'importe qui peut demander la zone complète au serveur DNS : tous les "
        "sous-domaines, y compris internes et de préproduction, sont révélés d'un coup.",
        evidence=detail,
        remediation="Restreignez AXFR aux serveurs secondaires légitimes (ACL / TSIG) sur chaque "
        "serveur autoritaire.",
        reference="https://www.rfc-editor.org/rfc/rfc5936",
    )


# ---------------------------------------------------------------------------
# Redirections ouvertes
# ---------------------------------------------------------------------------


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[name] = value
    return urlunparse(parts._replace(query=urlencode(query)))


def _is_reflected_redirect(response: HttpResponse) -> bool:
    if response.status not in (301, 302, 303, 307, 308):
        return False
    location = response.header("location")
    if not location:
        return False
    return "vulnlens.example" in location.lower()


async def check_open_redirect(fetcher: Fetcher, base_url: str) -> list[Finding]:
    """6 requêtes maximum, avec une destination de sonde neutre et non résolvable."""
    findings: list[Finding] = []
    hits: list[str] = []

    async def probe(param: str) -> tuple[str, HttpResponse]:
        url = _with_param(base_url, param, PROBE_URL)
        response = await fetcher.get(url, follow_redirects=False, max_bytes=2048, timeout=8)
        return param, response

    results = await asyncio.gather(*(probe(param) for param in REDIRECT_PARAMS))

    for param, response in results:
        if response.error:
            continue
        if _is_reflected_redirect(response):
            hits.append(
                f"?{param}={PROBE_URL} → {response.status} Location: {response.header('location')}"
            )

    if hits:
        findings.append(
            Finding(
                id="web.open-redirect",
                title="Redirection ouverte",
                severity=Severity.HIGH,
                category="Contenu & formulaires",
                description="Un paramètre d'URL contrôle la destination d'une redirection. Un "
                "attaquant l'utilise pour envoyer vos utilisateurs vers un site de phishing sous "
                "votre nom de domaine (et contourner les filtres de messagerie).",
                evidence="\n".join(hits[:5]),
                remediation="Validez la destination contre une liste blanche de chemins internes, "
                "ou utilisez un identifiant opaque plutôt qu'une URL complète.",
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Sous-domaines
# ---------------------------------------------------------------------------


async def _resolve_async(host: str, timeout: float = 3.0) -> list[str]:
    try:
        return await asyncio.wait_for(asyncio.to_thread(_resolve, host), timeout=timeout)
    except (TimeoutError, Exception):  # noqa: BLE001
        return []


def _wildcard_name(host: str) -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"vulnlens-{suffix}.{host}"


async def discover_subdomains(host: str, concurrency: int = 12) -> list[Finding]:
    if _is_ip(host):
        return []

    wildcard_addresses = set(await _resolve_async(_wildcard_name(host)))
    semaphore = asyncio.Semaphore(concurrency)

    async def probe(name: str) -> tuple[str, list[str]]:
        async with semaphore:
            return name, await _resolve_async(f"{name}.{host}")

    results = await asyncio.gather(*(probe(name) for name in SUBDOMAIN_WORDLIST))

    found: dict[str, list[str]] = {}
    for name, addresses in results:
        if not addresses:
            continue
        # DNS générique (wildcard) : toutes les réponses se ressemblent, donc rien d'exploitable.
        if wildcard_addresses and set(addresses) <= wildcard_addresses:
            continue
        found[f"{name}.{host}"] = addresses

    if not found:
        return []

    findings: list[Finding] = []
    listing = "\n".join(f"{name} → {', '.join(addresses[:2])}" for name, addresses in list(found.items())[:MAX_SUBDOMAINS])
    findings.append(
        Finding(
            id="recon.subdomains",
            title=f"{len(found)} sous-domaine(s) résolus",
            severity=Severity.INFO,
            category=CATEGORY,
            description="Les sous-domaines sont souvent moins surveillés que le site principal. "
            "Vérifiez qu'aucun d'eux n'expose d'environnement de test ou d'ancienne application.",
            evidence=listing + ("\n…" if len(found) > MAX_SUBDOMAINS else ""),
            remediation="Inventoriez vos sous-domaines, supprimez les enregistrements DNS orphelins "
            "et surveillez les nouvelles résolutions.",
            reference="https://owasp.org/www-community/attacks/Subdomain_takeover",
        )
    )

    risky = [
        name
        for name in found
        if any(token in name.split(".")[0] for token in ("dev", "test", "qa", "stage", "staging", "uat", "preprod", "demo", "old", "legacy"))
    ]
    if risky:
        findings.append(
            Finding(
                id="recon.staging-exposed",
                title="Environnement de test accessible publiquement",
                severity=Severity.LOW,
                category=CATEGORY,
                description="Des noms évoquant la préproduction ou le développement répondent "
                "publiquement : ces environnements contiennent souvent des données réelles, des "
                "modes debug et une authentification plus faible.",
                evidence="\n".join(f"{name} → {', '.join(list(found[name])[:2])}" for name in risky[:6]),
                remediation="Placez ces environnements derrière un VPN, une authentification "
                "fédérée ou une restriction d'IP.",
                reference="https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


async def run_deep(fetcher: Fetcher, host: str, base_url: str) -> list[Finding]:
    findings: list[Finding] = []

    zone_task = asyncio.create_task(check_zone_transfer(host))
    subs_task = asyncio.create_task(discover_subdomains(host))
    redirects = await check_open_redirect(fetcher, base_url)
    findings.extend(redirects)

    zone_finding = await zone_task
    if zone_finding:
        findings.append(zone_finding)

    try:
        findings.extend(await asyncio.wait_for(subs_task, timeout=25))
    except (TimeoutError, Exception):  # noqa: BLE001
        subs_task.cancel()

    return findings
