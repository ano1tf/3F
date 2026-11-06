"""Alertes sortantes (webhook) quand une analyse se dégrade.

Silencieux par défaut : rien n'est envoyé sans `VULNLENS_WEBHOOK_URL`.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import config
from .safety import is_blocked_host, is_public_ip


def webhook_allowed(url: str) -> bool:
    """Refuse un webhook qui viserait une cible interne (SSRF par mauvaise config).

    Les cibles privées restent possibles pour les tests locaux en activant
    `VULNLENS_ALLOW_PRIVATE=1`.
    """
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    if config.ALLOW_PRIVATE_TARGETS:
        return True
    host = parsed.hostname.lower()
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        return not is_blocked_host(host)
    return is_public_ip(literal)


def should_alert(report: dict[str, Any], previous: dict[str, Any] | None) -> tuple[bool, str]:
    if not config.WEBHOOK_URL:
        return False, ""

    score = int(report.get("score") or 0)
    critical = int((report.get("counts") or {}).get("critical", 0))

    if config.ALERT_THRESHOLD is not None and score < config.ALERT_THRESHOLD:
        return True, f"score {score} < seuil {config.ALERT_THRESHOLD}"

    if critical and config.ALERT_ON_CRITICAL:
        return True, f"{critical} constat(s) critique(s)"

    if previous is not None:
        drop = int(previous.get("score") or 0) - score
        if drop >= config.ALERT_MIN_DROP:
            return True, f"score en baisse de {drop} points"

    return False, ""


def payload(report: dict[str, Any], reason: str) -> dict[str, Any]:
    findings = report.get("findings") or []
    return {
        "source": config.APP_NAME,
        "version": config.APP_VERSION,
        "reason": reason,
        "scan_id": report.get("scan_id"),
        "target": report.get("final_url") or report.get("target"),
        "score": report.get("score"),
        "grade": report.get("grade"),
        "profile": report.get("profile"),
        "counts": report.get("counts"),
        "verified": bool(report.get("verified")),
        "priorities": [
            {"title": f.get("title"), "severity": f.get("severity")}
            for f in findings
            if f.get("id") in (report.get("priorities") or [])
        ],
    }


async def notify(report: dict[str, Any], previous: dict[str, Any] | None) -> bool:
    """Envoie une alerte si nécessaire. Ne lève jamais : best-effort."""
    triggered, reason = should_alert(report, previous)
    if not triggered or not webhook_allowed(config.WEBHOOK_URL):
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            response = await client.post(config.WEBHOOK_URL, json=payload(report, reason))
            return 200 <= response.status_code < 300
    except (httpx.HTTPError, OSError, ValueError):
        return False


async def notify_async(report: dict[str, Any], previous: dict[str, Any] | None) -> None:
    """Version non bloquante utilisée par l'API."""
    asyncio.ensure_future(notify(report, previous))
