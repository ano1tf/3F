"""Surveillance planifiée : réanalyser périodiquement les cibles suivies.

Un scan passif quotidien suffit à repérer une régression (en-tête de sécurité supprimé,
fichier de sauvegarde apparu, secret poussé par erreur). Les alertes réutilisent le webhook.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from . import alerts, config, db
from .safety import ScanError
from .scanner.engine import run_scan


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def is_due(entry: dict[str, Any], now: datetime | None = None) -> bool:
    if not entry.get("enabled"):
        return False
    moment = now or datetime.now(UTC)
    last = _parse(entry.get("last_run"))
    if last is None:
        return True
    return moment - last >= timedelta(hours=max(1, int(entry.get("interval_hours") or 24)))


def next_run(entry: dict[str, Any]) -> str | None:
    last = _parse(entry.get("last_run"))
    if not entry.get("enabled"):
        return None
    if last is None:
        return "dès que possible"
    return (last + timedelta(hours=max(1, int(entry.get("interval_hours") or 24)))).isoformat(
        timespec="seconds"
    )


def describe(entries: list[dict[str, Any]], now: datetime | None = None) -> list[dict[str, Any]]:
    moment = now or datetime.now(UTC)
    described = []
    for entry in entries:
        item = dict(entry)
        item["due"] = is_due(entry, moment)
        item["next_run"] = next_run(entry)
        item["scheduler"] = config.WATCH_ENABLED
        described.append(item)
    return described


async def run_watch(entry: dict[str, Any]) -> dict[str, Any]:
    """Analyse une cible surveillée, enregistre le rapport et alerte si régression."""
    host = entry["host"]
    profile = entry.get("profile") or "standard"
    target = host if "://" in host else f"https://{host}"

    async def noop(_event: dict) -> None:
        return None

    # L'historique est indexé par nom d'hôte (sans port) : on l'utilise pour comparer.
    previous = await db.previous_scan(host.split(":")[0])
    try:
        report = await run_scan(target, noop, profile=profile)
    except ScanError:
        # Un service interne peut très bien n'écouter qu'en HTTP : on retente une fois.
        if target.startswith("https://"):
            report = await run_scan(f"http://{host}", noop, profile=profile)
        else:
            raise
    await db.save_scan(report.to_dict(), profile=report.profile)
    await db.mark_watch_run(host, report.scan_id, report.score)
    await alerts.notify(report.to_dict(), previous)
    return {
        "host": host,
        "scan_id": report.scan_id,
        "score": report.score,
        "grade": report.grade,
        "previous_score": (previous or {}).get("score"),
        "findings": len(report.findings),
    }


async def run_due(now: datetime | None = None) -> list[dict[str, Any]]:
    """Passe en revue la liste de surveillance et analyse ce qui est échu."""
    entries = await db.list_watches()
    results = []
    for entry in entries:
        if not is_due(entry, now):
            continue
        try:
            results.append(await run_watch(entry))
        except Exception as exc:  # noqa: BLE001 - une cible cassée ne doit pas bloquer les autres
            results.append({"host": entry["host"], "error": str(exc)})
    return results


async def scheduler_loop(stop: asyncio.Event | None = None) -> None:
    """Boucle de fond : vérifie toutes les `WATCH_TICK_SECONDS` si une cible est échue."""
    while True:
        try:
            if stop is not None and stop.is_set():
                return
            await asyncio.sleep(max(30, config.WATCH_TICK_SECONDS))
            if stop is not None and stop.is_set():
                return
            await run_due()
        except asyncio.CancelledError:  # pragma: no cover - arrêt propre
            return
        except Exception:  # pragma: no cover - la boucle ne doit jamais mourir
            await asyncio.sleep(60)
