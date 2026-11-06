"""Persistance SQLite : historique des analyses, statistiques, tendances.

La base vit dans `data/vulnlens.db` (surchargeable via VULNLENS_DB). Elle ne
contient que des rapports d'analyse : aucune donnée personnelle, aucun secret.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .triage import VERDICTS as TRIAGE_LABELS

DB_PATH = Path(os.getenv("VULNLENS_DB", "data/vulnlens.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id             TEXT PRIMARY KEY,
    host           TEXT NOT NULL,
    target         TEXT NOT NULL,
    final_url      TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    profile        TEXT NOT NULL DEFAULT 'quick',
    score          INTEGER NOT NULL,
    grade          TEXT NOT NULL,
    duration_ms    INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    counts         TEXT NOT NULL DEFAULT '{}',
    verified       INTEGER NOT NULL DEFAULT 0,
    pages_count    INTEGER NOT NULL DEFAULT 0,
    report         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_host_date ON scans(host, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(created_at DESC);

CREATE TABLE IF NOT EXISTS verifications (
    host          TEXT PRIMARY KEY,
    token         TEXT NOT NULL,
    method        TEXT,
    created_at    TEXT NOT NULL,
    verified_at   TEXT
);

CREATE TABLE IF NOT EXISTS triage (
    scan_id    TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_triage_scan ON triage(scan_id);

CREATE TABLE IF NOT EXISTS watchlist (
    host           TEXT PRIMARY KEY,
    profile        TEXT NOT NULL DEFAULT 'standard',
    interval_hours INTEGER NOT NULL DEFAULT 24,
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL,
    last_run       TEXT,
    last_scan_id   TEXT,
    last_score     INTEGER
);
"""


_INITIALIZED: set[str] = set()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    # Initialisation paresseuse : le schéma est créé au premier accès, ce qui rend
    # la base utilisable aussi bien via l'API que via la CLI ou les tests.
    key = str(DB_PATH)
    if key not in _INITIALIZED:
        conn.executescript(SCHEMA)
        _migrate(conn)
        _INITIALIZED.add(key)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Migration douce : ajoute les colonnes manquantes aux bases existantes."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
    additions = {
        "verified": "ALTER TABLE scans ADD COLUMN verified INTEGER NOT NULL DEFAULT 0",
        "pages_count": "ALTER TABLE scans ADD COLUMN pages_count INTEGER NOT NULL DEFAULT 0",
        "profile": "ALTER TABLE scans ADD COLUMN profile TEXT NOT NULL DEFAULT 'quick'",
    }
    for column, statement in additions.items():
        if column not in columns:
            conn.execute(statement)


def _init_sync() -> None:
    with _connect() as conn:
        conn.executescript(SCHEMA)


async def init() -> None:
    await asyncio.to_thread(_init_sync)


def _host_of(report: dict[str, Any]) -> str:
    raw = report.get("final_url") or report.get("target") or ""
    try:
        return (urlparse(raw).hostname or raw).lower()
    except ValueError:
        return str(raw).lower()


def _row_to_summary(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "host": row["host"],
        "target": row["target"],
        "final_url": row["final_url"],
        "created_at": row["created_at"],
        "profile": row["profile"],
        "score": row["score"],
        "grade": row["grade"],
        "duration_ms": row["duration_ms"],
        "findings_count": row["findings_count"],
        "verified": bool(row["verified"]) if "verified" in row.keys() else False,
        "pages_count": int(row["pages_count"]) if "pages_count" in row.keys() else 0,
        "counts": json.loads(row["counts"] or "{}"),
    }


def _save_sync(report: dict[str, Any], profile: str) -> str:
    payload = json.dumps(report, ensure_ascii=False)
    scan_id = str(report.get("scan_id") or "")
    created = str(report.get("started_at") or datetime.now(UTC).isoformat())
    counts = report.get("counts") or {}
    with _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans
                (id, host, target, final_url, created_at, profile, score, grade,
                 duration_ms, findings_count, counts, verified, pages_count, report)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                _host_of(report),
                report.get("target", ""),
                report.get("final_url", ""),
                created,
                profile,
                int(report.get("score") or 0),
                str(report.get("grade") or "?"),
                int(report.get("duration_ms") or 0),
                int(sum(counts.values())) if counts else 0,
                json.dumps(counts, ensure_ascii=False),
                1 if report.get("verified") else 0,
                len(report.get("pages") or []),
                payload,
            ),
        )
    return scan_id


async def save_scan(report: dict[str, Any], profile: str = "quick") -> str:
    return await asyncio.to_thread(_save_sync, report, profile)


def _list_sync(host: str | None, limit: int) -> list[dict[str, Any]]:
    query = "SELECT * FROM scans"
    params: list[Any] = []
    if host:
        query += " WHERE host = ?"
        params.append(host.lower())
    query += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
    params.append(max(1, min(limit, 500)))
    with _connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_summary(row) for row in rows]


async def list_scans(host: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    return await asyncio.to_thread(_list_sync, host, limit)


def _get_sync(scan_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    report = json.loads(row["report"])
    report["profile"] = row["profile"]
    from . import triage as triage_module

    return triage_module.merge(report, _triage_sync(scan_id))


async def get_scan(scan_id: str) -> dict[str, Any] | None:
    return await asyncio.to_thread(_get_sync, scan_id)


def _delete_sync(scan_id: str) -> bool:
    with _connect() as conn:
        conn.execute("DELETE FROM triage WHERE scan_id = ?", (scan_id,))
        cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0


async def delete_scan(scan_id: str) -> bool:
    return await asyncio.to_thread(_delete_sync, scan_id)


def _stats_sync(limit_series: int = 40) -> dict[str, Any]:
    with _connect() as conn:
        totals = conn.execute(
            "SELECT COUNT(*) AS total, AVG(score) AS avg, COUNT(DISTINCT host) AS hosts FROM scans"
        ).fetchone()
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at ASC, rowid ASC"
        ).fetchall()
        watches = conn.execute(
            "SELECT COUNT(*) AS total, SUM(enabled) AS actives FROM watchlist"
        ).fetchone()

    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    hosts: dict[str, dict[str, Any]] = {}
    for row in rows:
        counts = json.loads(row["counts"] or "{}")
        for key in severity:
            severity[key] += int(counts.get(key, 0))
        host = row["host"]
        entry = hosts.setdefault(
            host,
            {"host": host, "scans": 0, "best": 100, "last_score": None, "last_at": None},
        )
        entry["scans"] += 1
        entry["best"] = min(entry["best"], int(row["score"]))
        entry["last_score"] = int(row["score"])
        entry["last_at"] = row["created_at"]

    series = [
        {
            "id": row["id"],
            "host": row["host"],
            "score": int(row["score"]),
            "created_at": row["created_at"],
        }
        for row in rows[-limit_series:]
    ]

    return {
        "watches": int(watches["total"] or 0),
        "watches_enabled": int(watches["actives"] or 0),
        "total_scans": int(totals["total"] or 0),
        "average_score": round(float(totals["avg"] or 0), 1),
        "hosts": sorted(hosts.values(), key=lambda item: item["last_at"] or "", reverse=True),
        "severity": severity,
        "series": series,
    }


async def stats() -> dict[str, Any]:
    return await asyncio.to_thread(_stats_sync)


def _previous_sync(host: str, exclude_id: str = "") -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM scans
            WHERE host = ? AND id != ?
            ORDER BY created_at DESC, rowid DESC
            LIMIT 1
            """,
            (host.lower(), exclude_id),
        ).fetchone()
    if row is None:
        return None
    return json.loads(row["report"])


async def previous_scan(host: str, exclude_id: str = "") -> dict[str, Any] | None:
    return await asyncio.to_thread(_previous_sync, host, exclude_id)


# ---------------------------------------------------------------------------
# Preuve de propriété d'un domaine
# ---------------------------------------------------------------------------


def _ensure_token_sync(host: str) -> dict[str, Any]:
    import secrets

    with _connect() as conn:
        row = conn.execute("SELECT * FROM verifications WHERE host = ?", (host.lower(),)).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO verifications (host, token, created_at) VALUES (?, ?, ?)",
                (host.lower(), secrets.token_hex(16), datetime.now(UTC).isoformat(timespec="seconds")),
            )
            row = conn.execute(
                "SELECT * FROM verifications WHERE host = ?", (host.lower(),)
            ).fetchone()
    return dict(row)


async def ensure_token(host: str) -> dict[str, Any]:
    """Retourne (et crée au besoin) le jeton de vérification d'un domaine."""
    return await asyncio.to_thread(_ensure_token_sync, host)


def _mark_verified_sync(host: str, method: str) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(
            "UPDATE verifications SET verified_at = ?, method = ? WHERE host = ?",
            (now, method, host.lower()),
        )
        row = conn.execute("SELECT * FROM verifications WHERE host = ?", (host.lower(),)).fetchone()
    return dict(row)


async def mark_verified(host: str, method: str) -> dict[str, Any]:
    return await asyncio.to_thread(_mark_verified_sync, host, method)


def _verification_sync(host: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM verifications WHERE host = ?", (host.lower(),)).fetchone()
    return dict(row) if row else None


async def verification(host: str) -> dict[str, Any] | None:
    return await asyncio.to_thread(_verification_sync, host)


def _is_verified_sync(host: str) -> bool:
    row = _verification_sync(host)
    return bool(row and row.get("verified_at"))


async def is_verified(host: str) -> bool:
    return await asyncio.to_thread(_is_verified_sync, host)


# --------------------------------------------------------------------------- #
# Triage des constats
# --------------------------------------------------------------------------- #


def _triage_sync(scan_id: str) -> dict[str, dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT finding_id, verdict, note, updated_at FROM triage WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
    return {
        row["finding_id"]: {
            "verdict": row["verdict"],
            "label": TRIAGE_LABELS.get(row["verdict"], row["verdict"]),
            "note": row["note"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    }


async def triage_for(scan_id: str) -> dict[str, dict[str, Any]]:
    return await asyncio.to_thread(_triage_sync, scan_id)


def _set_triage_sync(
    scan_id: str, finding_id: str, verdict: str, note: str, updated_at: str
) -> dict[str, dict[str, Any]]:
    stamp = updated_at or datetime.now(UTC).isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO triage (scan_id, finding_id, verdict, note, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, finding_id) DO UPDATE SET
                verdict = excluded.verdict,
                note = excluded.note,
                updated_at = excluded.updated_at
            """,
            (scan_id, finding_id, verdict, note, stamp),
        )
    return _triage_sync(scan_id)


async def set_triage(
    scan_id: str, finding_id: str, verdict: str, note: str = "", updated_at: str = ""
) -> dict[str, dict[str, Any]]:
    return await asyncio.to_thread(
        _set_triage_sync, scan_id, finding_id, verdict, note, updated_at
    )


def _clear_triage_sync(scan_id: str, finding_id: str) -> dict[str, dict[str, Any]]:
    with _connect() as conn:
        conn.execute(
            "DELETE FROM triage WHERE scan_id = ? AND finding_id = ?", (scan_id, finding_id)
        )
    return _triage_sync(scan_id)


async def clear_triage(scan_id: str, finding_id: str) -> dict[str, dict[str, Any]]:
    return await asyncio.to_thread(_clear_triage_sync, scan_id, finding_id)


# --------------------------------------------------------------------------- #
# Surveillance planifiée
# --------------------------------------------------------------------------- #

def _watch_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "host": row["host"],
        "profile": row["profile"],
        "interval_hours": row["interval_hours"],
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        "last_run": row["last_run"],
        "last_scan_id": row["last_scan_id"],
        "last_score": row["last_score"],
    }


def _list_watches_sync() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM watchlist ORDER BY host").fetchall()
    return [_watch_row(row) for row in rows]


async def list_watches() -> list[dict[str, Any]]:
    return await asyncio.to_thread(_list_watches_sync)


def _upsert_watch_sync(host: str, profile: str, interval_hours: int, enabled: bool) -> dict[str, Any]:
    from datetime import UTC, datetime

    now = datetime.now(UTC).isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO watchlist (host, profile, interval_hours, enabled, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(host) DO UPDATE SET
                profile = excluded.profile,
                interval_hours = excluded.interval_hours,
                enabled = excluded.enabled
            """,
            (host.lower(), profile, max(1, interval_hours), 1 if enabled else 0, now),
        )
        row = conn.execute("SELECT * FROM watchlist WHERE host = ?", (host.lower(),)).fetchone()
    return _watch_row(row)


async def upsert_watch(
    host: str, profile: str = "standard", interval_hours: int = 24, enabled: bool = True
) -> dict[str, Any]:
    return await asyncio.to_thread(_upsert_watch_sync, host, profile, interval_hours, enabled)


def _delete_watch_sync(host: str) -> bool:
    with _connect() as conn:
        cursor = conn.execute("DELETE FROM watchlist WHERE host = ?", (host.lower(),))
    return cursor.rowcount > 0


async def delete_watch(host: str) -> bool:
    return await asyncio.to_thread(_delete_watch_sync, host)


def _mark_watch_run_sync(host: str, scan_id: str, score: int) -> None:
    from datetime import UTC, datetime

    now = datetime.now(UTC).isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(
            "UPDATE watchlist SET last_run = ?, last_scan_id = ?, last_score = ? WHERE host = ?",
            (now, scan_id, score, host.lower()),
        )


async def mark_watch_run(host: str, scan_id: str, score: int) -> None:
    await asyncio.to_thread(_mark_watch_run_sync, host, scan_id, score)
