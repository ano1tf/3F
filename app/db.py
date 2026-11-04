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
    report         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_host_date ON scans(host, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(created_at DESC);
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
        _INITIALIZED.add(key)
    return conn


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
                 duration_ms, findings_count, counts, report)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    return report


async def get_scan(scan_id: str) -> dict[str, Any] | None:
    return await asyncio.to_thread(_get_sync, scan_id)


def _delete_sync(scan_id: str) -> bool:
    with _connect() as conn:
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
        "total_scans": int(totals["total"] or 0),
        "average_score": round(float(totals["avg"] or 0), 1),
        "hosts": sorted(hosts.values(), key=lambda item: item["last_at"] or "", reverse=True),
        "severity": severity,
        "series": series,
    }


async def stats() -> dict[str, Any]:
    return await asyncio.to_thread(_stats_sync)


def _previous_sync(host: str, exclude_id: str) -> dict[str, Any] | None:
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


async def previous_scan(host: str, exclude_id: str) -> dict[str, Any] | None:
    return await asyncio.to_thread(_previous_sync, host, exclude_id)
