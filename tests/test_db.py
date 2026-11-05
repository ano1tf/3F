"""Persistance : enregistrement, liste, lecture, statistiques, suppression."""

from __future__ import annotations

import asyncio

from app import db


def report(scan_id: str, host: str = "cible.test", score: int = 70, **kwargs) -> dict:
    base = {
        "scan_id": scan_id,
        "target": f"https://{host}/",
        "final_url": f"https://{host}/",
        "started_at": f"2026-03-{kwargs.get('day', 12)}T10:00:00+00:00",
        "score": score,
        "grade": "C" if score >= 65 else "D",
        "duration_ms": 900,
        "profile": "quick",
        "findings": [
            {
                "id": "headers.missing.content-security-policy",
                "title": "CSP absente",
                "severity": "high",
                "category": "Configuration HTTP",
            }
        ],
        "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    }
    base.update(kwargs)
    return base


def test_save_and_get(temp_db):
    scan_id = asyncio.run(db.save_scan(report("s1")))
    assert scan_id == "s1"
    stored = asyncio.run(db.get_scan("s1"))
    assert stored is not None
    assert stored["score"] == 70
    assert stored["profile"] == "quick"


def test_get_unknown_returns_none(temp_db):
    assert asyncio.run(db.get_scan("inconnu")) is None


def test_list_is_ordered_and_filterable(temp_db):
    asyncio.run(db.save_scan(report("s1", day=10)))
    asyncio.run(db.save_scan(report("s2", host="autre.test", day=11)))
    asyncio.run(db.save_scan(report("s3", day=12)))

    everything = asyncio.run(db.list_scans())
    assert [item["id"] for item in everything] == ["s3", "s2", "s1"]

    filtered = asyncio.run(db.list_scans(host="cible.test"))
    assert {item["id"] for item in filtered} == {"s1", "s3"}


def test_saving_same_id_overwrites(temp_db):
    asyncio.run(db.save_scan(report("s1", score=70)))
    asyncio.run(db.save_scan(report("s1", score=90)))
    scans = asyncio.run(db.list_scans())
    assert len(scans) == 1
    assert scans[0]["score"] == 90


def test_stats_aggregate(temp_db):
    asyncio.run(db.save_scan(report("s1", score=50, counts={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0})))
    asyncio.run(db.save_scan(report("s2", score=90, day=13)))

    stats = asyncio.run(db.stats())
    assert stats["total_scans"] == 2
    assert stats["average_score"] == 70.0
    assert stats["severity"]["critical"] == 1
    assert stats["severity"]["high"] == 1
    assert len(stats["series"]) == 2
    assert stats["hosts"][0]["host"] == "cible.test"


def test_previous_scan(temp_db):
    asyncio.run(db.save_scan(report("s1", score=40, day=10)))
    asyncio.run(db.save_scan(report("s2", score=80, day=12)))
    previous = asyncio.run(db.previous_scan("cible.test", exclude_id="s2"))
    assert previous is not None
    assert previous["score"] == 40


def test_delete(temp_db):
    asyncio.run(db.save_scan(report("s1")))
    assert asyncio.run(db.delete_scan("s1")) is True
    assert asyncio.run(db.delete_scan("s1")) is False
    assert asyncio.run(db.list_scans()) == []
