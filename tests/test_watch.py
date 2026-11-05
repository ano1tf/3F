"""Surveillance planifiée : échéances, persistance et API."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app import db, watch
from app.main import app

NOW = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)


def entry(**overrides) -> dict:
    base = {
        "host": "cible.test",
        "profile": "standard",
        "interval_hours": 24,
        "enabled": True,
        "last_run": None,
    }
    base.update(overrides)
    return base


def test_due_when_never_run():
    assert watch.is_due(entry(), NOW) is True


def test_disabled_is_never_due():
    assert watch.is_due(entry(enabled=False), NOW) is False


def test_recent_run_is_not_due():
    recent = (NOW - timedelta(hours=2)).isoformat()
    assert watch.is_due(entry(last_run=recent), NOW) is False


def test_old_run_is_due():
    old = (NOW - timedelta(hours=30)).isoformat()
    assert watch.is_due(entry(last_run=old), NOW) is True


def test_custom_interval_is_respected():
    last = (NOW - timedelta(hours=5)).isoformat()
    assert watch.is_due(entry(last_run=last, interval_hours=6), NOW) is False
    assert watch.is_due(entry(last_run=last, interval_hours=4), NOW) is True


def test_next_run_and_describe():
    last = (NOW - timedelta(hours=1)).isoformat()
    described = watch.describe([entry(last_run=last)], NOW)[0]
    assert described["due"] is False
    assert described["next_run"].startswith("2026-05-0")
    assert watch.describe([entry(enabled=False)], NOW)[0]["next_run"] is None


def test_db_roundtrip(temp_db):
    created = asyncio.run(db.upsert_watch("Cible.Test", "deep", 12, True))
    assert created["host"] == "cible.test"
    assert created["interval_hours"] == 12

    updated = asyncio.run(db.upsert_watch("cible.test", "quick", 6, False))
    assert updated["profile"] == "quick"
    assert updated["enabled"] is False

    asyncio.run(db.mark_watch_run("cible.test", "abc123", 77))
    listed = asyncio.run(db.list_watches())
    assert listed[0]["last_score"] == 77
    assert listed[0]["last_scan_id"] == "abc123"

    assert asyncio.run(db.delete_watch("cible.test")) is True
    assert asyncio.run(db.delete_watch("cible.test")) is False


@pytest.fixture()
def client(temp_db):
    with TestClient(app) as test_client:
        yield test_client


def test_watch_api_crud(client):
    created = client.post("/api/watch", json={"host": "https://cible.test/", "interval_hours": 12})
    assert created.status_code == 200
    item = created.json()["item"]
    assert item["host"] == "cible.test"
    assert item["interval_hours"] == 12

    listing = client.get("/api/watch").json()
    assert listing["items"][0]["host"] == "cible.test"

    assert client.delete("/api/watch/cible.test").status_code == 200
    assert client.get("/api/watch").json()["items"] == []
    assert client.delete("/api/watch/cible.test").status_code == 404


def test_watch_run_endpoint(client, monkeypatch):
    client.post("/api/watch", json={"host": "cible.test"})

    async def fake_run(_entry):
        return {"host": "cible.test", "score": 88, "scan_id": "xyz"}

    monkeypatch.setattr(watch, "run_watch", fake_run)
    payload = client.post("/api/watch/cible.test/run").json()
    assert payload["score"] == 88

    assert client.post("/api/watch/inconnu.test/run").status_code == 404


def test_trend_endpoint(client):
    import json

    for index, score in enumerate((40, 60, 80)):
        asyncio.run(
            db.save_scan(
                {
                    "scan_id": f"s{index}",
                    "target": "https://cible.test/",
                    "final_url": "https://cible.test/",
                    "started_at": f"2026-04-0{index + 1}T10:00:00+00:00",
                    "score": score,
                    "grade": "C",
                    "findings": [],
                    "counts": {},
                    "profile": "quick",
                    "pages": [],
                }
            )
        )
    payload = client.get("/api/trend/cible.test").json()
    assert [point["score"] for point in payload["points"]] == [40, 60, 80]
    assert json.dumps(payload)  # sérialisable


def test_run_watch_falls_back_to_http(monkeypatch, temp_db):
    """Un service interne qui n'écoute qu'en HTTP doit rester surveillable."""
    from app import watch

    calls: list[str] = []

    class FakeReport:
        scan_id = "abc"
        score = 70
        grade = "C"
        findings: list = []
        profile = "standard"

        def to_dict(self):
            return {
                "scan_id": "abc",
                "target": "http://interne:8080/",
                "final_url": "http://interne:8080/",
                "score": 70,
                "grade": "C",
                "findings": [],
                "counts": {},
            }

    async def fake_run(target, _emit, profile="standard"):
        calls.append(target)
        if target.startswith("https://"):
            from app.safety import ScanError

            raise ScanError("Impossible de joindre la cible", "unreachable")
        return FakeReport()

    async def fake_save(*_args, **_kwargs):
        return "abc"

    async def fake_mark(*_args, **_kwargs):
        return None

    async def fake_notify(*_args, **_kwargs):
        return None

    monkeypatch.setattr(watch, "run_scan", fake_run)
    monkeypatch.setattr(watch.db, "save_scan", fake_save)
    monkeypatch.setattr(watch.db, "mark_watch_run", fake_mark)
    monkeypatch.setattr(watch, "alerts", type("A", (), {"notify": staticmethod(fake_notify)})())

    result = asyncio.run(watch.run_watch({"host": "interne:8080", "profile": "standard"}))
    assert calls == ["https://interne:8080", "http://interne:8080"]
    assert result["score"] == 70
