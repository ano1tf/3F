"""API v3 : diff de scans, vérification de propriété, protection par jeton."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from app import config, db, verify
from app.main import app


def make_report(scan_id: str, score: int, findings: list[dict], day: str = "10") -> dict:
    return {
        "scan_id": scan_id,
        "target": "https://cible.test/",
        "final_url": "https://cible.test/",
        "started_at": f"2026-03-{day}T09:00:00+00:00",
        "duration_ms": 800,
        "score": score,
        "grade": "C",
        "profile": "quick",
        "counts": {"critical": 0, "high": len(findings), "medium": 0, "low": 0, "info": 0},
        "findings": findings,
        "priorities": [],
        "fingerprint": {},
        "checks": [],
        "pages": [],
    }


def f(fid: str, severity: str = "high") -> dict:
    return {
        "id": fid,
        "title": fid,
        "severity": severity,
        "severity_label": severity,
        "category": "cat",
        "description": "d",
    }


@pytest.fixture()
def client(temp_db):
    with TestClient(app) as test_client:
        yield test_client


def test_diff_endpoint(client):
    asyncio.run(db.save_scan(make_report("old", 40, [f("a"), f("b")], day="10")))
    asyncio.run(db.save_scan(make_report("new", 80, [f("b"), f("c")], day="12")))

    diff = client.get("/api/scans/new/diff").json()
    assert diff["available"] is True
    assert diff["score_delta"] == 40
    assert [item["id"] for item in diff["new"]] == ["c"]
    assert [item["id"] for item in diff["fixed"]] == ["a"]
    assert diff["summary"]["persistent"] == 1


def test_diff_endpoint_without_history(client):
    asyncio.run(db.save_scan(make_report("only", 55, [f("a")])))
    diff = client.get("/api/scans/only/diff").json()
    assert diff["available"] is False


def test_verify_status_endpoint(client):
    payload = client.get("/api/verify/cible.test").json()
    assert len(payload["token"]) == 32
    assert payload["verified"] is False
    assert payload["instructions"]["record_name"] == "_vulnlens.cible.test"


def test_verify_check_endpoint(client, monkeypatch):
    token = client.get("/api/verify/cible.test").json()["token"]

    async def fake_dns(_host: str, candidate: str) -> bool:
        return candidate == token

    monkeypatch.setattr(verify, "check_dns", fake_dns)
    payload = client.post("/api/verify/cible.test/check").json()
    assert payload["verified"] is True
    assert payload["method"] == "dns"


def test_verify_rejects_invalid_host(client):
    response = client.get("/api/verify/cible.test:99999")
    assert response.status_code == 400


def test_api_requires_token_when_configured(client, monkeypatch):
    monkeypatch.setattr(config, "AUTH_TOKEN", "s3cret")

    assert client.get("/api/meta").status_code == 401
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/meta", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert client.get("/api/meta", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/api/meta", headers={"X-API-Key": "faux"}).status_code == 401


def test_html_export_includes_diff_section(client):
    asyncio.run(db.save_scan(make_report("vieux", 40, [f("a")], day="10")))
    asyncio.run(db.save_scan(make_report("recent", 75, [f("b")], day="12")))

    html = client.get("/api/scans/recent/report.html").text
    assert "Évolution depuis la dernière analyse" in html
    assert "+35 pts" in html
    assert "Constats corrigés" in html

    sarif = client.get("/api/scans/recent/sarif").json()
    assert sarif["runs"][0]["properties"]["pagesAnalyzed"] == 0
