"""API d'historique : liste, détail, exports, suppression."""

from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from app import db
from app.main import app


def make_report(scan_id: str, score: int = 72, host: str = "cible.test") -> dict:
    return {
        "scan_id": scan_id,
        "target": f"https://{host}/",
        "final_url": f"https://{host}/",
        "started_at": f"2026-03-1{scan_id[-1]}T09:00:00+00:00",
        "duration_ms": 1500,
        "score": score,
        "grade": "C",
        "profile": "quick",
        "counts": {"critical": 1, "high": 0, "medium": 2, "low": 0, "info": 0},
        "priorities": ["exposure.git"],
        "fingerprint": {"serveur": "nginx"},
        "checks": [{"key": "headers", "label": "En-têtes", "status": "ok", "findings": []}],
        "findings": [
            {
                "id": "exposure.git",
                "title": "Dépôt Git exposé",
                "severity": "critical",
                "severity_label": "Critique",
                "category": "Exposition de fichiers",
                "description": "Le dossier .git est accessible.",
                "evidence": "ref: refs/heads/main",
                "remediation": "Bloquez .git/.",
                "reference": "https://owasp.org/",
            }
        ],
    }


@pytest.fixture()
def client(temp_db):
    with TestClient(app) as test_client:
        yield test_client


def seed(*reports: dict) -> None:
    for report in reports:
        asyncio.run(db.save_scan(report, profile=report.get("profile", "quick")))


def test_history_is_empty_initially(client):
    assert client.get("/api/scans").json() == {"scans": []}
    stats = client.get("/api/stats").json()
    assert stats["total_scans"] == 0
    assert stats["average_score"] == 0


def test_history_lists_saved_scans(client):
    seed(make_report("s1", 70), make_report("s2", 40))
    payload = client.get("/api/scans").json()
    assert len(payload["scans"]) == 2
    assert payload["scans"][0]["id"] == "s2"

    filtered = client.get("/api/scans", params={"host": "cible.test"}).json()["scans"]
    assert len(filtered) == 2

    other = client.get("/api/scans", params={"host": "absent.test"}).json()["scans"]
    assert other == []


def test_stats_reflect_scans(client):
    seed(make_report("s1", 70), make_report("s2", 90))
    stats = client.get("/api/stats").json()
    assert stats["total_scans"] == 2
    assert stats["average_score"] == 80.0
    assert stats["severity"]["critical"] == 2
    assert len(stats["series"]) == 2


def test_scan_detail_and_unknown(client):
    seed(make_report("s1"))
    detail = client.get("/api/scans/s1").json()
    assert detail["score"] == 72
    assert detail["findings"][0]["id"] == "exposure.git"

    missing = client.get("/api/scans/inconnu")
    assert missing.status_code == 404
    assert "introuvable" in missing.json()["error"]


def test_sarif_export(client):
    seed(make_report("s1"))
    response = client.get("/api/scans/s1/sarif")
    assert response.status_code == 200
    assert "sarif" in response.headers["content-type"]
    assert "attachment" in response.headers["content-disposition"]
    assert response.json()["runs"][0]["results"][0]["ruleId"] == "exposure.git"


def test_html_and_markdown_exports(client):
    seed(make_report("s1"))

    html = client.get("/api/scans/s1/report.html")
    assert html.status_code == 200
    assert "<!doctype html>" in html.text
    assert "Dépôt Git exposé" in html.text

    markdown = client.get("/api/scans/s1/markdown")
    assert markdown.status_code == 200
    assert "# Rapport VulnLens" in markdown.text

    raw = client.get("/api/scans/s1/json")
    assert json.loads(raw.text)["scan_id"] == "s1"


def test_delete_scan(client):
    seed(make_report("s1"))
    assert client.delete("/api/scans/s1").json()["deleted"] is True
    assert client.get("/api/scans/s1").status_code == 404
    assert client.delete("/api/scans/s1").status_code == 404


def test_scan_endpoint_persists_report(client, vulnerable_server):
    """Régression : une analyse lancée depuis l'UI doit atterrir dans l'historique."""
    response = client.post(
        "/api/scan",
        json={"url": vulnerable_server.url, "authorized": True, "profile": "quick"},
    )
    assert response.status_code == 200

    lines = [line for line in response.text.splitlines() if line.strip()]
    events = [json.loads(line) for line in lines]
    result = next(event for event in events if event["type"] == "result")
    scan_id = result["report"]["scan_id"]

    history = client.get("/api/scans").json()["scans"]
    assert [item["id"] for item in history] == [scan_id]
    assert history[0]["score"] == result["report"]["score"]
    assert history[0]["profile"] == "quick"

    detail = client.get(f"/api/scans/{scan_id}").json()
    assert detail["findings"]
    assert client.get("/api/stats").json()["total_scans"] == 1
