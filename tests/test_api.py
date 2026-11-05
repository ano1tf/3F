"""Contrat de l'API HTTP : guards, métadonnées, refus des entrées invalides."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_meta_lists_scope_and_limits():
    payload = client.get("/api/meta").json()
    assert payload["app"] == "VulnLens"
    assert len(payload["scope"]) >= 8
    assert len(payload["limits"]) >= 3
    assert {s["key"] for s in payload["severities"]} == {"critical", "high", "medium", "low", "info"}


def test_index_is_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "VulnLens" in response.text


def test_scan_requires_explicit_authorization():
    response = client.post("/api/scan", json={"url": "https://exemple.fr", "authorized": False})
    assert response.status_code == 403
    assert "autoris" in response.json()["error"].lower()


def test_scan_rejects_non_http_scheme():
    response = client.post("/api/scan", json={"url": "ftp://exemple.fr", "authorized": True})
    assert response.status_code == 400


def test_scan_rejects_empty_url():
    response = client.post("/api/scan", json={"url": "", "authorized": True})
    assert response.status_code == 422
