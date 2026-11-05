"""Alertes webhook : déclenchement et charge utile."""

from __future__ import annotations

from app import alerts, config


def report(score: int = 60, critical: int = 0) -> dict:
    return {
        "scan_id": "s1",
        "target": "https://cible.test/",
        "final_url": "https://cible.test/",
        "score": score,
        "grade": "C",
        "profile": "quick",
        "verified": False,
        "counts": {"critical": critical, "high": 0, "medium": 0, "low": 0, "info": 0},
        "findings": [
            {"id": "exposure.git", "title": "Dépôt Git exposé", "severity": "critical"},
        ],
        "priorities": ["exposure.git"],
    }


def test_no_webhook_means_no_alert(monkeypatch):
    monkeypatch.setattr(config, "WEBHOOK_URL", "")
    triggered, _ = alerts.should_alert(report(10, critical=3), None)
    assert triggered is False


def test_threshold_triggers(monkeypatch):
    monkeypatch.setattr(config, "WEBHOOK_URL", "https://hook.test/x")
    monkeypatch.setattr(config, "ALERT_THRESHOLD", 80)
    monkeypatch.setattr(config, "ALERT_ON_CRITICAL", False)
    triggered, reason = alerts.should_alert(report(50), None)
    assert triggered is True
    assert "seuil" in reason


def test_critical_triggers(monkeypatch):
    monkeypatch.setattr(config, "WEBHOOK_URL", "https://hook.test/x")
    monkeypatch.setattr(config, "ALERT_THRESHOLD", None)
    monkeypatch.setattr(config, "ALERT_ON_CRITICAL", True)
    triggered, reason = alerts.should_alert(report(90, critical=1), None)
    assert triggered is True
    assert "critique" in reason


def test_score_drop_triggers(monkeypatch):
    monkeypatch.setattr(config, "WEBHOOK_URL", "https://hook.test/x")
    monkeypatch.setattr(config, "ALERT_THRESHOLD", None)
    monkeypatch.setattr(config, "ALERT_ON_CRITICAL", False)
    monkeypatch.setattr(config, "ALERT_MIN_DROP", 10)
    triggered, reason = alerts.should_alert(report(50), report(80))
    assert triggered is True
    assert "baisse" in reason


def test_stable_score_does_not_trigger(monkeypatch):
    monkeypatch.setattr(config, "WEBHOOK_URL", "https://hook.test/x")
    monkeypatch.setattr(config, "ALERT_THRESHOLD", None)
    monkeypatch.setattr(config, "ALERT_ON_CRITICAL", False)
    monkeypatch.setattr(config, "ALERT_MIN_DROP", 10)
    triggered, _ = alerts.should_alert(report(78), report(80))
    assert triggered is False


def test_payload_is_actionable():
    body = alerts.payload(report(30, critical=1), "test")
    assert body["scan_id"] == "s1"
    assert body["priorities"][0]["title"] == "Dépôt Git exposé"
    assert body["counts"]["critical"] == 1
