"""Comparaison entre deux analyses : nouveaux, corrigés, persistants, dégradés."""

from __future__ import annotations

from app.diffing import diff_reports


def finding(fid: str, sev: str = "high", title: str = "t") -> dict:
    return {
        "id": fid,
        "title": title,
        "severity": sev,
        "severity_label": sev.capitalize(),
        "category": "cat",
    }


def report(scan_id: str, score: int, findings: list[dict]) -> dict:
    return {"scan_id": scan_id, "score": score, "findings": findings, "started_at": "2026-03-01T10:00:00+00:00"}


def test_no_previous_report():
    diff = diff_reports(report("b", 80, []), None)
    assert diff["available"] is False
    assert "antérieure" in diff["reason"]


def test_detects_new_fixed_and_persistent():
    previous = report("a", 40, [finding("old"), finding("kept")])
    current = report("b", 70, [finding("kept"), finding("new")])

    diff = diff_reports(current, previous)
    assert diff["available"] is True
    assert diff["score_delta"] == 30
    assert [f["id"] for f in diff["new"]] == ["new"]
    assert [f["id"] for f in diff["fixed"]] == ["old"]
    assert diff["persistent_count"] == 1
    assert diff["summary"] == {"new": 1, "fixed": 1, "persistent": 1}


def test_detects_severity_change():
    previous = report("a", 50, [finding("x", "medium")])
    current = report("b", 30, [finding("x", "critical")])
    diff = diff_reports(current, previous)
    assert diff["changed"][0]["from"] == "medium"
    assert diff["changed"][0]["to"] == "critical"
    assert diff["score_delta"] == -20


def test_results_are_sorted_by_severity():
    previous = report("a", 50, [])
    current = report("b", 10, [finding("low", "low"), finding("crit", "critical"), finding("med", "medium")])
    diff = diff_reports(current, previous)
    assert [f["severity"] for f in diff["new"]] == ["critical", "medium", "low"]
