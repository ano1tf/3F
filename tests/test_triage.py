"""Triage : verdicts du pentester, persistance et exports."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from app import db, main, reporting, standards, triage


def sample_scan() -> dict:
    return {
        "scan_id": "triage01",
        "target": "https://cible.test/",
        "final_url": "https://cible.test/",
        "host": "cible.test",
        "score": 62,
        "grade": "D",
        "findings": [
            {
                "id": "exposure.git",
                "title": "Dépôt Git exposé",
                "severity": "critical",
                "severity_label": "Critique",
                "category": "Exposition de fichiers",
                "description": "Le dossier .git est accessible.",
                "evidence": "GET /.git/HEAD → 200",
                "remediation": "Bloquez /.git/.",
                "reference": "https://owasp.org/",
            },
            {
                "id": "headers.missing.content-security-policy",
                "title": "CSP absente",
                "severity": "high",
                "severity_label": "Élevée",
                "category": "Configuration HTTP",
                "description": "Aucune CSP.",
                "evidence": "en-tête absent",
                "remediation": "Déployez une CSP.",
                "reference": "",
            },
        ],
        "counts": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
        "pages": [],
        "checks": [],
    }


# --------------------------------------------------------------------------
# Module
# --------------------------------------------------------------------------


def test_normalize_accepts_known_verdicts():
    for verdict in triage.VERDICTS:
        assert triage.normalize(verdict.upper()) == verdict


def test_normalize_rejects_unknown_verdict():
    with pytest.raises(triage.TriageError):
        triage.normalize("peut-etre")


def test_entry_stamps_and_cleans_note():
    record = triage.entry("confirme", "  vérifié   à la main \n sur 3 pages ")
    assert record["verdict"] == "confirme"
    assert record["label"] == "Confirmé"
    assert record["note"] == "vérifié à la main sur 3 pages"
    assert record["updated_at"]


def test_note_length_is_bounded():
    with pytest.raises(triage.TriageError):
        triage.entry("confirme", "a" * (triage.MAX_NOTE + 1))


def test_summary_counts_untriaged_findings():
    findings = [{"verdict": "confirme"}, {}, {"verdict": "faux-positif"}]
    result = triage.summary(findings)
    assert result["counts"]["a-verifier"] == 1
    assert result["counts"]["confirme"] == 1
    assert result["triaged"] == 2
    assert result["total"] == 3


def test_rescore_ignores_false_positives_and_accepted_risks():
    findings = [
        {"severity": "critical", "category": "Exposition", "verdict": "faux-positif"},
        {"severity": "high", "category": "HTTP", "verdict": "risque-accepte"},
        {"severity": "low", "category": "HTTP", "verdict": "confirme"},
    ]
    score, grade = triage.rescore(findings)
    assert score > 90
    assert grade in {"A", "B"}


def test_merge_injects_verdicts_and_score():
    report = sample_scan()
    entries = {
        "exposure.git": triage.entry("faux-positif", "dépôt de démonstration"),
        "headers.missing.content-security-policy": triage.entry("confirme", "vu 3 fois"),
    }
    triage.merge(report, entries)

    first, second = report["findings"]
    assert first["verdict"] == "faux-positif"
    assert first["verdict_note"] == "dépôt de démonstration"
    assert second["verdict_label"] == "Confirmé"
    assert report["triage_summary"]["triaged"] == 2
    assert report["score_after_triage"] > report["score"]


def test_merge_without_entries_clears_previous_state():
    report = sample_scan()
    triage.merge(report, {"exposure.git": triage.entry("confirme")})
    triage.merge(report, {})
    assert report["findings"][0]["verdict"] == ""
    assert report["triage_summary"] == {}
    assert report["score_after_triage"] is None


# --------------------------------------------------------------------------
# Persistance
# --------------------------------------------------------------------------


def test_triage_roundtrip_in_database(temp_db):
    asyncio.run(db.init())
    asyncio.run(db.save_scan(sample_scan(), "quick"))

    entries = asyncio.run(
        db.set_triage("triage01", "exposure.git", "faux-positif", "dépôt de démo")
    )
    assert entries["exposure.git"]["label"] == "Faux positif"

    report = asyncio.run(db.get_scan("triage01"))
    finding = next(f for f in report["findings"] if f["id"] == "exposure.git")
    assert finding["verdict"] == "faux-positif"
    assert finding["verdict_note"] == "dépôt de démo"
    assert report["score_after_triage"] is not None

    asyncio.run(db.clear_triage("triage01", "exposure.git"))
    report = asyncio.run(db.get_scan("triage01"))
    assert report["triage_summary"] == {}


def test_deleting_a_scan_removes_its_triage(temp_db):
    asyncio.run(db.init())
    asyncio.run(db.save_scan(sample_scan(), "quick"))
    asyncio.run(db.set_triage("triage01", "exposure.git", "confirme"))
    assert asyncio.run(db.delete_scan("triage01")) is True
    assert asyncio.run(db.triage_for("triage01")) == {}


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------


def api_client(temp_db) -> TestClient:
    asyncio.run(db.init())
    asyncio.run(db.save_scan(sample_scan(), "quick"))
    return TestClient(main.app)


def test_api_lists_and_updates_triage(temp_db):
    client = api_client(temp_db)

    empty = client.get("/api/scans/triage01/triage").json()
    assert empty["entries"] == {}
    assert empty["summary"]["total"] == 2

    updated = client.put(
        "/api/scans/triage01/findings/exposure.git/triage",
        json={"verdict": "confirme", "note": "reproduit"},
    )
    assert updated.status_code == 200
    payload = updated.json()
    assert payload["label"] == "Confirmé"
    assert payload["summary"]["triaged"] == 1
    assert payload["score_after_triage"] is not None

    listed = client.get("/api/scans/triage01/triage").json()
    assert listed["entries"]["exposure.git"]["verdict"] == "confirme"

    cleared = client.delete("/api/scans/triage01/findings/exposure.git/triage")
    assert cleared.status_code == 200
    assert cleared.json()["cleared"] is True


def test_api_refuses_unknown_finding_and_verdict(temp_db):
    client = api_client(temp_db)

    missing = client.put(
        "/api/scans/triage01/findings/inexistant/triage", json={"verdict": "confirme"}
    )
    assert missing.status_code == 404

    invalid = client.put(
        "/api/scans/triage01/findings/exposure.git/triage", json={"verdict": "peut-etre"}
    )
    assert invalid.status_code == 422


def test_api_requires_a_known_scan(temp_db):
    asyncio.run(db.init())
    client = TestClient(main.app)
    assert client.get("/api/scans/absent/triage").status_code == 404


# --------------------------------------------------------------------------
# Exports
# --------------------------------------------------------------------------


def triaged_report() -> dict:
    report = sample_scan()
    for finding in report["findings"]:
        finding.update(standards.describe(finding["id"]))
    triage.merge(
        report,
        {
            "exposure.git": triage.entry("faux-positif", "dépôt de démonstration"),
            "headers.missing.content-security-policy": triage.entry("confirme", "vérifié"),
        },
    )
    return report


def test_exports_show_verdicts_and_score_after_triage():
    report = triaged_report()

    html_out = reporting.to_html(report)
    assert "<h2>Triage</h2>" in html_out
    assert "verdict-chip" in html_out
    assert "dépôt de démonstration" in html_out
    assert "Score retenu après triage" in html_out

    md = reporting.to_markdown(report)
    assert "## Triage" in md
    assert "**Verdict :** Faux positif — « dépôt de démonstration »" in md
    assert "après triage" in md

    sarif = reporting.to_sarif(report)
    results = sarif["runs"][0]["results"]
    suppressed = [item for item in results if item.get("suppressions")]
    assert len(suppressed) == 1
    assert suppressed[0]["ruleId"] == "exposure.git"
    assert suppressed[0]["properties"]["verdict"] == "faux-positif"
    assert sarif["runs"][0]["properties"]["triage"]["triaged"] == 2
    assert sarif["runs"][0]["properties"]["scoreAfterTriage"] == report["score_after_triage"]
