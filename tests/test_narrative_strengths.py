"""Les points forts ne doivent jamais contredire un constat."""

from __future__ import annotations

from app.narrative import build


def report(**overrides) -> dict:
    base = {
        "score": 40,
        "final_url": "https://cible.test/",
        "target": "https://cible.test/",
        "counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
        "score_breakdown": {"Configuration HTTP": 3},
        "priorities": [],
        "third_parties": [],
        "verified": False,
        "checks": [
            {"key": "transport", "status": "ok", "findings": []},
            {"key": "headers", "status": "ok", "findings": []},
            {"key": "exposure", "status": "ok", "findings": []},
            {"key": "dns", "status": "ok", "findings": []},
            {"key": "secrets", "status": "ok", "findings": []},
            {"key": "surface", "status": "ok", "findings": []},
            {"key": "content", "status": "ok", "findings": []},
        ],
        "findings": [],
    }
    base.update(overrides)
    return base


def test_clean_https_site_gets_strengths():
    strengths = build(report())["strengths"]
    assert any("HTTPS" in item for item in strengths)
    assert any("Content-Security-Policy" in item for item in strengths)
    assert any("SPF" in item for item in strengths)


def test_weak_csp_is_not_a_strength():
    findings = [
        {
            "id": "headers.csp-wildcard",
            "title": "CSP avec joker",
            "severity": "medium",
            "severity_label": "Moyenne",
            "category": "Configuration HTTP",
        }
    ]
    strengths = build(report(findings=findings))["strengths"]
    assert not any("Content-Security-Policy" in item for item in strengths)


def test_http_target_has_no_https_strength():
    strengths = build(report(final_url="http://cible.test/", target="http://cible.test/"))["strengths"]
    assert not any("HTTPS" in item for item in strengths)
    assert not any("HSTS" in item for item in strengths)


def test_failed_check_does_not_produce_strength():
    checks = [{"key": "dns", "status": "error", "findings": []}]
    strengths = build(report(checks=checks))["strengths"]
    assert not any("SPF" in item for item in strengths)
    assert not any("DMARC" in item for item in strengths)


def test_exposed_file_removes_exposure_strength():
    findings = [
        {
            "id": "exposure.git",
            "title": "Dépôt Git exposé",
            "severity": "critical",
            "severity_label": "Critique",
            "category": "Exposition de fichiers",
        }
    ]
    strengths = build(report(findings=findings))["strengths"]
    assert not any("fichier de développement" in item for item in strengths)
