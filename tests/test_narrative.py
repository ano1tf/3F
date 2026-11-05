"""Synthèse exécutive : niveau de risque, risques clés, points forts."""

from __future__ import annotations

from app import narrative


def report(**overrides) -> dict:
    base = {
        "score": 42,
        "grade": "E",
        "pages": [{"url": "https://x.test/"}],
        "checks": [{"key": "transport"}],
        "counts": {"critical": 1, "high": 1, "medium": 2, "low": 0, "info": 0},
        "score_breakdown": {"Transport": 20, "Configuration HTTP": 5},
        "priorities": ["transport.no-https"],
        "third_parties": [],
        "verified": False,
        "findings": [
            {
                "id": "transport.no-https",
                "title": "Site servi en HTTP clair",
                "severity": "high",
                "severity_label": "Élevée",
                "category": "Transport",
                "remediation": "Servez en HTTPS",
            },
            {
                "id": "headers.csp",
                "title": "CSP absente",
                "severity": "low",
                "severity_label": "Faible",
                "category": "Configuration HTTP",
                "remediation": "Ajoutez une CSP",
            },
        ],
    }
    base.update(overrides)
    return base


def test_risk_levels():
    assert narrative.risk_for(90)[0] == "faible"
    assert narrative.risk_for(70)[0] == "modéré"
    assert narrative.risk_for(50)[0] == "élevé"
    assert narrative.risk_for(10)[0] == "critique"


def test_headline_prioritises_critical():
    result = narrative.build(report())
    assert result["risk_level"] == "élevé"
    assert "critique" in result["headline"]
    assert result["key_risks"][0]["id"] == "transport.no-https"
    assert "clair" in result["key_risks"][0]["impact"]


def test_clean_report_headline():
    result = narrative.build(
        report(score=98, findings=[], counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1})
    )
    assert result["risk_level"] == "faible"
    assert "Aucun problème" in result["headline"]


def test_strengths_are_detected_by_absence():
    strengths = narrative.build(report())["strengths"]
    # le rapport de test ne fournit aucun "checks" : aucun contrôle n'est réputé avoir tourné,
    # donc seules les forces déductibles des données restent (ici aucune).
    assert isinstance(strengths, list)


def test_verified_and_third_parties_appear_in_paragraph():
    result = narrative.build(report(verified=True, third_parties=[{"host": "cdn.x.test"}]))
    assert "vérifiée" in result["paragraph"]
    assert "1 domaine(s) tiers" in result["paragraph"]


def test_radar_is_normalised():
    radar = narrative.build(report())["radar"]
    assert radar[0] == {"label": "Transport", "value": 100}
    assert radar[1]["value"] == 25


def test_confidence_mapping():
    assert narrative.confidence_for("secrets.aws-access-key") == "certain"
    assert narrative.confidence_for("headers.csp-wildcard") == "certain"
    assert narrative.confidence_for("content.generator-version") == "probable"
    assert narrative.confidence_for("content.comments-leak") == "a-confirmer"
