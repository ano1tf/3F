"""Exports : SARIF (CI), rapport HTML autonome, Markdown."""

from __future__ import annotations

import json

from app import reporting


def sample_report() -> dict:
    return {
        "scan_id": "abc123",
        "target": "https://cible.test/",
        "final_url": "https://cible.test/",
        "started_at": "2026-03-12T10:00:00+00:00",
        "duration_ms": 1234,
        "score": 62,
        "grade": "D",
        "profile": "deep",
        "counts": {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0},
        "priorities": ["headers.missing.content-security-policy"],
        "fingerprint": {"serveur": "nginx/1.25.3", "tls_version": "TLSv1.3"},
        "checks": [
            {"key": "headers", "label": "En-têtes & cookies", "status": "ok", "findings": []},
            {"key": "tls", "label": "Certificat & TLS", "status": "error", "findings": []},
        ],
        "findings": [
            {
                "id": "exposure.git",
                "title": "Dépôt Git exposé",
                "severity": "critical",
                "severity_label": "Critique",
                "category": "Exposition de fichiers",
                "description": "Le dossier .git est accessible.",
                "evidence": "GET /.git/HEAD → HTTP 200\nref: refs/heads/main",
                "remediation": r"Bloquez /\.git/ et révoquez les secrets.",
                "reference": "https://owasp.org/",
            },
            {
                "id": "headers.missing.content-security-policy",
                "title": "Content-Security-Policy absent",
                "severity": "high",
                "severity_label": "Élevée",
                "category": "Configuration HTTP",
                "description": "Aucune CSP : XSS non mitigé.",
                "evidence": "En-tête absent",
                "remediation": "Déployez une CSP restrictive.",
                "reference": "",
            },
            {
                "id": "content.comments-leak",
                "title": "Commentaires sensibles",
                "severity": "low",
                "severity_label": "Faible",
                "category": "Fuite d'information",
                "description": "<script>alert('xss')</script> dans un commentaire.",
                "evidence": "<!-- TODO mot de passe -->",
                "remediation": "Nettoyez le HTML livré.",
                "reference": "https://owasp.org/",
            },
        ],
    }


def test_sarif_structure_is_valid():
    sarif = reporting.to_sarif(sample_report())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VulnLens"
    assert len(run["tool"]["driver"]["rules"]) == 3
    assert len(run["results"]) == 3


def test_sarif_levels_follow_severity():
    run = reporting.to_sarif(sample_report())["runs"][0]
    levels = {result["ruleId"]: result["level"] for result in run["results"]}
    assert levels["exposure.git"] == "error"
    assert levels["headers.missing.content-security-policy"] == "error"
    assert levels["content.comments-leak"] == "note"


def test_sarif_security_severity_property():
    run = reporting.to_sarif(sample_report())["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert rules["exposure.git"]["properties"]["security-severity"] == "9.5"
    assert "security" in rules["exposure.git"]["properties"]["tags"]


def test_sarif_locations_point_to_target():
    run = reporting.to_sarif(sample_report())["runs"][0]
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://cible.test/"


def test_sarif_is_serialisable():
    payload = reporting.dumps_sarif(sample_report())
    assert json.loads(payload)["version"] == "2.1.0"


def test_html_report_contains_key_sections():
    html = reporting.to_html(sample_report())
    assert "<!doctype html>" in html
    assert "Dépôt Git exposé" in html
    assert "62" in html  # score
    assert "À corriger en priorité" in html
    assert "nginx/1.25.3" in html
    assert "https://owasp.org/" in html


def test_html_report_escapes_user_content():
    html = reporting.to_html(sample_report())
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html


def test_markdown_report_lists_findings():
    markdown = reporting.to_markdown(sample_report())
    assert markdown.startswith("# Rapport VulnLens")
    assert "Dépôt Git exposé" in markdown
    assert "**Remédiation :**" in markdown
