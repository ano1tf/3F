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


def enriched_report() -> dict:
    report = sample_report()
    report["profile"] = "standard"
    report["verified"] = True
    report["pages"] = [
        {"url": "https://cible.test/", "status": 200, "title": "Accueil", "ms": 40},
        {"url": "https://cible.test/contact", "status": 200, "title": "Contact", "ms": 35},
    ]
    report["diff"] = {
        "available": True,
        "previous_score": 40,
        "score_delta": 22,
        "previous_at": "2026-03-01T09:00:00+00:00",
        "new": [{"id": "x", "title": "Nouveau souci", "severity": "high", "severity_label": "Élevée"}],
        "fixed": [{"id": "y", "title": "Ancien souci", "severity": "critical", "severity_label": "Critique"}],
        "summary": {"new": 1, "fixed": 1, "persistent": 3},
    }
    return report


def test_html_shows_verified_badge_pages_and_diff():
    html = reporting.to_html(enriched_report())
    assert "Domaine vérifié" in html
    assert "Pages analysées (2)" in html
    assert "https://cible.test/contact" in html
    assert "Évolution depuis la dernière analyse" in html
    assert "Nouveau souci" in html and "Ancien souci" in html
    assert "+22 pts" in html


def test_html_marks_unverified_domain():
    html = reporting.to_html(sample_report())
    assert "Domaine non vérifié" in html
    assert "Domaine vérifié" not in html


def test_html_omits_pages_block_for_single_page():
    report = sample_report()
    report["pages"] = [{"url": "https://cible.test/", "status": 200, "title": "Accueil"}]
    assert "Pages analysées" not in reporting.to_html(report)


def test_markdown_reports_verification_and_diff():
    markdown = reporting.to_markdown(enriched_report())
    assert "vérifiée ✓" in markdown
    assert "+22 pts" in markdown
    assert "Pages analysées" in markdown


def test_sarif_exposes_domain_metadata():
    sarif = reporting.to_sarif(enriched_report())
    properties = sarif["runs"][0]["properties"]
    assert properties["domainVerified"] is True
    assert properties["pagesAnalyzed"] == 2
    assert "https://cible.test/contact" in properties["pages"]


def test_html_contains_action_plan_and_third_parties():
    report = sample_report()
    report["third_parties"] = [
        {"host": "cdn.autre.test", "role": "CDN & polices", "resources": ["script"], "pages": 1},
    ]
    html = reporting.to_html(report)
    assert "Plan d'action" in html
    assert "Aujourd" in html
    assert "Dépendances tierces (1)" in html
    assert "cdn.autre.test" in html


def test_markdown_contains_action_plan():
    markdown = reporting.to_markdown(sample_report())
    assert "## Plan d'action" in markdown
    assert "Score actuel" in markdown


def test_html_includes_executive_summary_and_radar():
    report = sample_report()
    report["executive"] = {
        "risk_level": "élevé",
        "headline": "Deux failles exploitables",
        "paragraph": "Analyse de 3 pages.",
        "key_risks": [
            {
                "id": "exposure.git",
                "title": "Dépôt Git exposé",
                "severity": "critical",
                "severity_label": "Critique",
                "impact": "Le code source fuit.",
            }
        ],
        "strengths": ["SPF publié pour le domaine"],
        "radar": [
            {"label": "Exposition de fichiers", "value": 100},
            {"label": "Configuration HTTP", "value": 40},
        ],
    }
    html = reporting.to_html(report)
    assert "Synthèse" in html
    assert "Risque élevé" in html
    assert "Le code source fuit." in html
    assert "SPF publié pour le domaine" in html
    assert "<polygon" in html


def test_markdown_includes_executive_summary():
    report = sample_report()
    report["executive"] = {
        "risk_level": "critique",
        "headline": "Accès immédiat",
        "paragraph": "Un dépôt Git est public.",
        "key_risks": [
            {
                "id": "exposure.git",
                "title": "Dépôt Git exposé",
                "severity": "critical",
                "severity_label": "Critique",
                "impact": "Le code source fuit.",
            }
        ],
        "strengths": ["HTTPS actif"],
        "radar": [],
    }
    markdown = reporting.to_markdown(report)
    assert "**Risque critique**" in markdown
    assert "### Ce qui expose le plus" in markdown


def test_html_includes_situation_report_and_danger_meter():
    from app import attack

    report = sample_report()
    attack.annotate(report["findings"], "https://cible.test")
    report["executive"] = {"risk_level": "élevé", "headline": "h", "paragraph": "p",
                           "key_risks": [], "strengths": [], "radar": [], "danger_max": 10}
    html = reporting.to_html(report)
    assert "Rapport de situation" in html
    assert "Comment y arriver" in html
    assert "Ce que ça révèle" in html
    assert "danger-blocks" in html
    assert "10/10" in html


def test_sarif_security_severity_uses_danger():
    from app import attack

    report = sample_report()
    attack.annotate(report["findings"], "https://cible.test")
    sarif = reporting.to_sarif(report)
    rule = next(r for r in sarif["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "exposure.git")
    assert rule["properties"]["danger"] == 10
    assert rule["properties"]["security-severity"] == "10.0"


def test_markdown_includes_situation():
    from app import attack

    report = sample_report()
    attack.annotate(report["findings"], "https://cible.test")
    markdown = reporting.to_markdown(report)
    assert "## Rapport de situation" in markdown
    assert "danger 10/10" in markdown
    assert "**Comment y arriver :**" in markdown


def test_reports_state_what_each_finding_gives_access_to():
    """Chaque rapport nomme les actifs exposés (comptes, code, base…)."""
    from app import attack, impact

    report = sample_report()
    attack.annotate(report["findings"], report["final_url"])
    impact.annotate(report["findings"])
    reachable = impact.reachable(report["findings"])
    report["executive"] = {
        "risk_level": "élevé",
        "headline": "Un dépôt Git est public.",
        "paragraph": "Le code source est lisible par tous.",
        "key_risks": [],
        "strengths": [],
        "radar": [],
        "danger_max": 9,
        "reachable": reachable,
    }

    html_out = reporting.to_html(report)
    assert "Donne accès à" in html_out
    assert "Code source et historique Git" in html_out
    assert "peut atteindre" in html_out

    md = reporting.to_markdown(report)
    assert "**Donne accès à :** Code source et historique Git" in md
    assert "### Ce que l'attaquant peut atteindre" in md

    sarif = reporting.to_sarif(report)
    props = sarif["runs"][0]["results"][0]["properties"]
    assert "Code source et historique Git" in props["access-grants"]
    assert sarif["runs"][0]["properties"]["reachable"] == reachable
