"""« Ce que la faille donne accès » : mapping et synthèse des actifs atteignables."""

from __future__ import annotations

from app import impact


def test_known_family_maps_to_concrete_assets():
    granted = impact.labels("exposure.terraform-state")
    assert "Infrastructure cloud" in granted
    assert "Serveurs et accès système" in granted


def test_idor_exposes_accounts_and_database():
    granted = impact.labels("access.idor-object-id")
    assert granted == ["Comptes utilisateurs", "Données personnelles", "Base de données"]


def test_most_specific_rule_wins():
    # `secrets.jwt-alg-none` avant `secrets.`
    assert "Console d'administration" in impact.labels("secrets.jwt-alg-none")
    assert "Console d'administration" not in impact.labels("secrets.something-else")


def test_unknown_family_falls_back_to_content():
    assert impact.asset_keys("inconnu.truc") == impact.DEFAULT_ASSETS
    assert impact.labels("inconnu.truc") == ["Contenu et réputation du site"]


def test_every_rule_key_exists_in_assets():
    for _prefix, keys in impact.RULES:
        for key in keys:
            assert key in impact.ASSETS, key


def test_annotate_adds_grants_to_findings():
    findings = [
        {"id": "secrets.github", "severity": "critical"},
        {"id": "headers.version-disclosure", "severity": "info"},
    ]
    impact.annotate(findings)
    assert findings[0]["grants"] == ["Code source et historique Git", "Intégrations SaaS"]
    assert findings[0]["grants_text"] == "Code source et historique Git · Intégrations SaaS"
    assert findings[1]["grants"] == ["Navigateur des visiteurs"]


def test_reachable_orders_by_severity_weight():
    findings = [
        {"id": "access.idor-object-id", "severity": "critical"},
        {"id": "headers.csp-missing", "severity": "low"},
    ]
    impact.annotate(findings)
    reachable = impact.reachable(findings)
    assert reachable[0] == "Comptes utilisateurs"
    assert "Navigateur des visiteurs" in reachable


def test_reachable_deduplicates_and_limits():
    findings = [{"id": "exposure.git", "severity": "critical"} for _ in range(4)]
    impact.annotate(findings)
    reachable = impact.reachable(findings, limit=2)
    assert len(reachable) == 2
    assert len(set(reachable)) == 2


def test_reachable_is_empty_without_findings():
    assert impact.reachable([]) == []
