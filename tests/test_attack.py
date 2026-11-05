"""Rapport de situation : chemin d'accès, révélation, dangerosité 1-10."""

from __future__ import annotations

from app import attack


def finding(fid: str, severity: str = "high", confidence: str = "certain") -> dict:
    return {"id": fid, "title": fid, "severity": severity, "confidence": confidence}


def test_danger_follows_severity_and_exploitability():
    assert attack.scenario(finding("secrets.aws-access-key", "critical"), "https://x.test")["danger"] == 10
    assert attack.scenario(finding("transport.no-https", "high"), "https://x.test")["danger"] == 8
    assert attack.scenario(finding("headers.missing.nosniff", "low"), "https://x.test")["danger"] == 2
    assert attack.scenario(finding("recon.ct-subdomains", "info"), "https://x.test")["danger"] == 1


def test_uncertain_findings_are_downgraded():
    certain = attack.scenario(finding("content.generator-version", "low", "certain"), "https://x.test")
    probable = attack.scenario(finding("content.generator-version", "low", "probable"), "https://x.test")
    assert probable["danger"] == certain["danger"] - 1


def test_danger_is_always_bounded():
    for severity in ("critical", "high", "medium", "low", "info"):
        for fid in ("exposure.git", "recon.subdomain-takeover.x", "unknown.id"):
            value = attack.scenario(finding(fid, severity), "https://x.test")["danger"]
            assert 1 <= value <= 10


def test_steps_are_concrete_and_targeted():
    result = attack.scenario(finding("exposure.git", "critical"), "https://cible.test")
    assert len(result["access"]) >= 3
    assert any("https://cible.test" in step for step in result["access"])
    assert "code source" in result["reveals"].lower()
    assert result["skill"] in {"aucune", "faible", "intermédiaire"}


def test_unknown_finding_gets_default_family():
    result = attack.scenario(finding("bidule.inconnu", "medium"), "https://x.test")
    assert result["access"]
    assert result["reveals"]


def test_danger_labels():
    assert "immédiatement" in attack.danger_label(10)
    assert "Grave" in attack.danger_label(7)
    assert "Sérieux" in attack.danger_label(5)
    assert "Limité" in attack.danger_label(3)
    assert "Faible" in attack.danger_label(1)


def test_annotate_mutates_and_sorts_situation():
    findings = [
        finding("headers.missing.nosniff", "low"),
        finding("exposure.dotenv", "critical"),
        finding("cookies.flags", "medium"),
    ]
    attack.annotate(findings, "https://cible.test")
    assert all(item["danger"] for item in findings)
    table = attack.situation_table(findings, limit=2)
    assert [row["id"] for row in table] == ["exposure.dotenv", "cookies.flags"]
    assert attack.max_danger(findings) == 10


def test_situation_table_is_serialisable():
    import json

    findings = attack.annotate([finding("exposure.git", "critical")], "https://cible.test")
    json.dumps(attack.situation_table(findings))
