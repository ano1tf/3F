"""Plan de remédiation : classement par effort et projection de score."""

from __future__ import annotations

from app.remediation import build_plan, effort_for, to_markdown


def finding(fid: str, severity: str = "high") -> dict:
    return {
        "id": fid,
        "title": f"Constat {fid}",
        "severity": severity,
        "severity_label": severity.capitalize(),
        "category": "cat",
        "remediation": f"Corriger {fid}",
        "reference": "",
    }


def test_effort_mapping():
    assert effort_for("headers.missing.csp", "medium") == "quick"
    assert effort_for("exposure.git", "critical") == "quick"  # critique = immédiat
    assert effort_for("transport.no-https", "high") == "sprint"
    assert effort_for("secrets.aws-access-key", "critical") == "quick"
    assert effort_for("secrets.source-map", "medium") == "project"
    assert effort_for("recon.subdomain-takeover.x", "high") == "quick"
    assert effort_for("dns.dmarc-missing", "medium") == "sprint"
    assert effort_for("inconnu", "low") == "sprint"


def test_plan_buckets_and_counts():
    report = {
        "score": 55,
        "findings": [
            finding("headers.missing.csp", "medium"),
            finding("exposure.git", "critical"),
            finding("transport.no-https", "high"),
            finding("secrets.source-map", "medium"),
        ],
    }
    plan = build_plan(report)
    assert plan["available"] is True
    assert plan["total"] == 4
    assert plan["counts"] == {"quick": 2, "sprint": 1, "project": 1}
    assert plan["buckets"]["quick"]["items"][0]["severity"] == "critical"
    assert plan["quick_wins"][0] == "exposure.git"
    assert plan["current_score"] == 55


def test_potential_gain_is_capped():
    report = {"score": 95, "findings": [finding("exposure.git", "critical")]}
    plan = build_plan(report)
    assert plan["potential_gain"] == 5
    assert plan["projected_score"] == 100


def test_empty_plan():
    plan = build_plan({"score": 100, "findings": []})
    assert plan["available"] is False
    assert "rien à planifier" in to_markdown(plan)


def test_markdown_lists_buckets():
    plan = build_plan(
        {"score": 40, "findings": [finding("headers.x", "low"), finding("exposure.git", "critical")]}
    )
    markdown = to_markdown(plan)
    assert "Aujourd'hui" in markdown
    assert "Corriger headers.x" in markdown
    assert "40/100" in markdown
