"""Notation : pénalités, note et tri des constats."""

from __future__ import annotations

from app.models import Finding, Severity
from app.scanner.scoring import count_by_severity, grade_for, score_findings, sort_findings


def make(sev: Severity, fid: str = "x") -> Finding:
    return Finding(id=fid, title="t", severity=sev, category="c", description="d")


def test_no_findings_is_perfect():
    assert score_findings([]) == 100


def test_critical_penalty():
    assert score_findings([make(Severity.CRITICAL)]) == 80


def test_score_never_negative():
    findings = [make(Severity.CRITICAL, f"c{i}") for i in range(10)]
    assert score_findings(findings) == 0


def test_info_does_not_penalize():
    assert score_findings([make(Severity.INFO)]) == 100


def test_grades():
    assert grade_for(95)[0] == "A"
    assert grade_for(85)[0] == "B"
    assert grade_for(70)[0] == "C"
    assert grade_for(55)[0] == "D"
    assert grade_for(40)[0] == "E"
    assert grade_for(10)[0] == "F"


def test_counts_and_sorting():
    findings = [make(Severity.LOW, "l"), make(Severity.CRITICAL, "c"), make(Severity.MEDIUM, "m")]
    counts = count_by_severity(findings)
    assert counts["critical"] == 1 and counts["medium"] == 1 and counts["low"] == 1
    ordered = [f.severity for f in sort_findings(findings)]
    assert ordered == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]
