"""Notation : pénalités, rendements décroissants, note et tri des constats."""

from __future__ import annotations

from app.models import Finding, Severity
from app.scanner.scoring import (
    compute_breakdown,
    count_by_severity,
    grade_for,
    priorities,
    score_findings,
    sort_findings,
)


def make(sev: Severity, fid: str = "x", category: str = "c") -> Finding:
    return Finding(id=fid, title="t", severity=sev, category=category, description="d")


def test_no_findings_is_perfect():
    assert score_findings([]) == 100


def test_critical_penalty():
    assert score_findings([make(Severity.CRITICAL)]) == 80


def test_info_does_not_penalize():
    assert score_findings([make(Severity.INFO)]) == 100


def test_same_category_has_diminishing_returns():
    one = score_findings([make(Severity.HIGH, "a")])
    two = score_findings([make(Severity.HIGH, "a"), make(Severity.HIGH, "b")])
    assert two < one < 100
    assert (one - two) < (100 - one)  # le 2e constat coûte moins que le 1er


def test_different_categories_add_up():
    findings = [
        make(Severity.HIGH, "a", "En-têtes"),
        make(Severity.HIGH, "b", "Cookies"),
    ]
    assert score_findings(findings) == 100 - 8 - 8


def test_many_issues_still_bottom_out():
    findings = [make(Severity.CRITICAL, f"c{i}", f"cat{i}") for i in range(6)]
    assert score_findings(findings) == 0


def test_breakdown_explains_the_score():
    findings = [
        make(Severity.CRITICAL, "a", "Transport"),
        make(Severity.LOW, "b", "Transport"),
        make(Severity.MEDIUM, "c", "DNS"),
    ]
    breakdown = compute_breakdown(findings)
    assert set(breakdown) == {"Transport", "DNS"}
    assert sum(breakdown.values()) == 100 - score_findings(findings)
    assert breakdown["Transport"] > breakdown["DNS"]


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


def test_priorities_are_top_three_without_info():
    findings = [
        make(Severity.INFO, "info1"),
        make(Severity.LOW, "low1"),
        make(Severity.HIGH, "high1"),
        make(Severity.CRITICAL, "crit1"),
        make(Severity.MEDIUM, "med1"),
    ]
    top = priorities(findings)
    assert [f.id for f in top] == ["crit1", "high1", "med1"]
